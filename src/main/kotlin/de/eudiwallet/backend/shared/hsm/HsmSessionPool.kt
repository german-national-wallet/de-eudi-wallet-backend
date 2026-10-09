package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11Exception
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11Ffm
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.coroutines.cancellation.CancellationException

class HsmSessionPool(
    private val slotLabel: String,
    private val poolSize: Int,
    private val defaultBorrowTimeout: Duration,
    private val sessions: List<HsmSession>,
    private val dispatcher: CoroutineDispatcher,
    private val hsmMetrics: HsmMetrics,
    private val callerDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    internal val channel =
        Channel<HsmSession>(poolSize, onUndeliveredElement = { returnToPool(it) }).also { ch ->
            sessions.forEach { ch.trySend(it) }
        }
    private val leased = ConcurrentHashMap.newKeySet<HsmSession>()

    @Volatile
    private var closing = false

    @Suppress("TooGenericExceptionCaught")
    suspend fun <R> withSession(
        borrowTimeout: Duration? = null,
        block: (HsmSession) -> R,
    ): R =
        withContext(callerDispatcher) {
            var session = borrow(borrowTimeout ?: defaultBorrowTimeout)
            try {
                for (attempt in 1..SESSION_ATTEMPTS) {
                    try {
                        val result = withContext(dispatcher) { block(session) }
                        if (attempt > 1) hsmMetrics.countHsmSessionRetry(slotLabel, HsmRetryOutcome.RECOVERED)
                        return@withContext result
                    } catch (ex: CancellationException) {
                        throw ex
                    } catch (ex: Exception) {
                        if (!impairsSession(ex) || attempt == SESSION_ATTEMPTS) {
                            if (attempt > 1) hsmMetrics.countHsmSessionRetry(slotLabel, HsmRetryOutcome.EXHAUSTED)
                            throw ex
                        }
                        logImpairment(ex, attempt)
                        session = replaceImpaired(session, ex)
                    }
                }
                error("unreachable: every iteration returns or throws")
            } finally {
                session.release()
            }
        }

    private fun impairsSession(ex: Exception): Boolean {
        val failure = ex.pkcs11Cause() ?: return false
        hsmMetrics.countHsmPkcs11Error(slotLabel, failure)
        return failure.rv in SESSION_IMPAIRED_RVS
    }

    private fun logImpairment(
        ex: Exception,
        attempt: Int,
    ) {
        val message = "HSM session impaired, retrying on another session ($attempt of $SESSION_ATTEMPTS)"
        if (attempt == 1) log.warn(ex) { message } else log.warn { message }
    }

    private suspend fun replaceImpaired(
        impaired: HsmSession,
        impairment: Exception,
    ): HsmSession {
        val next =
            try {
                borrow(Duration.ZERO)
            } catch (_: HsmException.GetSessionFailedException) {
                hsmMetrics.countHsmSessionRetry(slotLabel, HsmRetryOutcome.NO_FREE_SESSION)
                throw impairment
            }
        impaired.release()
        return next
    }

    internal fun close(drainTimeout: Duration): Boolean {
        closing = true
        return runBlocking {
            withTimeoutOrNull(drainTimeout.toMillis()) { repeat(poolSize) { channel.receive() } }
        } != null
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    internal suspend fun borrow(borrowTimeout: Duration? = null): HsmSession {
        if (closing) throw HsmException.GetSessionFailedException("Pool is closing")
        val session =
            select<HsmSession?> {
                channel.onReceive { it }
                onTimeout((borrowTimeout ?: defaultBorrowTimeout).toMillis()) { null }
            } ?: throw HsmException.GetSessionFailedException("Timeout waiting for session")
        leased.add(session)
        return session
    }

    fun release(session: HsmSession) {
        if (!leased.remove(session)) return
        returnToPool(session)
    }

    private fun returnToPool(session: HsmSession) {
        if (channel.trySend(session).isFailure) {
            log.error { "BUG: HSM session could not be returned to the pool; pool capacity is reduced" }
        }
    }

    companion object {
        private val log = KotlinLogging.logger {}

        internal const val SESSION_ATTEMPTS = 10

        private val SESSION_IMPAIRED_RVS = setOf(Ck.CKR_SESSION_HANDLE_INVALID)

        private fun Throwable.pkcs11Cause(): Pkcs11Exception? =
            generateSequence(this) { it.cause }
                .take(MAX_CAUSE_DEPTH)
                .filterIsInstance<Pkcs11Exception>()
                .firstOrNull()

        private const val MAX_CAUSE_DEPTH = 8

        private val SHUTDOWN_DRAIN_TIMEOUT = Duration.ofSeconds(10)

        private val pools = ConcurrentHashMap<String, HsmSessionPool>()

        fun getOrCreate(
            slot: SlotConfig,
            moduleLibrary: String,
            wrappingMechanism: Long,
            borrowTimeout: Duration,
            telemetryService: TelemetryService,
            hsmMetrics: HsmMetrics,
        ): HsmSessionPool =
            pools.computeIfAbsent(slot.label) {
                create(
                    slot,
                    moduleLibrary,
                    wrappingMechanism,
                    borrowTimeout,
                    telemetryService,
                    hsmMetrics,
                )
            }

        private fun create(
            slot: SlotConfig,
            moduleLibrary: String,
            wrappingMechanism: Long,
            borrowTimeout: Duration,
            telemetryService: TelemetryService,
            hsmMetrics: HsmMetrics,
        ): HsmSessionPool {
            val pkcs11: Pkcs11
            val sessions: List<Long> =
                try {
                    pkcs11 = Pkcs11Ffm.load(moduleLibrary)
                    val slotId = findSlot(pkcs11, slot.label)
                    val primarySession = pkcs11.openSession(slotId)
                    val opened = mutableListOf(primarySession)
                    try {
                        pkcs11.login(primarySession, slot.pin.toCharArray())
                        repeat(slot.poolSize - 1) { opened.add(pkcs11.openSession(slotId)) }
                    } catch (ex: Pkcs11Exception) {
                        pkcs11.closeAll(opened)
                        throw ex
                    }
                    opened.toList()
                } catch (ex: Pkcs11Exception) {
                    throw HsmException.SessionPoolCreationFailedException(ex)
                } catch (ex: IllegalArgumentException) {
                    throw HsmException.SessionPoolCreationFailedException(ex)
                } catch (ex: IllegalStateException) {
                    throw HsmException.SessionPoolCreationFailedException(ex)
                } catch (ex: IllegalCallerException) {
                    throw HsmException.SessionPoolCreationFailedException(ex)
                }

            lateinit var pool: HsmSessionPool
            val hsmSessions =
                sessions.map {
                    HsmSession(
                        pkcs11,
                        it,
                        wrappingMechanism,
                        slot.label,
                        hsmMetrics,
                        telemetryService,
                        onRelease = { hsmSession -> pool.release(hsmSession) },
                    )
                }
            val workers =
                Executors.newFixedThreadPool(
                    slot.workerCount,
                    Thread.ofPlatform().name("hsm-${slot.label.trim()}-", 1).daemon().factory(),
                )
            val dispatcher = workers.asCoroutineDispatcher()
            pool = HsmSessionPool(slot.label, slot.poolSize, borrowTimeout, hsmSessions, dispatcher, hsmMetrics)
            Runtime.getRuntime().addShutdownHook(
                Thread {
                    if (!pool.close(SHUTDOWN_DRAIN_TIMEOUT)) {
                        log.warn {
                            "HSM sessions of slot ${slot.label} still in use after drain timeout; closing anyway"
                        }
                    }
                    pkcs11.closeAll(sessions)
                },
            )
            return pool
        }

        private fun findSlot(
            pkcs11: Pkcs11,
            slotLabel: String,
        ): Long {
            val labels = pkcs11.slotList().associateWith { pkcs11.tokenLabel(it) }
            return labels.entries.find { it.value.trim() == slotLabel.trim() }?.key
                ?: throw HsmException.SlotNotFoundException(slotLabel, labels.values.joinToString(","))
        }

        @Suppress("TooGenericExceptionCaught")
        private fun Pkcs11.closeAll(sessions: List<Long>) {
            try {
                logout(sessions.first())
            } catch (ex: Throwable) {
                log.error(ex) { "Cannot log out" }
            }
            sessions.forEach {
                try {
                    closeSession(it)
                } catch (ex: Throwable) {
                    log.error(ex) { "Cannot close session" }
                }
            }
        }
    }
}
