package de.eudiwallet.backend.shared.hsm

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

class HsmSessionPool(
    private val poolSize: Int,
    private val defaultBorrowTimeout: Duration,
    private val sessions: List<HsmSession>,
    private val dispatcher: CoroutineDispatcher,
    private val callerDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    internal val channel =
        Channel<HsmSession>(poolSize, onUndeliveredElement = { returnToPool(it) }).also { ch ->
            sessions.forEach { ch.trySend(it) }
        }
    private val leased = ConcurrentHashMap.newKeySet<HsmSession>()

    @Volatile
    private var closing = false

    suspend fun <R> withSession(
        borrowTimeout: Duration? = null,
        block: (HsmSession) -> R,
    ): R =
        withContext(callerDispatcher) {
            val session = borrow(borrowTimeout)
            try {
                withContext(dispatcher) { block(session) }
            } finally {
                session.release()
            }
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

        private val SHUTDOWN_DRAIN_TIMEOUT = Duration.ofSeconds(10)

        private val pools = ConcurrentHashMap<String, HsmSessionPool>()

        fun getOrCreate(
            slot: SlotConfig,
            moduleLibrary: String,
            wrappingMechanism: Long,
            borrowTimeout: Duration,
            telemetryService: TelemetryService,
        ): HsmSessionPool =
            pools.computeIfAbsent(slot.label) {
                create(slot, moduleLibrary, wrappingMechanism, borrowTimeout, telemetryService)
            }

        private fun create(
            slot: SlotConfig,
            moduleLibrary: String,
            wrappingMechanism: Long,
            borrowTimeout: Duration,
            telemetryService: TelemetryService,
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
                        telemetryService,
                        onRelease = { hsmSession -> pool.release(hsmSession) },
                    )
                }
            val workers =
                Executors.newFixedThreadPool(
                    slot.workerCount,
                    Thread.ofPlatform().name("hsm-${slot.label.trim()}-", 1).daemon().factory(),
                )
            pool = HsmSessionPool(slot.poolSize, borrowTimeout, hsmSessions, workers.asCoroutineDispatcher())
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
