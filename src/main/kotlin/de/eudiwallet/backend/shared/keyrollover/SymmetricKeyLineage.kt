package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmKeyRef
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.findPrimaryKey
import de.eudiwallet.backend.shared.telemetry.MetricsService
import de.eudiwallet.backend.shared.telemetry.runBlockingWithTelemetry
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import java.time.Instant
import java.time.LocalDate
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicReference

data class SymmetricKeySet(
    val validKeys: List<HsmKey>,
    val primaryId: HsmKeyId,
)

class SymmetricKeyLineage<T : HsmKeyRef>(
    override val name: String,
    private val keyPrefix: String,
    private val keyClass: HsmKeyClass<T>,
    private val hsmProvider: HsmProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) : RefreshableLineage,
    KeySource<SymmetricKeySet> {
    private val log = KotlinLogging.logger {}
    private val held = AtomicReference<SymmetricKeySet?>(null)

    override fun current(): SymmetricKeySet = requireNotNull(held.get()) { "$name lineage has no resolved key" }

    fun initialize() = roll(failFast = true)

    override fun refresh() = roll(failFast = false)

    private fun roll(failFast: Boolean) {
        val keys = scanKeys()
        val primary = keys.findPrimaryKey(Instant.now())
        if (primary == null) {
            check(!failFast) { "$name primary key not found for prefix '$keyPrefix'" }
            logHoldingLastGood()
            return
        }

        val candidate = SymmetricKeySet(keys, primary.keyId)
        val previous = held.getAndSet(candidate)
        metricsService.setPrimaryKeyExpiryDate(name, primary.endDate)
        if (previous != null && previous.primaryId != candidate.primaryId) {
            log.info { "$name: rolled over ${previous.primaryId} -> ${candidate.primaryId}" }
        }
    }

    private fun logHoldingLastGood() {
        val heldSet = held.get()
        val heldPrimary = heldSet?.validKeys?.find { it.keyId == heldSet.primaryId }
        val today = Instant.now().atZone(TimeZone.getDefault().toZoneId()).toLocalDate()
        if (heldPrimary != null && heldPrimary.endDate.isBefore(today)) {
            log.error {
                "$name: held primary ${heldSet.primaryId} expired on ${heldPrimary.endDate}; no valid primary " +
                    "in HSM scan for prefix '$keyPrefix' — now signing with an expired key"
            }
        } else {
            log.warn {
                "$name: no valid primary in HSM scan for prefix '$keyPrefix'; holding still-valid " +
                    "${heldSet?.primaryId}"
            }
        }
    }

    private fun scanKeys(): List<HsmKey> =
        runBlockingWithTelemetry(ioDispatcher) {
            hsmProvider.use("Scan $name keys") { hsm ->
                hsm.findKeysByPrefix(keyPrefix, Instant.now(), keyClass)
            }
        }
}

fun stubSymKeySource(): KeySource<SymmetricKeySet> =
    KeySource {
        SymmetricKeySet(
            listOf(HsmKey(HsmKeyId(STUB), STUB, LocalDate.MIN, LocalDate.MAX)),
            HsmKeyId(STUB),
        )
    }
