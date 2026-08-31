package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.certObjectKey
import de.eudiwallet.backend.shared.hsm.findActiveKeys
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
import de.eudiwallet.backend.shared.telemetry.MetricsService
import de.eudiwallet.backend.shared.telemetry.runBlockingWithTelemetry
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.LocalDate
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicReference

private const val POP_CHALLENGE_BYTES = 32

data class CertifiedKey(
    val keyId: HsmKeyId,
    val chain: List<X509Certificate>,
    val endDate: LocalDate,
)

class AsymmetricSigningLineage(
    override val name: String,
    private val keyPrefix: String,
    private val slotLabel: String,
    private val trustAnchor: X509Certificate,
    private val hsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) : RefreshableLineage,
    KeySource<CertifiedKey> {
    private val log = KotlinLogging.logger {}
    private val secureRandom = SecureRandom()

    private val held = AtomicReference<CertifiedKey?>(null)

    override fun current(): CertifiedKey = requireNotNull(held.get()) { "$name lineage has no resolved key" }

    fun initialize() = roll(failFast = true)

    override fun refresh() = roll(failFast = false)

    private fun roll(failFast: Boolean) {
        val candidates = scanKeys().findActiveKeys(Instant.now())
        if (candidates.isEmpty()) {
            check(!failFast) { "$name has no valid key in the HSM scan for prefix '$keyPrefix'" }
            logHoldingLastGood("no valid key in HSM scan for prefix '$keyPrefix'")
            return
        }
        adoptNewestResolvable(candidates, failFast)
    }

    @Suppress("TooGenericExceptionCaught")
    private fun adoptNewestResolvable(
        candidates: List<HsmKey>,
        failFast: Boolean,
    ) {
        val heldKeyId = held.get()?.keyId
        var firstFailure: Exception? = null
        for (candidate in candidates) {
            if (candidate.keyId == heldKeyId) return
            val resolved =
                try {
                    resolveCertifiedKey(candidate).also(::signProofOfPossession)
                } catch (e: Exception) {
                    firstFailure = firstFailure ?: e
                    log.warn(e) {
                        "$name (prefix '$keyPrefix'): ${candidate.keyId} did not resolve; " +
                            "falling back to the next-newest valid key"
                    }
                    continue
                }
            val previous = held.getAndSet(resolved)
            metricsService.setPrimaryKeyExpiryDate(name, resolved.endDate)
            log.info { "$name: rolled over ${previous?.keyId} -> ${resolved.keyId}" }
            return
        }
        if (failFast) throw checkNotNull(firstFailure) { "$name has no resolvable valid key" }
        logHoldingLastGood("no valid key resolved")
    }

    private fun logHoldingLastGood(reason: String) {
        val heldKey = held.get()
        val today = Instant.now().atZone(TimeZone.getDefault().toZoneId()).toLocalDate()
        if (heldKey != null && heldKey.endDate.isBefore(today)) {
            log.error {
                "$name: $reason; held key ${heldKey.keyId} expired on ${heldKey.endDate} — now signing with an " +
                    "expired key"
            }
        } else {
            log.warn { "$name: $reason; holding still-valid ${heldKey?.keyId}" }
        }
    }

    private fun resolveCertifiedKey(key: HsmKey): CertifiedKey {
        val chain = s3CertChainProvider.getVerifiedChain(key.certObjectKey(slotLabel), trustAnchor)
        return CertifiedKey(key.keyId, chain.filterNot { it.encoded.contentEquals(trustAnchor.encoded) }, key.endDate)
    }

    private fun signProofOfPossession(candidate: CertifiedKey) {
        val challenge = ByteArray(POP_CHALLENGE_BYTES).also(secureRandom::nextBytes)
        val signature =
            runBlockingWithTelemetry(ioDispatcher) {
                hsmProvider.use("Sign $name proof-of-possession") { hsm ->
                    val privateKey = hsm.getKey(candidate.keyId, HsmKeyClass.EcPrivate)
                    hsm.signEcdsaSha256(privateKey, challenge).toDer()
                }
            }
        val verifies =
            Signature.getInstance("SHA256withECDSA", BOUNCY_CASTLE_PROVIDER).run {
                initVerify(candidate.chain.first().publicKey)
                update(challenge)
                verify(signature)
            }
        require(verifies) { "$name leaf certificate public key does not match the HSM signing key ${candidate.keyId}" }
    }

    private fun scanKeys(): List<HsmKey> =
        runBlockingWithTelemetry(ioDispatcher) {
            hsmProvider.use("Scan $name keys") { hsm ->
                hsm.findKeysByPrefix(keyPrefix, Instant.now(), HsmKeyClass.EcPrivate)
            }
        }
}

fun stubCertifiedKeySource(): KeySource<CertifiedKey> =
    KeySource { CertifiedKey(HsmKeyId(STUB), emptyList(), LocalDate.MAX) }
