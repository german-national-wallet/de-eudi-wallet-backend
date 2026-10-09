package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.certObjectKey
import de.eudiwallet.backend.shared.hsm.findActiveKeys
import de.eudiwallet.backend.shared.hsm.findNextKey
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
import de.eudiwallet.backend.shared.telemetry.runBlockingWithTelemetry
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

private const val POP_CHALLENGE_BYTES = 32

data class CertifiedKey(
    val keyId: HsmKeyId,
    val chain: List<X509Certificate>,
    val expiresAt: Instant,
) {
    fun heldKey(): HeldKey = HeldKey(keyId, expiresAt)
}

class AsymmetricSigningLineage(
    override val name: String,
    private val keyPrefix: String,
    private val slotLabel: String,
    private val trustAnchor: X509Certificate,
    private val hsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val keyRolloverMetrics: KeyRolloverMetrics,
    private val clock: Clock = Clock.systemDefaultZone(),
) : RefreshableLineage,
    KeySource<CertifiedKey> {
    private val log = KotlinLogging.logger {}
    private val secureRandom = SecureRandom()

    private val held = AtomicReference<CertifiedKey?>(null)

    override fun current(): CertifiedKey {
        val key = requireNotNull(held.get()) { "$name lineage has no resolved key" }
        val heldKey = key.heldKey()
        if (heldKey.isExpiredAt(Instant.now(clock))) throw ExpiredKeyException(name, heldKey)
        return key
    }

    fun initialize() = roll(failFast = true)

    override fun refresh() = roll(failFast = false)

    private fun roll(failFast: Boolean) {
        val keys = scanKeys()
        val now = Instant.now(clock)
        if (keys.isNotEmpty()) keyRolloverMetrics.setNextKey(name, keys.findNextKey(now))
        val candidates = keys.findActiveKeys(now)
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
        val heldKey = held.get()?.heldKey()
        val holdUsable = heldKey != null && !heldKey.isExpiredAt(Instant.now(clock))
        var firstFailure: Exception? = null
        for (candidate in candidates) {
            val resolved =
                try {
                    val certified = resolveCertifiedKey(candidate)
                    signProofOfPossession(certified)
                    check(!certified.heldKey().isExpiredAt(Instant.now(clock))) {
                        "${candidate.keyId} resolved but already expired at ${certified.expiresAt}"
                    }
                    certified
                } catch (e: Exception) {
                    firstFailure = firstFailure ?: e
                    log.warn(e) { "$name (prefix '$keyPrefix'): ${candidate.keyId} did not resolve" }
                    null
                }
            if (resolved != null) {
                commit(resolved, candidate)
                return
            }
            if (candidate.keyId == heldKey?.keyId && holdUsable) break
        }
        if (failFast) throw checkNotNull(firstFailure) { "$name has no resolvable valid key" }
        logHoldingLastGood("no valid key resolved")
    }

    private fun commit(
        resolved: CertifiedKey,
        key: HsmKey,
    ) {
        val previous = held.getAndSet(resolved)
        if (resolved == previous) return
        keyRolloverMetrics.setPrimaryKeyExpiryDate(name, key, resolved.expiresAt.lastUsableDay())
        log.info {
            "$name: adopted ${key.label} (${resolved.keyId.value}), expires ${resolved.expiresAt}, " +
                "replacing ${previous?.keyId?.value}"
        }
    }

    private fun logHoldingLastGood(reason: String) {
        val heldKey = held.get()?.heldKey()
        if (heldKey != null && heldKey.isExpiredAt(Instant.now(clock))) {
            log.error {
                "$name: $reason; held key ${heldKey.keyId} expired at ${heldKey.expiresAt} — refusing to sign " +
                    "until a valid key resolves"
            }
        } else {
            log.warn { "$name: $reason; holding still-valid ${heldKey?.keyId}" }
        }
    }

    private fun resolveCertifiedKey(key: HsmKey): CertifiedKey {
        val chain =
            s3CertChainProvider.getVerifiedChain(key.certObjectKey(slotLabel), trustAnchor)
                .filterNot { it.encoded.contentEquals(trustAnchor.encoded) }
        val certificatesExpireAt = (chain + trustAnchor).minOf { it.notAfter.toInstant() }
        return CertifiedKey(key.keyId, chain, minOf(key.expiresAt(), certificatesExpireAt))
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
                hsm.findKeysByPrefix(keyPrefix, Instant.now(clock), HsmKeyClass.EcPrivate)
            }
        }
}

fun stubCertifiedKeySource(): KeySource<CertifiedKey> =
    KeySource { CertifiedKey(HsmKeyId(STUB), emptyList(), Instant.MAX) }
