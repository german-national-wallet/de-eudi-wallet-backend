package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.crypto.toBase64
import org.springframework.stereotype.Component
import java.security.SecureRandom

private const val CHALLENGE_LENGTH = 32

@Component
@Suppress("UnusedParameter")
class RaspVerifier(
    config: MdvmConfiguration,
) {
    private val keyIds = config.raspKeys.map { it.id }.toSet()
    private val random = SecureRandom()

    fun createChallenge(
        keyId: String,
        authChallenge: String,
    ): String {
        requireKnown(keyId)
        return ByteArray(CHALLENGE_LENGTH).also { random.nextBytes(it) }.toBase64()
    }

    fun verifyResponse(
        keyId: String?,
        authChallenge: String,
        response: String?,
        skipIntegrityChecks: SkipIntegrityChecks,
    ) {
        if (keyId == null || skipIntegrityChecks.skipKeyAttestation) return
        if (response == null) throw RaspException.InvalidResponse()
        requireKnown(keyId)
    }

    private fun requireKnown(keyId: String) {
        if (keyId !in keyIds) throw RaspException.UnknownKey(keyId)
    }
}
