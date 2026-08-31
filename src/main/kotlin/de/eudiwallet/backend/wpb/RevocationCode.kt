package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.crypto.toSha256
import org.ngengine.bech32.Bech32
import org.ngengine.bech32.Bech32EncodingException
import org.ngengine.bech32.Bech32Exception
import org.springframework.stereotype.Component
import java.nio.ByteBuffer
import java.security.SecureRandom

private const val REVOCATION_SECRET_BYTES = 16

private val BECH32_HRP = "rev".toByteArray()

class RevocationCode(
    val code: String,
    val hash: ByteArray,
) {
    override fun toString(): String = "RevocationCode(hash=${hash.contentToString()})"
}

@Component
class RevocationCodeGenerator {
    private val secureRandom: SecureRandom = SecureRandom()

    fun generate(): RevocationCode {
        val secret = ByteArray(REVOCATION_SECRET_BYTES).also(secureRandom::nextBytes)
        return RevocationCode(secret.bech32(), secret.toSha256())
    }

    private fun ByteArray.bech32() =
        try {
            Bech32.bech32Encode(BECH32_HRP, ByteBuffer.wrap(this))
        } catch (ex: Bech32EncodingException) {
            throw RevocationCodeGenerationException(ex)
        }
}

fun revocationCodeToHash(code: String): ByteArray =
    try {
        Bech32.bech32Decode(code).array().toSha256()
    } catch (ex: Bech32Exception) {
        throw RevocationCodeNotFoundException(ex)
    }
