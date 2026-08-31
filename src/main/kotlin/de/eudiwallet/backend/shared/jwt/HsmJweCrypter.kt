package de.eudiwallet.backend.shared.jwt

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWECryptoParts
import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.jca.JWEJCAContext
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.EncryptedData
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.HsmSession
import org.springframework.stereotype.Component

private class HsmJweEncrypter(
    private val hsm: HsmSession,
) : JWEEncrypter {
    private val jcaContext = JWEJCAContext().also { it.provider = BOUNCY_CASTLE_PROVIDER }

    override fun encrypt(
        header: JWEHeader?,
        clearText: ByteArray?,
        aad: ByteArray?,
    ): JWECryptoParts {
        if (header?.algorithm != JWEAlgorithm.DIR) {
            throw JOSEException("Unsupported JWE algorithm ${header?.algorithm}")
        }
        if (header.encryptionMethod != EncryptionMethod.A256GCM) {
            throw JOSEException("Unsupported JWE encryption method ${header.encryptionMethod}")
        }
        val encryptionKeyId = header.keyID ?: throw JOSEException("KeyId is not specified")

        return try {
            val encryptionKey = hsm.getKey(HsmKeyId(encryptionKeyId), HsmKeyClass.Aes)
            val cipherData = hsm.encrypt(encryptionKey, clearText, aad)
            JWECryptoParts(
                header,
                null,
                Base64URL.encode(cipherData.iv),
                Base64URL.encode(cipherData.cipherText),
                Base64URL.encode(cipherData.authTag),
            )
        } catch (ex: HsmException) {
            throw JOSEException(ex)
        }
    }

    override fun supportedJWEAlgorithms(): Set<JWEAlgorithm?> = setOf(JWEAlgorithm.DIR)

    override fun supportedEncryptionMethods(): Set<EncryptionMethod?> = setOf(EncryptionMethod.A256GCM)

    override fun getJCAContext(): JWEJCAContext = jcaContext
}

private class HsmJweDecrypter(
    private val hsm: HsmSession,
) : JWEDecrypter {
    private val jcaContext = JWEJCAContext().also { it.provider = BOUNCY_CASTLE_PROVIDER }

    override fun decrypt(
        header: JWEHeader?,
        encryptedKey: Base64URL?,
        iv: Base64URL?,
        cipherText: Base64URL?,
        authTag: Base64URL?,
        aad: ByteArray?,
    ): ByteArray {
        if (header?.algorithm != JWEAlgorithm.DIR) {
            throw JOSEException("Unsupported JWE algorithm ${header?.algorithm}")
        }
        if (header.encryptionMethod != EncryptionMethod.A256GCM) {
            throw JOSEException("Unsupported JWE encryption method ${header.encryptionMethod}")
        }
        val encryptionKeyId = header.keyID ?: throw JOSEException("KeyId is not specified")

        return try {
            val data =
                EncryptedData(
                    requireNotNull(cipherText).decode(),
                    requireNotNull(authTag).decode(),
                    requireNotNull(iv).decode(),
                )
            val decryptionKey = hsm.getKey(HsmKeyId(encryptionKeyId), HsmKeyClass.Aes)
            hsm.decrypt(decryptionKey, data, aad)
        } catch (ex: HsmException) {
            throw JOSEException(ex)
        }
    }

    override fun supportedJWEAlgorithms(): Set<JWEAlgorithm?> = setOf(JWEAlgorithm.DIR)

    override fun supportedEncryptionMethods(): Set<EncryptionMethod?> = setOf(EncryptionMethod.A256GCM)

    override fun getJCAContext(): JWEJCAContext = jcaContext
}

@Component
class HsmJweCrypter(
    private val hsmProvider: HsmProvider,
) {
    suspend fun encrypt(jwt: EncryptedJWT) =
        try {
            hsmProvider.use("Encrypt ${jwt.jwtType}") { hsm ->
                jwt.encrypt(HsmJweEncrypter(hsm))
            }
        } catch (e: JOSEException) {
            throw JwtException.EncryptionFailure(jwt.jwtType, e)
        }

    suspend fun decrypt(jwt: EncryptedJWT) =
        try {
            hsmProvider.use("Decrypt ${jwt.jwtType}") { hsm ->
                jwt.decrypt(HsmJweDecrypter(hsm))
            }
        } catch (e: JOSEException) {
            throw JwtException.DecryptionFailure(jwt.jwtType, e)
        }
}
