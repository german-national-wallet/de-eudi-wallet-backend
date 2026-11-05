package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import org.springframework.stereotype.Component
import java.text.ParseException

class PinSignatureDecryptionException(
    explanation: String,
    cause: Throwable? = null,
) : SignatureVerificationException(explanation, cause)

const val PIN_SIGNATURE_JWE_TYPE = "rwsca-pin-signature+jwe"
const val PIN_PUBK_JWE_TYPE = "rwsca-pin-pubk+jwe"

@Component
class PinSignatureDecrypter(
    private val pinEncryptionKey: PinEncryptionKey,
) {
    fun decryptSignature(encrypted: ByteArray): ByteArray = decrypt(encrypted.decodeToString(), PIN_SIGNATURE_JWE_TYPE)

    fun decryptPinPubk(encrypted: String): ByteArray = decrypt(encrypted, PIN_PUBK_JWE_TYPE)

    private fun decrypt(
        encrypted: String,
        type: String,
    ): ByteArray {
        val jwe =
            try {
                JWEObject.parse(encrypted)
            } catch (ex: ParseException) {
                throw PinSignatureDecryptionException("$type is not a JWE", ex)
            }
        requireExpectedHeader(jwe.header, type)
        val decrypter =
            ECDHDecrypter(pinEncryptionKey.privateKey).also { it.jcaContext.provider = BOUNCY_CASTLE_PROVIDER }
        return try {
            jwe.decrypt(decrypter)
            jwe.payload.toBytes()
        } catch (ex: JOSEException) {
            throw PinSignatureDecryptionException("$type does not decrypt", ex)
        }
    }

    private fun requireExpectedHeader(
        header: JWEHeader,
        type: String,
    ) {
        fun reject(reason: String): Nothing = throw PinSignatureDecryptionException("$type $reason")

        if (header.type?.type != type) reject("typ is ${header.type}")
        if (header.algorithm != JWEAlgorithm.ECDH_ES) reject("alg is not ECDH-ES")
        if (header.encryptionMethod != EncryptionMethod.A256GCM) reject("enc is not A256GCM")
        if (header.keyID != PIN_ENCRYPTION_KID) reject("kid is unknown")
        if (header.compressionAlgorithm != null) reject("is compressed")
        if (!header.criticalParams.isNullOrEmpty()) reject("has critical parameters")
    }
}
