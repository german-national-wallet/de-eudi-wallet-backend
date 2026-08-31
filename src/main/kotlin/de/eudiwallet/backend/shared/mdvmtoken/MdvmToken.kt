package de.eudiwallet.backend.shared.mdvmtoken

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.jwt.getConfirmationKey
import de.eudiwallet.backend.shared.jwt.getUUIDClaim
import de.eudiwallet.backend.shared.jwt.validateAlgorithm
import de.eudiwallet.backend.shared.jwt.validateCertificateChain
import de.eudiwallet.backend.shared.jwt.validateEcdsaSignature
import de.eudiwallet.backend.shared.jwt.validateExpirationTime
import de.eudiwallet.backend.shared.jwt.validateIssuer
import de.eudiwallet.backend.shared.jwt.validateType
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken.Companion.MDVM_WI_ID_CLAIM
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.springframework.stereotype.Component
import java.security.interfaces.ECPublicKey
import java.text.ParseException
import java.time.Instant
import java.util.UUID

@JvmInline
@Serializable(with = MdvmAccountIdSerializer::class)
value class MdvmAccountId(
    val id: UUID,
) {
    override fun toString() = id.toString()
}

object MdvmAccountIdSerializer : KSerializer<MdvmAccountId> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("MdvmAccountId", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: MdvmAccountId,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): MdvmAccountId = MdvmAccountId(UUID.fromString(decoder.decodeString()))
}

data class MdvmToken(
    val authKey: ECPublicKey,
    val mdvmAccountId: MdvmAccountId,
    val expirationTime: Instant,
) {
    companion object {
        const val JWT_TYPE = "mdvm-token+jwt"
        const val MDVM_WI_ID_CLAIM = "mdvm_wi_id"
    }
}

@Component
class MdvmTokenParser(
    private val mdvmConfiguration: MdvmTokenConfiguration,
) {
    fun parseAndValidate(jwtString: String): MdvmToken {
        val jwt =
            try {
                SignedJWT.parse(jwtString)
            } catch (cause: ParseException) {
                throw MdvmTokenVerificationException(cause)
            }
        try {
            jwt.validateType(MdvmToken.JWT_TYPE)
            jwt.validateAlgorithm(JWSAlgorithm.ES256)
            jwt.validateIssuer(mdvmConfiguration.issuer)
            jwt.validateExpirationTime()
            val certificate = jwt.validateCertificateChain(mdvmConfiguration.mdvmRootCert)
            jwt.validateEcdsaSignature(certificate.publicKey as ECPublicKey)
            return MdvmToken(
                authKey = jwt.getConfirmationKey(),
                mdvmAccountId = MdvmAccountId(jwt.getUUIDClaim(MDVM_WI_ID_CLAIM)),
                expirationTime = jwt.jwtClaimsSet.expirationTime.toInstant(),
            )
        } catch (e: JwtException) {
            throw MdvmTokenVerificationException(e)
        } catch (e: ClassCastException) {
            throw MdvmTokenVerificationException(e)
        }
    }
}
