package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmWrappedPrvk
import de.eudiwallet.backend.shared.jwt.HsmJweCrypter
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.jwt.getBase64DecodedClaim
import de.eudiwallet.backend.shared.jwt.getStringClaim
import de.eudiwallet.backend.shared.jwt.getUUIDClaim
import de.eudiwallet.backend.shared.jwt.validateIssuer
import de.eudiwallet.backend.shared.jwt.validateType
import de.eudiwallet.backend.shared.jwt.validatedKeyId
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import java.text.ParseException
import java.time.Instant
import java.util.Date

data class RwscaBoundWrappedPrvk(
    val rwscaAccountId: RwscaAccountId,
    val hsmWrappedPrvk: HsmWrappedPrvk,
    val masterKeyId: HsmKeyId,
)

@Component
class RwscaBoundWrappedPrvkBuilder(
    @Qualifier("rwscaAeadSymLineage")
    private val rwscaAeadSymLineage: KeySource<SymmetricKeySet>,
    private val rwscaConfiguration: RwscaConfiguration,
    private val jweCrypter: HsmJweCrypter,
) {
    companion object {
        const val JWT_TYPE = "rwsca-bound-wrapped-key+jwe"
        const val RWSCA_ACCOUNT_ID_CLAIM = "rwsca_account_id"
        const val RWSCA_MASTER_KEY_ID_CLAIM = "master_key_id"
        const val RWSCD_WRAPPED_KEY_CLAIM = "rwscd_wrapped_key"
    }

    fun create(
        rwscaAccountId: RwscaAccountId,
        hsmWrappedPrvk: HsmWrappedPrvk,
        masterKeyId: HsmKeyId,
    ): RwscaBoundWrappedPrvk = RwscaBoundWrappedPrvk(rwscaAccountId, hsmWrappedPrvk, masterKeyId)

    suspend fun RwscaBoundWrappedPrvk.serializeToJwe(): String {
        val aeadPrimaryId = rwscaAeadSymLineage.current().primaryId

        val header =
            JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .type(JOSEObjectType(JWT_TYPE))
                .keyID(aeadPrimaryId.value)
                .issuer(rwscaConfiguration.issuer)

        val claimsSet =
            JWTClaimsSet.Builder()
                .issueTime(Date.from(Instant.now()))
                .claim(RWSCA_ACCOUNT_ID_CLAIM, rwscaAccountId.toString())
                .claim(RWSCA_MASTER_KEY_ID_CLAIM, masterKeyId.value)
                .claim(RWSCD_WRAPPED_KEY_CLAIM, hsmWrappedPrvk.bytes.toBase64())

        val jwt = EncryptedJWT(header.build(), claimsSet.build())

        jweCrypter.encrypt(jwt)
        return jwt.serialize()
    }

    suspend fun parseAndDecrypt(jweString: String): RwscaBoundWrappedPrvk {
        val jwt =
            try {
                EncryptedJWT.parse(jweString)
            } catch (parseException: ParseException) {
                throw WrappedPrvkVerificationException(cause = parseException)
            }
        try {
            jwt.validateType(JWT_TYPE)
            jwt.validatedKeyId(rwscaAeadSymLineage.current().validKeys.map { it.keyId.value })
            jweCrypter.decrypt(jwt)
            jwt.validateIssuer(rwscaConfiguration.issuer)
            val masterKeyId = jwt.getStringClaim(RWSCA_MASTER_KEY_ID_CLAIM)
            val rwscaAccountId = RwscaAccountId(jwt.getUUIDClaim(RWSCA_ACCOUNT_ID_CLAIM))
            val hsmWrappedPrvk = HsmWrappedPrvk(jwt.getBase64DecodedClaim(RWSCD_WRAPPED_KEY_CLAIM))
            return RwscaBoundWrappedPrvk(rwscaAccountId, hsmWrappedPrvk, HsmKeyId(masterKeyId))
        } catch (jwtException: JwtException) {
            throw WrappedPrvkVerificationException(cause = jwtException)
        } catch (hsmException: HsmException) {
            throw WrappedPrvkVerificationException(cause = hsmException)
        }
    }
}
