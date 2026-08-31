package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.jwt.HsmHmacSigner
import de.eudiwallet.backend.shared.jwt.HsmHmacVerifier
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.jwt.getUUIDClaim
import de.eudiwallet.backend.shared.jwt.validateExpirationTime
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

data class PinSessionToken(
    val expirationTime: Instant,
    val rwscaAccountId: RwscaAccountId,
)

@Component
class PinSessionTokenBuilder(
    @Qualifier("rwscaPinSymLineage")
    private val rwscaPinSymLineage: KeySource<SymmetricKeySet>,
    private val rwscaConfiguration: RwscaConfiguration,
    private val hsmSigner: HsmHmacSigner,
    private val hsmVerifier: HsmHmacVerifier,
) {
    companion object {
        const val JWT_TYPE = "rwsca-pin-session-token+jwt"
        const val RWSCA_ACCOUNT_ID_CLAIM = "rwsca_account_id"
    }

    fun create(rwscaAccountId: RwscaAccountId): PinSessionToken =
        PinSessionToken(
            Instant.now().plus(rwscaConfiguration.pinSessionTokenExpireAfter),
            rwscaAccountId,
        )

    suspend fun parseAndValidate(jwtString: String): PinSessionToken {
        val jwt =
            try {
                SignedJWT.parse(jwtString)
            } catch (cause: ParseException) {
                throw PinSessionTokenVerificationException(cause)
            }
        try {
            jwt.validateType(JWT_TYPE)
            jwt.validateExpirationTime()
            jwt.validateIssuer(rwscaConfiguration.issuer)
            val keyId = jwt.validatedKeyId(rwscaPinSymLineage.current().validKeys.map { it.keyId.value })
            hsmVerifier.verify(jwt, HsmKeyId(keyId))
            return PinSessionToken(
                jwt.jwtClaimsSet.expirationTime.toInstant(),
                RwscaAccountId(jwt.getUUIDClaim(RWSCA_ACCOUNT_ID_CLAIM)),
            )
        } catch (jwtException: JwtException) {
            throw PinSessionTokenVerificationException(jwtException)
        }
    }

    suspend fun PinSessionToken.serializeToJwt(): String {
        val primaryId = rwscaPinSymLineage.current().primaryId

        val header =
            JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType(JWT_TYPE))
                .keyID(primaryId.value)
                .build()

        val claimsSet =
            JWTClaimsSet.Builder()
                .issuer(rwscaConfiguration.issuer)
                .issueTime(Date.from(Instant.now()))
                .claim(RWSCA_ACCOUNT_ID_CLAIM, rwscaAccountId.toString())
                .expirationTime(Date.from(expirationTime))
                .build()

        val jwt = SignedJWT(header, claimsSet)

        hsmSigner.sign(jwt, primaryId)

        return jwt.serialize()
    }
}
