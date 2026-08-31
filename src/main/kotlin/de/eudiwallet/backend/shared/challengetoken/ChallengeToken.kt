package de.eudiwallet.backend.shared.challengetoken

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.jwt.HsmHmacSigner
import de.eudiwallet.backend.shared.jwt.HsmHmacVerifier
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.jwt.validateIssueTime
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
import java.util.UUID

class ChallengeVerificationException(
    cause: Throwable,
) : RuntimeException("Challenge verification failed", cause)

@Component
class ChallengeTokenBuilder(
    @Qualifier("challengeSymkLineage")
    private val challengeSymkLineage: KeySource<SymmetricKeySet>,
    private val config: ChallengeConfiguration,
    private val hsmSigner: HsmHmacSigner,
    private val hsmVerifier: HsmHmacVerifier,
) {
    companion object {
        const val JWT_TYPE = "auth-challenge+jwt"
        const val NONCE_CLAIM = "nonce"
    }

    suspend fun createAndSerializeToJwt(issuer: String): String {
        val primaryId = challengeSymkLineage.current().primaryId

        val header =
            JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType(JWT_TYPE))
                .keyID(primaryId.value)
                .build()

        val claimsSet =
            JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim(NONCE_CLAIM, UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .build()

        val jwt = SignedJWT(header, claimsSet)

        hsmSigner.sign(jwt, primaryId)

        return jwt.serialize()
    }

    suspend fun parseAndValidate(
        jwtString: String,
        issuer: String,
    ) {
        try {
            val jwt = SignedJWT.parse(jwtString)
            jwt.validateType(JWT_TYPE)
            jwt.validateIssuer(issuer)
            val keyId = jwt.validatedKeyId(challengeSymkLineage.current().validKeys.map { it.keyId.value })
            jwt.validateIssueTime(config.challengeExpireAfter)
            hsmVerifier.verify(jwt, HsmKeyId(keyId))
        } catch (e: JwtException) {
            throw ChallengeVerificationException(e)
        } catch (e: ParseException) {
            throw ChallengeVerificationException(e)
        }
    }
}
