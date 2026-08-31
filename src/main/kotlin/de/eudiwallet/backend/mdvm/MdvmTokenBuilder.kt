package de.eudiwallet.backend.mdvm

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.crypto.toECJWK
import de.eudiwallet.backend.shared.jwt.CONFIRMATION_CLAIM
import de.eudiwallet.backend.shared.jwt.HsmEcdsaSigner
import de.eudiwallet.backend.shared.jwt.JWK_FIELD
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken.Companion.MDVM_WI_ID_CLAIM
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Date

@Component
class MdvmTokenBuilder(
    private val mdvmConfiguration: MdvmConfiguration,
    @Qualifier("mdvmAttestationLineage")
    private val mdvmAttestationLineage: KeySource<CertifiedKey>,
    private val ecdsaSigner: HsmEcdsaSigner,
) {
    fun create(
        attestedKey: ECPublicKey,
        mdvmAccountId: MdvmAccountId,
    ): MdvmToken =
        MdvmToken(
            authKey = attestedKey,
            mdvmAccountId = mdvmAccountId,
            expirationTime = Instant.now().plus(mdvmConfiguration.tokenExpireAfter),
        )

    suspend fun MdvmToken.serializeToJwt(): String {
        val certifiedKey = mdvmAttestationLineage.current()

        val header =
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(MdvmToken.JWT_TYPE))
                .x509CertChain(certifiedKey.chain.map { Base64(it.encoded.toBase64()) })
                .build()

        val claimsSet =
            JWTClaimsSet.Builder()
                .issuer(mdvmConfiguration.issuer)
                .issueTime(Date.from(Instant.now()))
                .claim(CONFIRMATION_CLAIM, mapOf(JWK_FIELD to authKey.toECJWK().toJSONObject()))
                .claim(MDVM_WI_ID_CLAIM, mdvmAccountId.toString())
                .expirationTime(Date.from(expirationTime))
                .build()

        val jwt = SignedJWT(header, claimsSet)

        ecdsaSigner.sign(jwt, certifiedKey.keyId)

        return jwt.serialize()
    }
}
