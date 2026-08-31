package de.eudiwallet.backend.wpb

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
import de.eudiwallet.backend.statuslist.StatusReference
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Date

@Component
class WalletInstanceAttestationBuilder(
    private val wpbConfiguration: WpbConfiguration,
    @Qualifier("wpbWiaAuthLineage")
    private val wpbWiaAuthLineage: KeySource<CertifiedKey>,
    private val ecdsaSigner: HsmEcdsaSigner,
) {
    companion object {
        const val JWT_TYPE = "oauth-client-attestation+jwt"
        const val CLIENT_STATUS_CLAIM = "client_status"
        const val WALLET_NAME_CLAIM = "wallet_name"
        const val WALLET_VERSION_CLAIM = "wallet_version"
        const val WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM = "wallet_solution_certification_information"
        const val WALLET_LINK_CLAIM = "wallet_link"
    }

    suspend fun createAndSerializeToJwt(
        authKey: ECPublicKey,
        statusReference: StatusReference,
    ): String {
        val certifiedKey = wpbWiaAuthLineage.current()

        val header =
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(JWT_TYPE))
                .x509CertChain(certifiedKey.chain.map { Base64(it.encoded.toBase64()) })

        val now = Instant.now()

        val claimsSet =
            JWTClaimsSet.Builder()
                .issuer(wpbConfiguration.issuer)
                .subject(wpbConfiguration.clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(wpbConfiguration.wiaExpireAfter)))
                .claim(CONFIRMATION_CLAIM, mapOf(JWK_FIELD to authKey.toECJWK().toJSONObject()))
                .claim(CLIENT_STATUS_CLAIM, statusReference.toClaim())
                .claim(WALLET_NAME_CLAIM, wpbConfiguration.walletName)
                .claim(WALLET_VERSION_CLAIM, wpbConfiguration.walletVersion)
                .claim(
                    WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM,
                    wpbConfiguration.walletSolutionCertificationInformation,
                )
                .claim(WALLET_LINK_CLAIM, wpbConfiguration.walletLink)

        val jwt = SignedJWT(header.build(), claimsSet.build())

        ecdsaSigner.sign(jwt, certifiedKey.keyId)
        return jwt.serialize()
    }
}

private fun StatusReference.toClaim(): Map<String, Any> =
    mapOf(
        "status" to mapOf("status_list" to mapOf("uri" to uri, "idx" to index)),
        "exp" to expiresAt.epochSecond,
    )
