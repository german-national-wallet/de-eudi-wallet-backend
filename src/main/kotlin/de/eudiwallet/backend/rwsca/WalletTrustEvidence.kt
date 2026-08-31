package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.crypto.toECJWK
import de.eudiwallet.backend.shared.jwt.HsmEcdsaSigner
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Date

data class WalletTrustEvidence(
    val attestedKeys: List<ECPublicKey>,
    val wteNonce: String,
)

const val ISO_18045_HIGH_VALUE = "iso_18045_high"

@Component
class WalletTrustEvidenceBuilder(
    private val rwscaConfiguration: RwscaConfiguration,
    @Qualifier("rwscaWteAuthLineage")
    private val rwscaWteAuthLineage: KeySource<CertifiedKey>,
    private val ecdsaSigner: HsmEcdsaSigner,
) {
    companion object Companion {
        const val JWT_TYPE = "key-attestation+jwt"
        const val ATTESTED_KEYS_CLAIM = "attested_keys"
        const val NONCE_CLAIM = "nonce"
        const val KEY_STORAGE_CLAIM = "key_storage"
        const val USER_AUTHENTICATION_CLAIM = "user_authentication"
    }

    fun create(
        attestedKeys: List<ECPublicKey>,
        wteNonce: String,
    ): WalletTrustEvidence = WalletTrustEvidence(attestedKeys, wteNonce)

    suspend fun WalletTrustEvidence.serializeToJwt(): String {
        val certifiedKey = rwscaWteAuthLineage.current()

        val header =
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(JWT_TYPE))
                .x509CertChain(certifiedKey.chain.map { Base64(it.encoded.toBase64()) })

        val now = Instant.now()

        val claimsSet =
            JWTClaimsSet.Builder()
                .issuer(rwscaConfiguration.issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(rwscaConfiguration.wteExpireAfter)))
                .claim(ATTESTED_KEYS_CLAIM, attestedKeys.map { it.toECJWK().toJSONObject() })
                .claim(KEY_STORAGE_CLAIM, listOf(ISO_18045_HIGH_VALUE))
                .claim(USER_AUTHENTICATION_CLAIM, listOf(ISO_18045_HIGH_VALUE))
                .claim(NONCE_CLAIM, wteNonce)

        val jwt = SignedJWT(header.build(), claimsSet.build())

        ecdsaSigner.sign(jwt, certifiedKey.keyId)
        return jwt.serialize()
    }
}
