package de.eudiwallet.backend.statuslist

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.jwt.HsmEcdsaSigner
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Date

@Component
class StatusListTokenBuilder(
    private val config: StatusListConfiguration,
    private val statusListSigningLineages: Map<Pool, KeySource<CertifiedKey>>,
    private val ecdsaSigner: HsmEcdsaSigner,
) {
    companion object {
        const val JWT_TYPE = "statuslist+jwt"
    }

    suspend fun build(
        list: StatusListEntity,
        pool: Pool,
    ): String {
        val signingLineage = statusListSigningLineages[pool] ?: throw JwtException.SignerNotFound(JWT_TYPE)
        val certifiedKey = signingLineage.current()

        val header =
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(JWT_TYPE))
                .x509CertChain(certifiedKey.chain.map { Base64(it.encoded.toBase64()) })

        val now = Instant.now()
        val statusList =
            mapOf(
                "bits" to list.bitsPerEntry,
                "lst" to StatusListCodec.encodeLst(list.data),
                "aggregation_uri" to config.aggregationUri(pool),
            )
        val claims =
            JWTClaimsSet.Builder()
                .issuer(pool.issuer)
                .subject(config.listUri(pool, list.id))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(pool.lifetime)))
                .claim("ttl", pool.ttl.seconds)
                .claim("status_list", statusList)
                .build()

        val jwt = SignedJWT(header.build(), claims)
        ecdsaSigner.sign(jwt, certifiedKey.keyId)
        return jwt.serialize()
    }
}
