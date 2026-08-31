package de.eudiwallet.backend.shared.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.HsmSession
import org.springframework.stereotype.Component

internal class HsmHmacJwsSigner(
    private val hsm: HsmSession,
    private val signingKeyId: HsmKeyId,
) : JWSSigner {
    private val jcaContext = JCAContext().also { it.provider = BOUNCY_CASTLE_PROVIDER }

    override fun sign(
        header: JWSHeader,
        signingInput: ByteArray,
    ): Base64URL =
        try {
            val signingKey = hsm.getKey(signingKeyId, HsmKeyClass.GenericSecret)
            Base64URL.encode(hsm.signHMAC(signingKey, signingInput))
        } catch (ex: HsmException) {
            throw JOSEException(ex)
        }

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(JWSAlgorithm.HS256)

    override fun getJCAContext(): JCAContext = jcaContext
}

@Component
class HsmHmacSigner(
    private val hsmProvider: HsmProvider,
) {
    suspend fun sign(
        jwt: SignedJWT,
        signingKeyId: HsmKeyId,
    ) = try {
        hsmProvider.use(spanName(jwt)) { hsm ->
            jwt.sign(HsmHmacJwsSigner(hsm, signingKeyId))
        }
    } catch (e: JOSEException) {
        throw JwtException.SignFailure(jwt.jwtType, e)
    }

    private fun spanName(jwt: SignedJWT) = "Sign ${jwt.jwtType} with HMAC signature"
}
