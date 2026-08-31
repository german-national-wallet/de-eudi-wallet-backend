package de.eudiwallet.backend.shared.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
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

internal class HsmHmacJwsVerifier(
    private val hsm: HsmSession,
    private val signingKeyId: HsmKeyId,
) : JWSVerifier {
    private val jcaContext = JCAContext().also { it.provider = BOUNCY_CASTLE_PROVIDER }

    override fun verify(
        header: JWSHeader,
        signingInput: ByteArray,
        signature: Base64URL,
    ): Boolean =
        try {
            val signingKey = hsm.getKey(signingKeyId, HsmKeyClass.GenericSecret)
            hsm.verifyHMAC(signingKey, signingInput, signature.decode())
        } catch (ex: HsmException) {
            throw JOSEException(ex)
        }

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm?> = setOf(JWSAlgorithm.HS256)

    override fun getJCAContext(): JCAContext = jcaContext
}

@Component
class HsmHmacVerifier(
    private val hsmProvider: HsmProvider,
) {
    suspend fun verify(
        jwt: SignedJWT,
        signingKeyId: HsmKeyId,
    ) {
        val verified =
            try {
                hsmProvider.use("Verify HMAC token signature") { hsm ->
                    jwt.verify(HsmHmacJwsVerifier(hsm, signingKeyId))
                }
            } catch (cause: JOSEException) {
                throw JwtException.VerificationFailure(jwt.jwtType, cause)
            }

        if (!verified) {
            throw JwtException.SignatureFailure(jwt.jwtType)
        }
    }
}
