package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.bouncycastle.jce.ECNamedCurveTable
import java.security.interfaces.ECPrivateKey
import java.text.ParseException

const val PIN_ENCRYPTION_KID = "1"

class PinEncryptionKey(
    privateJwk: String,
) {
    private val jwk = parse(privateJwk)

    val privateKey: ECPrivateKey = jwk.toECPrivateKey(BOUNCY_CASTLE_PROVIDER)

    val publicJwk: ECKey =
        ECKey
            .Builder(jwk.toPublicJWK())
            .keyID(PIN_ENCRYPTION_KID)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .build()

    val publicJwkJson: JsonObject = Json.parseToJsonElement(publicJwk.toJSONString()).jsonObject

    init {
        val derived = ECNamedCurveTable.getParameterSpec(Curve.P_256.stdName).g.multiply(privateKey.s).normalize()
        val published = jwk.toECPublicKey(BOUNCY_CASTLE_PROVIDER).w
        check(
            derived.affineXCoord.toBigInteger() == published.affineX &&
                derived.affineYCoord.toBigInteger() == published.affineY,
        ) {
            "rwsca.pin-encryption-key: d does not belong to x/y"
        }
    }

    private fun parse(privateJwk: String): ECKey {
        val jwk =
            try {
                ECKey.parse(privateJwk)
            } catch (_: ParseException) {
                null
            }
        check(jwk != null && jwk.curve == Curve.P_256 && jwk.isPrivate) {
            "rwsca.pin-encryption-key is not a private P-256 JWK"
        }
        return jwk
    }
}
