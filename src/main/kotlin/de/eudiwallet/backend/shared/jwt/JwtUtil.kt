package de.eudiwallet.backend.shared.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.fromBase64
import java.security.interfaces.ECPublicKey
import java.text.ParseException
import java.util.UUID

const val CONFIRMATION_CLAIM = "cnf"
const val JWK_FIELD = "jwk"

internal val JWT.jwtType: String
    get() = header.type?.toString() ?: "token"

@Suppress("ThrowsCount")
fun SignedJWT.getConfirmationKey(): ECPublicKey {
    val cnfClaim =
        try {
            jwtClaimsSet.getJSONObjectClaim(CONFIRMATION_CLAIM)
                ?: throw JwtException.MissingClaim(jwtType, CONFIRMATION_CLAIM)
        } catch (ex: ParseException) {
            throw JwtException.InvalidClaim(jwtType, CONFIRMATION_CLAIM, ex)
        }

    @Suppress("UNCHECKED_CAST")
    val keyClaimMap =
        cnfClaim[JWK_FIELD] as? Map<String, Any>
            ?: throw JwtException.InvalidClaim(jwtType, "Invalid field $JWK_FIELD")

    return try {
        ECKey.parse(keyClaimMap).toECPublicKey()
    } catch (ex: ParseException) {
        throw JwtException.InvalidKeyData(jwtType, ex)
    } catch (ex: JOSEException) {
        throw JwtException.InvalidKeyData(jwtType, ex)
    }
}

fun SignedJWT.getUUIDClaim(name: String): UUID = getUUIDClaim(jwtType, jwtClaimsSet, name)

fun EncryptedJWT.getUUIDClaim(name: String): UUID = getUUIDClaim(jwtType, jwtClaimsSet, name)

fun EncryptedJWT.getStringClaim(name: String): String = getStringClaim(jwtType, jwtClaimsSet, name)

private fun getStringClaim(
    jwtType: String,
    claimsSet: JWTClaimsSet,
    name: String,
): String =
    try {
        claimsSet.getStringClaim(name) ?: throw JwtException.MissingClaim(jwtType, name)
    } catch (ex: ParseException) {
        throw JwtException.InvalidClaim(jwtType, name, ex)
    }

private fun getUUIDClaim(
    jwtType: String,
    claimsSet: JWTClaimsSet,
    name: String,
): UUID =
    getStringClaim(jwtType, claimsSet, name).let { claimData ->
        try {
            UUID.fromString(claimData)
        } catch (ex: IllegalArgumentException) {
            throw JwtException.InvalidClaim(jwtType, name, ex)
        }
    }

fun EncryptedJWT.getBase64DecodedClaim(name: String): ByteArray {
    val wrappedKeyStr = getStringClaim(jwtType, jwtClaimsSet, name)
    try {
        return wrappedKeyStr.fromBase64()
    } catch (e: IllegalArgumentException) {
        throw JwtException.InvalidClaim(jwtType, name, e)
    }
}
