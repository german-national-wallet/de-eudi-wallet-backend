@file:Suppress("TooManyFunctions")

package de.eudiwallet.backend.shared.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME
import com.nimbusds.jwt.JWTClaimNames.ISSUED_AT
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.crypto.x509CertificateFactory
import java.security.InvalidAlgorithmParameterException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Duration
import java.time.Instant

fun SignedJWT.validateType(expectedType: String) {
    if (jwtType != expectedType) {
        throw JwtException.TypeMismatch(expectedType)
    }
}

fun SignedJWT.validateAlgorithm(expectedAlgorithm: JWSAlgorithm) {
    if (header.algorithm != expectedAlgorithm) {
        throw JwtException.AlgorithmMismatch(jwtType)
    }
}

fun SignedJWT.validatedKeyId(allowedKeyIds: List<String>): String = header.keyID.validatedKeyId(jwtType, allowedKeyIds)

fun SignedJWT.validateIssuer(expectedIssuer: String) {
    if (jwtClaimsSet.issuer != expectedIssuer) {
        throw JwtException.IssuerMismatch(jwtType)
    }
}

fun SignedJWT.validateIssueTime(issuanceValidWithIn: Duration) {
    val issueTime =
        this.jwtClaimsSet.issueTime ?: throw JwtException.MissingClaim(
            jwtType,
            ISSUED_AT,
        )
    if (issueTime.toInstant().isAfter(Instant.now())) {
        throw JwtException.InvalidClaim(jwtType, ISSUED_AT)
    } else if (issueTime.toInstant().plus(issuanceValidWithIn).isBefore(Instant.now())) {
        throw JwtException.Expired(jwtType)
    }
}

fun SignedJWT.validateExpirationTime() {
    val expirationTime =
        this.jwtClaimsSet.expirationTime ?: throw JwtException.MissingClaim(
            jwtType,
            EXPIRATION_TIME,
        )
    if (expirationTime.toInstant().isBefore(Instant.now())) {
        throw JwtException.Expired(jwtType)
    }
}

fun SignedJWT.validateEcdsaSignature(verificationKey: ECPublicKey) {
    val verified =
        try {
            verify(ECDSAVerifier(verificationKey).apply { jcaContext.provider = BOUNCY_CASTLE_PROVIDER })
        } catch (cause: JOSEException) {
            throw JwtException.VerificationFailure(jwtType, cause)
        }

    if (!verified) {
        throw JwtException.SignatureFailure(jwtType)
    }
}

fun SignedJWT.validateCertificateChain(pinnedCertificate: X509Certificate): X509Certificate {
    val certificates = validatedCertificates()
    val anchorIndex =
        certificates.indexOfFirst {
            it.encoded.contentEquals(pinnedCertificate.encoded)
        }
    if (anchorIndex == 0) {
        return certificates.first()
    }
    val chainToValidate = if (anchorIndex > 0) certificates.take(anchorIndex) else certificates
    try {
        val trustAnchors = setOf(TrustAnchor(pinnedCertificate, null))
        val pkixParameters = PKIXParameters(trustAnchors).apply { isRevocationEnabled = false }
        val certPath = x509CertificateFactory.generateCertPath(chainToValidate)
        val pkixCertPathValidator = CertPathValidator.getInstance("PKIX", BOUNCY_CASTLE_PROVIDER)
        pkixCertPathValidator.validate(certPath, pkixParameters)
    } catch (ex: CertPathValidatorException) {
        throw JwtException.CertificateFailure(jwtType, cause = ex)
    } catch (ex: InvalidAlgorithmParameterException) {
        throw JwtException.CertificateFailure(jwtType, cause = ex)
    }
    return certificates.first()
}

@Suppress("TooGenericExceptionCaught")
private fun SignedJWT.validatedCertificates(): List<X509Certificate> {
    val certChain = header.x509CertChain
    if (certChain.isNullOrEmpty()) {
        throw JwtException.CertificateFailure(jwtType, "Empty certificate chain")
    }
    return try {
        certChain.map {
            (x509CertificateFactory.generateCertificate(it.decode().inputStream()) as X509Certificate)
                .apply { checkValidity() }
        }
    } catch (ex: Exception) {
        throw JwtException.CertificateFailure(jwtType, cause = ex)
    }
}

fun EncryptedJWT.validateType(expectedType: String) {
    if (header.type?.toString() != expectedType) {
        throw JwtException.TypeMismatch(expectedType)
    }
}

fun EncryptedJWT.validateIssuer(expectedIssuer: String) {
    if (header.issuer != expectedIssuer) {
        throw JwtException.IssuerMismatch(jwtType)
    }
}

fun EncryptedJWT.validatedKeyId(allowedKeyIds: List<String>): String =
    header.keyID.validatedKeyId(jwtType, allowedKeyIds)

private fun String?.validatedKeyId(
    type: String,
    allowedKeyIds: List<String>,
): String {
    if (this == null) {
        throw JwtException.MissingHeader(type, "kid")
    }
    if (this !in allowedKeyIds) {
        throw JwtException.InvalidKeyId(type)
    }
    return this
}

sealed class JwtException(
    val type: String,
    message: String,
    cause: Throwable? = null,
) : RuntimeException("JWT (type=$type): $message", cause) {
    class ParseFailure(
        type: String,
        cause: Throwable,
    ) : JwtException(type, "failed to parse", cause)

    class SignFailure(
        type: String,
        cause: Throwable,
    ) : JwtException(type, "failed to sign", cause)

    class SignerNotFound(
        type: String,
    ) : JwtException(type, "signer not found")

    class EncryptionFailure(
        type: String,
        cause: Throwable,
    ) : JwtException(type, "failed to encrypt", cause)

    class DecryptionFailure(
        type: String,
        cause: Throwable,
    ) : JwtException(type, "failed to decrypt", cause)

    class AlgorithmMismatch(
        type: String,
    ) : JwtException(type, "algorithm mismatch")

    class TypeMismatch(
        expectedType: String,
    ) : JwtException(expectedType, "type does not match expected")

    class IssuerMismatch(
        type: String,
    ) : JwtException(type, "issuer does not match expected")

    class SignatureFailure(
        type: String,
    ) : JwtException(type, "signature validation failed")

    class CertificateFailure(
        type: String,
        message: String? = null,
        cause: Throwable? = null,
    ) : JwtException(type, "certificate validation failed: ${message ?: cause?.message}", cause)

    class Expired(
        type: String,
    ) : JwtException(type, "expired")

    class VerificationFailure(
        type: String,
        cause: Throwable? = null,
    ) : JwtException(type, "verification error", cause)

    class MissingClaim(
        type: String,
        claimName: String,
        cause: Throwable? = null,
    ) : JwtException(type, "missing claim $claimName", cause)

    class InvalidClaim(
        type: String,
        message: String,
        cause: Throwable? = null,
    ) : JwtException(type, "invalid claim $message", cause)

    class MissingHeader(
        type: String,
        headerName: String,
    ) : JwtException(type, "missing header $headerName")

    class InvalidKeyId(
        type: String,
        cause: Throwable? = null,
    ) : JwtException(type, "Invalid kid header", cause)

    class InvalidKeyData(
        type: String,
        cause: Throwable? = null,
    ) : JwtException(type, "Invalid key format", cause)

    class InvalidHeader(
        type: String,
        message: String,
        cause: Throwable? = null,
    ) : JwtException(type, "invalid header $message", cause)
}
