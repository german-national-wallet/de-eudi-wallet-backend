package de.eudiwallet.backend.shared.httpsignature

import com.authlete.hms.ComponentIdentifier
import com.authlete.hms.ComponentValueProvider
import com.authlete.hms.SignatureBase
import com.authlete.hms.SignatureBaseBuilder
import com.authlete.hms.SignatureEntry
import com.authlete.hms.SignatureField
import com.authlete.hms.SignatureInputField
import com.authlete.hms.SignatureMetadata
import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import java.security.InvalidKeyException
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPublicKey

const val SIGNATURE_HEADER = "Signature"
const val SIGNATURE_INPUT_HEADER = "Signature-Input"
const val CONTENT_DIGEST_HEADER = "Content-Digest"
const val METHOD_COMPONENT = "@method"
const val PATH_COMPONENT = "@path"

private val signatureAlgorithmMapping = mapOf("ecdsa-p256-sha256" to "SHA256withECDSA")

open class SignatureVerificationException(
    explanation: String?,
    cause: Throwable? = null,
) : RuntimeException(explanation, cause) {
    class WrongSignature(
        signatureLabel: String,
    ) : SignatureVerificationException("Signature $signatureLabel is invalid")

    class WrongSignatureMetadata(
        cause: Throwable? = null,
    ) : SignatureVerificationException("Signature headers are not formed correctly", cause)

    class WrongAlgorithm : SignatureVerificationException("Unsupported signature algorithm")

    class WrongSignedComponents(
        signatureLabel: String,
        received: List<String>,
        required: List<String>,
    ) : SignatureVerificationException(
            "Signature '$signatureLabel' is missing required components. Required: $required, Received: $received",
        )

    class InputFailure(
        cause: Throwable? = null,
    ) : SignatureVerificationException("Cannot collect signature data", cause)

    class VerifierFailure(
        cause: Throwable? = null,
    ) : SignatureVerificationException("Cannot build verifier with public key", cause)

    class MissingSignature(
        signatureLabel: String,
        cause: Throwable? = null,
    ) : SignatureVerificationException("Signature $signatureLabel is not found", cause)

    class MissingContentDigest(
        signatureLabel: String,
    ) : SignatureVerificationException(
            "Signature '$signatureLabel' requires '$CONTENT_DIGEST_HEADER' but the header is absent from the request",
        )
}

@Component
class HttpSignatureVerifier(
    private val telemetryService: TelemetryService,
) {
    suspend fun verifyRequestSignature(
        request: ServerHttpRequest,
        signatureLabel: String,
        requiredSignatureComponents: List<String>,
        ecPublicKey: ECPublicKey,
    ) = telemetryService.withSpanSync("HttpSignatureVerifier.verifyRequestSignature") {
        val entry = findSignatureEntry(request, signatureLabel)
        verifySignedComponents(request, entry.metadata, requiredSignatureComponents, signatureLabel)
        val algorithm =
            signatureAlgorithmMapping[entry.metadata.parameters.alg]
                ?: throw SignatureVerificationException.WrongAlgorithm()
        val base = computeSignatureBase(request, entry.metadata)
        val signatureVerifier = signatureVerifier(algorithm, ecPublicKey, base)
        val verificationResult =
            try {
                signatureVerifier.verify(entry.signature)
            } catch (_: SignatureException) {
                false
            }
        if (!verificationResult) {
            throw SignatureVerificationException.WrongSignature(signatureLabel)
        }
    }

    private fun findSignatureEntry(
        request: ServerHttpRequest,
        signatureLabel: String,
    ): SignatureEntry {
        val entries =
            try {
                val signatureField =
                    SignatureField.parse(request.headers.getOrEmpty(SIGNATURE_HEADER).joinToString(", "))
                val signatureInputField =
                    SignatureInputField.parse(request.headers.getOrEmpty(SIGNATURE_INPUT_HEADER).joinToString(", "))
                SignatureEntry.scan(signatureField, signatureInputField)
            } catch (ex: SignatureException) {
                throw SignatureVerificationException.WrongSignatureMetadata(ex)
            } catch (ex: IllegalArgumentException) {
                throw SignatureVerificationException.WrongSignatureMetadata(ex)
            }
        return entries[signatureLabel] ?: throw SignatureVerificationException.MissingSignature(signatureLabel)
    }

    private fun verifySignedComponents(
        request: ServerHttpRequest,
        metadata: SignatureMetadata,
        requiredSignatureComponents: List<String>,
        signatureLabel: String,
    ) {
        val requiredComponentsCanonical = requiredSignatureComponents.map { it.lowercase().trim() }
        if (!metadata.containsAll(requiredComponentsCanonical.map(::ComponentIdentifier))) {
            throw SignatureVerificationException.WrongSignedComponents(
                signatureLabel,
                received = metadata.map { it.serialize() },
                required = requiredComponentsCanonical,
            )
        }
        if (requiredComponentsCanonical.contains(CONTENT_DIGEST_HEADER.lowercase()) &&
            request.headers.getFirst(CONTENT_DIGEST_HEADER).isNullOrBlank()
        ) {
            throw SignatureVerificationException.MissingContentDigest(signatureLabel)
        }
    }

    private fun computeSignatureBase(
        request: ServerHttpRequest,
        metadata: SignatureMetadata,
    ): SignatureBase =
        try {
            val valueProvider = ComponentValueProvider()
            valueProvider.method = request.method.name()
            valueProvider.setTargetUri(request.uri)
            valueProvider.headers = request.headers.toMultiValueMap()
            SignatureBaseBuilder(valueProvider).build(metadata)
        } catch (ex: SignatureException) {
            throw SignatureVerificationException.InputFailure(ex)
        }

    private fun signatureVerifier(
        algorithm: String,
        ecPublicKey: ECPublicKey,
        base: SignatureBase,
    ) = try {
        val signatureVerifier = Signature.getInstance(algorithm, BOUNCY_CASTLE_PROVIDER)
        signatureVerifier.initVerify(ecPublicKey)
        signatureVerifier.update(base.serialize().encodeToByteArray())
        signatureVerifier
    } catch (ex: InvalidKeyException) {
        throw SignatureVerificationException.VerifierFailure(ex)
    } catch (ex: SignatureException) {
        throw SignatureVerificationException.VerifierFailure(ex)
    }

    private fun HttpHeaders.toMultiValueMap(): Map<String, List<String>> =
        headerNames().associateWith(::get).mapValues { (_, value) -> value?.toList() ?: emptyList() }
}
