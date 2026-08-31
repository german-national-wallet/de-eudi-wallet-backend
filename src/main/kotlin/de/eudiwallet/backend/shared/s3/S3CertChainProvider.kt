package de.eudiwallet.backend.shared.s3

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.crypto.x509CertificateFactory
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Component
import software.amazon.awssdk.core.exception.SdkException
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.GetObjectRequest
import software.amazon.awssdk.services.s3.model.NoSuchKeyException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

private val log = KotlinLogging.logger {}

class S3CertChainException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

@Component
class S3CertChainProvider(
    private val s3Client: S3Client,
    private val properties: S3Properties,
) {
    init {
        log.info { "S3CertChainProvider using endpoint ${properties.endpoint}, bucket ${properties.bucket}" }
    }

    fun getVerifiedChain(
        objectKey: String,
        trustAnchor: X509Certificate,
    ): List<X509Certificate> {
        val pemBytes = fetch(objectKey)
        val chain = parseChain(objectKey, pemBytes)
        validateToAnchor(objectKey, chain, trustAnchor)
        return chain
    }

    private fun fetch(objectKey: String): ByteArray =
        try {
            s3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                    .bucket(properties.bucket)
                    .key(objectKey)
                    .build(),
            ).asByteArray()
        } catch (e: NoSuchKeyException) {
            throw S3CertChainException("Certificate object not found: ${properties.bucket}/$objectKey", e)
        } catch (e: SdkException) {
            throw S3CertChainException("Failed to read certificate object ${properties.bucket}/$objectKey", e)
        }

    private fun parseChain(
        objectKey: String,
        pemBytes: ByteArray,
    ): List<X509Certificate> {
        val certificates =
            try {
                x509CertificateFactory.generateCertificates(pemBytes.inputStream()).toList()
            } catch (e: CertificateException) {
                throw S3CertChainException("Certificate object $objectKey is not a parseable PEM chain", e)
            }
        val chain = certificates.filterIsInstance<X509Certificate>()
        if (chain.isEmpty()) {
            throw S3CertChainException("Certificate object $objectKey contains no X.509 certificates")
        }
        return chain
    }

    private fun validateToAnchor(
        objectKey: String,
        chain: List<X509Certificate>,
        trustAnchor: X509Certificate,
    ) {
        val pathCerts = chain.filterNot { it.encoded.contentEquals(trustAnchor.encoded) }
        if (pathCerts.isEmpty()) {
            throw S3CertChainException("Certificate chain $objectKey contains only the trust anchor")
        }
        try {
            val certPath = x509CertificateFactory.generateCertPath(pathCerts)
            val parameters =
                PKIXParameters(setOf(TrustAnchor(trustAnchor, null))).apply {
                    isRevocationEnabled = false
                }
            CertPathValidator.getInstance("PKIX", BOUNCY_CASTLE_PROVIDER).validate(certPath, parameters)
        } catch (e: CertPathValidatorException) {
            throw S3CertChainException("Certificate chain $objectKey does not validate to the pinned root", e)
        } catch (e: CertificateException) {
            throw S3CertChainException("Certificate chain $objectKey is malformed", e)
        }
    }
}
