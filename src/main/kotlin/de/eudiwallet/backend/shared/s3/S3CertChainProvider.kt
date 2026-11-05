package de.eudiwallet.backend.shared.s3

import de.eudiwallet.backend.shared.crl.CrlCache
import de.eudiwallet.backend.shared.crypto.x509CertificateFactory
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Component
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

private val log = KotlinLogging.logger {}

private const val DIGITAL_SIGNATURE_INDEX = 0

private const val NOT_A_CA = -1

class S3CertChainException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

@Component
class S3CertChainProvider(
    private val s3Client: S3ObjectClient,
    private val properties: S3Properties,
    private val crlCache: CrlCache,
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
        val path = chain.takeWhile { !it.encoded.contentEquals(trustAnchor.encoded) }
        validateToAnchor(objectKey, path, trustAnchor)
        validateLeafCertificate(objectKey, path)
        return path
    }

    private fun fetch(objectKey: String): ByteArray =
        try {
            s3Client.getObject(properties.bucket, objectKey)
        } catch (e: S3ObjectNotFoundException) {
            throw S3CertChainException("Certificate object not found: ${properties.bucket}/$objectKey", e)
        } catch (e: S3ClientException) {
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
        pathCerts: List<X509Certificate>,
        trustAnchor: X509Certificate,
    ) {
        if (pathCerts.isEmpty()) {
            throw S3CertChainException("Certificate chain $objectKey starts at the trust anchor")
        }
        try {
            crlCache.validate(pathCerts, trustAnchor)
        } catch (e: CertPathValidatorException) {
            throw S3CertChainException(
                "Certificate chain $objectKey (${pathCerts.size} certificates, topmost issuer " +
                    "'${pathCerts.last().issuerX500Principal.name}') does not validate to the pinned anchor " +
                    "'${trustAnchor.subjectX500Principal.name}': ${e.message}",
                e,
            )
        } catch (e: CertificateException) {
            throw S3CertChainException("Certificate chain $objectKey is malformed", e)
        }
    }

    private fun validateLeafCertificate(
        objectKey: String,
        chain: List<X509Certificate>,
    ) {
        val leaf = chain.first()
        if (leaf.basicConstraints != NOT_A_CA) {
            throw S3CertChainException("Leaf certificate of $objectKey is a CA, not an end entity")
        }
        if (leaf.keyUsage?.getOrNull(DIGITAL_SIGNATURE_INDEX) != true) {
            throw S3CertChainException("Leaf certificate of $objectKey does not assert digitalSignature KeyUsage")
        }
    }
}
