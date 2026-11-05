package de.eudiwallet.backend.shared.crl

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.crypto.x509CertificateFactory
import io.github.oshai.kotlinlogging.KotlinLogging
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse.BodyHandlers
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit.MILLISECONDS
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock

private val FETCH_TIMEOUT = Duration.ofSeconds(5)

private val MISS_BACKOFF = Duration.ofMinutes(10)

private const val MAX_CRL_BYTES = 10 * 1024 * 1024

private const val HTTP_OK = 200

@Component
class CrlCache(
    private val clock: Clock = Clock.systemUTC(),
    private val fetchTimeout: Duration = FETCH_TIMEOUT,
    @Value($$"${crl.expiry-warning-interval:P1D}") private val expiryWarningInterval: Duration = Duration.ofDays(1),
) {
    private val log = KotlinLogging.logger {}

    private class Entry(
        val crl: X509CRL,
        val issuer: X509Certificate,
    )

    private val entries = ConcurrentHashMap<URI, Entry>()
    private val failedUntil = ConcurrentHashMap<URI, Instant>()
    private val missLock = ReentrantLock()
    private val httpClient by lazy {
        HttpClient.newBuilder().connectTimeout(fetchTimeout).followRedirects(HttpClient.Redirect.NORMAL).build()
    }

    fun validate(
        path: List<X509Certificate>,
        anchor: X509Certificate,
    ) {
        val certPath = x509CertificateFactory.generateCertPath(path)
        val validator = CertPathValidator.getInstance("PKIX", BOUNCY_CASTLE_PROVIDER)
        val trustAnchors = setOf(TrustAnchor(anchor, null))
        validator.validate(certPath, PKIXParameters(trustAnchors).apply { isRevocationEnabled = false })

        val crls =
            path.flatMapIndexed { index, certificate ->
                val issuer = path.getOrElse(index + 1) { anchor }
                distributionPoints(certificate).mapNotNull { uris -> crlFor(uris, issuer) }
            }

        val parameters =
            PKIXParameters(trustAnchors).apply {
                addCertStore(
                    CertStore.getInstance("Collection", CollectionCertStoreParameters(crls), BOUNCY_CASTLE_PROVIDER),
                )
            }
        validator.validate(certPath, parameters)
    }

    @Scheduled(
        scheduler = "crlRefreshScheduler",
        fixedDelayString = $$"${crl.refresh-interval:PT1H}",
        initialDelayString = $$"${crl.refresh-interval:PT1H}",
    )
    fun refresh() {
        entries.forEach { (uri, entry) ->
            runCatching { fetch(uri, entry.issuer) }
                .onSuccess { crl ->
                    if (!crl.thisUpdate.before(entry.crl.thisUpdate)) entries[uri] = Entry(crl, entry.issuer)
                }
                .onFailure { e ->
                    if (entry.crl.isUsableUntil()) {
                        log.warn(e) {
                            "CRL refresh from $uri failed; keeping the copy valid until ${entry.crl.nextUpdate}"
                        }
                    } else {
                        log.error(e) {
                            "CRL refresh from $uri failed and the cached copy expired at ${entry.crl.nextUpdate}: " +
                                "certificates it covers fail validation"
                        }
                    }
                }
            val crl = entries.getValue(uri).crl
            if (!crl.isUsableUntil(expiryWarningInterval)) {
                log.error {
                    "CRL from $uri expires at ${crl.nextUpdate}, before the next refresh, and no newer one was fetched"
                }
            }
        }
    }

    private fun crlFor(
        uris: List<URI>,
        issuer: X509Certificate,
    ): X509CRL? = cachedFor(uris) ?: fetchUnderLock(uris, issuer)

    private fun fetchUnderLock(
        uris: List<URI>,
        issuer: X509Certificate,
    ): X509CRL? {
        if (!missLock.tryLock(fetchTimeout.toMillis(), MILLISECONDS)) {
            log.warn { "Gave up waiting for another CRL fetch to finish before fetching from $uris" }
            return null
        }
        try {
            return cachedFor(uris) ?: uris.firstNotNullOfOrNull { uri -> fetchOnMiss(uri, issuer) }
        } finally {
            missLock.unlock()
        }
    }

    private fun cachedFor(uris: List<URI>): X509CRL? =
        uris.firstNotNullOfOrNull {
            entries[it]?.crl?.takeIf { crl -> crl.isUsableUntil() }
        }

    @Suppress("TooGenericExceptionCaught")
    private fun fetchOnMiss(
        uri: URI,
        issuer: X509Certificate,
    ): X509CRL? {
        val now = Instant.now(clock)
        if (failedUntil[uri]?.isAfter(now) == true) return null
        return try {
            fetch(uri, issuer).also {
                entries[uri] = Entry(it, issuer)
                check(it.isUsableUntil()) { "CRL from $uri expired at ${it.nextUpdate}" }
                failedUntil.remove(uri)
                log.info { "Cached CRL from $uri, next update ${it.nextUpdate}" }
            }
        } catch (e: Exception) {
            failedUntil[uri] = now.plus(MISS_BACKOFF)
            log.error(e) {
                "CRL fetch from $uri failed; not retried on the request path before ${now.plus(MISS_BACKOFF)}"
            }
            null
        }
    }

    private fun fetch(
        uri: URI,
        issuer: X509Certificate,
    ): X509CRL {
        val bytes =
            when (uri.scheme?.lowercase()) {
                "http", "https" -> download(uri)
                "file" -> uri.toURL().openStream().use { it.readNBytes(MAX_CRL_BYTES + 1) }
                else -> throw IllegalArgumentException("CRL distribution point scheme not fetched: $uri")
            }
        require(bytes.size <= MAX_CRL_BYTES) { "CRL from $uri exceeds $MAX_CRL_BYTES bytes" }
        val crl = x509CertificateFactory.generateCRL(bytes.inputStream()) as X509CRL
        require(crl.issuerX500Principal == issuer.subjectX500Principal) {
            "CRL from $uri is issued by '${crl.issuerX500Principal.name}', not '${issuer.subjectX500Principal.name}'"
        }
        crl.verify(issuer.publicKey, BOUNCY_CASTLE_PROVIDER)
        return crl
    }

    private fun download(uri: URI): ByteArray {
        val request = HttpRequest.newBuilder(uri).timeout(fetchTimeout).GET().build()
        val pending =
            httpClient.sendAsync(
                request,
                BodyHandlers.limiting(BodyHandlers.ofByteArray(), MAX_CRL_BYTES + 1L),
            )
        val response =
            try {
                pending.get(fetchTimeout.toMillis(), MILLISECONDS)
            } catch (e: TimeoutException) {
                pending.cancel(true)
                throw e
            }
        check(response.statusCode() == HTTP_OK) { "CRL from $uri answered HTTP ${response.statusCode()}" }
        return response.body()
    }

    private fun X509CRL.isUsableUntil(interval: Duration = Duration.ZERO) =
        nextUpdate?.toInstant()?.isAfter(Instant.now(clock).plus(interval)) ?: true
}

private fun distributionPoints(certificate: X509Certificate): List<List<URI>> {
    val extension = certificate.getExtensionValue(Extension.cRLDistributionPoints.id) ?: return emptyList()
    return CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extension)).distributionPoints
        .mapNotNull { it.distributionPoint }
        .filter { it.type == DistributionPointName.FULL_NAME }
        .map { name ->
            GeneralNames.getInstance(name.name).names
                .filter { it.tagNo == GeneralName.uniformResourceIdentifier }
                .map { URI(it.name.toString()) }
        }.filter { it.isNotEmpty() }
}
