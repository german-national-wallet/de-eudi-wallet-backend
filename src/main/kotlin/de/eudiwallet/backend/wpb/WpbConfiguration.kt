package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.crypto.readX509Cert
import de.eudiwallet.backend.shared.hsm.HsmConfiguration
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.keyrollover.AsymmetricSigningLineage
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.stubCertifiedKeySource
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
import de.eudiwallet.backend.shared.telemetry.MetricsService
import kotlinx.coroutines.CoroutineDispatcher
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.io.Resource
import java.security.cert.X509Certificate
import java.time.Duration

@ConfigurationProperties(prefix = "wpb")
class WpbConfiguration(
    val issuer: String,
    val clientId: String = "cbc61b45-907a-4c65-8467-3194d8af12ab",
    val walletName: String = "UNKNOWN",
    val walletVersion: String = "UNKNOWN",
    val walletSolutionCertificationInformation: String = "UNKNOWN",
    val walletLink: String = "UNKNOWN",
    val wpbWiaAuthKeyPrefix: String,
    val wpbWiaRootCertPath: Resource,
) {
    val wpbWiaRootCert: X509Certificate by lazy {
        readX509Cert(wpbWiaRootCertPath).apply { checkValidity() }
    }

    @Suppress("MagicNumber")
    val wiaExpireAfter: Duration = Duration.ofMinutes(10)
}

@Configuration
class WpbKeyProvider(
    private val config: WpbConfiguration,
    private val hsmConfiguration: HsmConfiguration,
    private val hsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) {
    @Bean(name = ["wpbWiaAuthLineage"])
    @Profile("!build-docs")
    fun wpbWiaAuthLineage(): AsymmetricSigningLineage =
        AsymmetricSigningLineage(
            name = "wpb-wia-auth",
            keyPrefix = config.wpbWiaAuthKeyPrefix,
            slotLabel = hsmConfiguration.slotLabel,
            trustAnchor = config.wpbWiaRootCert,
            hsmProvider = hsmProvider,
            s3CertChainProvider = s3CertChainProvider,
            ioDispatcher = ioDispatcher,
            metricsService = metricsService,
        ).also { it.initialize() }

    @Bean(name = ["wpbWiaAuthLineage"])
    @Profile("build-docs")
    fun docsWpbWiaAuthKeySource(): KeySource<CertifiedKey> = stubCertifiedKeySource()
}
