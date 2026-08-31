package de.eudiwallet.backend.mdvm

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

@ConfigurationProperties(prefix = "mdvm")
class MdvmConfiguration(
    val issuer: String,
    val mdvmAuthPrvkPrefix: String,
    val mdvmRootCertPath: Resource,
    val tokenExpireAfter: Duration = Duration.ofDays(1),
    val saveAnalytics: Boolean = false,
    val traceDebugInfo: Boolean = false,
) {
    val mdvmRootCert: X509Certificate by lazy {
        readX509Cert(mdvmRootCertPath).apply { checkValidity() }
    }
}

@Configuration
class MdvmTokenKeyProvider(
    private val config: MdvmConfiguration,
    private val hsmConfiguration: HsmConfiguration,
    private val hsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) {
    @Bean("mdvmAttestationLineage")
    @Profile("!build-docs")
    fun mdvmAttestationLineage(): AsymmetricSigningLineage =
        AsymmetricSigningLineage(
            name = "mdvm-attestation",
            keyPrefix = config.mdvmAuthPrvkPrefix,
            slotLabel = hsmConfiguration.slotLabel,
            trustAnchor = config.mdvmRootCert,
            hsmProvider = hsmProvider,
            s3CertChainProvider = s3CertChainProvider,
            ioDispatcher = ioDispatcher,
            metricsService = metricsService,
        ).also { it.initialize() }

    @Bean("mdvmAttestationLineage")
    @Profile("build-docs")
    fun docsMdvmAttestationKeySource(): KeySource<CertifiedKey> = stubCertifiedKeySource()
}
