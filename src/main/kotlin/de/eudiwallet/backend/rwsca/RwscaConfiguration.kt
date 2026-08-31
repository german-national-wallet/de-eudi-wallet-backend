package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.readX509Cert
import de.eudiwallet.backend.shared.hsm.HsmConfiguration
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyRef
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.SlotConfig
import de.eudiwallet.backend.shared.keyrollover.AsymmetricSigningLineage
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeyLineage
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import de.eudiwallet.backend.shared.keyrollover.stubCertifiedKeySource
import de.eudiwallet.backend.shared.keyrollover.stubSymKeySource
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
import de.eudiwallet.backend.shared.telemetry.MetricsService
import kotlinx.coroutines.CoroutineDispatcher
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.io.Resource
import java.security.cert.X509Certificate
import java.time.Duration

@ConfigurationProperties(prefix = "rwsca")
class RwscaConfiguration(
    val issuer: String,
    val rwscdMasterKeyPrefix: String,
    val rwscdWteAuthKeyPrefix: String,
    val rwscdPinSymkPrefix: String,
    val rwscdAeadSymkPrefix: String,
    val rwscdWteRootCertPath: Resource,
    val wiSlot: SlotConfig,
    val pinRetry: PinRetryConfigurationProperties = PinRetryConfigurationProperties(),
) {
    val rwscdWteRootCert: X509Certificate by lazy {
        readX509Cert(rwscdWteRootCertPath).apply { checkValidity() }
    }

    @Suppress("MagicNumber")
    val pinSessionTokenExpireAfter: Duration = Duration.ofMinutes(5)

    @Suppress("MagicNumber")
    val wteExpireAfter: Duration = Duration.ofDays(1)
}

@Suppress("MagicNumber")
data class PinRetryConfigurationProperties(
    val maxTries: Int = 3,
    val backoffDurations: List<Duration> =
        listOf(
            Duration.ZERO,
            Duration.ZERO,
        ),
)

@Configuration
class RwscaKeyProvider(
    private val config: RwscaConfiguration,
    private val hsmConfiguration: HsmConfiguration,
    private val hsmProvider: HsmProvider,
    @Qualifier(RWSCA_WI_HSM_PROVIDER)
    private val rwscaWiHsmProvider: HsmProvider,
    private val s3CertChainProvider: S3CertChainProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) {
    @Bean("rwscaMasterLineage")
    @Profile("!build-docs")
    fun rwscaMasterLineage(): SymmetricKeyLineage<HsmKeyRef.AesKeyRef> =
        SymmetricKeyLineage(
            "rwsca-master",
            config.rwscdMasterKeyPrefix,
            HsmKeyClass.Aes,
            rwscaWiHsmProvider,
            ioDispatcher,
            metricsService,
        ).also { it.initialize() }

    @Bean("rwscaWteAuthLineage")
    @Profile("!build-docs")
    fun rwscaWteAuthLineage(): AsymmetricSigningLineage =
        AsymmetricSigningLineage(
            name = "rwsca-wte-auth",
            keyPrefix = config.rwscdWteAuthKeyPrefix,
            slotLabel = hsmConfiguration.slotLabel,
            trustAnchor = config.rwscdWteRootCert,
            hsmProvider = hsmProvider,
            s3CertChainProvider = s3CertChainProvider,
            ioDispatcher = ioDispatcher,
            metricsService = metricsService,
        ).also { it.initialize() }

    @Bean("rwscaPinSymLineage")
    @Profile("!build-docs")
    fun rwscaPinSymLineage(): SymmetricKeyLineage<HsmKeyRef.GenericSecretKeyRef> =
        SymmetricKeyLineage(
            "rwsca-pin-symk",
            config.rwscdPinSymkPrefix,
            HsmKeyClass.GenericSecret,
            hsmProvider,
            ioDispatcher,
            metricsService,
        ).also { it.initialize() }

    @Bean("rwscaAeadSymLineage")
    @Profile("!build-docs")
    fun rwscaAeadSymLineage(): SymmetricKeyLineage<HsmKeyRef.AesKeyRef> =
        SymmetricKeyLineage(
            "rwsca-aead-symk",
            config.rwscdAeadSymkPrefix,
            HsmKeyClass.Aes,
            hsmProvider,
            ioDispatcher,
            metricsService,
        ).also { it.initialize() }

    @Bean("rwscaMasterLineage")
    @Profile("build-docs")
    fun docsRwscaMasterKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()

    @Bean("rwscaWteAuthLineage")
    @Profile("build-docs")
    fun docsRwscaWteAuthKeySource(): KeySource<CertifiedKey> = stubCertifiedKeySource()

    @Bean("rwscaPinSymLineage")
    @Profile("build-docs")
    fun docsRwscaPinSymKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()

    @Bean("rwscaAeadSymLineage")
    @Profile("build-docs")
    fun docsRwscaAeadSymKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()
}
