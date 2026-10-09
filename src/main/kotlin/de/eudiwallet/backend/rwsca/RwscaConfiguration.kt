package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.readX509Cert
import de.eudiwallet.backend.shared.hsm.HsmConfiguration
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyRef
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.SlotConfig
import de.eudiwallet.backend.shared.keyrollover.AsymmetricSigningLineage
import de.eudiwallet.backend.shared.keyrollover.CertifiedKey
import de.eudiwallet.backend.shared.keyrollover.KeyRolloverMetrics
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeyLineage
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import de.eudiwallet.backend.shared.keyrollover.stubCertifiedKeySource
import de.eudiwallet.backend.shared.keyrollover.stubSymKeySource
import de.eudiwallet.backend.shared.s3.S3CertChainProvider
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
    private val keyRolloverMetrics: KeyRolloverMetrics,
) {
    @Bean("rwscdMasterLineage")
    @Profile("!build-docs")
    fun rwscdMasterLineage(): SymmetricKeyLineage<HsmKeyRef.AesKeyRef> =
        SymmetricKeyLineage(
            "rwscd-master",
            config.rwscdMasterKeyPrefix,
            HsmKeyClass.Aes,
            rwscaWiHsmProvider,
            ioDispatcher,
            keyRolloverMetrics,
        ).also { it.initialize() }

    @Bean("rwscdWteAuthLineage")
    @Profile("!build-docs")
    fun rwscdWteAuthLineage(): AsymmetricSigningLineage =
        AsymmetricSigningLineage(
            name = "rwscd-wte-auth",
            keyPrefix = config.rwscdWteAuthKeyPrefix,
            slotLabel = hsmConfiguration.slotLabel,
            trustAnchor = config.rwscdWteRootCert,
            hsmProvider = hsmProvider,
            s3CertChainProvider = s3CertChainProvider,
            ioDispatcher = ioDispatcher,
            keyRolloverMetrics = keyRolloverMetrics,
        ).also { it.initialize() }

    @Bean("rwscdPinSymLineage")
    @Profile("!build-docs")
    fun rwscdPinSymLineage(): SymmetricKeyLineage<HsmKeyRef.GenericSecretKeyRef> =
        SymmetricKeyLineage(
            "rwscd-pin-symk",
            config.rwscdPinSymkPrefix,
            HsmKeyClass.GenericSecret,
            hsmProvider,
            ioDispatcher,
            keyRolloverMetrics,
        ).also { it.initialize() }

    @Bean("rwscdAeadSymLineage")
    @Profile("!build-docs")
    fun rwscdAeadSymLineage(): SymmetricKeyLineage<HsmKeyRef.AesKeyRef> =
        SymmetricKeyLineage(
            "rwscd-aead-symk",
            config.rwscdAeadSymkPrefix,
            HsmKeyClass.Aes,
            hsmProvider,
            ioDispatcher,
            keyRolloverMetrics,
        ).also { it.initialize() }

    @Bean("rwscdMasterLineage")
    @Profile("build-docs")
    fun docsRwscdMasterKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()

    @Bean("rwscdWteAuthLineage")
    @Profile("build-docs")
    fun docsRwscdWteAuthKeySource(): KeySource<CertifiedKey> = stubCertifiedKeySource()

    @Bean("rwscdPinSymLineage")
    @Profile("build-docs")
    fun docsRwscdPinSymKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()

    @Bean("rwscdAeadSymLineage")
    @Profile("build-docs")
    fun docsRwscdAeadSymKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()
}
