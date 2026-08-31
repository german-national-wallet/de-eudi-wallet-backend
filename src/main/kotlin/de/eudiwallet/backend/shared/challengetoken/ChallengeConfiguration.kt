package de.eudiwallet.backend.shared.challengetoken

import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyRef
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeyLineage
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import de.eudiwallet.backend.shared.keyrollover.stubSymKeySource
import de.eudiwallet.backend.shared.telemetry.MetricsService
import kotlinx.coroutines.CoroutineDispatcher
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import java.time.Duration

@ConfigurationProperties(prefix = "challenge")
class ChallengeConfiguration(
    val rwscdChallengeSymkPrefix: String,
) {
    @Suppress("MagicNumber")
    val challengeExpireAfter: Duration = Duration.ofMinutes(5)
}

@Configuration
class ChallengeKeyProvider(
    private val config: ChallengeConfiguration,
    private val hsmProvider: HsmProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) {
    @Bean("challengeSymkLineage")
    @Profile("!build-docs")
    fun challengeSymkLineage(): SymmetricKeyLineage<HsmKeyRef.GenericSecretKeyRef> =
        SymmetricKeyLineage(
            "challenge-symk",
            config.rwscdChallengeSymkPrefix,
            HsmKeyClass.GenericSecret,
            hsmProvider,
            ioDispatcher,
            metricsService,
        ).also { it.initialize() }

    @Bean("challengeSymkLineage")
    @Profile("build-docs")
    fun docsChallengeKeySource(): KeySource<SymmetricKeySet> = stubSymKeySource()
}
