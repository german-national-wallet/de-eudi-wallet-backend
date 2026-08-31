package de.eudiwallet.backend.shared.hsm

import kotlinx.coroutines.reactor.mono
import org.springframework.boot.health.contributor.Health
import org.springframework.boot.health.contributor.ReactiveHealthIndicator
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.time.Duration
import kotlin.coroutines.cancellation.CancellationException

@Component
class HsmHealthIndicator(
    hsmProvider: HsmProvider,
    hsmConfiguration: HsmConfiguration,
) : HsmHealthIndicatorBase(hsmProvider, hsmConfiguration.moduleLibrary, hsmConfiguration.slotLabel)

@Suppress("TooGenericExceptionCaught")
open class HsmHealthIndicatorBase(
    private val hsmProvider: HsmProvider,
    private val moduleLibrary: String,
    private val slotLabel: String,
) : ReactiveHealthIndicator {
    override fun health(): Mono<Health> =
        mono {
            try {
                val isAlive =
                    hsmProvider.use("Check session alive", borrowTimeout = Duration.ZERO) { hsm -> hsm.isAlive() }
                if (isAlive) {
                    Health.up()
                        .withDetail("library", moduleLibrary)
                        .withDetail("slot", slotLabel)
                        .build()
                } else {
                    Health.down()
                        .withDetail("reason", "Cannot get session info")
                        .withDetail("library", moduleLibrary)
                        .withDetail("slot", slotLabel)
                        .build()
                }
            } catch (ex: HsmException.GetSessionFailedException) {
                Health.unknown()
                    .withDetail("reason", ex.message ?: "Failed to get session from the pool")
                    .withDetail("library", moduleLibrary)
                    .withDetail("slot", slotLabel)
                    .build()
            } catch (ex: CancellationException) {
                throw ex
            } catch (ex: Exception) {
                Health.down()
                    .withDetail("reason", ex.message ?: "Failed to get session info")
                    .withDetail("library", moduleLibrary)
                    .withDetail("slot", slotLabel)
                    .build()
            }
        }
}
