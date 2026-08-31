package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.opentelemetry.api.trace.Span
import io.opentelemetry.api.trace.StatusCode
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.time.Duration
import kotlin.coroutines.cancellation.CancellationException

class HsmProviderImpl(
    private val telemetryService: TelemetryService,
    private val slotLabel: String,
    private val pool: HsmSessionPool,
) : HsmProvider {
    @Suppress("TooGenericExceptionCaught")
    override suspend fun <R> use(
        spanName: String,
        borrowTimeout: Duration?,
        block: (HsmSession) -> R,
    ): R =
        telemetryService.withSpan("HSM get session") {
            pool.withSession(borrowTimeout) { session ->
                telemetryService.withSpanSync(spanName) {
                    Span.current().setAttribute("hsm.slot", slotLabel)
                    Span.current().setAttribute("hsm.session_handle", session.sessionHandle)
                    try {
                        block(session)
                    } catch (ex: CancellationException) {
                        throw ex
                    } catch (ex: Throwable) {
                        Span.current().recordException(ex)
                        Span.current().setStatus(StatusCode.ERROR)
                        throw ex
                    }
                }
            }
        }
}

@Component
@Profile("!build-docs")
class HsmModule(
    private val config: HsmConfiguration,
    private val telemetryService: TelemetryService,
) {
    fun provider(slot: SlotConfig): HsmProvider =
        HsmProviderImpl(
            telemetryService,
            slot.label,
            HsmSessionPool.getOrCreate(
                slot,
                config.moduleLibrary,
                config.wrappingMechanism,
                config.poolBorrowTimeout,
                telemetryService,
            ),
        )
}

class BuildDocsHsmProvider : HsmProvider {
    override suspend fun <R> use(
        spanName: String,
        borrowTimeout: Duration?,
        block: (HsmSession) -> R,
    ): R = error("HSM is not available in the build-docs profile")
}

@Configuration
class HsmProviderConfiguration {
    @Bean
    @Primary
    @Profile("!build-docs")
    fun hsmProvider(
        hsmModule: HsmModule,
        config: HsmConfiguration,
    ): HsmProvider = hsmModule.provider(config.defaultSlot)

    @Bean
    @Primary
    @Profile("build-docs")
    fun buildDocsHsmProvider(): HsmProvider = BuildDocsHsmProvider()
}
