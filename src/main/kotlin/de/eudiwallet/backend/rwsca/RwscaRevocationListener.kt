package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.messaging.MessagingMetrics
import de.eudiwallet.backend.shared.messaging.Module
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.messaging.report
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty(prefix = "messaging.kafka", name = ["enabled"], havingValue = "true")
class RwscaRevocationListener(
    private val rwscaAccountService: RwscaAccountService,
    private val json: Json,
    private val telemetryService: TelemetryService,
    private val messagingMetrics: MessagingMetrics,
) {
    private val log = KotlinLogging.logger {}

    @KafkaListener(topics = [$$"${wallet-revocation.topic}"], groupId = $$"${wallet-revocation.group.rwsca}")
    fun onRevocation(payload: String) {
        telemetryService.withSpanSync("RwscaRevocationListener.onRevocation") {
            val event = json.decodeFromString<WalletInstanceRevocationEvent>(payload)
            runBlocking { rwscaAccountService.revokeByWiHandle(event.wiHandle) }
                .report(Module.RWSCA, event, messagingMetrics, log)
        }
    }
}
