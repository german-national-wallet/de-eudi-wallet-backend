package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty(prefix = "messaging.kafka", name = ["enabled"], havingValue = "true")
class WpbRevocationListener(
    private val wpbAccountService: WpbAccountService,
    private val json: Json,
    private val telemetryService: TelemetryService,
) {
    @KafkaListener(topics = [$$"${wallet-revocation.topic}"], groupId = $$"${wallet-revocation.group.wpb}")
    fun onRevocation(payload: String) {
        telemetryService.withSpanSync("WpbRevocationListener.onRevocation") {
            val event = json.decodeFromString<WalletInstanceRevocationEvent>(payload)
            runBlocking { wpbAccountService.revokeByWiHandle(event.wiHandle) }
        }
    }
}
