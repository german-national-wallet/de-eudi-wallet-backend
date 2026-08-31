package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.telemetry.TelemetryService
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
) {
    @KafkaListener(topics = [$$"${wallet-revocation.topic}"], groupId = $$"${wallet-revocation.group.rwsca}")
    fun onRevocation(payload: String) {
        telemetryService.withSpanSync("RwscaRevocationListener.onRevocation") {
            val event = json.decodeFromString<WalletInstanceRevocationEvent>(payload)
            runBlocking { rwscaAccountService.revokeByWiHandle(event.wiHandle) }
        }
    }
}
