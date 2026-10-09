package de.eudiwallet.backend.mdvm

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
class MdvmRevocationListener(
    private val mdvmAccountService: MdvmAccountService,
    private val json: Json,
    private val telemetryService: TelemetryService,
    private val messagingMetrics: MessagingMetrics,
) {
    private val log = KotlinLogging.logger {}

    @KafkaListener(topics = [$$"${wallet-revocation.topic}"], groupId = $$"${wallet-revocation.group.mdvm}")
    fun onRevocation(payload: String) {
        telemetryService.withSpanSync("MdvmRevocationListener.onRevocation") {
            val event = json.decodeFromString<WalletInstanceRevocationEvent>(payload)
            runBlocking { mdvmAccountService.revokeByWiHandle(event.wiHandle) }
                .report(Module.MDVM, event, messagingMetrics, log)
        }
    }
}
