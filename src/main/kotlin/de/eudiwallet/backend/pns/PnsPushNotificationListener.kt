package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.messaging.PushNotificationEvent
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty(name = [KAFKA_ENABLED_PROPERTY, PUSH_CONSUMER_ENABLED_PROPERTY], havingValue = "true")
class PnsPushNotificationListener(
    private val deliveryService: PnsDeliveryService,
    private val json: Json,
    private val telemetryService: TelemetryService,
) {
    @KafkaListener(
        topics = [$$"${push-notification.topic}"],
        groupId = $$"${push-notification.group.pns}",
        containerFactory = PUSH_NOTIFICATION_CONTAINER_FACTORY,
    )
    fun onPushNotification(payload: String) {
        telemetryService.withSpanSync("PnsPushNotificationListener.onPushNotification") {
            val event = json.decodeFromString<PushNotificationEvent>(payload)
            runBlocking { deliveryService.deliver(event) }
        }
    }
}
