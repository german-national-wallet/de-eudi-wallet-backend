package de.eudiwallet.backend.shared.messaging

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.future.await
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty(prefix = "messaging.kafka", name = ["enabled"], havingValue = "true")
class KafkaPushNotificationPublisher(
    private val kafkaTemplate: KafkaTemplate<String, String>,
    private val json: Json,
    @Value($$"${push-notification.topic}") private val topic: String,
) : PushNotificationPublisher {
    @Suppress("TooGenericExceptionCaught")
    override suspend fun publish(event: PushNotificationEvent) {
        val payload = json.encodeToString(event)
        try {
            kafkaTemplate.send(topic, event.accountId, payload).await()
        } catch (ex: CancellationException) {
            throw ex
        } catch (ex: Exception) {
            throw MessagingUnavailableException(ex)
        }
    }
}
