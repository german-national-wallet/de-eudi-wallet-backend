package de.eudiwallet.backend.shared.messaging

import kotlinx.coroutines.future.await
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.stereotype.Component
import org.apache.kafka.common.KafkaException as ClientKafkaException
import org.springframework.kafka.KafkaException as SpringKafkaException

@Component
@ConditionalOnProperty(prefix = "messaging.kafka", name = ["enabled"], havingValue = "true")
class KafkaWalletInstanceRevocationPublisher(
    private val kafkaTemplate: KafkaTemplate<String, String>,
    private val json: Json,
    @Value($$"${wallet-revocation.topic}") private val topic: String,
) : WalletInstanceRevocationPublisher {
    override suspend fun publish(event: WalletInstanceRevocationEvent) {
        val payload = json.encodeToString(event)
        try {
            kafkaTemplate.send(topic, event.wiHandle, payload).await()
        } catch (ex: SpringKafkaException) {
            throw MessagingUnavailableException(ex)
        } catch (ex: ClientKafkaException) {
            throw MessagingUnavailableException(ex)
        }
    }
}
