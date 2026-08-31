package de.eudiwallet.backend.shared.messaging

import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.SerializationException
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.kafka.listener.ConsumerRecordRecoverer
import org.springframework.kafka.listener.DefaultErrorHandler
import org.springframework.util.backoff.FixedBackOff

private const val RETRY_BACKOFF_MS = 5_000L

@Configuration
@ConditionalOnProperty(prefix = "messaging.kafka", name = ["enabled"], havingValue = "true")
class KafkaMessagingConfig {
    private val log = KotlinLogging.logger {}

    @Bean
    fun revocationErrorHandler(): DefaultErrorHandler {
        val recoverer =
            ConsumerRecordRecoverer { record, ex ->
                log.error(ex) {
                    "Skipping poison revocation record at " +
                        "${record.topic()}-${record.partition()}@${record.offset()} (key=${record.key()})"
                }
            }
        val backOff = FixedBackOff(RETRY_BACKOFF_MS, FixedBackOff.UNLIMITED_ATTEMPTS)
        val errorHandler = DefaultErrorHandler(recoverer, backOff)
        errorHandler.addNotRetryableExceptions(SerializationException::class.java)
        return errorHandler
    }
}
