package de.eudiwallet.backend.pns

import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.SerializationException
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.springframework.beans.factory.config.BeanFactoryPostProcessor
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.kafka.autoconfigure.ConcurrentKafkaListenerContainerFactoryConfigurer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory
import org.springframework.kafka.core.ConsumerFactory
import org.springframework.kafka.listener.ConsumerRecordRecoverer
import org.springframework.kafka.listener.DefaultErrorHandler
import org.springframework.util.backoff.FixedBackOff

internal const val KAFKA_ENABLED_PROPERTY = "messaging.kafka.enabled"
internal const val PUSH_CONSUMER_ENABLED_PROPERTY = "pns.push.enabled"

internal const val PUSH_NOTIFICATION_CONTAINER_FACTORY = "pushNotificationListenerContainerFactory"

private const val RETRY_BACKOFF_MS = 5_000L

private const val MAX_POLL_RECORDS = 5

@Configuration
@ConditionalOnProperty(name = [KAFKA_ENABLED_PROPERTY, PUSH_CONSUMER_ENABLED_PROPERTY], havingValue = "true")
class PnsPushMessagingConfig {
    private val log = KotlinLogging.logger {}

    @Bean(PUSH_NOTIFICATION_CONTAINER_FACTORY)
    fun pushNotificationListenerContainerFactory(
        configurer: ConcurrentKafkaListenerContainerFactoryConfigurer,
        consumerFactory: ConsumerFactory<Any, Any>,
    ): ConcurrentKafkaListenerContainerFactory<Any, Any> {
        val factory = ConcurrentKafkaListenerContainerFactory<Any, Any>()
        configurer.configure(factory, consumerFactory)
        factory.containerProperties.kafkaConsumerProperties
            .setProperty(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, MAX_POLL_RECORDS.toString())
        factory.setCommonErrorHandler(pushNotificationErrorHandler())
        return factory
    }

    private fun pushNotificationErrorHandler(): DefaultErrorHandler {
        val recoverer =
            ConsumerRecordRecoverer { record, ex ->
                log.error(ex) {
                    "Skipping poison push notification record at " +
                        "${record.topic()}-${record.partition()}@${record.offset()} (key=${record.key()})"
                }
            }
        val errorHandler =
            DefaultErrorHandler(recoverer, FixedBackOff(RETRY_BACKOFF_MS, FixedBackOff.UNLIMITED_ATTEMPTS))
        errorHandler.addNotRetryableExceptions(SerializationException::class.java)
        return errorHandler
    }

    companion object {
        @Bean
        @JvmStatic
        fun pushTransportGuard(): BeanFactoryPostProcessor =
            BeanFactoryPostProcessor { beanFactory ->
                check(beanFactory.getBeanNamesForType(MppPushClient::class.java, true, false).isNotEmpty()) {
                    "$PUSH_CONSUMER_ENABLED_PROPERTY=true needs a push transport: " +
                        "set pns.fcm.enabled=true with provisioned credentials, or disable push consumption"
                }
            }
    }
}
