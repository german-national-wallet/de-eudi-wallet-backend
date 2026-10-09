package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.messaging.PushNotificationEvent
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.SerializationException
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import java.util.UUID

@Service
@ConditionalOnProperty(name = [KAFKA_ENABLED_PROPERTY, PUSH_CONSUMER_ENABLED_PROPERTY], havingValue = "true")
class PnsDeliveryService(
    private val repository: PnsRepository,
    private val mppPushClient: MppPushClient,
    private val pnsMetrics: PnsMetrics,
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    suspend fun deliver(event: PushNotificationEvent) =
        telemetryService.withSpan("PnsDeliveryService.deliver") {
            val accountId = event.accountUuid()
            val registration = repository.findByAccountId(accountId)
            if (registration == null) {
                log.info { "Account $accountId has no push registration, dropping push notification ${event.eventId}" }
                pnsMetrics.countPushNotification(PushMetricOutcome.NO_REGISTRATION)
                return@withSpan
            }
            when (val outcome = mppPushClient.send(registration.mppRegistrationToken, event.toPushNotification())) {
                is PushOutcome.Delivered -> {
                    pnsMetrics.countPushNotification(PushMetricOutcome.DELIVERED)
                    log.debug { "Delivered push notification ${event.eventId} as ${outcome.messageId}" }
                }

                is PushOutcome.Terminal -> {
                    pnsMetrics.countPushNotification(PushMetricOutcome.TERMINAL)
                    log.warn { "Dropping push notification ${event.eventId} for $accountId: ${outcome.reason}" }
                }

                is PushOutcome.Transient -> {
                    pnsMetrics.countPushNotification(PushMetricOutcome.TRANSIENT)
                    throw PushDeliveryUnavailableException(event.eventId, outcome.reason)
                }
            }
        }

    private fun PushNotificationEvent.accountUuid(): UUID =
        try {
            UUID.fromString(accountId)
        } catch (ex: IllegalArgumentException) {
            throw SerializationException("Push notification $eventId carries a malformed accountId", ex)
        }

    private fun PushNotificationEvent.toPushNotification() =
        PushNotification(titleLocKey = titleLocKey, bodyLocKey = bodyLocKey, data = data)
}

class PushDeliveryUnavailableException(
    eventId: String,
    reason: String,
) : RuntimeException("Push notification $eventId could not be delivered: $reason")
