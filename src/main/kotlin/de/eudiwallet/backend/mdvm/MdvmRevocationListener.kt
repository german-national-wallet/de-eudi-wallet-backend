package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.messaging.PushNotificationPublisher
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.telemetry.MetricsService
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
    private val pushNotificationPublisher: PushNotificationPublisher,
    private val json: Json,
    private val telemetryService: TelemetryService,
    private val metricsService: MetricsService,
) {
    private val log = KotlinLogging.logger {}

    @KafkaListener(topics = [$$"${wallet-revocation.topic}"], groupId = $$"${wallet-revocation.group.mdvm}")
    fun onRevocation(payload: String) {
        telemetryService.withSpanSync("MdvmRevocationListener.onRevocation") {
            val event = json.decodeFromString<WalletInstanceRevocationEvent>(payload)
            runBlocking {
                mdvmAccountService.revokeByWiHandle(event.wiHandle)?.let { accountId ->
                    try {
                        pushNotificationPublisher.publish(revocationPushNotification(accountId))
                    } catch (ex: MessagingUnavailableException) {
                        metricsService.countPushPublishFailure()
                        log.error(ex) { "Dropping revocation push for $accountId, the revocation itself stands" }
                    }
                }
            }
        }
    }
}
