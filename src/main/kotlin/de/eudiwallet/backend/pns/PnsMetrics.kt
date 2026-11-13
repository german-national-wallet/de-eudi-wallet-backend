package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component

enum class PushMetricOutcome {
    DELIVERED,
    TERMINAL,
    TRANSIENT,
    REJECTED,
    RETRIES_EXHAUSTED,
    NO_REGISTRATION,
}

@Component
class PnsMetrics(
    meter: Meter,
) {
    private val deliveryCounter =
        meter.walletCounterBuilder(
            "push_notification_delivery",
            "Push notifications handled by PNS, by delivery outcome",
        ).build()

    init {
        PushMetricOutcome.entries.forEach { deliveryCounter.add(0, outcomeAttributes(it)) }
    }

    fun countPushNotification(outcome: PushMetricOutcome) = deliveryCounter.add(1, outcomeAttributes(outcome))

    private fun outcomeAttributes(outcome: PushMetricOutcome) =
        Attributes.of(stringKey("outcome"), outcome.name.lowercase())
}
