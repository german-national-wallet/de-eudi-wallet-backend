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

    fun countPushNotification(outcome: PushMetricOutcome) =
        deliveryCounter.add(1, Attributes.of(stringKey("outcome"), outcome.name.lowercase()))
}
