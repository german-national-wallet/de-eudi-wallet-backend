package de.eudiwallet.backend.shared.telemetry

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.concurrent.ConcurrentHashMap

enum class PushMetricOutcome {
    DELIVERED,
    TERMINAL,
    TRANSIENT,
    NO_REGISTRATION,
}

@Component
class MetricsService(
    private val openTelemetry: OpenTelemetry,
) {
    private val meter: Meter get() = openTelemetry.getMeter("de.eudiwallet.backend")

    private val primaryKeyTimeToExpiryByLineage = ConcurrentHashMap<String, LocalDate>()

    private val pushNotificationCounter by lazy {
        meter.counterBuilder("push_notification_delivery")
            .setDescription("Push notifications handled by PNS, by delivery outcome")
            .build()
    }

    private val pushPublishFailureCounter by lazy {
        meter.counterBuilder("push_notification_publish_failure")
            .setDescription("Push notifications dropped because the publish to the topic failed")
            .build()
    }

    init {
        meter.gaugeBuilder("primary_key_time_to_expiry")
            .ofLongs()
            .setUnit("d")
            .setDescription("Days until the primary key of a lineage expires")
            .buildWithCallback { measurement ->
                primaryKeyTimeToExpiryByLineage.forEach { (lineage, expiryDate) ->
                    measurement.record(
                        ChronoUnit.DAYS.between(LocalDate.now(), expiryDate),
                        Attributes.of(stringKey("lineage"), lineage),
                    )
                }
            }
    }

    fun countPushNotification(outcome: PushMetricOutcome) =
        pushNotificationCounter.add(1, Attributes.of(stringKey("outcome"), outcome.name.lowercase()))

    fun countPushPublishFailure() = pushPublishFailureCounter.add(1)

    fun setPrimaryKeyExpiryDate(
        lineage: String,
        expiryDate: LocalDate,
    ) {
        if (expiryDate != LocalDate.MAX) {
            primaryKeyTimeToExpiryByLineage[lineage] = expiryDate
        } else {
            primaryKeyTimeToExpiryByLineage.remove(lineage)
        }
    }
}
