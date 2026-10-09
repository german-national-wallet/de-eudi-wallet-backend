package de.eudiwallet.backend.shared.telemetry

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.LongCounterBuilder
import io.opentelemetry.api.metrics.Meter
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component

const val METRICS_PREFIX = "wallet_backend_"

fun Meter.walletCounterBuilder(
    name: String,
    description: String,
): LongCounterBuilder =
    counterBuilder("$METRICS_PREFIX$name")
        .setDescription(description)

fun Meter.walletGaugeBuilder(
    name: String,
    description: String,
) = gaugeBuilder("$METRICS_PREFIX$name")
    .setDescription(description)

@Configuration
class MeterConfiguration {
    @Bean
    fun meter(openTelemetry: OpenTelemetry): Meter = openTelemetry.getMeter("de.eudiwallet.backend")
}

@Component
class ApplicationMetrics(
    meter: Meter,
    @Value($$"${info.application.version}") applicationVersion: String,
) {
    init {
        meter.walletGaugeBuilder("application_version", "Deployed backend version")
            .ofLongs()
            .buildWithCallback { measurement ->
                measurement.record(1, Attributes.of(stringKey("version"), applicationVersion))
            }
    }
}
