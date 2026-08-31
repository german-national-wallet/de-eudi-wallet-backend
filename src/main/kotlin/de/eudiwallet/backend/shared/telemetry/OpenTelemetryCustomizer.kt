package de.eudiwallet.backend.shared.telemetry

import io.github.oshai.kotlinlogging.KotlinLogging
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.context.Context
import io.opentelemetry.contrib.sampler.RuleBasedRoutingSampler
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider
import io.opentelemetry.sdk.trace.ReadWriteSpan
import io.opentelemetry.sdk.trace.ReadableSpan
import io.opentelemetry.sdk.trace.SpanProcessor
import io.opentelemetry.semconv.UrlAttributes
import jakarta.annotation.PostConstruct
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenTelemetryCustomizer {
    private val log = KotlinLogging.logger {}

    @Value($$"${otel.service.name:unknown_service}")
    private lateinit var serviceName: String

    @Value($$"${otel.exporter.otlp.endpoint:not-set}")
    private lateinit var otlpExporterEndpoint: String

    @PostConstruct
    fun logConfiguration() {
        log.info { "OpenTelemetry exporting to $otlpExporterEndpoint with serviceName: $serviceName" }
    }

    @Bean
    fun otelCustomizer(telemetryConfig: TelemetryConfig): AutoConfigurationCustomizerProvider =
        AutoConfigurationCustomizerProvider { autoConfigurationCustomizer ->
            autoConfigurationCustomizer.addSamplerCustomizer { fallback, _ ->
                RuleBasedRoutingSampler.builder(SpanKind.SERVER, fallback)
                    .drop(UrlAttributes.URL_PATH, "^/actuator")
                    .build()
            }

            autoConfigurationCustomizer.addTracerProviderCustomizer { tracerProviderBuilder, _ ->
                if (telemetryConfig.filterIpAttributes) {
                    tracerProviderBuilder.addSpanProcessor(
                        AttributeFilterSpanProcessor(listOf(CLIENT_ADDRESS_KEY, NETWORK_PEER_ADDRESS_KEY)),
                    )
                }
                if (telemetryConfig.filterClientUrlAttributes) {
                    tracerProviderBuilder.addSpanProcessor(AttributeFilterSpanProcessor(listOf(URL_FULL_KEY)))
                }

                tracerProviderBuilder
            }
        }

    companion object {
        private val CLIENT_ADDRESS_KEY = AttributeKey.stringKey("client.address")
        private val NETWORK_PEER_ADDRESS_KEY = AttributeKey.stringKey("network.peer.address")
        private val URL_FULL_KEY = AttributeKey.stringKey("url.full")
    }
}

class AttributeFilterSpanProcessor(
    val attributeKeys: List<AttributeKey<String>>,
) : SpanProcessor {
    override fun isStartRequired(): Boolean = true

    override fun onStart(
        parentContext: Context,
        span: ReadWriteSpan,
    ) {
        for (key in attributeKeys) {
            val value = span.attributes[key]
            if (value != null) {
                span.setAttribute(key, "***")
            }
        }
    }

    override fun isEndRequired(): Boolean = false

    override fun onEnd(span: ReadableSpan) = Unit
}
