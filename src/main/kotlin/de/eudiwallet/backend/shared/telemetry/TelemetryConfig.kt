package de.eudiwallet.backend.shared.telemetry

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "telemetry")
data class TelemetryConfig(
    var filterClientUrlAttributes: Boolean = true,
    var filterIpAttributes: Boolean = true,
)
