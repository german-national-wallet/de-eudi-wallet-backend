package de.eudiwallet.backend.pns

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "pns")
class PnsConfiguration(
    val issuer: String,
)
