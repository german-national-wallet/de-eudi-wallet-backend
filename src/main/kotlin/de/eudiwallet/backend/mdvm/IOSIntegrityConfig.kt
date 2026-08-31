package de.eudiwallet.backend.mdvm

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@ConfigurationProperties(prefix = "ios.integrity")
@Component
data class IOSIntegrityConfig(
    var allowSkipKeyAttestation: Boolean = false,
    var appId: String = "RKHWDWUG28",
    var acceptableBundleIdList: List<String> = emptyList(),
    var allowAppAttestDevEnvironment: Boolean = false,
    var minimalOsVersion: String = "18.0",
    var minimalBuildNumber: String = "22A3351",
)
