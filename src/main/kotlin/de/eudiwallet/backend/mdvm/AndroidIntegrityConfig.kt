package de.eudiwallet.backend.mdvm

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.Resource
import org.springframework.stereotype.Component

@ConfigurationProperties(prefix = "android.integrity")
@Component
data class AndroidIntegrityConfig(
    var allowSkipKeyAttestation: Boolean = false,
    var allowSoftwareKeyAttestation: Boolean = false,
    var expectedPackageNames: List<String> = emptyList(),
    var expectedSignerFingerprints: List<String> = emptyList(),
    var minimalAndroidVersion: String? = "14.0.0",
    var patchLevelFreshness: Int? = 12,
    var minimalAppVersion: Long? = 1204,
    var revocationListResource: Resource? = ClassPathResource("android/certificate-revocations.json"),
)
