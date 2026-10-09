package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.TrustedRootPair
import at.asitplus.attestation.android.TrustedRoot
import com.vdurmont.semver4j.Semver
import de.eudiwallet.backend.shared.crypto.readX509Cert
import de.eudiwallet.backend.shared.json.fromJson
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.Serializable
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.Resource

@ConfigurationProperties(prefix = "ios.integrity")
class IOSIntegrityConfig(
    val allowSkipKeyAttestation: Boolean = false,
    val appId: String,
    val acceptableBundleIdList: List<String>,
    val allowAppAttestDevEnvironment: Boolean = false,
    val minimalOsVersion: String,
    val minimalBuildNumber: String,
    val vulnerableClassesResource: Resource? = ClassPathResource("ios/vulnerable_device_classes.json"),
    val counterJumpLoggingThreshold: Long,
    val additionalTrustedRoot: Resource? = null,
) {
    private val log = KotlinLogging.logger {}

    val vulnerableClassEntries: List<VulnerableIosDeviceClassEntry> = loadVulnerableClasses()

    val additionalTrustedRootPair: Set<TrustedRootPair> = loadAdditionalTrustedRootPair()

    private fun loadVulnerableClasses(): List<VulnerableIosDeviceClassEntry> {
        val resource = vulnerableClassesResource
        if (resource == null) {
            log.info { "No vulnerable iOS device classes resource provided" }
            return emptyList()
        }

        val json = resource.inputStream.bufferedReader().use { it.readText() }
        val vulnerableClasses = json.fromJson<VulnerableIosDeviceClasses>()
        log.info {
            "Loaded ${vulnerableClasses.entries.size} vulnerable iOS device class entries " +
                "from ${resource.description}"
        }

        return vulnerableClasses.entries.onEach { entry -> entry.verify() }
    }

    private fun loadAdditionalTrustedRootPair(): Set<TrustedRootPair> {
        if (additionalTrustedRoot == null) {
            return emptySet()
        }
        val certificate = readX509Cert(additionalTrustedRoot)
        log.warn {
            "Trusting an additional App Attest root from ${additionalTrustedRoot.description}: " +
                "${certificate.subjectX500Principal.name}. This must never be set in production."
        }
        return setOf(
            TrustedRootPair(
                TrustedRoot.Certificate(certificate),
                TrustedRoot.Certificate(certificate),
            ),
        )
    }
}

@Serializable
data class VulnerableIosDeviceClasses(
    val entries: List<VulnerableIosDeviceClassEntry> = emptyList(),
)

@Serializable
data class VulnerableIosDeviceClassEntry(
    val id: String,
    val classification: VulnerabilityClassification,
    val affectedClasses: List<AffectedIosDeviceClass> = emptyList(),
    val caseId: String? = null,
    val references: List<String> = emptyList(),
    val category: Int? = null,
) {
    fun verify() {
        require(affectedClasses.isNotEmpty()) { "Vulnerability $id names no affected classes" }
        affectedClasses.forEach { classEntry ->
            require(classEntry.model != null) { "Affected class of $id doesn't specify model" }
            classEntry.parsedFixingOsVersion
        }
    }
}

@Serializable
data class AffectedIosDeviceClass(
    val model: String? = null,
    val fixingOsVersion: String? = null,
) {
    val parsedFixingOsVersion: Semver? by lazy { fixingOsVersion?.let { Semver(it, Semver.SemverType.LOOSE) } }

    fun affects(deviceModel: String?): Boolean = model != null && model.equals(deviceModel, ignoreCase = true)

    fun isFixedOn(deviceVersion: Semver): Boolean {
        val fixingVersion = parsedFixingOsVersion
        return fixingVersion != null && !deviceVersion.isLowerThan(fixingVersion)
    }
}
