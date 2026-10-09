package de.eudiwallet.backend.mdvm

import com.vdurmont.semver4j.Requirement
import com.vdurmont.semver4j.Semver
import de.eudiwallet.backend.shared.json.fromJson
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.Serializable
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.Resource
import java.time.YearMonth

@ConfigurationProperties(prefix = "android.integrity")
class AndroidIntegrityConfig(
    val allowSkipKeyAttestation: Boolean = false,
    val allowSoftwareKeyAttestation: Boolean = false,
    val expectedPackageNames: List<String>,
    val expectedSignerFingerprints: List<String>,
    val minimalAndroidVersion: String,
    val patchLevelFreshness: Int,
    val minimalAppVersion: Long,
    val revocationListResource: Resource? = ClassPathResource("android/certificate-revocations.json"),
    val vulnerableClassesResource: Resource? = ClassPathResource("android/vulnerable_device_classes.json"),
    val additionalTrustedRoot: Resource? = null,
) {
    private val log = KotlinLogging.logger {}

    val vulnerableClassEntries: List<VulnerableAndroidDeviceClassEntry> = loadVulnerableClasses()

    private fun loadVulnerableClasses(): List<VulnerableAndroidDeviceClassEntry> {
        val resource = vulnerableClassesResource
        if (resource == null) {
            log.info { "No vulnerable Android device classes resource provided" }
            return emptyList()
        }

        val json = resource.inputStream.bufferedReader().use { it.readText() }
        val vulnerableClasses = json.fromJson<VulnerableAndroidDeviceClasses>()
        log.info {
            "Loaded ${vulnerableClasses.entries.size} vulnerable Android device class entries " +
                "from ${resource.description}"
        }

        return vulnerableClasses.entries.onEach { entry -> entry.verify() }
    }
}

@Serializable
data class VulnerableAndroidDeviceClasses(
    val entries: List<VulnerableAndroidDeviceClassEntry> = emptyList(),
)

@Serializable
data class VulnerableAndroidDeviceClassEntry(
    val id: String,
    val affectedClasses: List<AffectedAndroidDeviceClass> = emptyList(),
    val classification: VulnerabilityClassification,
    val caseId: String? = null,
    val references: List<String> = emptyList(),
    val category: Int? = null,
) {
    fun verify() {
        require(affectedClasses.isNotEmpty()) { "Vulnerability $id names no affected classes" }
        affectedClasses.forEach { classEntry ->
            require(classEntry.hasDeviceIdentifier) { "Affected class of $id names no attestationId* identifier" }
            classEntry.parsedFixingPatchLevel
            classEntry.parsedOsVersion
        }
    }
}

@Serializable
data class AffectedAndroidDeviceClass(
    val attestationIdModel: String? = null,
    val attestationIdProduct: String? = null,
    val attestationIdDevice: String? = null,
    val osVersion: String? = null,
    val fixingPatchLevel: String? = null,
) {
    val hasDeviceIdentifier: Boolean
        get() = attestationIdModel != null || attestationIdProduct != null || attestationIdDevice != null

    val parsedFixingPatchLevel: YearMonth? by lazy { fixingPatchLevel?.let { YearMonth.parse(it) } }

    val parsedOsVersion: Requirement? by lazy { osVersion?.let { Requirement.buildNPM(it) } }

    fun affects(details: AndroidAttestationDetails): Boolean {
        if (!hasDeviceIdentifier) return false
        val modelMatch = attestationIdModel?.equals(details.attestationIdModel, ignoreCase = true) ?: true
        val productMatch = attestationIdProduct?.equals(details.attestationIdProduct, ignoreCase = true) ?: true
        val deviceMatch = attestationIdDevice?.equals(details.attestationIdDevice, ignoreCase = true) ?: true

        return modelMatch && productMatch && deviceMatch &&
            (parsedOsVersion?.isOsVersionMatch(details.osVersion) ?: true)
    }

    private fun Requirement.isOsVersionMatch(attestedOsVersion: String?): Boolean =
        attestedOsVersion != null &&
            runCatching {
                isSatisfiedBy(Semver(attestedOsVersion, Semver.SemverType.LOOSE))
            }.getOrDefault(false)

    fun isFixedOn(details: AndroidAttestationDetails): Boolean {
        val fixingPatchLevel = parsedFixingPatchLevel
        val devicePatchLevel = details.osPatchLevel?.toYearMonth()
        if (fixingPatchLevel == null || devicePatchLevel == null) return false
        return !devicePatchLevel.isBefore(fixingPatchLevel)
    }
}

fun String.toYearMonth(): YearMonth? {
    val parts = split(".")
    val patchLevel =
        if (parts.size == 2) {
            runCatching { YearMonth.of(parts[0].toInt(), parts[1].toInt()) }.getOrNull()
        } else {
            null
        }
    return patchLevel
}
