package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.attestation.android.AndroidRevocationList
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.parseHex
import com.vdurmont.semver4j.Semver
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.Resource
import java.math.BigInteger
import java.time.YearMonth
import java.util.Locale
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

@Configuration
class MakotoConfiguration(
    private val iosConfig: IOSIntegrityConfig,
    private val androidConfig: AndroidIntegrityConfig,
) {
    @Bean
    fun makoto() =
        Makoto(
            androidAttestationConfiguration =
                AndroidAttestationConfiguration(
                    enableSoftwareAttestation = androidConfig.allowSoftwareKeyAttestation,
                    applications =
                        androidConfig.expectedPackageNames.map { packageName ->
                            AndroidAttestationConfiguration.AppData(
                                packageName = packageName,
                                signerFingerprints =
                                    androidConfig.expectedSignerFingerprints.map {
                                        it.replace(":", "").parseHex()
                                    }.toSet(),
                            )
                        },
                    attestationStatementValiditySeconds = 1.hours.inWholeSeconds,
                    androidVersion = androidConfig.minimalAndroidVersion?.androidVersionAsNumber(),
                    patchLevel = androidConfig.patchLevelFreshness?.asPatchLevel(),
                    allowBootloaderUnlock = false,
                    revocation =
                        listOf(
                            AndroidRevocationList.GoogleDefaultLoaderConfig,
                            AndroidRevocationList.InMemoryLoader.Configuration(
                                androidConfig.revocationListResource.loadAndroidRevocationList(),
                            ),
                        ),
                ),
            iosAttestationConfiguration =
                IosAttestationConfiguration(
                    applications =
                        buildList {
                            addAll(iosConfig.acceptableBundleIdList.asAppData(isProduction = true))
                            if (iosConfig.allowAppAttestDevEnvironment) {
                                addAll(iosConfig.acceptableBundleIdList.asAppData(isProduction = false))
                            }
                        },
                    attestationStatementValiditySeconds = 1.hours.inWholeSeconds,
                    iosVersion =
                        IosAttestationConfiguration.OsVersions(
                            iosConfig.minimalOsVersion,
                            iosConfig.minimalBuildNumber,
                        ),
                ),
            clock = Clock.System,
        )

    private fun List<String>.asAppData(isProduction: Boolean) =
        map { bundle ->
            IosAttestationConfiguration.AppData(
                teamIdentifier = iosConfig.appId,
                bundleIdentifier = bundle,
                sandbox = !isProduction,
            )
        }

    @Suppress("MagicNumber")
    private fun String.androidVersionAsNumber(): Int {
        val version = Semver(this, Semver.SemverType.STRICT)
        return version.major.toInt() * 10000 + version.minor.toInt() * 100 + version.patch.toInt()
    }

    private fun Int.asPatchLevel() = PatchLevel(YearMonth.now().minusMonths(this.toLong()))

    private fun Resource?.loadAndroidRevocationList(): AndroidRevocationList =
        if (this != null) {
            val json = inputStream.bufferedReader().use { it.readText() }

            val list =
                AndroidRevocationList.deserialize(json).run {
                    copy(entries = entries.mapKeys { (serial, _) -> serial.normalize() })
                }
            log.info { "Loaded ${list.entries.size} additional Android revocation entries from $description" }

            list
        } else {
            log.info { "No additional Android revocation entries provided" }
            AndroidRevocationList(emptyMap())
        }

    @Suppress("MagicNumber")
    private fun String.normalize(): String = BigInteger(this, 16).toString(16).lowercase(Locale.getDefault())

    private val log = KotlinLogging.logger {}
}
