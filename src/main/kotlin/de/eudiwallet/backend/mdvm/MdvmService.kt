package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.Makoto
import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.parseHex
import at.asitplus.attestation.canonicalize
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toCryptoPublicKey
import ch.veehait.devicecheck.appattest.assertion.Assertion
import ch.veehait.devicecheck.appattest.attestation.ValidatedAttestation
import com.vdurmont.semver4j.Semver
import com.vdurmont.semver4j.SemverException
import de.eudiwallet.backend.mdvm.AndroidAttestationDetails.Companion.toAndroidAttestationDetails
import de.eudiwallet.backend.shared.crypto.fromBase64
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.json.toPostgresJson
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.r2dbc.postgresql.codec.Json
import org.springframework.stereotype.Service
import java.security.interfaces.ECPublicKey
import java.time.LocalDate
import java.time.YearMonth
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

private val HARDWARE_SECURITY_LEVELS =
    setOf(
        AttestationKeyDescription.SecurityLevel.TRUSTED_ENVIRONMENT,
        AttestationKeyDescription.SecurityLevel.STRONGBOX,
    )

@Service
@Suppress("TooGenericExceptionCaught", "TooManyFunctions")
class MdvmService(
    private val makoto: Makoto,
    private val mdvmAnalyticsRepository: MdvmAnalyticsRepository,
    private val telemetryService: TelemetryService,
    private val iosConfig: IOSIntegrityConfig,
    private val androidConfig: AndroidIntegrityConfig,
) {
    private val log = KotlinLogging.logger {}

    suspend fun verifyAndroidKeyAttestation(
        keyAttestationCertificateChain: List<String>,
        expectedNonce: ByteArray,
        skipIntegrityChecks: SkipIntegrityChecks,
    ): AndroidDeviceAttestationData? =
        telemetryService.withSpan("MdvmService.verifyAndroidKeyAttestation") {
            if (skipIntegrityChecks.skipKeyAttestation) {
                if (!androidConfig.allowSkipKeyAttestation) {
                    throw SkipIntegrityChecksNotAllowedException(skipIntegrityChecks)
                }
                null
            } else {
                verifiedAndroidAttestationData(keyAttestationCertificateChain, expectedNonce)
            }
        }

    private fun decodeCertificateChain(keyAttestationCertificateChain: List<String>) =
        try {
            keyAttestationCertificateChain.map {
                X509Certificate.decodeFromByteArray(it.fromBase64())
                    ?: throw AndroidKeyAttestationException.InvalidKeyCertificateException()
            }
        } catch (ex: IllegalArgumentException) {
            throw AndroidKeyAttestationException.InvalidKeyCertificateException(ex)
        }

    private suspend fun verifiedAndroidAttestationData(
        keyAttestationCertificateChain: List<String>,
        expectedNonce: ByteArray,
    ): AndroidDeviceAttestationData {
        val attestation = AndroidKeystoreAttestation(decodeCertificateChain(keyAttestationCertificateChain))
        val keyAttestationResponse =
            telemetryService.withSpan("Makoto.verifyKeyAttestation") {
                makoto.verifyKeyAttestation(attestation, expectedNonce)
            }

        when (val details = keyAttestationResponse.details) {
            is AttestationResult.Android.Verified -> {
                val attestedKey =
                    keyAttestationResponse.attestedPublicKey as? ECPublicKey
                        ?: throw AndroidKeyAttestationException.AttestedKeyNotFoundException(keyAttestationResponse)
                return AndroidDeviceAttestationData(
                    details.androidAttestationExtension.toAndroidAttestationDetails(
                        androidConfig.allowSoftwareKeyAttestation,
                    ),
                    attestedKey,
                )
            }

            is AttestationResult.Error -> {
                val debugInfo = runCatching { makoto.collectDebugInfo(attestation, expectedNonce).serializeCompact() }
                throw AndroidKeyAttestationException.AttestationError(
                    keyAttestationResponse.details as AttestationResult.Error,
                    debugInfo.getOrElse { "debug info unavailable" },
                )
            }

            else -> {
                throw AndroidKeyAttestationException.WrongAttestationResult(keyAttestationResponse.details)
            }
        }
    }

    suspend fun verifyIosDeviceAttestation(
        deviceAttestation: String,
        publicKey: ECPublicKey,
        expectedNonce: ByteArray,
        skipIntegrityChecks: SkipIntegrityChecks,
    ): IosDeviceAttestationData? =
        telemetryService.withSpan("MdvmService.verifyIosDeviceAttestation") {
            if (skipIntegrityChecks.skipKeyAttestation) {
                if (!iosConfig.allowSkipKeyAttestation) {
                    throw SkipIntegrityChecksNotAllowedException(skipIntegrityChecks)
                }
                return@withSpan null
            }
            val decodedAttestation =
                try {
                    deviceAttestation.fromBase64()
                } catch (ex: Exception) {
                    throw IosKeyAttestationException.MalformedAttestation(deviceAttestation, ex)
                }

            val attestation = IosHomebrewAttestation(decodedAttestation, buildIosClientData(publicKey, expectedNonce))
            val keyAttestationResult =
                telemetryService.withSpan("Makoto.verifyKeyAttestation") {
                    makoto.verifyKeyAttestation(attestation, expectedNonce)
                }

            when (keyAttestationResult.details) {
                is AttestationResult.IOS.Verified -> {
                    val attestedKey =
                        (keyAttestationResult.attestedPublicKey as? ECPublicKey)
                            ?: throw IosKeyAttestationException.AttestedKeyNotFoundException(keyAttestationResult)
                    IosDeviceAttestationData(
                        (keyAttestationResult.details as AttestationResult.IOS.Verified).attestation.canonicalize(),
                        attestedKey,
                    )
                }

                is AttestationResult.Error -> {
                    val debugInfo =
                        runCatching { makoto.collectDebugInfo(attestation, expectedNonce).serializeCompact() }
                    throw IosKeyAttestationException.AttestationError(
                        keyAttestationResult.details as AttestationResult.Error,
                        debugInfo.getOrElse { "debug info unavailable" },
                    )
                }

                else -> {
                    throw IosKeyAttestationException.WrongAttestationResult(keyAttestationResult.details)
                }
            }
        }

    suspend fun verifyIosDeviceAssertion(
        deviceAttestation: ValidatedAttestation?,
        deviceAssertion: String,
        publicKey: ECPublicKey,
        expectedNonce: ByteArray,
        previousCounter: Long,
        skipIntegrityChecks: SkipIntegrityChecks,
    ): IosDeviceAssertionData? =
        telemetryService.withSpan("MdvmService.verifyIosDeviceAssertion") {
            if (skipIntegrityChecks.skipKeyAttestation) {
                if (!iosConfig.allowSkipKeyAttestation) {
                    throw SkipIntegrityChecksNotAllowedException(skipIntegrityChecks)
                }
                return@withSpan null
            }
            if (deviceAttestation == null) {
                throw IosKeyAttestationException.MissingAttestation()
            }
            val decodedAssertion =
                try {
                    deviceAssertion.fromBase64()
                } catch (ex: Exception) {
                    throw IosKeyAttestationException.MalformedAssertion(deviceAssertion, ex)
                }
            val assertionResult: Result<Assertion> =
                telemetryService.withSpan("Makoto.Ios.verifyAssertion") {
                    makoto.ios.validateAssertionOverChallenge(
                        validatedAttestation = deviceAttestation,
                        assertion = decodedAssertion,
                        expectedChallenge = buildIosClientData(publicKey, expectedNonce),
                        lastSeenCounter = previousCounter,
                    )
                }
            if (assertionResult.isSuccess) {
                IosDeviceAssertionData(assertionResult.getOrThrow().authenticatorData.signCount)
            } else {
                throw IosKeyAttestationException.DeviceAssertionError(
                    assertionResult.exceptionOrNull(),
                )
            }
        }

    private fun buildIosClientData(
        publicKey: ECPublicKey,
        expectedNonce: ByteArray,
    ): ByteArray {
        val keyAsCryptoPublicKey =
            try {
                publicKey.toCryptoPublicKey().getOrThrow()
            } catch (ex: Exception) {
                throw MalformedPublicKey(publicKey.toString(), ex)
            }
        return IosHomebrewAttestation.ClientData(keyAsCryptoPublicKey, expectedNonce).prepareDigestInput()
    }

    suspend fun saveMdvmAnalytics(
        operationName: String,
        authChallenge: String,
        skipIntegrityChecks: SkipIntegrityChecks,
        request: Json,
        exceptionDetails: Map<String, String>?,
    ): Unit =
        telemetryService.withSpan("MdvmService.saveMdvmAnalytics") {
            try {
                mdvmAnalyticsRepository.save(
                    MdvmAnalyticsEntity(
                        id = UUID.randomUUID(),
                        operationName = operationName,
                        authChallenge = authChallenge,
                        skipIntegrityChecks = skipIntegrityChecks.value(),
                        request = request,
                        exceptionDetails = exceptionDetails?.toPostgresJson(),
                    ),
                )
            } catch (ex: CancellationException) {
                throw ex
            } catch (ex: Throwable) {
                log.warn(ex) { "Unable to save analytics data for $operationName" }
            }
        }

    fun verifyAndroidDeviceProperties(
        attestedDetails: AndroidAttestationDetails,
        storedDetails: AndroidAttestationDetails?,
    ) {
        verifyAndroidKeyStorage(attestedDetails)
        verifyAndroidSystemIntegrity(attestedDetails)
        verifyAndroidOsVersion(attestedDetails)
        verifyAndroidPatchLevel(attestedDetails)
        verifyAndroidApplication(attestedDetails.packageInfo)
        storedDetails?.let { verifyAndroidDevicePlausibility(attestedDetails, it) }
    }

    private fun verifyAndroidKeyStorage(details: AndroidAttestationDetails) {
        if (androidConfig.allowSoftwareKeyAttestation) {
            return
        }
        if (details.attestationSecurityLevel !in HARDWARE_SECURITY_LEVELS ||
            details.keyMintSecurityLevel !in HARDWARE_SECURITY_LEVELS
        ) {
            throw AndroidKeyAttestationException.SecurityLevelViolation(
                details.attestationSecurityLevel,
                details.keyMintSecurityLevel,
            )
        }
        if (details.origin != AuthorizationList.Origin.GENERATED) {
            throw AndroidKeyAttestationException.KeyNotGenerated(details.origin)
        }
    }

    private fun verifyAndroidSystemIntegrity(details: AndroidAttestationDetails) {
        if (androidConfig.allowSoftwareKeyAttestation) {
            return
        }
        if (details.deviceLocked != true) {
            throw AndroidKeyAttestationException.BootloaderUnlocked(details.deviceLocked)
        }
        if (details.verifiedBootState != AuthorizationList.RootOfTrust.VerifiedBootState.Verified) {
            throw AndroidKeyAttestationException.BootStateUnverified(details.verifiedBootState)
        }
    }

    private fun verifyAndroidOsVersion(details: AndroidAttestationDetails) {
        val minimalVersion = androidConfig.minimalAndroidVersion ?: return
        val deviceVersion =
            details.osVersion?.toSemverOrNull()
                ?: throw AndroidKeyAttestationException.MinimalOsVersionViolation(details.osVersion, minimalVersion)
        if (deviceVersion.isLowerThan(Semver(minimalVersion, Semver.SemverType.STRICT))) {
            throw AndroidKeyAttestationException.MinimalOsVersionViolation(details.osVersion, minimalVersion)
        }
    }

    private fun verifyAndroidPatchLevel(details: AndroidAttestationDetails) {
        val freshnessInMonths = androidConfig.patchLevelFreshness ?: return
        val minimalPatchLevel = YearMonth.from(LocalDate.now().minusMonths(freshnessInMonths.toLong()))
        val devicePatchLevel =
            details.osPatchLevel?.toYearMonthOrNull()
                ?: throw AndroidKeyAttestationException.MinimalPatchLevelViolation(
                    details.osPatchLevel,
                    minimalPatchLevel.toString(),
                )
        if (devicePatchLevel.isBefore(minimalPatchLevel)) {
            throw AndroidKeyAttestationException.MinimalPatchLevelViolation(
                details.osPatchLevel,
                minimalPatchLevel.toString(),
            )
        }
    }

    private fun verifyAndroidApplication(packageInfo: AndroidPackageInfo?) {
        val expectedPackageNames = androidConfig.expectedPackageNames
        if (expectedPackageNames.isNotEmpty()) {
            if (packageInfo?.packageName == null || packageInfo.packageName.none { it in expectedPackageNames }) {
                throw AndroidKeyAttestationException.PackageNameMismatch(packageInfo?.packageName, expectedPackageNames)
            }
        }
        androidConfig.minimalAppVersion?.let { minimalAppVersion ->
            val appVersion = packageInfo?.packageVersion
            if (appVersion == null || appVersion.all { it.toLong() < minimalAppVersion }) {
                throw AndroidKeyAttestationException.MinimalAppVersionViolation(appVersion, minimalAppVersion)
            }
        }
        val expectedSignatureDigests =
            androidConfig.expectedSignerFingerprints.map {
                it.replace(":", "").parseHex().toBase64()
            }
        if (expectedSignatureDigests.isNotEmpty()) {
            if (packageInfo?.signatureDigest == null ||
                packageInfo.signatureDigest.none { it in expectedSignatureDigests }
            ) {
                throw AndroidKeyAttestationException.SignatureDigestMismatch(packageInfo?.signatureDigest)
            }
        }
    }

    private fun verifyAndroidDevicePlausibility(
        attestedDetails: AndroidAttestationDetails,
        storedDetails: AndroidAttestationDetails,
    ) {
        requireAndroidStableValue(
            "attestationIdModel",
            attestedDetails.attestationIdModel,
            storedDetails.attestationIdModel,
        )
        requireAndroidStableValue(
            "attestationIdProduct",
            attestedDetails.attestationIdProduct,
            storedDetails.attestationIdProduct,
        )
        requireAndroidStableValue(
            "attestationIdDevice",
            attestedDetails.attestationIdDevice,
            storedDetails.attestationIdDevice,
        )

        storedDetails.osVersion?.toSemverOrNull()?.let { storedVersion ->
            val deviceVersion = attestedDetails.osVersion?.toSemverOrNull()
            if (deviceVersion == null || deviceVersion.isLowerThan(storedVersion)) {
                throw AndroidKeyAttestationException.VersionDecrease(
                    "osVersion",
                    attestedDetails.osVersion,
                    storedDetails.osVersion,
                )
            }
        }
        storedDetails.osPatchLevel?.toYearMonthOrNull()?.let { storedPatchLevel ->
            val devicePatchLevel = attestedDetails.osPatchLevel?.toYearMonthOrNull()
            if (devicePatchLevel == null || devicePatchLevel.isBefore(storedPatchLevel)) {
                throw AndroidKeyAttestationException.VersionDecrease(
                    "osPatchLevel",
                    attestedDetails.osPatchLevel,
                    storedDetails.osPatchLevel,
                )
            }
        }
        storedDetails.packageInfo?.packageVersion?.let { storedAppVersion ->
            val deviceAppVersion = attestedDetails.packageInfo?.packageVersion
            if (deviceAppVersion == null ||
                deviceAppVersion.any { newVersion -> storedAppVersion.any { oldVersion -> oldVersion > newVersion } }
            ) {
                throw AndroidKeyAttestationException.VersionDecrease(
                    "packageVersion",
                    deviceAppVersion?.toString(),
                    storedAppVersion.toString(),
                )
            }
        }
    }

    private fun requireAndroidStableValue(
        signal: String,
        deviceValue: String?,
        storedValue: String?,
    ) {
        if (storedValue != null && deviceValue != storedValue) {
            throw AndroidKeyAttestationException.DeviceMismatch(signal, deviceValue, storedValue)
        }
    }

    private fun String.toSemverOrNull() =
        try {
            Semver(this, Semver.SemverType.LOOSE)
        } catch (ex: SemverException) {
            log.warn(ex) { "Unparseable Android OS version $this" }
            null
        }

    private fun String.toYearMonthOrNull(): YearMonth? {
        val parts = split(".")
        val patchLevel =
            if (parts.size == 2) {
                runCatching { YearMonth.of(parts[0].toInt(), parts[1].toInt()) }.getOrNull()
            } else {
                null
            }
        if (patchLevel == null) log.warn { "Unparseable Android security patch level $this" }
        return patchLevel
    }

    fun verifyIosDeviceProperties(
        requestedDeviceClass: DeviceInfo,
        storedDeviceClass: DeviceInfo?,
    ) {
        verifyIosVersion(requestedDeviceClass)
        if (storedDeviceClass != null) {
            verifyIosDevicePlausibility(requestedDeviceClass, storedDeviceClass)
        }
    }

    private fun verifyIosVersion(requestedDeviceClass: DeviceInfo) {
        val deviceVersion = requestedDeviceClass.parsedVersion()
        if (deviceVersion.isLowerThan(iosConfig.minimalOsVersion)) {
            throw IosKeyAttestationException.MinimalVersionViolation(
                requestedDeviceClass.info["systemVersion"],
                iosConfig.minimalOsVersion,
            )
        }
    }

    private fun verifyIosDevicePlausibility(
        requestedDeviceClass: DeviceInfo,
        storedDeviceClass: DeviceInfo,
    ) {
        if (requestedDeviceClass.info["model"] != storedDeviceClass.info["model"]) {
            throw IosKeyAttestationException.ModelMismatch(
                requestedDeviceClass.info["model"],
                storedDeviceClass.info["model"],
            )
        }
        val deviceVersion = requestedDeviceClass.parsedVersion()
        val storedVersion = storedDeviceClass.parsedVersion()
        if (deviceVersion.isLowerThan(storedVersion)) {
            throw IosKeyAttestationException.VersionDecrease(
                requestedDeviceClass.info["systemVersion"],
                storedDeviceClass.info["systemVersion"],
            )
        }
    }

    private fun DeviceInfo.parsedVersion(): Semver {
        if (info["systemVersion"] == null) {
            throw IosKeyAttestationException.MalformedVersionInformation(this)
        }
        return try {
            Semver(info["systemVersion"], Semver.SemverType.LOOSE)
        } catch (ex: SemverException) {
            throw IosKeyAttestationException.MalformedVersionInformation(this, ex)
        }
    }
}
