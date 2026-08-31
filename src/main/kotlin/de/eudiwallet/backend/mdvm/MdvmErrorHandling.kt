@file:Suppress("TooManyFunctions")

package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.AttestationException
import at.asitplus.attestation.AttestationResult
import at.asitplus.attestation.IosAttestationException
import at.asitplus.attestation.KeyAttestation
import at.asitplus.attestation.android.AttestationKeyDescription.SecurityLevel
import at.asitplus.attestation.android.AuthorizationList
import at.asitplus.attestation.android.PatchLevel
import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import de.eudiwallet.backend.shared.challengetoken.ChallengeVerificationException
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import de.eudiwallet.backend.shared.json.toJson
import de.eudiwallet.backend.shared.jwt.JwtException
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.media.Schema
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.dao.DataAccessException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.server.ServerWebInputException
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.LocalDateTime

abstract class MdvmException(
    explanation: String?,
    cause: Throwable? = null,
) : RuntimeException(explanation, cause) {
    abstract val internalErrorCode: InternalErrorCode

    abstract fun diagnosticDetails(): Map<String, String>
}

private const val MDVM_ERROR_KEY = "mdvm.error"
private const val MDVM_ATTESTATION_KEY = "mdvm.attestation"
private const val MDVM_ATTESTATION_RESULT_KEY = "mdvm.attestation_result"
private const val MDVM_SIGNAL_KEY = "mdvm.signal"
private const val MDVM_DEBUG_INFO_KEY = "mdvm.debug_info"
const val MDVM_INTERNAL_ERROR_CODE_KEY = "mdvm.internal_error_code"

fun Throwable?.exceptionDiagnostics(): Map<String, String> =
    exceptionDiagnosticsInternal().mapKeys { "$MDVM_ERROR_KEY.${it.key}" }

abstract class AndroidKeyAttestationException(
    explanation: String?,
    cause: Throwable? = null,
) : MdvmException(explanation, cause) {
    class InvalidKeyCertificateException(
        cause: Throwable? = null,
    ) : AndroidKeyAttestationException("Invalid key certificate in the chain.", cause) {
        override val internalErrorCode = InternalErrorCode.KA_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "InvalidKeyCertificateException") + cause.exceptionDiagnostics()
    }

    class WrongAttestedKeyException(
        private val attestedKey: PublicKey,
        private val expectedKey: ECPublicKey,
    ) : AndroidKeyAttestationException("Requested attested key mismatch with attestation") {
        override val internalErrorCode = InternalErrorCode.KA_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "WrongAttestedKeyException") + attestedKeyDiagnostics(attestedKey, expectedKey)
    }

    class WrongAttestationResult(
        private val details: AttestationResult,
    ) : AndroidKeyAttestationException("Unexpected verification result") {
        override val internalErrorCode = InternalErrorCode.KA_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "WrongAttestationResult",
                MDVM_ATTESTATION_RESULT_KEY to (details::class.simpleName ?: "unknown"),
            )
    }

    class AttestedKeyNotFoundException(
        private val attestation: KeyAttestation<PublicKey>,
    ) : AndroidKeyAttestationException("Could not extract ECPublicKey from attestation") {
        override val internalErrorCode = InternalErrorCode.KA_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "AttestedKeyNotFoundException",
                MDVM_ATTESTATION_KEY to attestation.toString(),
            )
    }

    class AttestationError(
        private val details: AttestationResult.Error,
        private val debugInfo: String,
    ) : AndroidKeyAttestationException(details.explanation, details.cause) {
        override val internalErrorCode get() = details.cause.findAndroidKeyAttestationCode()

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "AttestationError",
                MDVM_DEBUG_INFO_KEY to debugInfo,
            ) + details.cause.exceptionDiagnostics()
    }

    class SecurityLevelViolation(
        private val attestationSecurityLevel: SecurityLevel,
        private val keyMintSecurityLevel: SecurityLevel,
    ) : AndroidKeyAttestationException("Key is not held in secure hardware") {
        override val internalErrorCode get() = InternalErrorCode.KA_SECURITY_LEVEL_MISMATCH

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "SecurityLevelViolation",
                "mdvm.attestation_security_level" to attestationSecurityLevel.name,
                "mdvm.keymint_security_level" to keyMintSecurityLevel.name,
            )
    }

    class KeyNotGenerated(
        private val origin: AuthorizationList.Origin?,
    ) : AndroidKeyAttestationException("Key was not generated inside secure hardware") {
        override val internalErrorCode get() = InternalErrorCode.KA_KEY_NOT_GENERATED

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "KeyNotGenerated", "mdvm.key_origin" to (origin?.name ?: "unknown"))
    }

    class MinimalOsVersionViolation(
        private val deviceVersion: String?,
        private val minimalVersion: String,
    ) : AndroidKeyAttestationException("Device OS version is lower than required") {
        override val internalErrorCode get() = InternalErrorCode.KA_OS_MINIMUM_VERSION

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "MinimalOsVersionViolation",
                "mdvm.device_version" to (deviceVersion ?: "unknown"),
                "mdvm.minimal_version" to minimalVersion,
            )
    }

    class MinimalPatchLevelViolation(
        private val devicePatchLevel: String?,
        private val minimalPatchLevel: String,
    ) : AndroidKeyAttestationException("Device security patch level is older than required") {
        override val internalErrorCode get() = InternalErrorCode.KA_MINIMUM_PATCH_LEVEL

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "MinimalPatchLevelViolation",
                "mdvm.device_patch_level" to (devicePatchLevel ?: "unknown"),
                "mdvm.minimal_patch_level" to minimalPatchLevel,
            )
    }

    class BootloaderUnlocked(
        private val deviceLocked: Boolean?,
    ) : AndroidKeyAttestationException("Device bootloader is not locked") {
        override val internalErrorCode get() = InternalErrorCode.KA_BOOTLOADER_UNLOCKED

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "BootloaderUnlocked",
                "mdvm.device_locked" to (deviceLocked?.toString() ?: "unknown"),
            )
    }

    class BootStateUnverified(
        private val verifiedBootState: AuthorizationList.RootOfTrust.VerifiedBootState?,
    ) : AndroidKeyAttestationException("Device did not report a verified boot state") {
        override val internalErrorCode get() = InternalErrorCode.KA_BOOT_STATE_UNVERIFIED

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "BootStateUnverified",
                "mdvm.verified_boot_state" to (verifiedBootState?.name ?: "unknown"),
            )
    }

    class PackageNameMismatch(
        private val packageName: List<String>?,
        private val expectedPackageNames: List<String>,
    ) : AndroidKeyAttestationException("Attested application package name is not accepted") {
        override val internalErrorCode get() = InternalErrorCode.KA_PACKAGE_NAME_MISMATCH

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "PackageNameMismatch",
                "mdvm.package_name" to (packageName?.joinToString(",") ?: "unknown"),
                "mdvm.expected_package_names" to expectedPackageNames.joinToString(),
            )
    }

    class MinimalAppVersionViolation(
        private val appVersion: List<UInt>?,
        private val minimalAppVersion: Long,
    ) : AndroidKeyAttestationException("Application version is lower than required") {
        override val internalErrorCode get() = InternalErrorCode.KA_MINIMUM_APP_VERSION

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "MinimalAppVersionViolation",
                "mdvm.app_version" to (appVersion?.joinToString(",") ?: "unknown"),
                "mdvm.minimal_app_version" to minimalAppVersion.toString(),
            )
    }

    class SignatureDigestMismatch(
        private val signatureDigest: List<String>?,
    ) : AndroidKeyAttestationException("Application signing certificate digest is not accepted") {
        override val internalErrorCode get() = InternalErrorCode.KA_SIGNATURE_DIGEST_MISMATCH

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "SignatureDigestMismatch",
                "mdvm.signature_digest" to (signatureDigest?.joinToString(",") ?: "unknown"),
            )
    }

    class DeviceMismatch(
        private val signal: String,
        private val deviceValue: String?,
        private val storedValue: String?,
    ) : AndroidKeyAttestationException("Attested device does not match the stored device") {
        override val internalErrorCode get() = InternalErrorCode.KA_PLAUSIBILITY_DEVICE_MISMATCH

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "DeviceMismatch",
                MDVM_SIGNAL_KEY to signal,
                "mdvm.device_value" to (deviceValue ?: "unknown"),
                "mdvm.stored_value" to (storedValue ?: "unknown"),
            )
    }

    class VersionDecrease(
        private val signal: String,
        private val deviceValue: String?,
        private val storedValue: String?,
    ) : AndroidKeyAttestationException("Attested value is lower than the stored value") {
        override val internalErrorCode get() = InternalErrorCode.KA_PLAUSIBILITY_VERSION_DECREASE

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "VersionDecrease",
                MDVM_SIGNAL_KEY to signal,
                "mdvm.device_value" to (deviceValue ?: "unknown"),
                "mdvm.stored_value" to (storedValue ?: "unknown"),
            )
    }
}

class MalformedPublicKey(
    private val publicKey: String,
    cause: Throwable? = null,
) : MdvmException("Malformed attested key", cause) {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_MALFORMED_KEY

    override fun diagnosticDetails() =
        mapOf(MDVM_ERROR_KEY to "MalformedPublicKey", "mdvm.malformed_key" to publicKey) + cause.exceptionDiagnostics()
}

class SkipIntegrityChecksNotAllowedException(
    private val skipIntegrityChecks: SkipIntegrityChecks,
) : MdvmException("Skipping the requested integrity check is not permitted in this environment") {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_SKIP_INTEGRITY_CHECKS_NOT_ALLOWED

    override fun diagnosticDetails() =
        mapOf(
            MDVM_ERROR_KEY to "SkipIntegrityChecksNotAllowedException",
            "mdvm.skip_integrity_checks" to skipIntegrityChecks.value(),
        )
}

class AccountNotFound(
    private val accountId: MdvmAccountId,
) : MdvmException("Account with given ID does not exist") {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_ACCOUNT_NOT_FOUND

    override fun diagnosticDetails() =
        mapOf(MDVM_ERROR_KEY to "AccountNotFound", "mdvm.account_id" to accountId.toString())
}

class WrongDeviceType(
    private val accountId: MdvmAccountId,
    private val deviceType: DeviceType,
    private val expectedType: DeviceType,
) : MdvmException("Account with given ID has different device type") {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_WRONG_DEVICE_TYPE

    override fun diagnosticDetails() =
        mapOf(
            MDVM_ERROR_KEY to "WrongDeviceType",
            "mdvm.account_id" to accountId.toString(),
            "mdvm.device_type" to deviceType.toString(),
            "mdvm.expected_type" to expectedType.toString(),
        )
}

class AccountRevokedException(
    private val revokedAt: java.time.Instant,
) : MdvmException("MdvmAccount revoked") {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_ACCOUNT_REVOKED

    override fun diagnosticDetails() =
        mapOf(MDVM_ERROR_KEY to "AccountRevokedException", "mdvm.revoked_at" to revokedAt.toString())
}

class KeyAlreadyRegisteredException(
    cause: Throwable? = null,
) : MdvmException("An account is already registered for this key", cause) {
    override val internalErrorCode: InternalErrorCode = InternalErrorCode.DV_KEY_ALREADY_REGISTERED

    override fun diagnosticDetails() =
        mapOf(MDVM_ERROR_KEY to "KeyAlreadyRegisteredException") + cause.exceptionDiagnostics()
}

abstract class IosKeyAttestationException(
    explanation: String?,
    cause: Throwable? = null,
) : MdvmException(explanation, cause) {
    class MalformedAttestation(
        private val attestation: String,
        cause: Throwable,
    ) : IosKeyAttestationException("Malformed base-64 encoded attestation", cause) {
        override val internalErrorCode = InternalErrorCode.DCAT_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "MalformedAttestation", MDVM_ATTESTATION_KEY to attestation) +
                cause.exceptionDiagnostics()
    }

    class MalformedAssertion(
        private val assertion: String,
        cause: Throwable,
    ) : IosKeyAttestationException("Malformed base-64 encoded assertion", cause) {
        override val internalErrorCode = InternalErrorCode.DCAS_ASSERTION_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "MalformedAssertion", "mdvm.assertion" to assertion) + cause.exceptionDiagnostics()
    }

    class WrongAttestationResult(
        private val details: AttestationResult,
    ) : IosKeyAttestationException("Unexpected verification result") {
        override val internalErrorCode = InternalErrorCode.DCAT_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "WrongAttestationResult",
                MDVM_ATTESTATION_RESULT_KEY to (details::class.simpleName ?: "unknown"),
            )
    }

    class WrongAttestedKeyException(
        private val attestedKey: PublicKey,
        private val expectedKey: ECPublicKey,
    ) : IosKeyAttestationException("Requested attested key mismatch with attestation") {
        override val internalErrorCode = InternalErrorCode.DCAT_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "WrongAttestedKeyException") + attestedKeyDiagnostics(attestedKey, expectedKey)
    }

    class MissingAttestation : IosKeyAttestationException("Attestation data is not provided") {
        override val internalErrorCode = InternalErrorCode.DCAS_ASSERTION_VALIDATION_ERROR

        override fun diagnosticDetails() = mapOf(MDVM_ERROR_KEY to "MissingAttestation")
    }

    class AttestedKeyNotFoundException(
        private val attestation: KeyAttestation<PublicKey>,
    ) : IosKeyAttestationException("Could not extract public key from attestation") {
        override val internalErrorCode = InternalErrorCode.DCAT_CERT_VALIDATION_ERROR

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "AttestedKeyNotFoundException", MDVM_ATTESTATION_KEY to attestation.toString())
    }

    class AttestationError(
        private val details: AttestationResult.Error,
        private val debugInfo: String,
    ) : IosKeyAttestationException(details.explanation, details.cause) {
        override val internalErrorCode get() = details.cause.findIosAttestationReason().toAttestationCode()

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "AttestationError",
                MDVM_ATTESTATION_RESULT_KEY to (details::class.simpleName ?: "unknown"),
                MDVM_DEBUG_INFO_KEY to debugInfo,
            ) + details.cause.exceptionDiagnostics()
    }

    class DeviceAssertionError(
        override val cause: Throwable?,
    ) : IosKeyAttestationException(cause?.message, cause) {
        override val internalErrorCode get() = cause.findIosAttestationReason().toAssertionCode()

        override fun diagnosticDetails() =
            mapOf(MDVM_ERROR_KEY to "DeviceAssertionError") + cause.exceptionDiagnostics()
    }

    class ModelMismatch(
        private val deviceModel: String?,
        private val storedModel: String?,
    ) : IosKeyAttestationException("Device model does not match the stored value") {
        override val internalErrorCode get() = InternalErrorCode.IDP_MODEL_MISMATCH

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "ModelMismatch",
                "mdvm.device_model" to (deviceModel ?: "unknown"),
                "mdvm.stored_model" to (storedModel ?: "unknown"),
            )
    }

    class VersionDecrease(
        private val deviceVersion: String?,
        private val storedVersion: String?,
    ) : IosKeyAttestationException("Device version is lower than stored version") {
        override val internalErrorCode get() = InternalErrorCode.IDP_VERSION_DECREASE

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "VersionDecrease",
                "mdvm.device_version" to (deviceVersion ?: "unknown"),
                "mdvm.stored_version" to (storedVersion ?: "unknown"),
            )
    }

    class MinimalVersionViolation(
        private val deviceVersion: String?,
        private val minimalVersion: String?,
    ) : IosKeyAttestationException("Device version is lower than required") {
        override val internalErrorCode get() = InternalErrorCode.IDP_MINIMUM_OS_VERSION

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "MinimalVersionViolation",
                "mdvm.device_version" to (deviceVersion ?: "unknown"),
                "mdvm.minimal_version" to (minimalVersion ?: "unknown"),
            )
    }

    class MalformedVersionInformation(
        private val deviceInfo: DeviceInfo,
        override val cause: Throwable? = null,
    ) : IosKeyAttestationException("Device version is missing or malformed") {
        override val internalErrorCode get() = InternalErrorCode.IDP_MALFORMED_OS_VERSION

        override fun diagnosticDetails() =
            mapOf(
                MDVM_ERROR_KEY to "MalformedVersionInformation",
                "mdvm.device_info" to deviceInfo.info.toJson(),
            ) + cause.exceptionDiagnostics()
    }
}

@ControllerAdvice(basePackages = ["de.eudiwallet.backend.mdvm"])
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmErrorHandler(
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(
        MdvmException::class,
    )
    fun handleMdvmFailure(e: MdvmException): ResponseEntity<MdvmErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(e.internalErrorCode.responseCode, e)
    }

    @ExceptionHandler(
        SignatureVerificationException::class,
    )
    fun handleSignatureVerificationException(e: SignatureVerificationException): ResponseEntity<MdvmErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(MdvmErrorResponseCode.SIGNATURE_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(ChallengeVerificationException::class)
    fun handleChallengeVerification(e: ChallengeVerificationException): ResponseEntity<MdvmErrorResponse> {
        val errorCode =
            if (e.cause is JwtException.Expired) {
                MdvmErrorResponseCode.CHALLENGE_EXPIRED
            } else {
                MdvmErrorResponseCode.CHALLENGE_VERIFICATION_FAILURE
            }
        log.warn(e) {}
        return createErrorResponseEntity(errorCode, e)
    }

    @ExceptionHandler(
        IllegalArgumentException::class,
        ServerWebInputException::class,
    )
    fun handleBadRequest(e: Exception): ResponseEntity<MdvmErrorResponse> {
        val description =
            (e as? BindingResult)
                ?.fieldErrors
                ?.filterNot { it.isBindingFailure }
                ?.mapNotNull { it.defaultMessage }
                ?.takeIf { it.isNotEmpty() }
                ?.joinToString("; ")
                ?: MdvmErrorResponseCode.BAD_REQUEST.description
        return createErrorResponseEntity(MdvmErrorResponseCode.BAD_REQUEST, e, description)
    }

    @ExceptionHandler(
        DataAccessException::class,
    )
    fun handleDataAccessException(e: DataAccessException): ResponseEntity<MdvmErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(MdvmErrorResponseCode.DB_UNAVAILABLE, e)
    }

    @ExceptionHandler(HsmException.GetSessionFailedException::class)
    fun handleHsmSessionUnavailable(e: HsmException.GetSessionFailedException): ResponseEntity<MdvmErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(MdvmErrorResponseCode.HSM_UNAVAILABLE, e)
    }

    @ExceptionHandler(
        Exception::class,
    )
    fun handleInternalServerError(e: Exception): ResponseEntity<MdvmErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(MdvmErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    private fun createErrorResponseEntity(
        code: MdvmErrorResponseCode,
        cause: Throwable? = null,
        description: String = code.description,
    ): ResponseEntity<MdvmErrorResponse> {
        telemetryService.traceErrorCode(code.name)
        telemetryService.traceException(cause)
        return ResponseEntity(
            MdvmErrorResponse(
                code = code,
                description = description,
                traceId = telemetryService.getCurrentTraceId(),
            ),
            code.httpStatus,
        )
    }
}

private fun Throwable?.findIosAttestationReason(): IosAttestationException.Reason? {
    var current = this
    var depth = 0
    while (current != null && depth < MAX_CAUSE_DEPTH) {
        if (current is IosAttestationException) return current.reason
        current = current.cause
        depth++
    }
    return null
}

private fun IosAttestationException.Reason?.toAttestationCode() =
    when (this) {
        IosAttestationException.Reason.CHALLENGE -> InternalErrorCode.DCAT_CHALLENGE_INVALID
        IosAttestationException.Reason.IDENTIFIER -> InternalErrorCode.DCAT_RP_ID_MISMATCH
        IosAttestationException.Reason.SIG_CTR -> InternalErrorCode.DCAT_ATTESTATION_COUNTER_INVALID
        IosAttestationException.Reason.OS_VERSION -> InternalErrorCode.IDP_MINIMUM_OS_VERSION
        else -> InternalErrorCode.DCAT_CERT_VALIDATION_ERROR
    }

private fun IosAttestationException.Reason?.toAssertionCode() =
    when (this) {
        IosAttestationException.Reason.CHALLENGE -> InternalErrorCode.DCAS_CHALLENGE_INVALID
        IosAttestationException.Reason.IDENTIFIER -> InternalErrorCode.DCAS_RP_ID_MISMATCH
        IosAttestationException.Reason.SIG_CTR -> InternalErrorCode.DCAS_ATTESTATION_COUNTER_INVALID
        IosAttestationException.Reason.OS_VERSION -> InternalErrorCode.IDP_MINIMUM_OS_VERSION
        else -> InternalErrorCode.DCAS_ASSERTION_VALIDATION_ERROR
    }

private fun Throwable?.findAndroidKeyAttestationCode(): InternalErrorCode {
    var current = this
    var depth = 0
    while (current != null && depth < MAX_CAUSE_DEPTH) {
        if (current is AttestationValueException) {
            return current.toKeyAttestationCode()
        }
        current = current.cause
        depth++
    }
    return InternalErrorCode.KA_CERT_VALIDATION_ERROR
}

private fun AttestationValueException.toKeyAttestationCode() =
    when (reason) {
        AttestationValueException.Reason.CHALLENGE -> {
            InternalErrorCode.KA_CHALLENGE_INVALID
        }

        AttestationValueException.Reason.SEC_LEVEL -> {
            InternalErrorCode.KA_SECURITY_LEVEL_MISMATCH
        }

        AttestationValueException.Reason.OS_VERSION -> {
            if (expectedValue is PatchLevel) {
                InternalErrorCode.KA_MINIMUM_PATCH_LEVEL
            } else {
                InternalErrorCode.KA_OS_MINIMUM_VERSION
            }
        }

        AttestationValueException.Reason.SYSTEM_INTEGRITY -> {
            when (expectedValue) {
                is Boolean -> InternalErrorCode.KA_BOOTLOADER_UNLOCKED
                else -> InternalErrorCode.KA_BOOT_STATE_UNVERIFIED
            }
        }

        AttestationValueException.Reason.PACKAGE_NAME -> {
            InternalErrorCode.KA_PACKAGE_NAME_MISMATCH
        }

        AttestationValueException.Reason.APP_VERSION -> {
            InternalErrorCode.KA_MINIMUM_APP_VERSION
        }

        AttestationValueException.Reason.APP_SIGNER_DIGEST -> {
            InternalErrorCode.KA_SIGNATURE_DIGEST_MISMATCH
        }

        else -> {
            InternalErrorCode.KA_CERT_VALIDATION_ERROR
        }
    }

enum class MdvmErrorResponseCode(
    val httpStatus: HttpStatus,
    val description: String,
) {
    MALFORMED_KEY(HttpStatus.BAD_REQUEST, "Malformed attested key"),
    ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "MdvmAccount not found"),
    ACCOUNT_REVOKED(HttpStatus.FORBIDDEN, "MdvmAccount revoked"),
    SECURITY_VIOLATION(HttpStatus.FORBIDDEN, "Device doesn't meet security requirements"),
    OUTDATED_OS_VERSION(HttpStatus.FORBIDDEN, "Device OS version is no longer supported"),
    OUTDATED_PATCH_LEVEL(HttpStatus.FORBIDDEN, "Device OS doesn't have required security patches"),
    OUTDATED_APP_VERSION(HttpStatus.FORBIDDEN, "Wallet app version is no longer supported"),
    INVALID_BOOTLOADER_STATE(HttpStatus.FORBIDDEN, "Device bootloader is unlocked"),
    KEY_ALREADY_REGISTERED(HttpStatus.CONFLICT, "An account is already registered for this key"),
    SIGNATURE_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Signature verification failed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    CHALLENGE_EXPIRED(HttpStatus.BAD_REQUEST, "Challenge expired"),
    SKIP_INTEGRITY_CHECKS_NOT_ALLOWED(HttpStatus.BAD_REQUEST, "Skipping integrity checks is not permitted"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    HSM_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "HSM is temporarily unavailable, please retry later"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
}

enum class InternalErrorCode(
    val responseCode: MdvmErrorResponseCode,
) {
    DCAT_CERT_VALIDATION_ERROR(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAT_CHALLENGE_INVALID(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAT_RP_ID_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAT_ATTESTATION_COUNTER_INVALID(MdvmErrorResponseCode.SECURITY_VIOLATION),

    DCAS_ASSERTION_VALIDATION_ERROR(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAS_CHALLENGE_INVALID(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAS_RP_ID_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    DCAS_ATTESTATION_COUNTER_INVALID(MdvmErrorResponseCode.SECURITY_VIOLATION),

    IDP_MODEL_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    IDP_VERSION_DECREASE(MdvmErrorResponseCode.SECURITY_VIOLATION),
    IDP_MINIMUM_OS_VERSION(MdvmErrorResponseCode.OUTDATED_OS_VERSION),
    IDP_MALFORMED_OS_VERSION(MdvmErrorResponseCode.BAD_REQUEST),

    KA_CERT_VALIDATION_ERROR(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_CHALLENGE_INVALID(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_SECURITY_LEVEL_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_KEY_NOT_GENERATED(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_OS_MINIMUM_VERSION(MdvmErrorResponseCode.OUTDATED_OS_VERSION),
    KA_MINIMUM_PATCH_LEVEL(MdvmErrorResponseCode.OUTDATED_PATCH_LEVEL),
    KA_BOOTLOADER_UNLOCKED(MdvmErrorResponseCode.INVALID_BOOTLOADER_STATE),
    KA_BOOT_STATE_UNVERIFIED(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_PACKAGE_NAME_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_MINIMUM_APP_VERSION(MdvmErrorResponseCode.OUTDATED_APP_VERSION),
    KA_SIGNATURE_DIGEST_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_PLAUSIBILITY_DEVICE_MISMATCH(MdvmErrorResponseCode.SECURITY_VIOLATION),
    KA_PLAUSIBILITY_VERSION_DECREASE(MdvmErrorResponseCode.SECURITY_VIOLATION),

    DV_MALFORMED_KEY(MdvmErrorResponseCode.MALFORMED_KEY),
    DV_ACCOUNT_NOT_FOUND(MdvmErrorResponseCode.ACCOUNT_NOT_FOUND),
    DV_WRONG_DEVICE_TYPE(MdvmErrorResponseCode.ACCOUNT_NOT_FOUND),
    DV_ACCOUNT_REVOKED(MdvmErrorResponseCode.ACCOUNT_REVOKED),
    DV_KEY_ALREADY_REGISTERED(MdvmErrorResponseCode.KEY_ALREADY_REGISTERED),
    DV_SKIP_INTEGRITY_CHECKS_NOT_ALLOWED(MdvmErrorResponseCode.SKIP_INTEGRITY_CHECKS_NOT_ALLOWED),
}

const val TRACE_ID = "trace_id"

@Serializable
data class MdvmErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: MdvmErrorResponseCode,
    @Schema(description = "Human-readable error description")
    val description: String? = null,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = LocalDateTime.now().toString(),
    @SerialName(TRACE_ID)
    @Schema(description = "Trace ID for correlating logs and debugging")
    val traceId: String? = null,
)

private fun attestedKeyDiagnostics(
    attestedKey: PublicKey,
    expectedKey: ECPublicKey,
) = mapOf(
    "mdvm.attested_key" to ((attestedKey as? ECPublicKey)?.jwkThumbprint()?.toString() ?: "unavailable"),
    "mdvm.expected_key" to expectedKey.jwkThumbprint().toString(),
)

private const val MAX_CAUSE_DEPTH = 10

private fun Throwable?.exceptionDiagnosticsInternal(
    depth: Int = 0,
    visited: Set<Throwable> = emptySet(),
): Map<String, String> {
    if (this == null || depth >= MAX_CAUSE_DEPTH || this in visited) return emptyMap()
    val causeDiagnostics =
        cause.exceptionDiagnosticsInternal(depth + 1, visited + this).mapKeys { "cause.${it.key}" }
    return mapOf(
        "class" to javaClass.canonicalName,
        "message" to (message ?: "unknown"),
    ) + attestationDiagnostics() + causeDiagnostics
}

private fun Throwable.attestationDiagnostics(): Map<String, String> =
    when (this) {
        is AttestationValueException -> {
            mapOf(
                "reason" to reason.toPrintableString(),
                "expectedValue" to expectedValue.toPrintableString(),
                "actualValue" to actualValue.toPrintableString(),
            )
        }

        is CertificateInvalidException -> {
            certificateInvalidDiagnostics() +
                if (this is CertificateInvalidException.OtherMatchingRoot) {
                    mapOf("rootCertStage" to rootCertStage.toPrintableString())
                } else {
                    emptyMap()
                }
        }

        is RevocationException.Revoked -> {
            mapOf(
                "reason" to reason.toPrintableString(),
                "certificateChain" to certificateChain.toPrintableString(),
                "revokedCertificate" to revokedCertificate.toPrintableString(),
                "entry" to entry.toPrintableString(),
            )
        }

        is RevocationException -> {
            mapOf("reason" to reason.toPrintableString())
        }

        is IosAttestationException -> {
            mapOf("reason" to reason.toPrintableString())
        }

        is AttestationException -> {
            mapOf("platform" to platform.toPrintableString())
        }

        else -> {
            emptyMap()
        }
    }

private fun CertificateInvalidException.certificateInvalidDiagnostics() =
    mapOf(
        "reason" to reason.toPrintableString(),
        "certificateChain" to certificateChain.toPrintableString(),
        "invalidCertificate" to invalidCertificate.toPrintableString(),
    )

private fun Any?.toPrintableString(): String =
    when (this) {
        null -> "none"
        is ByteArray -> toHexString(HexFormat { bytes.byteSeparator = ":" })
        is X509Certificate -> toPrintableCertificate()
        is Collection<*> -> joinToString(prefix = "[", postfix = "]", separator = ",") { it.toPrintableString() }
        else -> toString()
    }

fun X509Certificate.toPrintableCertificate() = "subject=${subjectX500Principal.name}, serial=$serialNumber"
