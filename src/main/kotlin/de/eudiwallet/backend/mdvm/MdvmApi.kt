package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder
import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.fromBase64
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.crypto.toCanonicalP256
import de.eudiwallet.backend.shared.crypto.toSha256
import de.eudiwallet.backend.shared.httpsignature.CONTENT_DIGEST_HEADER
import de.eudiwallet.backend.shared.httpsignature.ContentDigestHeader
import de.eudiwallet.backend.shared.httpsignature.HttpMessageSignatureHeaders
import de.eudiwallet.backend.shared.httpsignature.HttpSignatureVerifier
import de.eudiwallet.backend.shared.httpsignature.METHOD_COMPONENT
import de.eudiwallet.backend.shared.httpsignature.PATH_COMPONENT
import de.eudiwallet.backend.shared.json.toPostgresJson
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.tags.Tag
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.security.interfaces.ECPublicKey
import java.security.spec.InvalidKeySpecException
import kotlin.time.Instant
import kotlin.time.toKotlinInstant

const val AUTH_CHALLENGE_HEADER = "Auth-Challenge"
const val SKIP_INTEGRITY_CHECKS_HEADER = "Skip-Integrity-Checks"
const val MDVM_WI_ID_HEADER = "Mdvm-Wi-Id"

const val MDVM_AUTH_CHALLENGE_FIELD = "mdvm_auth_challenge"
const val WI_DEVICE_CLASS_FIELD = "wi_device_class"
const val WI_ANDROID_KEY_ATTESTATION_FIELD = "wi_android_key_attestation"
const val WI_MDVM_AUTH_PUBK_FIELD = "wi_mdvm_auth_pubk"
const val PAP_DEVICECHECK_ATTESTATION_FIELD = "pap_devicecheck_attestation"
const val PAP_DEVICECHECK_ASSERTION_FIELD = "pap_devicecheck_assertion"

const val MDVM_WI_ID_FIELD = "mdvm_wi_id"
const val MDVM_TOKEN_FIELD = "mdvm_token"
const val MDVM_TOKEN_EXPIRATION_TIME_FIELD = "mdvm_token_expiration_time"

const val MDVM_AUTH_SIGNATURE_NAME = "mdvm-auth-sig"
const val MDVM_ANDROID_REATTEST_SIGNATURE_NAME = "mdvm-reattest-sig"

val REQUIRED_SIGNATURE_REGISTER_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        AUTH_CHALLENGE_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_RENEWAL_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        MDVM_WI_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        MDVM_WI_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
    )

@Serializable
data class ChallengeResponse(
    @SerialName(MDVM_AUTH_CHALLENGE_FIELD)
    @Schema(description = "Base64url-encoded MDVM authentication challenge JWT", example = MDVM_AUTH_CHALLENGE_EXAMPLE)
    val authChallenge: String,
)

@Serializable
data class AndroidRegisterRequest(
    @SerialName(WI_MDVM_AUTH_PUBK_FIELD)
    @Schema(description = "Base64-encoded X.509 EC public key for MDVM authentication")
    val authPubk: String,
    @SerialName(WI_DEVICE_CLASS_FIELD)
    @Schema(description = "Device class properties as key-value pairs", example = ANDROID_DEVICE_INFO_EXAMPLE)
    val deviceClass: Map<String, String>,
    @SerialName(WI_ANDROID_KEY_ATTESTATION_FIELD)
    @Schema(
        description = "Base64-encoded X.509 certificate chain from Android Key Attestation",
        example = ANDROID_KEY_ATTESTATION_EXAMPLE,
    )
    val keyAttestationCertificateChain: List<String>,
)

@Serializable
data class AndroidRenewalRequest(
    @SerialName(WI_DEVICE_CLASS_FIELD)
    @Schema(description = "Device class properties as key-value pairs", example = ANDROID_DEVICE_INFO_EXAMPLE)
    val deviceClass: Map<String, String>,
    @SerialName(WI_ANDROID_KEY_ATTESTATION_FIELD)
    @Schema(
        description = "Base64-encoded X.509 certificate chain from Android Key Attestation",
        example = ANDROID_KEY_ATTESTATION_EXAMPLE,
    )
    val keyAttestationCertificateChain: List<String>,
)

@Serializable
data class IosRegisterRequest(
    @SerialName(WI_MDVM_AUTH_PUBK_FIELD)
    @Schema(description = "Base64-encoded X.509 EC public key for MDVM authentication")
    val authPubk: String,
    @SerialName(WI_DEVICE_CLASS_FIELD)
    @Schema(description = "Device class properties as key-value pairs", example = IOS_DEVICE_INFO_EXAMPLE)
    val deviceClass: Map<String, String>,
    @SerialName(PAP_DEVICECHECK_ATTESTATION_FIELD)
    @Schema(description = "Base64-encoded Apple DeviceCheck attestation", example = DEVICECHECK_ATTESTATION_EXAMPLE)
    val deviceAttestation: String,
    @SerialName(PAP_DEVICECHECK_ASSERTION_FIELD)
    @Schema(description = "Base64-encoded Apple DeviceCheck assertion", example = DEVICECHECK_ASSERTION_EXAMPLE)
    val deviceAssertion: String,
)

@Serializable
data class IosRenewalRequest(
    @SerialName(WI_DEVICE_CLASS_FIELD)
    @Schema(description = "Device class properties as key-value pairs", example = IOS_DEVICE_INFO_EXAMPLE)
    val deviceClass: Map<String, String>,
    @SerialName(PAP_DEVICECHECK_ASSERTION_FIELD)
    @Schema(description = "Base64-encoded Apple DeviceCheck assertion", example = DEVICECHECK_ASSERTION_EXAMPLE)
    val deviceAssertion: String,
)

@Serializable
data class MdvmRegisterResponse(
    @SerialName(MDVM_WI_ID_FIELD)
    @Schema(description = "Unique identifier for the registered MDVM wallet instance")
    val mdvmAccountId: MdvmAccountId,
    @SerialName(MDVM_TOKEN_FIELD)
    @Schema(description = "Signed MDVM JWT token for subsequent authenticated requests", example = MDVM_TOKEN_EXAMPLE)
    val mdvmToken: String,
    @SerialName(MDVM_TOKEN_EXPIRATION_TIME_FIELD)
    @Schema(description = "MDVM token expiration time", example = EXAMPLE_INSTANT)
    val mdvmTokenExpirationTime: Instant,
)

@Serializable
data class MdvmRenewalResponse(
    @SerialName(MDVM_TOKEN_FIELD)
    @Schema(description = "Signed MDVM JWT token for subsequent authenticated requests", example = MDVM_TOKEN_EXAMPLE)
    val mdvmToken: String,
    @SerialName(MDVM_TOKEN_EXPIRATION_TIME_FIELD)
    @Schema(description = "MDVM token expiration time", example = EXAMPLE_INSTANT)
    val mdvmTokenExpirationTime: Instant,
)

@RestController
@RequestMapping("/v1/mdvm")
@Tag(name = "mdvm", description = "Mobile Device Vulnerability Management API")
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmApi(
    private val mdvmService: MdvmService,
    private val mdvmAccountService: MdvmAccountService,
    private val config: MdvmConfiguration,
    private val httpSignatureVerifier: HttpSignatureVerifier,
    private val telemetryService: TelemetryService,
    private val mdvmTokenBuilder: MdvmTokenBuilder,
    private val challengeTokenBuilder: ChallengeTokenBuilder,
) {
    @Operation(
        summary = "Generate an authentication challenge for MDVM operations",
        description = CHALLENGE_DOCS,
    )
    @PostMapping("/challenge")
    @ResponseBody
    suspend fun challenge(): ChallengeResponse =
        telemetryService.withSpan("MdvmApi.challenge") {
            ChallengeResponse(challengeTokenBuilder.createAndSerializeToJwt(config.issuer))
        }

    @Operation(
        summary = "Verify and register Android device",
        description = ANDROID_REGISTER_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/android/register", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    suspend fun androidRegister(
        @Parameter(description = "MDVM authentication challenge")
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @Parameter(description = "Which device integrity checks can be skipped")
        @RequestHeader(SKIP_INTEGRITY_CHECKS_HEADER, defaultValue = "none") skipIntegrityChecks: SkipIntegrityChecks,
        @RequestBody request: AndroidRegisterRequest,
        httpRequest: ServerHttpRequest,
    ): MdvmRegisterResponse =
        withTelemetryAndAnalytics("MdvmApi.androidRegister", authChallenge, skipIntegrityChecks, request) {
            val authPubk =
                authorizeOperationForNewAccount(
                    request.authPubk,
                    authChallenge,
                    httpRequest,
                    REQUIRED_SIGNATURE_REGISTER_COMPONENTS,
                )

            val attestationNonce = authChallenge.toSha256()
            val attestationData =
                mdvmService.verifyAndroidKeyAttestation(
                    request.keyAttestationCertificateChain,
                    attestationNonce,
                    skipIntegrityChecks,
                )
            attestationData?.let {
                if (authPubk.jwkThumbprint() != it.publicKey.jwkThumbprint()) {
                    throw AndroidKeyAttestationException.WrongAttestedKeyException(it.publicKey, authPubk)
                }

                mdvmService.verifyAndroidDeviceProperties(
                    attestedDetails = it.attestationDetails,
                    storedDetails = null,
                )
            }
            val account =
                mdvmAccountService.createAndroidAccount(
                    authPubk = authPubk,
                    deviceClass = DeviceInfo(request.deviceClass),
                    attestationData = attestationData,
                )
            val mdvmToken = mdvmTokenBuilder.create(authPubk, account.mdvmAccountId)
            MdvmRegisterResponse(
                account.mdvmAccountId,
                with(mdvmTokenBuilder) { mdvmToken.serializeToJwt() },
                mdvmToken.expirationTime.toKotlinInstant(),
            )
        }

    @Operation(
        summary = "Verify Android device and renew token",
        description = ANDROID_RENEWAL_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/android/renewal", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    suspend fun androidRenewal(
        @Parameter(description = "Unique identifier for the registered MDVM wallet instance")
        @RequestHeader(MDVM_WI_ID_HEADER) mdvmAccountId: MdvmAccountId,
        @Parameter(description = "MDVM authentication challenge")
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @Parameter(description = "Which device integrity checks can be skipped")
        @RequestHeader(SKIP_INTEGRITY_CHECKS_HEADER, defaultValue = "none") skipIntegrityChecks: SkipIntegrityChecks,
        @RequestBody request: AndroidRenewalRequest,
        httpRequest: ServerHttpRequest,
    ): MdvmRenewalResponse =
        withTelemetryAndAnalytics("MdvmApi.androidRenewal", authChallenge, skipIntegrityChecks, request) {
            val account =
                authorizeOperationForExistingAccount(
                    mdvmAccountId,
                    authChallenge,
                    httpRequest,
                    REQUIRED_SIGNATURE_RENEWAL_COMPONENTS,
                )
            account.requireNotRevoked()
            account.verifyDeviceType(DeviceType.ANDROID)
            val authPubk = account.authPublicKey

            val attestationNonce = authChallenge.toSha256()
            val attestationData =
                mdvmService.verifyAndroidKeyAttestation(
                    request.keyAttestationCertificateChain,
                    attestationNonce,
                    skipIntegrityChecks,
                )

            if (!skipIntegrityChecks.skipKeyAttestation) {
                val attestation =
                    checkNotNull(attestationData) {
                        "AndroidDeviceAttestationData must be present when key attestation is not skipped"
                    }
                httpSignatureVerifier.verifyRequestSignature(
                    httpRequest,
                    MDVM_ANDROID_REATTEST_SIGNATURE_NAME,
                    REQUIRED_SIGNATURE_RENEWAL_COMPONENTS,
                    attestation.publicKey,
                )
            }
            attestationData?.let {
                mdvmService.verifyAndroidDeviceProperties(
                    attestedDetails = it.attestationDetails,
                    storedDetails = account.androidDeviceAttestation,
                )
            }

            mdvmAccountService.saveNonRevokedAccount(
                account.mdvmAccountId,
                deviceClass = DeviceInfo(request.deviceClass),
                androidAttestationDetails = attestationData?.attestationDetails,
            )
            val mdvmToken = mdvmTokenBuilder.create(authPubk, account.mdvmAccountId)
            MdvmRenewalResponse(
                with(mdvmTokenBuilder) { mdvmToken.serializeToJwt() },
                mdvmToken.expirationTime.toKotlinInstant(),
            )
        }

    @Operation(
        summary = "Verify and register iOS device",
        description = IOS_REGISTER_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/ios/register", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    suspend fun iosRegister(
        @Parameter(description = "MDVM authentication challenge")
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @Parameter(description = "Which device integrity checks can be skipped")
        @RequestHeader(SKIP_INTEGRITY_CHECKS_HEADER, defaultValue = "none") skipIntegrityChecks: SkipIntegrityChecks,
        @RequestBody request: IosRegisterRequest,
        httpRequest: ServerHttpRequest,
    ): MdvmRegisterResponse =
        withTelemetryAndAnalytics("MdvmApi.iosRegister", authChallenge, skipIntegrityChecks, request) {
            val authPubk =
                authorizeOperationForNewAccount(
                    request.authPubk,
                    authChallenge,
                    httpRequest,
                    REQUIRED_SIGNATURE_REGISTER_COMPONENTS,
                )

            val keyAttestationNonce = authChallenge.toSha256()
            val attestation =
                mdvmService.verifyIosDeviceAttestation(
                    request.deviceAttestation,
                    authPubk,
                    keyAttestationNonce,
                    skipIntegrityChecks,
                )

            attestation?.let {
                if (authPubk.jwkThumbprint() != it.publicKey.jwkThumbprint()) {
                    throw IosKeyAttestationException.WrongAttestedKeyException(it.publicKey, authPubk)
                }
            }

            val assertion =
                mdvmService.verifyIosDeviceAssertion(
                    attestation?.canonicalAttestation?.toValidatedAttestation(),
                    request.deviceAssertion,
                    authPubk,
                    keyAttestationNonce,
                    0,
                    skipIntegrityChecks,
                )
            mdvmService.verifyIosDeviceProperties(DeviceInfo(request.deviceClass), storedDeviceClass = null)

            val account =
                mdvmAccountService.createIosAccount(
                    authPubk = authPubk,
                    deviceClass = DeviceInfo(request.deviceClass),
                    deviceAttestation = attestation,
                    deviceAssertion = assertion,
                )
            val mdvmToken = mdvmTokenBuilder.create(authPubk, account.mdvmAccountId)
            MdvmRegisterResponse(
                account.mdvmAccountId,
                with(mdvmTokenBuilder) { mdvmToken.serializeToJwt() },
                mdvmToken.expirationTime.toKotlinInstant(),
            )
        }

    @Operation(
        summary = "Renew MDVM token for iOS device",
        description = IOA_RENEWAL_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/ios/renewal", consumes = [MediaType.APPLICATION_JSON_VALUE])
    @ResponseBody
    suspend fun iosRenewal(
        @Parameter(description = "Unique identifier for the registered MDVM wallet instance")
        @RequestHeader(MDVM_WI_ID_HEADER) mdvmAccountId: MdvmAccountId,
        @Parameter(description = "MDVM authentication challenge")
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @Parameter(description = "Which device integrity checks can be skipped")
        @RequestHeader(SKIP_INTEGRITY_CHECKS_HEADER, defaultValue = "none") skipIntegrityChecks: SkipIntegrityChecks,
        @RequestBody request: IosRenewalRequest,
        httpRequest: ServerHttpRequest,
    ): MdvmRenewalResponse =
        withTelemetryAndAnalytics("MdvmApi.iosRenewal", authChallenge, skipIntegrityChecks, request) {
            val account =
                authorizeOperationForExistingAccount(
                    mdvmAccountId,
                    authChallenge,
                    httpRequest,
                    REQUIRED_SIGNATURE_RENEWAL_COMPONENTS,
                )
            account.requireNotRevoked()
            account.verifyDeviceType(DeviceType.IOS)
            val authPubk = account.authPublicKey

            val keyAssertionNonce = authChallenge.toSha256()
            val assertion =
                mdvmService.verifyIosDeviceAssertion(
                    account.iosDeviceAttestation?.toValidatedAttestation(),
                    request.deviceAssertion,
                    authPubk,
                    keyAssertionNonce,
                    account.iosDeviceAssertion?.counter ?: 0,
                    skipIntegrityChecks,
                )

            mdvmService.verifyIosDeviceProperties(DeviceInfo(request.deviceClass), account.deviceClass)

            mdvmAccountService.saveNonRevokedAccount(
                account.mdvmAccountId,
                deviceClass = DeviceInfo(request.deviceClass),
                iosDeviceAssertion = assertion,
            )

            val mdvmToken = mdvmTokenBuilder.create(authPubk, account.mdvmAccountId)
            MdvmRenewalResponse(
                with(mdvmTokenBuilder) { mdvmToken.serializeToJwt() },
                mdvmToken.expirationTime.toKotlinInstant(),
            )
        }

    @Operation(
        summary = "Delete account",
        description = DELETE_ACCOUNT_DOCS,
    )
    @HttpMessageSignatureHeaders
    @DeleteMapping("/deleteAccount")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun deleteAccount(
        @Parameter(description = "Unique identifier for the registered MDVM wallet instance")
        @RequestHeader(MDVM_WI_ID_HEADER) mdvmAccountId: MdvmAccountId,
        @Parameter(description = "MDVM authentication challenge")
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("MdvmApi.deleteAccount") {
        val account =
            authorizeOperationForExistingAccount(
                mdvmAccountId,
                authChallenge,
                httpRequest,
                REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS,
            )

        mdvmAccountService.deleteMdvmAccount(account.mdvmAccountId)
    }

    private suspend fun authorizeOperationForExistingAccount(
        mdvmAccountId: MdvmAccountId,
        authChallenge: String,
        httpRequest: ServerHttpRequest,
        requiredSignatureComponents: List<String>,
    ): MdvmAccount {
        challengeTokenBuilder.parseAndValidate(authChallenge, config.issuer)

        val account = mdvmAccountService.findMdvmAccount(mdvmAccountId)
        val authPubk = account.authPublicKey
        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            MDVM_AUTH_SIGNATURE_NAME,
            requiredSignatureComponents,
            authPubk,
        )
        return account
    }

    private suspend fun authorizeOperationForNewAccount(
        requestedPubk: String,
        authChallenge: String,
        httpRequest: ServerHttpRequest,
        requiredSignatureComponents: List<String>,
    ): ECPublicKey {
        challengeTokenBuilder.parseAndValidate(authChallenge, config.issuer)

        val authPubk = extractECPublicKey(requestedPubk)
        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            MDVM_AUTH_SIGNATURE_NAME,
            requiredSignatureComponents,
            authPubk,
        )
        return authPubk
    }

    private suspend fun extractECPublicKey(authPubk: String) =
        try {
            authPubk.fromBase64().ecPublicKeyFromX509().toCanonicalP256()
        } catch (ex: InvalidKeySpecException) {
            throw MalformedPublicKey(authPubk, ex)
        } catch (ex: IllegalArgumentException) {
            throw MalformedPublicKey(authPubk, ex)
        }

    @Suppress("TooGenericExceptionCaught", "InstanceOfCheckForException")
    private suspend inline fun <reified Req : Any, Res> withTelemetryAndAnalytics(
        spanName: String,
        authChallenge: String,
        skipIntegrityChecks: SkipIntegrityChecks,
        request: Req,
        crossinline block: suspend () -> Res,
    ): Res =
        telemetryService.withSpan(spanName) {
            val requestJson by lazy { request.toPostgresJson() }
            try {
                val response = block()
                if (config.saveAnalytics) {
                    mdvmService.saveMdvmAnalytics(spanName, authChallenge, skipIntegrityChecks, requestJson, null)
                }
                response
            } catch (ex: Throwable) {
                val details by lazy {
                    if (ex is MdvmException) {
                        mapOf(MDVM_INTERNAL_ERROR_CODE_KEY to ex.internalErrorCode.toString()) +
                            ex.diagnosticDetails()
                    } else {
                        ex.exceptionDiagnostics()
                    }
                }
                if (config.traceDebugInfo) {
                    telemetryService.traceAttributes(details)
                }
                if (config.saveAnalytics) {
                    mdvmService.saveMdvmAnalytics(spanName, authChallenge, skipIntegrityChecks, requestJson, details)
                }
                throw ex
            }
        }
}
