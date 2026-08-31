package de.eudiwallet.backend.rwsca

import com.nimbusds.jose.jwk.Curve
import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder
import de.eudiwallet.backend.shared.crypto.RECOMMENDED_EC_CURVE
import de.eudiwallet.backend.shared.crypto.SHA256_DIGEST_SIZE
import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.fromBase64
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.httpsignature.CONTENT_DIGEST_HEADER
import de.eudiwallet.backend.shared.httpsignature.ContentDigestHeader
import de.eudiwallet.backend.shared.httpsignature.HttpMessageSignatureHeaders
import de.eudiwallet.backend.shared.httpsignature.HttpSignatureVerifier
import de.eudiwallet.backend.shared.httpsignature.METHOD_COMPONENT
import de.eudiwallet.backend.shared.httpsignature.PATH_COMPONENT
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenParser
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import jakarta.validation.constraints.Max
import jakarta.validation.constraints.Min
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
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

const val RWSCA_AUTH_SIGNATURE_NAME = "rwsca-auth-sig"
const val RWSCA_PIN_SIGNATURE_NAME = "rwsca-pin-sig"

val REQUIRED_SIGNATURE_REGISTER_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )
val REQUIRED_SIGNATURE_INIT_PIN_AUTH_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        RWSCA_ACCOUNT_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
        CONTENT_DIGEST_HEADER,
    )
val REQUIRED_SIGNATURE_START_SESSION_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        RWSCA_ACCOUNT_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )

val REQUIRED_SIGNATURE_CREATE_KEYS_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        RWSCA_ACCOUNT_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_SIGN_DATA_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        RWSCA_ACCOUNT_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
        PIN_SESSION_TOKEN_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        RWSCA_ACCOUNT_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )

const val RWSCA_AUTH_CHALLENGE_FIELD = "rwsca_auth_challenge"
const val AUTH_CHALLENGE_HEADER = "Auth-Challenge"
const val MDVM_TOKEN_HEADER = "Mdvm-Token"
const val RWSCA_ACCOUNT_ID_FIELD = "rwsca_account_id"
const val RWSCA_ACCOUNT_ID_HEADER = "Rwsca-Account-Id"
const val WI_RWSCA_PIN_PUBK_FIELD = "wi_rwsca_pin_pubk"
const val RWSCA_PIN_SESSION_TOKEN_FIELD = "rwsca_pin_session_token"
const val RWSCA_PIN_SESSION_EXPIRATION_TIME_FIELD = "rwsca_pin_session_expiration_time"
const val RWSCA_WI_WRAPPED_PRVK_FIELD = "rwsca_wi_wrapped_prvk"
const val RWSCD_WI_PUBK_FIELD = "rwscd_wi_pubk"
const val RWSCA_WI_KEYS_FIELD = "rwsca_wi_keys"
const val RWSCA_WTE_FIELD = "rwsca_wte"
const val NUMBER_OF_KEYS_FIELD = "number_of_keys"
const val PP_C_NONCE_FIELD = "pp_c_nonce"
const val WI_KEY_BINDING_DATA_HASH_FIELD = "wi_key_binding_data_hash"
const val RWSCD_KEY_BINDING_SIGNATURE_FIELD = "rwscd_key_binding_signature"
const val PIN_SESSION_TOKEN_HEADER = "Rwsca-Pin-Session-Token"

@Serializable
data class RwscaChallengeResponse(
    @SerialName(RWSCA_AUTH_CHALLENGE_FIELD)
    @Schema(description = "RWSCA authentication challenge JWT", example = CHALLENGE_EXAMPLE)
    val authChallenge: String,
)

@Serializable
data class RwscaRegisterResponse(
    @SerialName(RWSCA_ACCOUNT_ID_FIELD)
    @Schema(description = "Unique identifier for the registered RWSCA account")
    val rwscaAccountId: RwscaAccountId,
)

@Serializable
data class InitializePinAndStartPinSessionRequest(
    @SerialName(WI_RWSCA_PIN_PUBK_FIELD)
    @Schema(description = "Base64-encoded X.509 EC public key")
    val wiRwscaPinPubk: String,
)

@Serializable
data class PinSessionResponse(
    @SerialName(RWSCA_PIN_SESSION_TOKEN_FIELD)
    @Schema(description = "Signed Pin session token", example = PIN_SESSION_TOKEN_EXAMPLE)
    val pinSessionToken: String,
    @SerialName(RWSCA_PIN_SESSION_EXPIRATION_TIME_FIELD)
    @Schema(description = "Pin session token expiration time", example = EXAMPLE_INSTANT)
    val pinSessionExpirationTime: Instant,
)

@Serializable
data class CreateKeysRequest(
    @SerialName(NUMBER_OF_KEYS_FIELD)
    @Schema(example = "1", minimum = "1", maximum = "10")
    @field:Min(value = 1, message = "$NUMBER_OF_KEYS_FIELD must be at least 1")
    @field:Max(value = 10, message = "$NUMBER_OF_KEYS_FIELD must be at most 10")
    val numberOfKeys: Int,
    @SerialName(PP_C_NONCE_FIELD)
    @Schema(description = "Issuer-provided nonce", example = BASE64_ENCODED_HASH_EXAMPLE)
    val ppcNonce: String,
)

@Serializable
data class CreateKeysResponse(
    @SerialName(RWSCA_WI_KEYS_FIELD)
    @Schema(description = "List of keys")
    val keys: List<KeyInfo>,
    @SerialName(RWSCA_WTE_FIELD)
    @Schema(description = "WTE for all keys", example = WTE_EXAMPLE)
    val rwscaWte: String,
) {
    @Serializable
    data class KeyInfo(
        @SerialName(RWSCD_WI_PUBK_FIELD)
        @Schema(description = "Base64-encoded X.509 EC public key", example = BASE64_ENCODED_PUBK_EXAMPLE)
        val rwscdWiPublicKey: String,
        @SerialName(RWSCA_WI_WRAPPED_PRVK_FIELD)
        @Schema(description = "Wrapped private key", example = WRAPPED_PRVK_EXAMPLE)
        val rwscaWiWrappedKey: String,
    )
}

@Serializable
data class SignDataRequest(
    @SerialName(RWSCA_WI_WRAPPED_PRVK_FIELD)
    @Schema(description = "Wrapped private key", example = WRAPPED_PRVK_EXAMPLE)
    val rwscaWiWrappedPrvk: String,
    @SerialName(WI_KEY_BINDING_DATA_HASH_FIELD)
    @Schema(description = "Base64-encoded SHA-256 hash", example = BASE64_ENCODED_HASH_EXAMPLE)
    val wiKeyBindingDataHash: String,
)

@Serializable
data class SignDataResponse(
    @SerialName(RWSCD_KEY_BINDING_SIGNATURE_FIELD)
    @Schema(description = "Base64-encoded ASN.1 signature", example = BASE64_ENCODED_SIGNATURE_EXAMPLE)
    val signature: String,
)

@RestController
@RequestMapping("/v1/rwsca")
@Tag(name = "rwsca", description = "Remote WSCA API")
@Suppress("LongParameterList")
@ConditionalOnProperty(prefix = "rwsca", name = ["enabled"], havingValue = "true")
class RwscaApi(
    private val rwscaAccountService: RwscaAccountService,
    private val config: RwscaConfiguration,
    @Qualifier("rwscaMasterLineage")
    private val rwscaMasterLineage: KeySource<SymmetricKeySet>,
    private val mdvmTokenParser: MdvmTokenParser,
    private val pinSessionTokenBuilder: PinSessionTokenBuilder,
    @Qualifier(RWSCA_WI_HSM_PROVIDER)
    private val hsmProvider: HsmProvider,
    private val telemetryService: TelemetryService,
    private val httpSignatureVerifier: HttpSignatureVerifier,
    private val rwscaBoundWrappedPrvkBuilder: RwscaBoundWrappedPrvkBuilder,
    private val wteBuilder: WalletTrustEvidenceBuilder,
    private val challengeTokenBuilder: ChallengeTokenBuilder,
) {
    @Operation(
        summary = "Generate a challenge for remote WSCA operations",
        description = CHALLENGE_DOCS,
    )
    @PostMapping("/challenge")
    @ResponseBody
    suspend fun challenge(): RwscaChallengeResponse =
        telemetryService.withSpan("RwscaApi.challenge") {
            RwscaChallengeResponse(
                authChallenge = challengeTokenBuilder.createAndSerializeToJwt(config.issuer),
            )
        }

    @Operation(
        summary = "Register a new RWSCA account",
        description = REGISTER_DOCS,
    )
    @HttpMessageSignatureHeaders
    @PostMapping("/register")
    @ResponseBody
    suspend fun register(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        httpRequest: ServerHttpRequest,
    ): RwscaRegisterResponse =
        telemetryService.withSpan("RwscaApi.register") {
            val parsedMdvmToken =
                authorizeOperation(
                    rwscaAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_REGISTER_COMPONENTS,
                )

            val rwscaAccount =
                rwscaAccountService.createAccount(parsedMdvmToken.authKey, parsedMdvmToken.mdvmAccountId)

            RwscaRegisterResponse(rwscaAccount.rwscaAccountId)
        }

    @Operation(
        summary = "Initialize pin, and start pin session",
        description = INITIALIZE_PIN_AND_START_PIN_SESSION_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/initializePinAndStartPinSession")
    @ResponseBody
    suspend fun initializePinAndStartPinSession(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        @RequestBody request: InitializePinAndStartPinSessionRequest,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("RwscaApi.initializePinAndStartPinSession") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                rwscaAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_INIT_PIN_AUTH_COMPONENTS,
            ).authKey

        val wiRwscaPinPubk = extractPinPubk(request.wiRwscaPinPubk)

        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            RWSCA_PIN_SIGNATURE_NAME,
            REQUIRED_SIGNATURE_INIT_PIN_AUTH_COMPONENTS,
            wiRwscaPinPubk,
        )

        val pinSessionToken = pinSessionTokenBuilder.create(rwscaAccountId)

        rwscaAccountService.initializePin(rwscaAccountId, wiMdvmAuthPubk, wiRwscaPinPubk)

        PinSessionResponse(
            with(pinSessionTokenBuilder) { pinSessionToken.serializeToJwt() },
            pinSessionToken.expirationTime.toKotlinInstant(),
        )
    }

    @Operation(
        summary = "Start pin session",
        description = START_PIN_SESSION_DOCS,
    )
    @HttpMessageSignatureHeaders
    @PostMapping("/startPinSession")
    @ResponseBody
    suspend fun startPinSession(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        httpRequest: ServerHttpRequest,
    ): PinSessionResponse =
        telemetryService.withSpan("RwscaApi.startPinSession") {
            val wiMdvmAuthPubk =
                authorizeOperation(
                    rwscaAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_START_SESSION_COMPONENTS,
                ).authKey

            rwscaAccountService.verifyPin(rwscaAccountId, wiMdvmAuthPubk) { account ->
                try {
                    httpSignatureVerifier.verifyRequestSignature(
                        httpRequest,
                        RWSCA_PIN_SIGNATURE_NAME,
                        REQUIRED_SIGNATURE_START_SESSION_COMPONENTS,
                        account.pinPubKey,
                    )
                    true
                } catch (_: SignatureVerificationException.WrongSignature) {
                    false
                }
            }

            val pinSessionToken = pinSessionTokenBuilder.create(rwscaAccountId)
            PinSessionResponse(
                with(pinSessionTokenBuilder) { pinSessionToken.serializeToJwt() },
                pinSessionToken.expirationTime.toKotlinInstant(),
            )
        }

    @Operation(
        summary = "Create keys",
        description = CREATE_KEYS_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/createKeys")
    @ResponseBody
    @Suppress("LongMethod")
    suspend fun createKeys(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        @Valid @RequestBody request: CreateKeysRequest,
        httpRequest: ServerHttpRequest,
    ): CreateKeysResponse =
        telemetryService.withSpan("RwscaApi.createKeys") {
            val wiMdvmAuthPubk =
                authorizeOperation(
                    rwscaAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_CREATE_KEYS_COMPONENTS,
                ).authKey
            val account =
                rwscaAccountService.findActiveAccount(rwscaAccountId, wiMdvmAuthPubk)

            val masterKeyId = rwscaMasterLineage.current().primaryId

            val keys =
                coroutineScope {
                    (1..request.numberOfKeys).map {
                        async {
                            hsmProvider.use("Create and wrap RWSCA key pair") { hsm ->
                                val (publicKey, wrappedPrivateKey) = hsm.createWrappedKeyPair(masterKeyId)
                                val rwscaBoundWrappedKey =
                                    rwscaBoundWrappedPrvkBuilder.create(
                                        account.rwscaAccountId,
                                        wrappedPrivateKey,
                                        masterKeyId,
                                    )
                                RwscaKeyInfo(publicKey, rwscaBoundWrappedKey)
                            }
                        }
                    }.awaitAll()
                }

            val rwscaWte = wteBuilder.create(keys.map { it.publicKey }, request.ppcNonce)

            val serializedWte = with(wteBuilder) { rwscaWte.serializeToJwt() }

            val wrappedKeys =
                coroutineScope {
                    keys.map {
                        async {
                            CreateKeysResponse.KeyInfo(
                                rwscdWiPublicKey = it.publicKey.encoded.toBase64(),
                                rwscaWiWrappedKey =
                                    with(rwscaBoundWrappedPrvkBuilder) {
                                        it.wrappedPrivateKey.serializeToJwe()
                                    },
                            )
                        }
                    }.awaitAll()
                }
            CreateKeysResponse(
                keys = wrappedKeys,
                rwscaWte = serializedWte,
            )
        }

    @Operation(summary = "Sign data", description = SIGN_DATA_DOCS)
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/signData")
    @ResponseBody
    suspend fun signData(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        @RequestHeader(PIN_SESSION_TOKEN_HEADER) pinSessionTokenHeader: String,
        @RequestBody request: SignDataRequest,
        httpRequest: ServerHttpRequest,
    ): SignDataResponse =
        telemetryService.withSpan("RwscaApi.signData") {
            val wiMdvmAuthPubk =
                authorizeOperation(
                    rwscaAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_SIGN_DATA_COMPONENTS,
                ).authKey

            val pinSessionToken = pinSessionTokenBuilder.parseAndValidate(pinSessionTokenHeader)
            if (pinSessionToken.rwscaAccountId != rwscaAccountId) {
                throw PinSessionTokenVerificationException(AccountIdMismatchException())
            }

            val account =
                rwscaAccountService.findActiveAccount(rwscaAccountId, wiMdvmAuthPubk)

            val rwscaBoundWrappedPrvk = rwscaBoundWrappedPrvkBuilder.parseAndDecrypt(request.rwscaWiWrappedPrvk)
            if (rwscaBoundWrappedPrvk.rwscaAccountId != account.rwscaAccountId) {
                throw WrappedPrvkVerificationException(AccountIdMismatchException())
            }

            val dataHash = extractDataHash(request.wiKeyBindingDataHash)
            val signature =
                hsmProvider.use("Unwrap ephemeral key and sign data") { hsm ->
                    try {
                        hsm.signWithWrappedKey(
                            rwscaBoundWrappedPrvk.hsmWrappedPrvk,
                            rwscaBoundWrappedPrvk.masterKeyId,
                            dataHash,
                        )
                    } catch (ex: HsmException.KeyNotFoundException) {
                        throw WrappedPrvkVerificationException(ex)
                    }
                }

            SignDataResponse(signature = signature.toDer().toBase64())
        }

    @Operation(
        summary = "Delete account",
        description = DELETE_ACCOUNT_DOCS,
    )
    @HttpMessageSignatureHeaders
    @DeleteMapping("/deleteAccount")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun deleteAccount(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("RwscaApi.deleteAccount") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                rwscaAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS,
            ).authKey
        val account = rwscaAccountService.findAccount(rwscaAccountId, wiMdvmAuthPubk)

        rwscaAccountService.deleteAccount(account.rwscaAccountId)
    }

    private suspend fun authorizeOperation(
        rwscaAuthChallenge: String,
        mdvmToken: String,
        httpRequest: ServerHttpRequest,
        requiredSignatureComponents: List<String>,
    ): MdvmToken {
        challengeTokenBuilder.parseAndValidate(rwscaAuthChallenge, config.issuer)

        val parsedMdvmToken = mdvmTokenParser.parseAndValidate(mdvmToken)

        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            RWSCA_AUTH_SIGNATURE_NAME,
            requiredSignatureComponents,
            parsedMdvmToken.authKey,
        )

        return parsedMdvmToken
    }

    private fun extractPinPubk(base64EncodedECPubKDer: String): ECPublicKey {
        val key =
            try {
                base64EncodedECPubKDer.fromBase64().ecPublicKeyFromX509()
            } catch (ex: IllegalArgumentException) {
                throw MalformedPinPubKeyException(ex)
            } catch (ex: InvalidKeySpecException) {
                throw MalformedPinPubKeyException(ex)
            }
        if (Curve.forECParameterSpec(key.params) != RECOMMENDED_EC_CURVE) {
            throw MalformedPinPubKeyException(
                InvalidKeySpecException("EC curve does not match $RECOMMENDED_EC_CURVE"),
            )
        }
        return key
    }

    private fun extractDataHash(base64EncodedHash: String): ByteArray {
        val bytes =
            try {
                base64EncodedHash.fromBase64()
            } catch (e: IllegalArgumentException) {
                throw MalformedDataHashException(e)
            }
        if (bytes.size != SHA256_DIGEST_SIZE) {
            throw MalformedDataHashException(
                IllegalArgumentException("Expected SHA-256 digest (32 bytes), got ${bytes.size}"),
            )
        }
        return bytes
    }

    private class AccountIdMismatchException : Exception("rwsca_account_id does not match")
}
