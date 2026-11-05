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
import de.eudiwallet.backend.shared.httpsignature.ContentDigestHeader
import de.eudiwallet.backend.shared.httpsignature.HttpMessageSignatureHeaders
import de.eudiwallet.backend.shared.httpsignature.HttpSignatureVerifier
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
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.security.interfaces.ECPublicKey
import java.security.spec.InvalidKeySpecException
import kotlin.time.toKotlinInstant

const val RWSCA_PIN_ENC_PUBK_FIELD = "rwsca_pin_enc_pubk"

@Serializable
data class WiMetaDataResponse(
    @SerialName(RWSCA_PIN_ENC_PUBK_FIELD)
    @Schema(
        implementation = Map::class,
        description = "Public JWK the WI encrypts its PIN signature and $WI_RWSCA_PIN_PUBK_FIELD to",
        example = PIN_ENCRYPTION_JWK_EXAMPLE,
    )
    val rwscaPinEncPubk: JsonObject,
)

@Serializable
data class InitializePinAndStartPinSessionRequestV2(
    @SerialName(WI_RWSCA_PIN_PUBK_FIELD)
    @Schema(
        description = "X.509 EC public key (DER) encrypted to $RWSCA_PIN_ENC_PUBK_FIELD",
        example = ENCRYPTED_PIN_VALUE_EXAMPLE,
    )
    val wiRwscaPinPubk: String,
)

@RestController
@RequestMapping("/v2/rwsca")
@Tag(name = "rwsca-v2", description = "Remote WSCA API with an encrypted PIN signature")
@Suppress("LongParameterList")
@ConditionalOnProperty(prefix = "rwsca", name = ["enabled"], havingValue = "true")
class RwscaApiV2(
    private val rwscaAccountService: RwscaAccountService,
    private val config: RwscaConfiguration,
    @Qualifier("rwscdMasterLineage")
    private val rwscdMasterLineage: KeySource<SymmetricKeySet>,
    private val mdvmTokenParser: MdvmTokenParser,
    private val pinSessionTokenBuilder: PinSessionTokenBuilder,
    @Qualifier(RWSCA_WI_HSM_PROVIDER)
    private val hsmProvider: HsmProvider,
    private val telemetryService: TelemetryService,
    private val httpSignatureVerifier: HttpSignatureVerifier,
    private val rwscaBoundWrappedPrvkBuilder: RwscaBoundWrappedPrvkBuilder,
    private val wteBuilder: WalletTrustEvidenceBuilder,
    private val challengeTokenBuilder: ChallengeTokenBuilder,
    private val pinEncryptionKey: PinEncryptionKey,
    private val pinSignatureDecrypter: PinSignatureDecrypter,
) {
    @Operation(
        summary = "Get the metadata the WI needs for RWSCA operations",
        description = WI_METADATA_DOCS,
    )
    @GetMapping("/wiMetaData")
    @ResponseBody
    suspend fun wiMetaData(): WiMetaDataResponse =
        telemetryService.withSpan("RwscaApiV2.wiMetaData") {
            WiMetaDataResponse(pinEncryptionKey.publicJwkJson)
        }

    @Operation(
        summary = "Generate a challenge for remote WSCA operations",
        description = CHALLENGE_DOCS,
    )
    @PostMapping("/challenge")
    @ResponseBody
    suspend fun challenge(): RwscaChallengeResponse =
        telemetryService.withSpan("RwscaApiV2.challenge") {
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
        telemetryService.withSpan("RwscaApiV2.register") {
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
        description = INITIALIZE_PIN_AND_START_PIN_SESSION_V2_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/initializePinAndStartPinSession")
    @ResponseBody
    suspend fun initializePinAndStartPinSession(
        @RequestHeader(AUTH_CHALLENGE_HEADER) rwscaAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(RWSCA_ACCOUNT_ID_HEADER) rwscaAccountId: RwscaAccountId,
        @RequestBody request: InitializePinAndStartPinSessionRequestV2,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("RwscaApiV2.initializePinAndStartPinSession") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                rwscaAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_INIT_PIN_AUTH_COMPONENTS,
            ).authKey

        val wiRwscaPinPubk = decryptPinPubk(request.wiRwscaPinPubk)

        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            RWSCA_PIN_SIGNATURE_NAME,
            REQUIRED_SIGNATURE_INIT_PIN_AUTH_COMPONENTS,
            wiRwscaPinPubk,
            pinSignatureDecrypter::decryptSignature,
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
        description = START_PIN_SESSION_V2_DOCS,
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
        telemetryService.withSpan("RwscaApiV2.startPinSession") {
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
                        pinSignatureDecrypter::decryptSignature,
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
        telemetryService.withSpan("RwscaApiV2.createKeys") {
            val wiMdvmAuthPubk =
                authorizeOperation(
                    rwscaAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_CREATE_KEYS_COMPONENTS,
                ).authKey
            val account =
                rwscaAccountService.findActiveAccount(rwscaAccountId, wiMdvmAuthPubk)

            val masterKeyId = rwscdMasterLineage.current().primaryId

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
        telemetryService.withSpan("RwscaApiV2.signData") {
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
    ) = telemetryService.withSpan("RwscaApiV2.deleteAccount") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                rwscaAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS,
            ).authKey
        rwscaAccountService.deleteAccount(rwscaAccountId, wiMdvmAuthPubk)
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

    private fun decryptPinPubk(encrypted: String): ECPublicKey {
        val key =
            try {
                pinSignatureDecrypter.decryptPinPubk(encrypted).ecPublicKeyFromX509()
            } catch (ex: PinSignatureDecryptionException) {
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
