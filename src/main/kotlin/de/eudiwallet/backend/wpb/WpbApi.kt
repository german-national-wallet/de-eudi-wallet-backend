package de.eudiwallet.backend.wpb

import com.nimbusds.jose.jwk.Curve
import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder
import de.eudiwallet.backend.shared.crypto.RECOMMENDED_EC_CURVE
import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.fromBase64
import de.eudiwallet.backend.shared.httpsignature.CONTENT_DIGEST_HEADER
import de.eudiwallet.backend.shared.httpsignature.ContentDigestHeader
import de.eudiwallet.backend.shared.httpsignature.HttpMessageSignatureHeaders
import de.eudiwallet.backend.shared.httpsignature.HttpSignatureVerifier
import de.eudiwallet.backend.shared.httpsignature.METHOD_COMPONENT
import de.eudiwallet.backend.shared.httpsignature.PATH_COMPONENT
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenParser
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationPublisher
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
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
import java.util.UUID

const val WPB_AUTH_SIGNATURE_NAME = "wpb-auth-sig"
const val WPB_WIA_SIGNATURE_NAME = "wpb-wia-sig"

const val WPB_WIA_POOL = "wpb-wia"

const val AUTH_CHALLENGE_HEADER = "Auth-Challenge"
const val MDVM_TOKEN_HEADER = "Mdvm-Token"
const val WPB_WI_ID_HEADER = "Wpb-Wi-Id"

val REQUIRED_SIGNATURE_REGISTER_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )

val REQUIRED_SIGNATURE_ATTESTATION_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        WPB_WI_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        WPB_WI_ID_HEADER,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )

const val WPB_AUTH_CHALLENGE_FIELD = "wpb_auth_challenge"
const val WPB_WI_ID_FIELD = "wpb_wi_id"
const val WPB_WI_REVOCATION_CODE_FIELD = "wpb_wi_revocation_code"
const val WPB_WIA_FIELD = "wpb_wia"
const val WI_WIA_PUBK_FIELD = "wi_wia_pubk"
const val WPB_CLIENT_INSTANCE_ID_FIELD = "wpb_client_instance_id"

@Serializable
data class WpbChallengeResponse(
    @SerialName(WPB_AUTH_CHALLENGE_FIELD)
    @Schema(description = "WPB authentication challenge JWT", example = CHALLENGE_EXAMPLE)
    val authChallenge: String,
)

@Serializable
data class WpbRegisterResponse(
    @SerialName(WPB_WI_ID_FIELD)
    @Schema(description = "Unique identifier for the registered WPB account")
    val wpbWiId: WpbAccountId,
    @SerialName(WPB_WI_REVOCATION_CODE_FIELD)
    @Schema(
        description = "Bech32-encoded revocation code, returned to the WI exactly once and never recoverable later",
        example = REVOCATION_CODE_EXAMPLE,
    )
    val wpbWiRevocationCode: String,
) {
    override fun toString(): String = "WpbRegisterResponse(wpbWiId=$wpbWiId, wpbWiRevocationCode='<value is hidden>')"
}

@Serializable
data class WpbRevokeRequest(
    @SerialName(WPB_WI_REVOCATION_CODE_FIELD)
    @Schema(
        description = "Bech32-encoded revocation code issued to the Wallet Instance at registration",
        example = REVOCATION_CODE_EXAMPLE,
    )
    val wpbWiRevocationCode: String,
) {
    override fun toString(): String = "WpbRevokeRequest(wpbWiRevocationCode='<value is hidden>')"
}

@Serializable
data class WpbAttestationRequest(
    @SerialName(WI_WIA_PUBK_FIELD)
    @Schema(description = "Base64-encoded X.509 EC public key")
    val wiWiaPubk: String,
    @SerialName(WPB_CLIENT_INSTANCE_ID_FIELD)
    @Schema(description = "Handle for the status-list entry; omit to allocate a new one; reuse to renew.")
    val wpbClientInstanceId: WpbClientInstanceId?,
)

@Serializable
data class WpbAttestationResponse(
    @SerialName(WPB_WIA_FIELD)
    @Schema(description = "Wallet Instance Attestation", example = WIA_EXAMPLE)
    val wpbWia: String,
    @SerialName(WPB_CLIENT_INSTANCE_ID_FIELD)
    @Schema(description = "Handle of the provisioned status-list entry.")
    val wpbClientInstanceId: WpbClientInstanceId,
)

@Serializable(with = WpbClientInstanceIdSerializer::class)
@JvmInline
value class WpbClientInstanceId(
    val id: UUID,
) {
    override fun toString() = id.toString()
}

object WpbClientInstanceIdSerializer : KSerializer<WpbClientInstanceId> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("WpbClientInstanceId", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: WpbClientInstanceId,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): WpbClientInstanceId =
        try {
            WpbClientInstanceId(UUID.fromString(decoder.decodeString()))
        } catch (ex: java.lang.IllegalArgumentException) {
            throw SerializationException("Cannot deserialize WpbClientInstanceId", ex)
        }
}

@RestController
@RequestMapping("/v1/wpb")
@Tag(name = "wpb", description = "Wallet Provider Backend API")
@ConditionalOnProperty(prefix = "wpb", name = ["enabled"], havingValue = "true")
class WpbApi(
    private val config: WpbConfiguration,
    private val wiaBuilder: WalletInstanceAttestationBuilder,
    private val challengeTokenBuilder: ChallengeTokenBuilder,
    private val mdvmTokenParser: MdvmTokenParser,
    private val wpbAccountService: WpbAccountService,
    private val httpSignatureVerifier: HttpSignatureVerifier,
    private val telemetryService: TelemetryService,
    private val revocationPublisherProvider: ObjectProvider<WalletInstanceRevocationPublisher>,
) {
    @Operation(
        summary = "Generate a challenge for wallet provider backend operations",
        description = CHALLENGE_DOCS,
    )
    @PostMapping("/challenge")
    suspend fun challenge(): WpbChallengeResponse =
        telemetryService.withSpan("WpbApi.challenge") {
            WpbChallengeResponse(
                authChallenge = challengeTokenBuilder.createAndSerializeToJwt(config.issuer),
            )
        }

    @Operation(
        summary = "Register a new WPB account",
        description = REGISTER_DOCS,
    )
    @HttpMessageSignatureHeaders
    @PostMapping("/register")
    suspend fun register(
        @RequestHeader(AUTH_CHALLENGE_HEADER) wpbAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        httpRequest: ServerHttpRequest,
    ): WpbRegisterResponse =
        telemetryService.withSpan("WpbApi.register") {
            val parsedMdvmToken =
                authorizeOperation(
                    wpbAuthChallenge,
                    mdvmToken,
                    httpRequest,
                    REQUIRED_SIGNATURE_REGISTER_COMPONENTS,
                )
            val registration =
                wpbAccountService.createAccount(parsedMdvmToken.authKey, parsedMdvmToken.mdvmAccountId)
            WpbRegisterResponse(registration.account.wpbAccountId, registration.revocationCode)
        }

    @Operation(
        summary = "Revoke a Wallet Instance",
        description = REVOKE_DOCS,
    )
    @ApiResponses(
        ApiResponse(responseCode = "202", description = "Revocation accepted and published"),
        ApiResponse(responseCode = "200", description = "Already revoked; nothing was published"),
    )
    @PostMapping("/revoke")
    suspend fun revoke(
        @RequestBody request: WpbRevokeRequest,
    ): ResponseEntity<Unit> =
        telemetryService.withSpan("WpbApi.revoke") {
            val publisher = revocationPublisherProvider.getIfAvailable() ?: throw MessagingUnavailableException()
            val event =
                wpbAccountService.buildRevocationEvent(request.wpbWiRevocationCode)
                    ?: return@withSpan ResponseEntity.ok().build()
            publisher.publish(event)
            ResponseEntity.accepted().build()
        }

    @Operation(
        summary = "Issue Wallet Instance Attestation",
        description = ATTESTATION_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/attestation")
    @ResponseBody
    suspend fun attestation(
        @RequestHeader(AUTH_CHALLENGE_HEADER) wpbAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(WPB_WI_ID_HEADER) wpbAccountId: WpbAccountId,
        @RequestBody request: WpbAttestationRequest,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("WpbApi.attestation") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                wpbAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_ATTESTATION_COMPONENTS,
            ).authKey
        val wiWiaPubk = extractWiaPubk(request.wiWiaPubk)
        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            WPB_WIA_SIGNATURE_NAME,
            REQUIRED_SIGNATURE_ATTESTATION_COMPONENTS,
            wiWiaPubk,
        )
        val statusReference =
            wpbAccountService.findAccountAndProvisionWiaEntry(
                wpbAccountId,
                wiMdvmAuthPubk,
                request.wpbClientInstanceId?.id,
            )
        WpbAttestationResponse(
            wiaBuilder.createAndSerializeToJwt(wiWiaPubk, statusReference),
            WpbClientInstanceId(statusReference.clientInstanceId),
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
        @RequestHeader(AUTH_CHALLENGE_HEADER) wpbAuthChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @RequestHeader(WPB_WI_ID_HEADER) wpbAccountId: WpbAccountId,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("WpbApi.deleteAccount") {
        val wiMdvmAuthPubk =
            authorizeOperation(
                wpbAuthChallenge,
                mdvmToken,
                httpRequest,
                REQUIRED_SIGNATURE_DELETE_ACCOUNT_COMPONENTS,
            ).authKey
        wpbAccountService.deleteAccount(wpbAccountId, wiMdvmAuthPubk)
    }

    private suspend fun authorizeOperation(
        wpbAuthChallenge: String,
        mdvmToken: String,
        httpRequest: ServerHttpRequest,
        requiredSignatureComponents: List<String>,
    ): MdvmToken {
        challengeTokenBuilder.parseAndValidate(wpbAuthChallenge, config.issuer)

        val parsedMdvmToken = mdvmTokenParser.parseAndValidate(mdvmToken)

        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            WPB_AUTH_SIGNATURE_NAME,
            requiredSignatureComponents,
            parsedMdvmToken.authKey,
        )

        return parsedMdvmToken
    }

    private fun extractWiaPubk(base64EncodedECPubKDer: String): ECPublicKey {
        val key =
            try {
                base64EncodedECPubKDer.fromBase64().ecPublicKeyFromX509()
            } catch (ex: IllegalArgumentException) {
                throw MalformedWiaPubKeyException(ex)
            } catch (ex: InvalidKeySpecException) {
                throw MalformedWiaPubKeyException(ex)
            }
        val curve = Curve.forECParameterSpec(key.params)
        if (curve != RECOMMENDED_EC_CURVE) {
            throw MalformedWiaPubKeyException(
                InvalidKeySpecException("EC curve ${curve ?: "unknown"} does not match $RECOMMENDED_EC_CURVE"),
            )
        }
        return key
    }
}
