package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder
import de.eudiwallet.backend.shared.httpsignature.CONTENT_DIGEST_HEADER
import de.eudiwallet.backend.shared.httpsignature.ContentDigestHeader
import de.eudiwallet.backend.shared.httpsignature.HttpMessageSignatureHeaders
import de.eudiwallet.backend.shared.httpsignature.HttpSignatureVerifier
import de.eudiwallet.backend.shared.httpsignature.METHOD_COMPONENT
import de.eudiwallet.backend.shared.httpsignature.PATH_COMPONENT
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenParser
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import jakarta.validation.constraints.Size
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

const val PNS_AUTH_SIGNATURE_NAME = "pns-auth-sig"

const val AUTH_CHALLENGE_HEADER = "Auth-Challenge"
const val MDVM_TOKEN_HEADER = "Mdvm-Token"

const val MPP_REGISTRATION_TOKEN_FIELD = "mpp_registration_token"

const val PNS_AUTH_CHALLENGE_FIELD = "pns_auth_challenge"

const val MAX_MPP_REGISTRATION_TOKEN_LENGTH = 1024

val REQUIRED_SIGNATURE_REGISTER_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
        CONTENT_DIGEST_HEADER,
    )

val REQUIRED_SIGNATURE_DELETE_COMPONENTS =
    listOf(
        METHOD_COMPONENT,
        PATH_COMPONENT,
        AUTH_CHALLENGE_HEADER,
        MDVM_TOKEN_HEADER,
    )

@Serializable
data class PnsRegisterRequest(
    @SerialName(MPP_REGISTRATION_TOKEN_FIELD)
    @Schema(
        description = "Push-notification token issued to the WI by the Mobile Platform Provider",
        maxLength = MAX_MPP_REGISTRATION_TOKEN_LENGTH,
    )
    @field:Size(max = MAX_MPP_REGISTRATION_TOKEN_LENGTH)
    val mppRegistrationToken: String,
) {
    override fun toString(): String = "PnsRegisterRequest(mppRegistrationToken='<value is hidden>')"
}

@Serializable
data class PnsChallengeResponse(
    @SerialName(PNS_AUTH_CHALLENGE_FIELD)
    @Schema(description = "PNS authentication challenge JWT")
    val authChallenge: String,
)

@RestController
@RequestMapping("/v1/pns")
@Tag(name = "PNS", description = "Push Notifications registration API")
@ConditionalOnProperty(prefix = "pns", name = ["enabled"], havingValue = "true")
class PnsApi(
    private val config: PnsConfiguration,
    private val challengeTokenBuilder: ChallengeTokenBuilder,
    private val mdvmTokenParser: MdvmTokenParser,
    private val httpSignatureVerifier: HttpSignatureVerifier,
    private val pnsService: PnsService,
    private val telemetryService: TelemetryService,
) {
    @Operation(
        summary = "Generate a challenge for push-notification registration",
        description = CHALLENGE_DOCS,
    )
    @PostMapping("/challenge")
    suspend fun challenge(): PnsChallengeResponse =
        telemetryService.withSpan("PnsApi.challenge") {
            PnsChallengeResponse(
                authChallenge = challengeTokenBuilder.createAndSerializeToJwt(config.issuer),
            )
        }

    @Operation(
        summary = "Register a push-notification token for a Wallet Instance",
        description = REGISTER_DOCS,
    )
    @HttpMessageSignatureHeaders
    @ContentDigestHeader
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun register(
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        @Valid @RequestBody request: PnsRegisterRequest,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("PnsApi.register") {
        val mdvmAccountId =
            authorizeOperation(authChallenge, mdvmToken, httpRequest, REQUIRED_SIGNATURE_REGISTER_COMPONENTS)
        pnsService.register(mdvmAccountId, request.mppRegistrationToken)
    }

    @Operation(
        summary = "Delete registration",
        description = DELETE_DOCS,
    )
    @HttpMessageSignatureHeaders
    @DeleteMapping("/delete")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun deleteRegistration(
        @RequestHeader(AUTH_CHALLENGE_HEADER) authChallenge: String,
        @RequestHeader(MDVM_TOKEN_HEADER) mdvmToken: String,
        httpRequest: ServerHttpRequest,
    ) = telemetryService.withSpan("PnsApi.deleteRegistration") {
        val mdvmAccountId =
            authorizeOperation(authChallenge, mdvmToken, httpRequest, REQUIRED_SIGNATURE_DELETE_COMPONENTS)
        pnsService.delete(mdvmAccountId)
    }

    private suspend fun authorizeOperation(
        authChallenge: String,
        mdvmToken: String,
        httpRequest: ServerHttpRequest,
        requiredSignatureComponents: List<String>,
    ): MdvmAccountId {
        challengeTokenBuilder.parseAndValidate(authChallenge, config.issuer)

        val parsedMdvmToken = mdvmTokenParser.parseAndValidate(mdvmToken)
        val wiMdvmAuthPubk = parsedMdvmToken.authKey

        httpSignatureVerifier.verifyRequestSignature(
            httpRequest,
            PNS_AUTH_SIGNATURE_NAME,
            requiredSignatureComponents,
            wiMdvmAuthPubk,
        )

        return parsedMdvmToken.mdvmAccountId
    }
}
