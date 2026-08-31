package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.challengetoken.ChallengeVerificationException
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenVerificationException
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.media.Schema
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.dao.DataAccessResourceFailureException
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.validation.BindingResult
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.server.ServerWebInputException
import java.time.Instant

class AccountNotFoundException : RuntimeException("WpbAccount not found")

class AccountRevokedException : RuntimeException("WpbAccount revoked")

class KeyAlreadyRegisteredException(
    cause: Throwable? = null,
) : RuntimeException("An account is already registered for this MDVM account", cause)

class MalformedWiaPubKeyException(
    cause: Throwable,
) : RuntimeException("Malformed $WI_WIA_PUBK_FIELD", cause)

class RevocationCodeGenerationException(
    cause: Throwable,
) : RuntimeException("Failed to generate revocation code", cause)

class RevocationCodeNotFoundException(
    cause: Throwable? = null,
) : RuntimeException("Revocation code not found", cause)

@ControllerAdvice(basePackages = ["de.eudiwallet.backend.wpb"])
@ConditionalOnProperty(prefix = "wpb", name = ["enabled"], havingValue = "true")
@Suppress("TooManyFunctions")
class WpbErrorHandler(
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(
        DataAccessResourceFailureException::class,
    )
    fun handleServiceUnavailable(e: Exception): ResponseEntity<WpbErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.DB_UNAVAILABLE, e)
    }

    @ExceptionHandler(HsmException.GetSessionFailedException::class)
    fun handleHsmSessionUnavailable(e: HsmException.GetSessionFailedException): ResponseEntity<WpbErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.HSM_UNAVAILABLE, e)
    }

    @ExceptionHandler(SignatureVerificationException::class)
    fun handleSignatureVerificationException(e: SignatureVerificationException): ResponseEntity<WpbErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.SIGNATURE_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(ChallengeVerificationException::class)
    fun handleChallengeVerification(e: ChallengeVerificationException) =
        createErrorResponseEntity(WpbErrorResponseCode.CHALLENGE_VERIFICATION_FAILURE, e)

    @ExceptionHandler(MdvmTokenVerificationException::class)
    fun handleMdvmTokenVerification(e: MdvmTokenVerificationException) =
        createErrorResponseEntity(WpbErrorResponseCode.MDVM_TOKEN_VERIFICATION_FAILURE, e)

    @ExceptionHandler(MalformedWiaPubKeyException::class)
    fun handleMalformedKey(e: MalformedWiaPubKeyException) =
        createErrorResponseEntity(WpbErrorResponseCode.MALFORMED_WIA_PUB_KEY, e)

    @ExceptionHandler(
        ServerWebInputException::class,
        MethodArgumentNotValidException::class,
    )
    fun handleBadRequest(e: Exception): ResponseEntity<WpbErrorResponse> {
        val description =
            (e as? BindingResult)
                ?.fieldErrors
                ?.filterNot { it.isBindingFailure() }
                ?.mapNotNull { it.defaultMessage }
                ?.takeIf { it.isNotEmpty() }
                ?.joinToString("; ")
                ?: WpbErrorResponseCode.BAD_REQUEST.description
        return createErrorResponseEntity(WpbErrorResponseCode.BAD_REQUEST, e, description)
    }

    @ExceptionHandler(AccountNotFoundException::class)
    fun handleAccountNotFound(e: AccountNotFoundException) =
        createErrorResponseEntity(WpbErrorResponseCode.ACCOUNT_NOT_FOUND, e)

    @ExceptionHandler(AccountRevokedException::class)
    fun handleAccountRevoked(e: AccountRevokedException) =
        createErrorResponseEntity(WpbErrorResponseCode.ACCOUNT_REVOKED, e)

    @ExceptionHandler(KeyAlreadyRegisteredException::class)
    fun handleKeyAlreadyRegistered(e: KeyAlreadyRegisteredException): ResponseEntity<WpbErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.KEY_ALREADY_REGISTERED, e)
    }

    @ExceptionHandler(RevocationCodeGenerationException::class)
    fun handleRevocationCodeGenerationException(e: Exception): ResponseEntity<WpbErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    @ExceptionHandler(RevocationCodeNotFoundException::class)
    fun handleRevocationCodeNotFound(e: RevocationCodeNotFoundException) =
        createErrorResponseEntity(WpbErrorResponseCode.REVOCATION_CODE_NOT_FOUND, e)

    @ExceptionHandler(MessagingUnavailableException::class)
    fun handleMessagingUnavailable(e: MessagingUnavailableException): ResponseEntity<WpbErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.MESSAGING_UNAVAILABLE, e)
    }

    @ExceptionHandler(Exception::class)
    fun handleInternalServerError(e: Exception): ResponseEntity<WpbErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(WpbErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    private fun createErrorResponseEntity(
        code: WpbErrorResponseCode,
        cause: Throwable,
        description: String = code.description,
    ): ResponseEntity<WpbErrorResponse> {
        telemetryService.traceErrorCode(code.name)
        telemetryService.traceException(cause)
        return ResponseEntity
            .status(code.httpStatus)
            .contentType(MediaType.APPLICATION_JSON)
            .body(
                WpbErrorResponse(
                    code = code,
                    traceId = telemetryService.getCurrentTraceId(),
                    description = description,
                ),
            )
    }
}

enum class WpbErrorResponseCode(
    val httpStatus: HttpStatus,
    val description: String,
) {
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    HSM_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "HSM is temporarily unavailable, please retry later"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    MDVM_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "MDVM token verification failed"),
    SIGNATURE_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Signature verification failed"),
    MALFORMED_WIA_PUB_KEY(HttpStatus.BAD_REQUEST, "Malformed $WI_WIA_PUBK_FIELD"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
    ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "WpbAccount not found"),
    ACCOUNT_REVOKED(HttpStatus.FORBIDDEN, "WpbAccount revoked"),
    KEY_ALREADY_REGISTERED(HttpStatus.CONFLICT, "An account is already registered for this MDVM account"),
    REVOCATION_CODE_NOT_FOUND(HttpStatus.NOT_FOUND, "Revocation code not found"),
    MESSAGING_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Messaging temporarily unavailable, please retry later"),
}

const val TRACE_ID = "trace_id"

@Serializable
data class WpbErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: WpbErrorResponseCode,
    @Schema(description = "Human-readable error description")
    val description: String? = null,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = Instant.now().toString(),
    @SerialName(TRACE_ID)
    @Schema(description = "Trace ID for correlating logs and debugging")
    val traceId: String?,
)
