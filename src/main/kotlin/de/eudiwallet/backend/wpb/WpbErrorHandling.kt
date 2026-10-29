package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.error.ErrorResponseCode
import de.eudiwallet.backend.shared.error.ServiceErrorHandler
import de.eudiwallet.backend.shared.error.TRACE_ID
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.media.Schema
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
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
class WpbErrorHandler(
    telemetryService: TelemetryService,
) : ServiceErrorHandler<WpbErrorResponseCode, WpbErrorResponse>(
        telemetryService,
        WpbErrorResponseCode.entries,
        WpbErrorResponse.serializer(),
    ) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(MalformedWiaPubKeyException::class)
    fun handleMalformedKey(e: MalformedWiaPubKeyException) =
        errorResponse(WpbErrorResponseCode.MALFORMED_WIA_PUB_KEY, e)

    @ExceptionHandler(AccountNotFoundException::class)
    fun handleAccountNotFound(e: AccountNotFoundException) = errorResponse(WpbErrorResponseCode.ACCOUNT_NOT_FOUND, e)

    @ExceptionHandler(AccountRevokedException::class)
    fun handleAccountRevoked(e: AccountRevokedException) = errorResponse(WpbErrorResponseCode.ACCOUNT_REVOKED, e)

    @ExceptionHandler(KeyAlreadyRegisteredException::class)
    fun handleKeyAlreadyRegistered(e: KeyAlreadyRegisteredException): ResponseEntity<String> {
        log.warn(e) {}
        return errorResponse(WpbErrorResponseCode.KEY_ALREADY_REGISTERED, e)
    }

    @ExceptionHandler(RevocationCodeGenerationException::class)
    fun handleRevocationCodeGeneration(e: RevocationCodeGenerationException) =
        errorResponse(WpbErrorResponseCode.INTERNAL_SERVER_ERROR, e)

    @ExceptionHandler(RevocationCodeNotFoundException::class)
    fun handleRevocationCodeNotFound(e: RevocationCodeNotFoundException) =
        errorResponse(WpbErrorResponseCode.REVOCATION_CODE_NOT_FOUND, e)

    override fun errorBody(
        code: WpbErrorResponseCode,
        description: String?,
        traceId: String?,
    ) = WpbErrorResponse(code = code, description = description ?: code.description, traceId = traceId)
}

enum class WpbErrorResponseCode(
    override val httpStatus: HttpStatus,
    val description: String,
) : ErrorResponseCode {
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    HSM_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "HSM is temporarily unavailable, please retry later"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    CHALLENGE_EXPIRED(HttpStatus.BAD_REQUEST, "Challenge expired"),
    MDVM_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "MDVM token verification failed"),
    MDVM_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "MDVM token expired"),
    SIGNATURE_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Signature verification failed"),
    MALFORMED_WIA_PUB_KEY(HttpStatus.BAD_REQUEST, "Malformed $WI_WIA_PUBK_FIELD"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
    ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "WpbAccount not found"),
    ACCOUNT_REVOKED(HttpStatus.FORBIDDEN, "WpbAccount revoked"),
    KEY_ALREADY_REGISTERED(HttpStatus.CONFLICT, "An account is already registered for this MDVM account"),
    REVOCATION_CODE_NOT_FOUND(HttpStatus.NOT_FOUND, "Revocation code not found"),
    MESSAGING_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Messaging temporarily unavailable, please retry later"),
}

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
