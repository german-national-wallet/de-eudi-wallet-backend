package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.error.ErrorResponseCode
import de.eudiwallet.backend.shared.error.ServiceErrorHandler
import de.eudiwallet.backend.shared.error.TRACE_ID
import de.eudiwallet.backend.shared.hsm.HsmException
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

class MalformedPinPubKeyException(
    cause: Throwable,
) : RuntimeException("Malformed $WI_RWSCA_PIN_PUBK_FIELD", cause)

class AccountNotFoundException : RuntimeException("RwscaAccount not found")

class AccountRevokedException : RuntimeException("RwscaAccount revoked")

class KeyAlreadyRegisteredException(
    cause: Throwable? = null,
) : RuntimeException("An account is already registered for this MDVM account", cause)

class PinAlreadyInitializedException : RuntimeException("Pin already initialized")

class AccountLockedException : RuntimeException("Account locked")

class PinNotInitializedException : RuntimeException("Pin not initialized")

class PinVerificationFailedException(
    val tryCounter: Int,
    val tryAllowedAfter: Instant,
) : RuntimeException("Pin verification failed")

class PinRetryBlockedException(
    val tryCounter: Int,
    val tryAllowedAfter: Instant,
) : RuntimeException("PIN retry blocked due to backoff delay")

class PinSessionTokenVerificationException(
    cause: Throwable,
) : RuntimeException("Malformed $PIN_SESSION_TOKEN_HEADER", cause)

class WrappedPrvkVerificationException(
    cause: Throwable,
) : RuntimeException("Malformed $RWSCA_WI_WRAPPED_PRVK_FIELD", cause)

class MalformedDataHashException(
    cause: Throwable,
) : RuntimeException("Malformed $WI_KEY_BINDING_DATA_HASH_FIELD", cause)

@Suppress("TooManyFunctions")
@ControllerAdvice(basePackages = ["de.eudiwallet.backend.rwsca"])
@ConditionalOnProperty(prefix = "rwsca", name = ["enabled"], havingValue = "true")
class RwscaErrorHandler(
    telemetryService: TelemetryService,
) : ServiceErrorHandler<RwscaErrorResponseCode, RwscaErrorResponse>(
        telemetryService,
        RwscaErrorResponseCode.entries,
        RwscaErrorResponse.serializer(),
    ) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(HsmException::class)
    fun handleHsmException(e: HsmException) = errorResponse(RwscaErrorResponseCode.HSM_UNAVAILABLE, e)

    @ExceptionHandler(AccountNotFoundException::class)
    fun handleAccountNotFound(e: AccountNotFoundException) = errorResponse(RwscaErrorResponseCode.ACCOUNT_NOT_FOUND, e)

    @ExceptionHandler(AccountRevokedException::class)
    fun handleAccountRevoked(e: AccountRevokedException) = errorResponse(RwscaErrorResponseCode.ACCOUNT_REVOKED, e)

    @ExceptionHandler(KeyAlreadyRegisteredException::class)
    fun handleKeyAlreadyRegistered(e: KeyAlreadyRegisteredException): ResponseEntity<String> {
        log.warn(e) {}
        return errorResponse(RwscaErrorResponseCode.KEY_ALREADY_REGISTERED, e)
    }

    @ExceptionHandler(PinSessionTokenVerificationException::class)
    fun handlePinSessionTokenVerification(e: PinSessionTokenVerificationException) =
        errorResponse(RwscaErrorResponseCode.PIN_SESSION_TOKEN_VERIFICATION_FAILURE, e)

    @ExceptionHandler(WrappedPrvkVerificationException::class)
    fun handleWrappedPrvkVerification(e: WrappedPrvkVerificationException) =
        errorResponse(RwscaErrorResponseCode.WRAPPED_PRVK_VERIFICATION_FAILURE, e)

    @ExceptionHandler(PinAlreadyInitializedException::class)
    fun handlePinAlreadyInitialized(e: PinAlreadyInitializedException) =
        errorResponse(RwscaErrorResponseCode.PIN_ALREADY_INITIALIZED, e)

    @ExceptionHandler(AccountLockedException::class)
    fun handleAccountLocked(e: AccountLockedException) = errorResponse(RwscaErrorResponseCode.ACCOUNT_LOCKED, e)

    @ExceptionHandler(MalformedPinPubKeyException::class)
    fun handleMalformedKey(e: MalformedPinPubKeyException) =
        errorResponse(RwscaErrorResponseCode.MALFORMED_PIN_PUB_KEY, e)

    @ExceptionHandler(MalformedDataHashException::class)
    fun handleMalformedDataHash(e: MalformedDataHashException) =
        errorResponse(RwscaErrorResponseCode.MALFORMED_DATA_HASH, e)

    @ExceptionHandler(PinNotInitializedException::class)
    fun handlePinNotInitialized(e: PinNotInitializedException) =
        errorResponse(RwscaErrorResponseCode.PIN_NOT_INITIALIZED, e)

    @ExceptionHandler(PinVerificationFailedException::class)
    fun handlePinVerificationFailed(e: PinVerificationFailedException) =
        pinTryErrorResponse(RwscaErrorResponseCode.PIN_VERIFICATION_FAILED, e, e.tryCounter, e.tryAllowedAfter)

    @ExceptionHandler(PinRetryBlockedException::class)
    fun handlePinRetryBlocked(e: PinRetryBlockedException) =
        pinTryErrorResponse(RwscaErrorResponseCode.PIN_RETRY_BLOCKED, e, e.tryCounter, e.tryAllowedAfter)

    override fun errorBody(
        code: RwscaErrorResponseCode,
        description: String?,
        traceId: String?,
    ) = RwscaErrorResponse(code = code, description = description ?: code.description, traceId = traceId)

    private fun pinTryErrorResponse(
        code: RwscaErrorResponseCode,
        cause: Throwable,
        tryCounter: Int,
        tryAllowedAfter: Instant,
    ) = errorResponse(code, cause) { traceId ->
        errorBody(code, null, traceId).copy(tryCounter = tryCounter, tryAllowedAfter = tryAllowedAfter.toString())
    }
}

enum class RwscaErrorResponseCode(
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
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
    ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "RwscaAccount not found"),
    ACCOUNT_REVOKED(HttpStatus.FORBIDDEN, "RwscaAccount revoked"),
    KEY_ALREADY_REGISTERED(HttpStatus.CONFLICT, "An account is already registered for this MDVM account"),
    PIN_ALREADY_INITIALIZED(HttpStatus.CONFLICT, "Pin already initialized"),
    ACCOUNT_LOCKED(HttpStatus.FORBIDDEN, "Account locked"),
    MALFORMED_PIN_PUB_KEY(HttpStatus.BAD_REQUEST, "Malformed $WI_RWSCA_PIN_PUBK_FIELD"),
    MALFORMED_DATA_HASH(HttpStatus.BAD_REQUEST, "Malformed $WI_KEY_BINDING_DATA_HASH_FIELD"),
    PIN_NOT_INITIALIZED(HttpStatus.CONFLICT, "Pin not initialized"),
    PIN_VERIFICATION_FAILED(HttpStatus.UNAUTHORIZED, "Pin verification failed"),
    PIN_RETRY_BLOCKED(HttpStatus.TOO_MANY_REQUESTS, "PIN retry blocked due to backoff delay"),
    PIN_SESSION_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Malformed $PIN_SESSION_TOKEN_HEADER"),
    WRAPPED_PRVK_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Malformed $RWSCA_WI_WRAPPED_PRVK_FIELD"),
}

const val TRY_COUNTER = "try_counter"
const val TRY_ALLOWED_AFTER = "try_allowed_after"

@Serializable
data class RwscaErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: RwscaErrorResponseCode,
    @Schema(description = "Human-readable error description")
    val description: String? = null,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = Instant.now().toString(),
    @SerialName(TRACE_ID)
    @Schema(description = "Trace ID for correlating logs and debugging")
    val traceId: String? = null,
    @SerialName(TRY_COUNTER)
    @Schema(description = "Remaining PIN verification attempts")
    val tryCounter: Int? = null,
    @SerialName(TRY_ALLOWED_AFTER)
    @Schema(description = "Earliest time when the next PIN attempt is allowed", format = "date-time")
    val tryAllowedAfter: String? = null,
)
