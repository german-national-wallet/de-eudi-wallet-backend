package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.challengetoken.ChallengeVerificationException
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenVerificationException
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.media.Schema
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.dao.DataAccessResourceFailureException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.BindingResult
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.server.ServerWebInputException
import java.time.Instant
import java.time.LocalDateTime

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
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(
        DataAccessResourceFailureException::class,
    )
    fun handleServiceUnavailable(e: Exception): ResponseEntity<RwscaErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(RwscaErrorResponseCode.DB_UNAVAILABLE, e)
    }

    @ExceptionHandler(HsmException::class)
    fun handleHsmException(e: HsmException): ResponseEntity<RwscaErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(RwscaErrorResponseCode.HSM_UNAVAILABLE, e)
    }

    @ExceptionHandler(
        ServerWebInputException::class,
        MethodArgumentNotValidException::class,
    )
    fun handleBadRequest(e: Exception): ResponseEntity<RwscaErrorResponse> {
        val description =
            (e as? BindingResult)
                ?.fieldErrors
                ?.filterNot { it.isBindingFailure() }
                ?.mapNotNull { it.defaultMessage }
                ?.takeIf { it.isNotEmpty() }
                ?.joinToString("; ")
                ?: RwscaErrorResponseCode.BAD_REQUEST.description
        return createErrorResponseEntity(RwscaErrorResponseCode.BAD_REQUEST, e, description)
    }

    @ExceptionHandler(AccountNotFoundException::class)
    fun handleAccountNotFound(e: AccountNotFoundException) =
        createErrorResponseEntity(RwscaErrorResponseCode.ACCOUNT_NOT_FOUND, e)

    @ExceptionHandler(AccountRevokedException::class)
    fun handleAccountRevoked(e: AccountRevokedException) =
        createErrorResponseEntity(RwscaErrorResponseCode.ACCOUNT_REVOKED, e)

    @ExceptionHandler(KeyAlreadyRegisteredException::class)
    fun handleKeyAlreadyRegistered(e: KeyAlreadyRegisteredException): ResponseEntity<RwscaErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(RwscaErrorResponseCode.KEY_ALREADY_REGISTERED, e)
    }

    @ExceptionHandler(PinSessionTokenVerificationException::class)
    fun handlePinSessionTokenVerification(e: PinSessionTokenVerificationException) =
        createErrorResponseEntity(RwscaErrorResponseCode.PIN_SESSION_TOKEN_VERIFICATION_FAILURE, e)

    @ExceptionHandler(WrappedPrvkVerificationException::class)
    fun handleWrappedPrvkVerification(e: WrappedPrvkVerificationException) =
        createErrorResponseEntity(RwscaErrorResponseCode.WRAPPED_PRVK_VERIFICATION_FAILURE, e)

    @ExceptionHandler(ChallengeVerificationException::class)
    fun handleChallengeVerification(e: ChallengeVerificationException) =
        createErrorResponseEntity(RwscaErrorResponseCode.CHALLENGE_VERIFICATION_FAILURE, e)

    @ExceptionHandler(MdvmTokenVerificationException::class)
    fun handleMdvmTokenVerification(e: MdvmTokenVerificationException) =
        createErrorResponseEntity(RwscaErrorResponseCode.MDVM_TOKEN_VERIFICATION_FAILURE, e)

    @ExceptionHandler(PinAlreadyInitializedException::class)
    fun handlePinAlreadyInitialized(e: PinAlreadyInitializedException) =
        createErrorResponseEntity(RwscaErrorResponseCode.PIN_ALREADY_INITIALIZED, e)

    @ExceptionHandler(AccountLockedException::class)
    fun handleAccountLocked(e: AccountLockedException) =
        createErrorResponseEntity(RwscaErrorResponseCode.ACCOUNT_LOCKED, e)

    @ExceptionHandler(MalformedPinPubKeyException::class)
    fun handleMalformedKey(e: MalformedPinPubKeyException) =
        createErrorResponseEntity(RwscaErrorResponseCode.MALFORMED_PIN_PUB_KEY, e)

    @ExceptionHandler(MalformedDataHashException::class)
    fun handleMalformedDataHash(e: MalformedDataHashException) =
        createErrorResponseEntity(RwscaErrorResponseCode.MALFORMED_DATA_HASH, e)

    @ExceptionHandler(PinNotInitializedException::class)
    fun handlePinNotInitialized(e: PinNotInitializedException) =
        createErrorResponseEntity(RwscaErrorResponseCode.PIN_NOT_INITIALIZED, e)

    @ExceptionHandler(PinVerificationFailedException::class)
    fun handlePinVerificationFailed(e: PinVerificationFailedException) =
        createErrorResponseEntity(
            RwscaErrorResponseCode.PIN_VERIFICATION_FAILED,
            e,
            tryCounter = e.tryCounter,
            tryAllowedAfter = e.tryAllowedAfter.toString(),
        )

    @ExceptionHandler(PinRetryBlockedException::class)
    fun handlePinRetryBlocked(e: PinRetryBlockedException) =
        createErrorResponseEntity(
            RwscaErrorResponseCode.PIN_RETRY_BLOCKED,
            e,
            tryCounter = e.tryCounter,
            tryAllowedAfter = e.tryAllowedAfter.toString(),
        )

    @ExceptionHandler(SignatureVerificationException::class)
    fun handleSignatureVerificationException(e: SignatureVerificationException): ResponseEntity<RwscaErrorResponse> {
        log.warn(e) {}
        return createErrorResponseEntity(RwscaErrorResponseCode.SIGNATURE_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(Exception::class)
    fun handleInternalServerError(e: Exception): ResponseEntity<RwscaErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(RwscaErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    private fun createErrorResponseEntity(
        code: RwscaErrorResponseCode,
        cause: Throwable? = null,
        description: String = code.description,
        tryCounter: Int? = null,
        tryAllowedAfter: String? = null,
    ): ResponseEntity<RwscaErrorResponse> {
        telemetryService.traceErrorCode(code.name)
        telemetryService.traceException(cause)
        return ResponseEntity(
            RwscaErrorResponse(
                code = code,
                traceId = telemetryService.getCurrentTraceId(),
                description = description,
                tryCounter = tryCounter,
                tryAllowedAfter = tryAllowedAfter,
            ),
            code.httpStatus,
        )
    }
}

enum class RwscaErrorResponseCode(
    val httpStatus: HttpStatus,
    val description: String,
) {
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    HSM_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "HSM is temporarily unavailable, please retry later"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    MDVM_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Malformed MDVM token"),
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

const val TRACE_ID = "trace_id"
const val TRY_COUNTER = "try_counter"
const val TRY_ALLOWED_AFTER = "try_allowed_after"

@Serializable
data class RwscaErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: RwscaErrorResponseCode,
    @Schema(description = "Human-readable error description")
    val description: String? = null,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = LocalDateTime.now().toString(),
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
