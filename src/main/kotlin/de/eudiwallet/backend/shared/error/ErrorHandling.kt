package de.eudiwallet.backend.shared.error

import de.eudiwallet.backend.shared.challengetoken.ChallengeExpiredException
import de.eudiwallet.backend.shared.challengetoken.ChallengeVerificationException
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.httpsignature.SignatureVerificationException
import de.eudiwallet.backend.shared.json.kotlinJson
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenExpiredException
import de.eudiwallet.backend.shared.mdvmtoken.MdvmTokenVerificationException
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.KSerializer
import org.springframework.dao.DataAccessException
import org.springframework.dao.DataAccessResourceFailureException
import org.springframework.dao.TransientDataAccessException
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.HttpStatusCode
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.web.server.firewall.ServerExchangeRejectedException
import org.springframework.validation.BindingResult
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebInputException

const val TRACE_ID = "trace_id"

interface ErrorResponseCode {
    val name: String
    val httpStatus: HttpStatus
}

enum class CommonError {
    DB_UNAVAILABLE,
    HSM_UNAVAILABLE,
    MESSAGING_UNAVAILABLE,
    BAD_REQUEST,
    CHALLENGE_VERIFICATION_FAILURE,
    CHALLENGE_EXPIRED,
    MDVM_TOKEN_VERIFICATION_FAILURE,
    MDVM_TOKEN_EXPIRED,
    SIGNATURE_VERIFICATION_FAILURE,
    INTERNAL_SERVER_ERROR,
}

fun <R : Any> TelemetryService.errorResponseEntity(
    code: ErrorResponseCode,
    cause: Throwable,
    status: HttpStatusCode = code.httpStatus,
    headers: HttpHeaders = HttpHeaders.EMPTY,
    body: (traceId: String?) -> R,
): ResponseEntity<R> {
    traceErrorCode(code.name)
    traceException(cause)
    return ResponseEntity
        .status(status)
        .headers(headers)
        .contentType(MediaType.APPLICATION_JSON)
        .body(body(getCurrentTraceId()))
}

@Suppress("TooManyFunctions")
abstract class ServiceErrorHandler<C : ErrorResponseCode, R : Any>(
    private val telemetryService: TelemetryService,
    private val errorMetrics: ErrorMetrics,
    private val module: String,
    codes: List<C>,
    private val bodySerializer: KSerializer<R>,
) {
    private val log = KotlinLogging.logger {}

    private val commonCodes: Map<CommonError, C> =
        CommonError.entries
            .mapNotNull { error -> codes.find { it.name == error.name }?.let { error to it } }
            .toMap()

    private val internalServerError =
        checkNotNull(commonCodes[CommonError.INTERNAL_SERVER_ERROR]) { "Error codes lack INTERNAL_SERVER_ERROR" }

    init {
        errorMetrics.register(module, codes)
    }

    protected abstract fun errorBody(
        code: C,
        description: String?,
        traceId: String?,
    ): R

    @ExceptionHandler(DataAccessResourceFailureException::class, TransientDataAccessException::class)
    fun handleDbUnavailable(e: DataAccessException) = commonErrorResponse(CommonError.DB_UNAVAILABLE, e)

    @ExceptionHandler(HsmException.GetSessionFailedException::class)
    fun handleHsmSessionUnavailable(e: HsmException.GetSessionFailedException) =
        commonErrorResponse(CommonError.HSM_UNAVAILABLE, e)

    @ExceptionHandler(MessagingUnavailableException::class)
    fun handleMessagingUnavailable(e: MessagingUnavailableException) =
        commonErrorResponse(CommonError.MESSAGING_UNAVAILABLE, e)

    @ExceptionHandler(SignatureVerificationException::class)
    fun handleSignatureVerification(e: SignatureVerificationException): ResponseEntity<String> {
        log.warn(e) {}
        return commonErrorResponse(CommonError.SIGNATURE_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(ChallengeExpiredException::class)
    fun handleChallengeExpired(e: ChallengeExpiredException): ResponseEntity<String> {
        log.warn(e) {}
        return commonErrorResponse(CommonError.CHALLENGE_EXPIRED, e)
    }

    @ExceptionHandler(ChallengeVerificationException::class)
    fun handleChallengeVerification(e: ChallengeVerificationException): ResponseEntity<String> {
        log.warn(e) {}
        return commonErrorResponse(CommonError.CHALLENGE_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(MdvmTokenExpiredException::class)
    fun handleMdvmTokenExpired(e: MdvmTokenExpiredException): ResponseEntity<String> {
        log.warn(e) {}
        return commonErrorResponse(CommonError.MDVM_TOKEN_EXPIRED, e)
    }

    @ExceptionHandler(MdvmTokenVerificationException::class)
    fun handleMdvmTokenVerification(e: MdvmTokenVerificationException): ResponseEntity<String> {
        log.warn(e) {}
        return commonErrorResponse(CommonError.MDVM_TOKEN_VERIFICATION_FAILURE, e)
    }

    @ExceptionHandler(
        ServerWebInputException::class,
        MethodArgumentNotValidException::class,
        ServerExchangeRejectedException::class,
    )
    fun handleBadRequest(e: Exception): ResponseEntity<String> {
        val description =
            (e as? BindingResult)
                ?.fieldErrors
                ?.filterNot { it.isBindingFailure }
                ?.mapNotNull { it.defaultMessage }
                ?.takeIf { it.isNotEmpty() }
                ?.joinToString("; ")
        return commonErrorResponse(CommonError.BAD_REQUEST, e, description)
    }

    @ExceptionHandler(ResponseStatusException::class)
    fun handleResponseStatus(e: ResponseStatusException): ResponseEntity<String> =
        if (e.statusCode.is4xxClientError) {
            commonErrorResponse(CommonError.BAD_REQUEST, e, status = e.statusCode, headers = e.headers)
        } else {
            errorResponse(internalServerError, e)
        }

    @ExceptionHandler(Exception::class)
    fun handleInternalServerError(e: Exception) = errorResponse(internalServerError, e)

    protected fun errorResponse(
        code: C,
        cause: Throwable,
        description: String? = null,
        status: HttpStatusCode = code.httpStatus,
        headers: HttpHeaders = HttpHeaders.EMPTY,
    ) = errorResponse(code, cause, status, headers) { traceId -> errorBody(code, description, traceId) }

    protected fun errorResponse(
        code: C,
        cause: Throwable,
        status: HttpStatusCode = code.httpStatus,
        headers: HttpHeaders = HttpHeaders.EMPTY,
        body: (traceId: String?) -> R,
    ): ResponseEntity<String> {
        if (status.is5xxServerError) log.error(cause) {}
        errorMetrics.countError(module, code, status)
        return telemetryService.errorResponseEntity(code, cause, status, headers) { traceId ->
            kotlinJson.encodeToString(bodySerializer, body(traceId))
        }
    }

    private fun commonErrorResponse(
        error: CommonError,
        cause: Throwable,
        description: String? = null,
        status: HttpStatusCode? = null,
        headers: HttpHeaders = HttpHeaders.EMPTY,
    ): ResponseEntity<String> {
        val code = commonCodes[error] ?: return errorResponse(internalServerError, cause, description)
        return errorResponse(code, cause, description, status ?: code.httpStatus, headers)
    }
}
