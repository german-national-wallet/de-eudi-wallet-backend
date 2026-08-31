package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.challengetoken.ChallengeVerificationException
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
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.server.ServerWebInputException
import java.time.Instant

@ControllerAdvice(basePackages = ["de.eudiwallet.backend.pns"])
@ConditionalOnProperty(prefix = "pns", name = ["enabled"], havingValue = "true")
class PnsErrorHandler(
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(DataAccessResourceFailureException::class)
    fun handleServiceUnavailable(e: Exception): ResponseEntity<PnsErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(PnsErrorResponseCode.DB_UNAVAILABLE, e)
    }

    @ExceptionHandler(SignatureVerificationException::class)
    fun handleSignatureVerification(e: SignatureVerificationException) =
        createErrorResponseEntity(PnsErrorResponseCode.SIGNATURE_VERIFICATION_FAILURE, e)

    @ExceptionHandler(ChallengeVerificationException::class)
    fun handleChallengeVerification(e: ChallengeVerificationException) =
        createErrorResponseEntity(PnsErrorResponseCode.CHALLENGE_VERIFICATION_FAILURE, e)

    @ExceptionHandler(MdvmTokenVerificationException::class)
    fun handleMdvmTokenVerification(e: MdvmTokenVerificationException) =
        createErrorResponseEntity(PnsErrorResponseCode.MDVM_TOKEN_VERIFICATION_FAILURE, e)

    @ExceptionHandler(
        ServerWebInputException::class,
        MethodArgumentNotValidException::class,
    )
    fun handleBadRequest(e: Exception) = createErrorResponseEntity(PnsErrorResponseCode.BAD_REQUEST, e)

    @ExceptionHandler(Exception::class)
    fun handleInternalServerError(e: Exception): ResponseEntity<PnsErrorResponse> {
        log.error(e) {}
        return createErrorResponseEntity(PnsErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    private fun createErrorResponseEntity(
        code: PnsErrorResponseCode,
        cause: Throwable,
        description: String = code.description,
    ): ResponseEntity<PnsErrorResponse> {
        telemetryService.traceErrorCode(code.name)
        telemetryService.traceException(cause)
        return ResponseEntity
            .status(code.httpStatus)
            .contentType(MediaType.APPLICATION_JSON)
            .body(
                PnsErrorResponse(
                    code = code,
                    traceId = telemetryService.getCurrentTraceId(),
                    description = description,
                ),
            )
    }
}

enum class PnsErrorResponseCode(
    val httpStatus: HttpStatus,
    val description: String,
) {
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    MDVM_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "MDVM token verification failed"),
    SIGNATURE_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Signature verification failed"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
}

const val TRACE_ID = "trace_id"

@Serializable
data class PnsErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: PnsErrorResponseCode,
    @Schema(description = "Human-readable error description")
    val description: String? = null,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = Instant.now().toString(),
    @SerialName(TRACE_ID)
    @Schema(description = "Trace ID for correlating logs and debugging")
    val traceId: String?,
)
