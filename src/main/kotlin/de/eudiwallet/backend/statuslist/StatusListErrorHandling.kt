package de.eudiwallet.backend.statuslist

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
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import java.time.Instant

@ControllerAdvice(basePackages = ["de.eudiwallet.backend.statuslist"])
@ConditionalOnProperty(prefix = "statuslist", name = ["enabled"], havingValue = "true")
class StatusListErrorHandler(
    private val telemetryService: TelemetryService,
) {
    private val log = KotlinLogging.logger {}

    @ExceptionHandler(NoSuchListException::class)
    fun handleNoSuchList(e: NoSuchListException) =
        createErrorResponseEntity(StatusListErrorResponseCode.NO_SUCH_LIST, e)

    @ExceptionHandler(NotAcceptableStatusListMediaTypeException::class)
    fun handleNotAcceptable(e: NotAcceptableStatusListMediaTypeException) =
        createErrorResponseEntity(StatusListErrorResponseCode.NOT_ACCEPTABLE, e)

    @ExceptionHandler(MalformedAcceptHeaderException::class)
    fun handleMalformedAcceptHeader(e: MalformedAcceptHeaderException) =
        createErrorResponseEntity(StatusListErrorResponseCode.MALFORMED_ACCEPT_HEADER, e)

    @ExceptionHandler(DataAccessResourceFailureException::class)
    fun handleServiceUnavailable(e: DataAccessResourceFailureException): ResponseEntity<StatusListErrorResponse> {
        log.error(e) { "DB unavailable serving status list" }
        return createErrorResponseEntity(StatusListErrorResponseCode.DB_UNAVAILABLE, e)
    }

    @ExceptionHandler(Exception::class)
    fun handleInternalServerError(e: Exception): ResponseEntity<StatusListErrorResponse> {
        log.error(e) { "Status-list internal error" }
        return createErrorResponseEntity(StatusListErrorResponseCode.INTERNAL_SERVER_ERROR, e)
    }

    private fun createErrorResponseEntity(
        code: StatusListErrorResponseCode,
        cause: Throwable,
    ): ResponseEntity<StatusListErrorResponse> {
        telemetryService.traceErrorCode(code.name)
        telemetryService.traceException(cause)
        return ResponseEntity
            .status(code.httpStatus)
            .contentType(MediaType.APPLICATION_JSON)
            .body(
                StatusListErrorResponse(
                    code = code,
                    traceId = telemetryService.getCurrentTraceId(),
                ),
            )
    }
}

enum class StatusListErrorResponseCode(
    val httpStatus: HttpStatus,
) {
    NO_SUCH_LIST(HttpStatus.NOT_FOUND),
    MALFORMED_ACCEPT_HEADER(HttpStatus.BAD_REQUEST),
    NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE),
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR),
}

const val TRACE_ID = "trace_id"

@Serializable
data class StatusListErrorResponse(
    @Schema(description = "Error code indicating the type of error")
    val code: StatusListErrorResponseCode,
    @Schema(description = "Timestamp of the error occurrence", format = "date-time")
    val timestamp: String = Instant.now().toString(),
    @SerialName(TRACE_ID)
    @Schema(description = "Trace ID for correlating logs and debugging")
    val traceId: String? = null,
)
