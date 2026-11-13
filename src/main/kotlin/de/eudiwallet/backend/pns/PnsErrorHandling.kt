package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.error.ErrorMetrics
import de.eudiwallet.backend.shared.error.ErrorResponseCode
import de.eudiwallet.backend.shared.error.ServiceErrorHandler
import de.eudiwallet.backend.shared.error.TRACE_ID
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.media.Schema
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ControllerAdvice
import java.time.Instant

@ControllerAdvice(basePackages = ["de.eudiwallet.backend.pns"])
@ConditionalOnProperty(prefix = "pns", name = ["enabled"], havingValue = "true")
class PnsErrorHandler(
    telemetryService: TelemetryService,
    errorMetrics: ErrorMetrics,
) : ServiceErrorHandler<PnsErrorResponseCode, PnsErrorResponse>(
        telemetryService,
        errorMetrics,
        "pns",
        PnsErrorResponseCode.entries,
        PnsErrorResponse.serializer(),
    ) {
    override fun errorBody(
        code: PnsErrorResponseCode,
        description: String?,
        traceId: String?,
    ) = PnsErrorResponse(code = code, description = description ?: code.description, traceId = traceId)
}

enum class PnsErrorResponseCode(
    override val httpStatus: HttpStatus,
    val description: String,
) : ErrorResponseCode {
    DB_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "DB temporarily unavailable, please retry later"),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, "The request is malformed"),
    CHALLENGE_VERIFICATION_FAILURE(HttpStatus.BAD_REQUEST, "Challenge verification failed"),
    CHALLENGE_EXPIRED(HttpStatus.BAD_REQUEST, "Challenge expired"),
    MDVM_TOKEN_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "MDVM token verification failed"),
    MDVM_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "MDVM token expired"),
    SIGNATURE_VERIFICATION_FAILURE(HttpStatus.UNAUTHORIZED, "Signature verification failed"),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
}

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
