package de.eudiwallet.backend.shared.error

import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.http.HttpStatusCode
import org.springframework.stereotype.Component

@Component
class ErrorMetrics(
    meter: Meter,
) {
    private val errorCounter =
        meter.walletCounterBuilder("errors", "Error responses, by module, error code and HTTP status").build()

    fun register(
        module: String,
        codes: List<ErrorResponseCode>,
    ) = codes.forEach { errorCounter.add(0, attributes(module, it, it.httpStatus)) }

    fun countError(
        module: String,
        code: ErrorResponseCode,
        status: HttpStatusCode = code.httpStatus,
    ) = errorCounter.add(1, attributes(module, code, status))

    private fun attributes(
        module: String,
        code: ErrorResponseCode,
        status: HttpStatusCode,
    ) = Attributes.of(
        stringKey("module"),
        module,
        stringKey("code"),
        code.name,
        stringKey("status"),
        status.value().toString(),
    )
}
