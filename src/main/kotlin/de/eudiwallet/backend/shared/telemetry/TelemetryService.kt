package de.eudiwallet.backend.shared.telemetry

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.trace.Span
import io.opentelemetry.api.trace.Tracer
import io.opentelemetry.context.Context
import io.opentelemetry.extension.kotlin.asContextElement
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Component

private const val ERROR_CODE_ATTR = "error.code"

@Component
class TelemetryService(
    private val openTelemetry: OpenTelemetry,
) {
    val tracer: Tracer get() = openTelemetry.getTracer("de.eudiwallet.backend")

    @Suppress("TooGenericExceptionCaught")
    suspend fun <T> withSpan(
        spanName: String,
        block: suspend () -> T,
    ): T {
        val span = tracer.spanBuilder(spanName).startSpan()
        try {
            return withContext(span.asContextElement()) {
                block()
            }
        } catch (ex: Throwable) {
            span.recordException(ex)
            throw ex
        } finally {
            span.end()
        }
    }

    @Suppress("TooGenericExceptionCaught")
    fun <T> withSpanSync(
        spanName: String,
        block: () -> T,
    ): T {
        val span = tracer.spanBuilder(spanName).startSpan()
        return try {
            span.makeCurrent().use {
                block()
            }
        } catch (ex: Throwable) {
            span.recordException(ex)
            throw ex
        } finally {
            span.end()
        }
    }

    private fun currentSpan(): Span? =
        try {
            Span.current()
        } catch (_: Exception) {
            null
        }

    fun getCurrentTraceId(): String? {
        val span = currentSpan() ?: return null
        val spanContext = span.spanContext
        return if (spanContext.isValid) {
            spanContext.traceId
        } else {
            null
        }
    }

    fun traceErrorCode(errorCode: String?) {
        errorCode?.let { currentSpan()?.setAttribute(ERROR_CODE_ATTR, it) }
    }

    fun traceException(cause: Throwable?) {
        cause?.let { currentSpan()?.recordException(cause) }
    }

    fun traceAttributes(attributes: Map<String, String>) {
        if (attributes.isEmpty()) return
        val span = currentSpan() ?: return
        attributes.forEach { (key, value) -> span.setAttribute(key, value) }
    }
}

fun <T> runBlockingWithTelemetry(
    dispatcher: CoroutineDispatcher,
    block: suspend CoroutineScope.() -> T,
): T {
    val context = Context.current()
    return context.makeCurrent().use {
        runBlocking(context.asContextElement()) {
            withContext(dispatcher) {
                block()
            }
        }
    }
}
