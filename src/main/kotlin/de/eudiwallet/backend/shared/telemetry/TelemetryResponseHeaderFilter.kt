package de.eudiwallet.backend.shared.telemetry

import org.springframework.boot.info.GitProperties
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

const val X_SERVICE_VERSION = "X-Service-Version"
const val X_TRACE_ID = "X-Trace-Id"

@Component
class TelemetryResponseHeaderFilter(
    private val gitProperties: GitProperties,
    private val telemetryService: TelemetryService,
) : WebFilter {
    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        telemetryService.getCurrentTraceId().let { traceId ->
            exchange.response.headers.add(X_SERVICE_VERSION, gitProperties.shortCommitId)
            exchange.response.headers.add(X_TRACE_ID, traceId)
        }
        return chain.filter(exchange)
    }
}
