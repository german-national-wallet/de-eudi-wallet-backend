package de.eudiwallet.backend.mdvm

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

private const val ADMIN_PATH_PREFIX = "/v1/mdvm/admin/"
private const val SEC_FETCH_SITE = "Sec-Fetch-Site"
private const val SAME_ORIGIN = "same-origin"
private val SAFE_METHODS = setOf(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS)

@Component
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmAdminSameOriginFilter : WebFilter {
    private val log = KotlinLogging.logger {}

    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        val request = exchange.request
        val site = request.headers.getFirst(SEC_FETCH_SITE)
        val crossOrigin = site != null && site != SAME_ORIGIN
        if (crossOrigin && request.method !in SAFE_METHODS && request.path.value().startsWith(ADMIN_PATH_PREFIX)) {
            log.warn { "Rejected ${request.method} ${request.path} from $SEC_FETCH_SITE $site" }
            exchange.response.statusCode = HttpStatus.FORBIDDEN
            return exchange.response.setComplete()
        }
        return chain.filter(exchange)
    }
}
