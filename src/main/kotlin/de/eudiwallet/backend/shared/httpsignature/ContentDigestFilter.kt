package de.eudiwallet.backend.shared.httpsignature

import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.crypto.toSha256
import de.eudiwallet.backend.shared.json.kotlinJson
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.serialization.Serializable
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.DataBufferLimitException
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.core.io.buffer.DefaultDataBufferFactory
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpRequestDecorator
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.LocalDateTime

const val MAXIMUM_CONTENT_SIZE = 1024 * 1024
const val CONTENT_DIGEST_PREFIX = "sha-256=:"
const val CONTENT_DIGEST_SUFFIX = ":"
const val EMPTY_STRING = ""

@Component
class ContentDigestFilter(
    private val telemetryService: TelemetryService,
) : WebFilter {
    override fun filter(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> {
        val passedDigest = exchange.request.headers.getFirst(CONTENT_DIGEST_HEADER) ?: return chain.filter(exchange)
        val emptyBuffer =
            DefaultDataBufferFactory().wrap(ByteArray(0))

        return DataBufferUtils.join(exchange.request.body, MAXIMUM_CONTENT_SIZE)
            .defaultIfEmpty(emptyBuffer)
            .flatMap { dataBuffer ->
                if (dataBuffer.readableByteCount() == 0) {
                    val emptyBodyDigest =
                        CONTENT_DIGEST_PREFIX + EMPTY_STRING.toSha256().toBase64() + CONTENT_DIGEST_SUFFIX
                    if (passedDigest.isBlank() || emptyBodyDigest == passedDigest) {
                        chain.filter(exchange)
                    } else {
                        errorResponse(exchange, ContentDigestErrorResponseCode.WRONG_CONTENT_DIGEST)
                    }
                } else {
                    val bodyBytes = ByteArray(dataBuffer.readableByteCount())
                    dataBuffer.read(bodyBytes)
                    DataBufferUtils.release(dataBuffer)

                    val computedDigest = CONTENT_DIGEST_PREFIX + bodyBytes.toSha256().toBase64() + CONTENT_DIGEST_SUFFIX
                    if (computedDigest != passedDigest) {
                        errorResponse(exchange, ContentDigestErrorResponseCode.WRONG_CONTENT_DIGEST)
                    } else {
                        val decorated =
                            object : ServerHttpRequestDecorator(exchange.request) {
                                override fun getBody(): Flux<DataBuffer> =
                                    Flux.just(DefaultDataBufferFactory().wrap(bodyBytes))
                            }
                        val mutated: ServerWebExchange = exchange.mutate().request(decorated).build()
                        chain.filter(mutated)
                    }
                }
            }
            .onErrorResume(DataBufferLimitException::class.java) {
                errorResponse(exchange, ContentDigestErrorResponseCode.CONTENT_LENGTH_EXCEEDED)
            }
    }

    private fun errorResponse(
        exchange: ServerWebExchange,
        errorCode: ContentDigestErrorResponseCode,
    ): Mono<Void> {
        telemetryService.traceErrorCode(errorCode.name)
        val responseBody =
            kotlinJson.encodeToString(
                ContentDigestErrorResponse(
                    code = errorCode,
                    description = errorCode.description,
                    traceId = telemetryService.getCurrentTraceId(),
                ),
            )
        val buffer = exchange.response.bufferFactory().wrap(responseBody.encodeToByteArray())
        exchange.response.statusCode = errorCode.httpStatus
        return exchange.response.writeWith(Mono.just(buffer))
    }

    @Serializable
    data class ContentDigestErrorResponse(
        val code: ContentDigestErrorResponseCode,
        val description: String,
        val timestamp: String = LocalDateTime.now().toString(),
        val traceId: String?,
    )

    enum class ContentDigestErrorResponseCode(
        val httpStatus: HttpStatus,
        val description: String,
    ) {
        WRONG_CONTENT_DIGEST(HttpStatus.UNAUTHORIZED, "Content-Digest header doesn't correspond to the request body"),
        CONTENT_LENGTH_EXCEEDED(HttpStatus.BAD_REQUEST, "Request body is too long"),
    }
}
