package de.eudiwallet.backend.statuslist

import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.CacheControl
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.InvalidMediaTypeException
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

val STATUS_LIST_JWT_MEDIA_TYPE: MediaType = MediaType("application", "statuslist+jwt")

class NotAcceptableStatusListMediaTypeException : RuntimeException("Not acceptable")

class MalformedAcceptHeaderException(
    cause: Throwable,
) : RuntimeException("Malformed Accept header", cause)

@Serializable
data class StatusListAggregationResponse(
    @SerialName("status_lists")
    val statusLists: List<String>,
)

@RestController
@Tag(name = "status-list", description = "Token Status List")
@ConditionalOnProperty(prefix = "statuslist", name = ["enabled"], havingValue = "true")
class StatusListApi(
    private val config: StatusListConfiguration,
    private val statusListService: StatusListService,
    private val tokenBuilder: StatusListTokenBuilder,
    private val telemetryService: TelemetryService,
) {
    @Operation(summary = "Fetch a signed Status List Token")
    @GetMapping("/status-lists/{segment}/{poolId}/{listId}")
    suspend fun token(
        @PathVariable segment: String,
        @PathVariable poolId: String,
        @PathVariable listId: String,
        @RequestHeader(HttpHeaders.ACCEPT, required = false) accept: String?,
        @RequestHeader(HttpHeaders.IF_NONE_MATCH, required = false) ifNoneMatch: String?,
    ): ResponseEntity<ByteArray> =
        telemetryService.withSpan("StatusListApi.token") {
            requireJwtAcceptable(accept)
            val id = listId.toUuidOrNull() ?: throw NoSuchListException()

            val head = statusListService.findListHead(id) ?: throw NoSuchListException()
            val pool = config.poolById(head.pool) ?: throw NoSuchListException()
            if (segment != config.pathSegment || poolId != pool.id) throw NoSuchListException()
            if (matches(ifNoneMatch, etag(head.version))) {
                ResponseEntity.status(HttpStatus.NOT_MODIFIED)
                    .eTag(etag(head.version))
                    .cacheControl(CacheControl.maxAge(pool.ttl))
                    .build()
            } else {
                val list = statusListService.findList(id) ?: throw NoSuchListException()
                ResponseEntity.ok()
                    .eTag(etag(list.version))
                    .cacheControl(CacheControl.maxAge(pool.ttl))
                    .contentType(STATUS_LIST_JWT_MEDIA_TYPE)
                    .body(tokenBuilder.build(list, pool).toByteArray())
            }
        }

    @Operation(summary = "List the Status List Token URIs for a pool")
    @GetMapping("/status-lists/{segment}/{poolId}/aggregation")
    suspend fun aggregation(
        @PathVariable segment: String,
        @PathVariable poolId: String,
    ): ResponseEntity<StatusListAggregationResponse> =
        telemetryService.withSpan("StatusListApi.aggregation") {
            val pool = config.poolById(poolId) ?: throw NoSuchListException()
            if (segment != config.pathSegment) throw NoSuchListException()
            ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(pool.ttl))
                .contentType(MediaType.APPLICATION_JSON)
                .body(StatusListAggregationResponse(statusListService.listUris(pool.id)))
        }

    private fun requireJwtAcceptable(accept: String?) {
        if (accept.isNullOrBlank()) return
        val requested =
            try {
                MediaType.parseMediaTypes(accept)
            } catch (e: InvalidMediaTypeException) {
                throw MalformedAcceptHeaderException(e)
            }
        if (requested.none { it.includes(STATUS_LIST_JWT_MEDIA_TYPE) }) {
            throw NotAcceptableStatusListMediaTypeException()
        }
    }

    private fun etag(version: Int): String = "W/\"$version\""

    private fun matches(
        ifNoneMatch: String?,
        etag: String,
    ): Boolean =
        ifNoneMatch
            ?.split(",")
            ?.map { it.trim() }
            ?.any { it == etag || it == "*" }
            ?: false

    private fun String.toUuidOrNull(): UUID? = runCatching { UUID.fromString(this) }.getOrNull()
}
