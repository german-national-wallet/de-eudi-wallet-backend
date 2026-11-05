package de.eudiwallet.backend.mdvm

import io.swagger.v3.oas.annotations.Hidden
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.Resource
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping

private const val ADMIN_PAGE_DIR = "mdvm/admin"
private const val ADMIN_INDEX = "index.html"

private const val ADMIN_PAGE_CSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"

private val MEDIA_TYPES =
    mapOf(
        "html" to MediaType.TEXT_HTML,
        "js" to MediaType("text", "javascript"),
        "css" to MediaType("text", "css"),
    )

@Hidden
@Controller
@RequestMapping("/v1/mdvm/admin")
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmAdminPage {
    @GetMapping(
        "/",
        "/device-classes.html",
        "/leaked-keys.html",
        "/admin.css",
        "/admin.js",
        "/device-classes.js",
        "/leaked-keys.js",
    )
    fun file(request: ServerHttpRequest): ResponseEntity<Resource> {
        val name = request.path.value().substringAfterLast('/').ifEmpty { ADMIN_INDEX }
        return ResponseEntity.ok()
            .contentType(MEDIA_TYPES.getValue(name.substringAfterLast('.')))
            .header("Content-Security-Policy", ADMIN_PAGE_CSP)
            .body(ClassPathResource("$ADMIN_PAGE_DIR/$name"))
    }
}
