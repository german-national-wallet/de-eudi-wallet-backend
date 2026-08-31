package de.eudiwallet.backend.mdvm

import com.fasterxml.jackson.annotation.JsonValue
import io.swagger.v3.oas.annotations.media.Schema
import org.springframework.core.convert.converter.Converter
import org.springframework.stereotype.Component

enum class SkipIntegrityChecks(
    val skipKeyAttestation: Boolean,
    vararg val aliases: String,
) {
    @Schema(description = "Allows to skip all integrity checks")
    ALL(true, "all", "true", "key-attestation"),

    @Schema(description = "No checks are skipped")
    NONE(false, "none", "false", "play-integrity"),
    ;

    @JsonValue
    fun value(): String = aliases.first()
}

@Component
class SkipIntegrityChecksConverter : Converter<String, SkipIntegrityChecks> {
    override fun convert(source: String): SkipIntegrityChecks =
        SkipIntegrityChecks.entries.find { source in it.aliases }
            ?: throw IllegalArgumentException("Unknown value: $source")
}
