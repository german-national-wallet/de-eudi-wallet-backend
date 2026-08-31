package de.eudiwallet.backend.shared.json

import io.r2dbc.spi.ConnectionFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions
import org.springframework.data.r2dbc.dialect.DialectResolver

@WritingConverter
class JsonObjectWriteConverter : Converter<JsonObject, String> {
    override fun convert(source: JsonObject): String = source.toString()
}

@ReadingConverter
class JsonObjectReadConverter : Converter<String, JsonObject> {
    override fun convert(source: String): JsonObject = Json.decodeFromString<JsonObject>(source)
}

@Configuration
class R2dbcConverterConfig {
    @Bean
    fun r2dbcCustomConversions(connectionFactory: ConnectionFactory): R2dbcCustomConversions {
        val dialect = DialectResolver.getDialect(connectionFactory)
        return R2dbcCustomConversions.of(
            dialect,
            listOf(
                JsonObjectWriteConverter(),
                JsonObjectReadConverter(),
            ),
        )
    }
}
