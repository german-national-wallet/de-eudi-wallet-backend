package de.eudiwallet.backend.shared.json

import kotlinx.serialization.json.Json
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.json.KotlinSerializationJsonHttpMessageConverter

val kotlinJson =
    Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        explicitNulls = false
    }

@Configuration
class SerializationConfig {
    @Bean
    fun json(): Json = kotlinJson

    @Bean
    fun kotlinSerializationJsonHttpMessageConverter(json: Json): KotlinSerializationJsonHttpMessageConverter =
        KotlinSerializationJsonHttpMessageConverter(json)
}

inline fun <reified T : Any> T.toJson() = kotlinJson.encodeToString(this)

inline fun <reified T : Any> String.fromJson() = kotlinJson.decodeFromString<T>(this)

inline fun <reified T : Any> T.toPostgresJson(): io.r2dbc.postgresql.codec.Json =
    io.r2dbc.postgresql.codec.Json.of(this.toJson())

inline fun <reified T : Any> io.r2dbc.postgresql.codec.Json.fromPostgresJson() = this.asString().fromJson<T>()
