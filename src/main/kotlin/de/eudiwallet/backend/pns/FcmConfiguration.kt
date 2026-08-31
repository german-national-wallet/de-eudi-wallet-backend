package de.eudiwallet.backend.pns

import com.google.auth.oauth2.GoogleCredentials
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.client.WebClient
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

private const val FCM_HOST = "fcm.googleapis.com"
private const val FCM_BASE_URL = "https://$FCM_HOST"

@ConfigurationProperties(prefix = "pns.fcm")
class FcmConfiguration(
    val projectId: String = "",
    val serviceAccountKeyPath: String = "",
    val baseUrl: String = FCM_BASE_URL,
)

@Configuration
@ConditionalOnProperty(prefix = "pns.fcm", name = ["enabled"], havingValue = "true")
class FcmClientConfiguration {
    @Bean
    fun fcmCredentials(config: FcmConfiguration): GoogleCredentials {
        require(config.serviceAccountKeyPath.isNotBlank()) {
            "pns.fcm.service-account-key-path must be set when pns.fcm.enabled=true"
        }
        return Files.newInputStream(Path.of(config.serviceAccountKeyPath)).use { GoogleCredentials.fromStream(it) }
    }

    @Bean
    fun mppPushClient(
        config: FcmConfiguration,
        credentials: GoogleCredentials,
        json: Json,
        webClientBuilder: WebClient.Builder,
    ): MppPushClient {
        require(config.projectId.isNotBlank()) { "pns.fcm.project-id must be set when pns.fcm.enabled=true" }
        require(config.baseUrl.startsWith("https://")) { "pns.fcm.base-url must be https, got ${config.baseUrl}" }
        require(URI(config.baseUrl).host == FCM_HOST) {
            "pns.fcm.base-url must point at $FCM_HOST, got ${config.baseUrl}"
        }
        return FcmPushClient(credentials, config.projectId, config.baseUrl, json, webClientBuilder)
    }
}
