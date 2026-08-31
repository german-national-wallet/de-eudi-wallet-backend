package de.eudiwallet.backend.shared

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "deployment")
class DeploymentProperties(
    environment: String?,
) {
    private val log = KotlinLogging.logger {}

    val environment: String =
        requireNotNull(environment?.takeIf { it.isNotBlank() }) {
            "deployment.environment must be set (e.g. via the DEPLOYMENT_ENVIRONMENT environment variable)"
        }

    init {
        log.info { "Deployment environment: $environment" }
    }
}
