package de.eudiwallet.backend.shared

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.runApplication
import java.security.Security

private val log = KotlinLogging.logger {}

fun registerCryptoProviders() {
    BOUNCY_CASTLE_PROVIDER
}

@Suppress("SpreadOperator")
inline fun <reified T : Any> runWalletService(
    args: Array<String>,
    profile: String,
) {
    registerCryptoProviders()
    logCryptoProviders()
    runApplication<T>(*args) {
        setAdditionalProfiles(profile)
    }
}

fun logCryptoProviders() {
    log.info {
        "Cryptography Providers: ${
            Security.getProviders().mapIndexed { index, provider -> "${index + 1}. ${provider.name}" }
        }"
    }
}
