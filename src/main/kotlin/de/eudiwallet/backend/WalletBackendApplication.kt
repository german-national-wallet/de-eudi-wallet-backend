package de.eudiwallet.backend

import de.eudiwallet.backend.shared.runWalletService
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan

@SpringBootApplication
@ConfigurationPropertiesScan
@Suppress("UtilityClassWithPublicConstructor")
class WalletBackendApplication

fun main(args: Array<String>) {
    runWalletService<WalletBackendApplication>(args, "combined")
}
