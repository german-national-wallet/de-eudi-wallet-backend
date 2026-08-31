package de.eudiwallet.backend

import de.eudiwallet.backend.shared.runWalletService
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan

@SpringBootApplication(
    scanBasePackages = [
        "de.eudiwallet.backend.wpb",
        "de.eudiwallet.backend.statuslist",
        "de.eudiwallet.backend.shared",
        "de.eudiwallet.backend.openapi",
    ],
)
@ConfigurationPropertiesScan(
    basePackages = [
        "de.eudiwallet.backend.wpb",
        "de.eudiwallet.backend.statuslist",
        "de.eudiwallet.backend.shared",
    ],
)
@Suppress("UtilityClassWithPublicConstructor")
class WpbApplication

fun main(args: Array<String>) {
    runWalletService<WpbApplication>(args, "wpb")
}
