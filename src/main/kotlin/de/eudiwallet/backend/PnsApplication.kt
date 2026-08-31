package de.eudiwallet.backend

import de.eudiwallet.backend.shared.runWalletService
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan

@SpringBootApplication(
    scanBasePackages = [
        "de.eudiwallet.backend.pns",
        "de.eudiwallet.backend.shared",
        "de.eudiwallet.backend.openapi",
    ],
)
@ConfigurationPropertiesScan(
    basePackages = [
        "de.eudiwallet.backend.pns",
        "de.eudiwallet.backend.shared",
    ],
)
@Suppress("UtilityClassWithPublicConstructor")
class PnsApplication

fun main(args: Array<String>) {
    runWalletService<PnsApplication>(args, "pns")
}
