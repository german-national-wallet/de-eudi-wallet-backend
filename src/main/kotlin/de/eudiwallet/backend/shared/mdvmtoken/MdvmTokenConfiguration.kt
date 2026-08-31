package de.eudiwallet.backend.shared.mdvmtoken

import de.eudiwallet.backend.shared.crypto.readX509Cert
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.security.cert.X509Certificate

@ConfigurationProperties(prefix = "mdvm-token")
class MdvmTokenConfiguration(
    val issuer: String = "mdvm",
    val mdvmRootCertPath: Resource,
) {
    val mdvmRootCert: X509Certificate by lazy {
        readX509Cert(mdvmRootCertPath).apply { checkValidity() }
    }
}
