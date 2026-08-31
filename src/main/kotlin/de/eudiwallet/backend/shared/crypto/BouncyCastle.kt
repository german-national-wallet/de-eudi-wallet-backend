package de.eudiwallet.backend.shared.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

val BOUNCY_CASTLE_PROVIDER =
    BouncyCastleProvider().also {
        Security.removeProvider(it.name)
        Security.insertProviderAt(it, 1)
    }
