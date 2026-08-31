package de.eudiwallet.backend.rwsca

import java.security.interfaces.ECPublicKey

data class RwscaKeyInfo(
    val publicKey: ECPublicKey,
    val wrappedPrivateKey: RwscaBoundWrappedPrvk,
)
