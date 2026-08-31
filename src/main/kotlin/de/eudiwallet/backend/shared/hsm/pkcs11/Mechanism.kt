package de.eudiwallet.backend.shared.hsm.pkcs11

internal sealed class Mechanism(
    val id: Long,
) {
    object EcKeyPairGen : Mechanism(Ck.CKM_EC_KEY_PAIR_GEN)

    object Ecdsa : Mechanism(Ck.CKM_ECDSA)

    object Sha256Hmac : Mechanism(Ck.CKM_SHA256_HMAC)

    class AesGcm(
        val iv: ByteArray,
        val aad: ByteArray?,
        val tagBits: Long,
    ) : Mechanism(Ck.CKM_AES_GCM)

    data class Plain(
        val mechanismId: Long,
    ) : Mechanism(mechanismId)
}
