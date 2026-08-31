package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec

sealed class HsmKeyRef {
    abstract val handle: Long

    data class EcPrivateKeyRef(
        override val handle: Long,
    ) : HsmKeyRef()

    class EcPublicKeyRef(
        override val handle: Long,
        val ecPoint: ByteArray,
    ) : HsmKeyRef()

    data class AesKeyRef(
        override val handle: Long,
    ) : HsmKeyRef()

    data class GenericSecretKeyRef(
        override val handle: Long,
    ) : HsmKeyRef()
}

sealed class HsmKeyClass<T : HsmKeyRef>(
    internal val objectClass: Long,
    internal val keyType: Long,
) {
    internal abstract fun ref(handle: Long): T

    object EcPrivate : HsmKeyClass<HsmKeyRef.EcPrivateKeyRef>(Ck.CKO_PRIVATE_KEY, Ck.CKK_EC) {
        override fun ref(handle: Long) = HsmKeyRef.EcPrivateKeyRef(handle)
    }

    object Aes : HsmKeyClass<HsmKeyRef.AesKeyRef>(Ck.CKO_SECRET_KEY, Ck.CKK_AES) {
        override fun ref(handle: Long) = HsmKeyRef.AesKeyRef(handle)
    }

    object GenericSecret : HsmKeyClass<HsmKeyRef.GenericSecretKeyRef>(Ck.CKO_SECRET_KEY, Ck.CKK_GENERIC_SECRET) {
        override fun ref(handle: Long) = HsmKeyRef.GenericSecretKeyRef(handle)
    }
}

internal data class HsmKeyPair(
    val publicKey: HsmKeyRef.EcPublicKeyRef,
    val privateKey: HsmKeyRef.EcPrivateKeyRef,
)

const val HSM_EC_CURVE = "secp256r1"

fun HsmKeyRef.EcPublicKeyRef.toECPublicKey(): ECPublicKey {
    val curveParams = CustomNamedCurves.getByName(HSM_EC_CURVE)
    val spec = ECNamedCurveSpec(HSM_EC_CURVE, curveParams.curve, curveParams.g, curveParams.n, curveParams.h)
    val pointBytes = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(ecPoint)).octets
    val point = ECPointUtil.decodePoint(spec.curve, pointBytes)
    val keyFactory = KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
    return keyFactory.generatePublic(ECPublicKeySpec(point, spec)) as ECPublicKey
}
