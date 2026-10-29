package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import de.eudiwallet.backend.shared.hsm.pkcs11.AttributeValues
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
        val id: HsmKeyId,
    ) : HsmKeyRef()

    data class GenericSecretKeyRef(
        override val handle: Long,
    ) : HsmKeyRef()
}

sealed class HsmKeyClass<T : HsmKeyRef>(
    internal val objectClass: Long,
    internal val keyType: Long,
    private val usages: Set<Long>,
    internal val strengthAttribute: Long,
) {
    internal abstract fun ref(
        handle: Long,
        id: HsmKeyId,
    ): T

    internal abstract fun strengthViolation(attributes: AttributeValues): String?

    internal fun violations(attributes: AttributeValues): List<String> =
        buildList {
            strengthViolation(attributes)?.let(::add)
            if (attributes.bool(Ck.CKA_SENSITIVE) != true) add("CKA_SENSITIVE is not true")
            if (attributes.bool(Ck.CKA_ALWAYS_SENSITIVE) != true) add("CKA_ALWAYS_SENSITIVE is not true")
            if (attributes.bool(Ck.CKA_EXTRACTABLE) != false) add("CKA_EXTRACTABLE is not false")
            if (attributes.bool(Ck.CKA_NEVER_EXTRACTABLE) != true) add("CKA_NEVER_EXTRACTABLE is not true")
            if (attributes.bool(Ck.CKA_DERIVE) == true) add("CKA_DERIVE is true")
            USAGE_FLAGS.forEach { (type, name) ->
                val expected = type in usages
                if ((attributes.bool(type) == true) != expected) add("$name is not $expected")
            }
        }

    internal fun warnings(attributes: AttributeValues): List<String> =
        buildList {
            if (attributes.bool(Ck.CKA_MODIFIABLE) != false) add("CKA_MODIFIABLE is not false")
        }

    object EcPrivate : HsmKeyClass<HsmKeyRef.EcPrivateKeyRef>(
        Ck.CKO_PRIVATE_KEY,
        Ck.CKK_EC,
        setOf(Ck.CKA_SIGN),
        Ck.CKA_EC_PARAMS,
    ) {
        override fun ref(
            handle: Long,
            id: HsmKeyId,
        ) = HsmKeyRef.EcPrivateKeyRef(handle)

        override fun strengthViolation(attributes: AttributeValues) =
            "CKA_EC_PARAMS is not $HSM_EC_CURVE".takeUnless {
                attributes.bytes(Ck.CKA_EC_PARAMS).contentEquals(HSM_EC_CURVE_OID_DER)
            }
    }

    object AesKeyWrap : HsmKeyClass<HsmKeyRef.AesKeyRef>(
        Ck.CKO_SECRET_KEY,
        Ck.CKK_AES,
        setOf(Ck.CKA_WRAP, Ck.CKA_UNWRAP),
        Ck.CKA_VALUE_LEN,
    ) {
        override fun ref(
            handle: Long,
            id: HsmKeyId,
        ) = HsmKeyRef.AesKeyRef(handle, id)

        override fun strengthViolation(attributes: AttributeValues) = aes256Violation(attributes)
    }

    object AesGcm : HsmKeyClass<HsmKeyRef.AesKeyRef>(
        Ck.CKO_SECRET_KEY,
        Ck.CKK_AES,
        setOf(Ck.CKA_ENCRYPT, Ck.CKA_DECRYPT),
        Ck.CKA_VALUE_LEN,
    ) {
        override fun ref(
            handle: Long,
            id: HsmKeyId,
        ) = HsmKeyRef.AesKeyRef(handle, id)

        override fun strengthViolation(attributes: AttributeValues) = aes256Violation(attributes)
    }

    object GenericSecret : HsmKeyClass<HsmKeyRef.GenericSecretKeyRef>(
        Ck.CKO_SECRET_KEY,
        Ck.CKK_GENERIC_SECRET,
        setOf(Ck.CKA_SIGN, Ck.CKA_VERIFY),
        Ck.CKA_VALUE_LEN,
    ) {
        override fun ref(
            handle: Long,
            id: HsmKeyId,
        ) = HsmKeyRef.GenericSecretKeyRef(handle)

        override fun strengthViolation(attributes: AttributeValues) =
            "CKA_VALUE_LEN is below $KEY_256_BYTES".takeUnless {
                (attributes.ulong(Ck.CKA_VALUE_LEN) ?: 0) >= KEY_256_BYTES
            }
    }

    internal companion object {
        val USAGE_FLAGS =
            listOf(
                Ck.CKA_ENCRYPT to "CKA_ENCRYPT",
                Ck.CKA_DECRYPT to "CKA_DECRYPT",
                Ck.CKA_SIGN to "CKA_SIGN",
                Ck.CKA_VERIFY to "CKA_VERIFY",
                Ck.CKA_WRAP to "CKA_WRAP",
                Ck.CKA_UNWRAP to "CKA_UNWRAP",
            )

        val PROFILE_ATTRIBUTES =
            USAGE_FLAGS.map { it.first }.toLongArray() +
                longArrayOf(
                    Ck.CKA_SENSITIVE,
                    Ck.CKA_EXTRACTABLE,
                    Ck.CKA_DERIVE,
                    Ck.CKA_MODIFIABLE,
                    Ck.CKA_ALWAYS_SENSITIVE,
                    Ck.CKA_NEVER_EXTRACTABLE,
                )

        private fun aes256Violation(attributes: AttributeValues) =
            "CKA_VALUE_LEN is not $KEY_256_BYTES".takeUnless {
                attributes.ulong(Ck.CKA_VALUE_LEN) == KEY_256_BYTES
            }
    }
}

private const val KEY_256_BYTES = 32L

internal data class HsmKeyPair(
    val publicKey: HsmKeyRef.EcPublicKeyRef,
    val privateKey: HsmKeyRef.EcPrivateKeyRef,
)

const val HSM_EC_CURVE = "secp256r1"
internal val HSM_EC_CURVE_OID_DER: ByteArray = CustomNamedCurves.getOID(HSM_EC_CURVE).encoded

fun HsmKeyRef.EcPublicKeyRef.toECPublicKey(): ECPublicKey {
    val curveParams = CustomNamedCurves.getByName(HSM_EC_CURVE)
    val spec = ECNamedCurveSpec(HSM_EC_CURVE, curveParams.curve, curveParams.g, curveParams.n, curveParams.h)
    val pointBytes = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(ecPoint)).octets
    val point = ECPointUtil.decodePoint(spec.curve, pointBytes)
    val keyFactory = KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
    return keyFactory.generatePublic(ECPublicKeySpec(point, spec)) as ECPublicKey
}
