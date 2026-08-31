package de.eudiwallet.backend.shared.hsm

import com.nimbusds.jose.crypto.impl.ECDSA
import de.eudiwallet.backend.shared.crypto.toSha256
import de.eudiwallet.backend.shared.hsm.pkcs11.Attr
import de.eudiwallet.backend.shared.hsm.pkcs11.AttributeValues
import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import de.eudiwallet.backend.shared.hsm.pkcs11.Mechanism
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11Exception
import de.eudiwallet.backend.shared.hsm.pkcs11.Template
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import org.bouncycastle.crypto.ec.CustomNamedCurves
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.ZoneId

@JvmInline
value class HsmWrappedPrvk(
    val bytes: ByteArray,
)

@JvmInline
value class EcdsaSignature(
    val bytes: ByteArray,
) {
    fun toDer(): ByteArray = ECDSA.transcodeSignatureToDER(bytes)
}

data class WrappedKeyPair(
    val publicKey: ECPublicKey,
    val wrappedPrivateKey: HsmWrappedPrvk,
)

const val AES_TAG_BITS = 128L
const val AES_TAG_BYTES = AES_TAG_BITS.toInt() / 8
const val IV_BYTES = 12

internal const val HSM_KEY_ID_ATTR = "hsm.key_id"
internal const val HSM_KEY_LABEL_ATTR = "hsm.key_label"

data class EncryptedData(
    val cipherText: ByteArray,
    val authTag: ByteArray,
    val iv: ByteArray,
) {
    companion object {
        fun fromCipherData(
            data: ByteArray,
            iv: ByteArray,
        ): EncryptedData {
            if (data.size < AES_TAG_BYTES) {
                throw HsmException.EncryptionFailedException(
                    IllegalStateException("Not enough encrypted data to contain authentication tag"),
                )
            }
            return EncryptedData(
                data.copyOfRange(0, data.size - AES_TAG_BYTES),
                data.copyOfRange(data.size - AES_TAG_BYTES, data.size),
                iv,
            )
        }
    }
}

@Suppress("TooManyFunctions")
class HsmSession internal constructor(
    private val pkcs11: Pkcs11,
    val sessionHandle: Long,
    private val wrappingMechanism: Long,
    private val telemetryService: TelemetryService,
    private val onRelease: (HsmSession) -> Unit,
) {
    private val log = KotlinLogging.logger {}

    private class CachedKey(
        val ref: HsmKeyRef,
        val id: HsmKeyId,
        val label: String?,
    )

    private val keyCache = HashMap<Pair<HsmKeyId, HsmKeyClass<*>>, CachedKey>()

    private val secureRandom = SecureRandom()

    fun release() = onRelease(this)

    fun isAlive() =
        try {
            telemetryService.withSpanSync("session.sessionInfo") {
                pkcs11.sessionInfo(sessionHandle)
            }
            true
        } catch (_: Pkcs11Exception) {
            false
        }

    @Suppress("TooGenericExceptionCaught")
    fun createWrappedKeyPair(masterKeyId: HsmKeyId): WrappedKeyPair {
        val masterKey = getKey(masterKeyId, HsmKeyClass.Aes)
        val keyPair = createKey()
        try {
            val publicKey =
                try {
                    keyPair.publicKey.toECPublicKey()
                } catch (e: Exception) {
                    throw HsmException.KeyCreationFailedException(e)
                }
            return WrappedKeyPair(publicKey, wrapWithMasterKey(keyPair.privateKey, masterKey))
        } finally {
            destroyKeysQuietly(keyPair.privateKey, keyPair.publicKey)
        }
    }

    fun signWithWrappedKey(
        wrappedPrivateKey: HsmWrappedPrvk,
        masterKeyId: HsmKeyId,
        sha256Digest: ByteArray,
    ): EcdsaSignature {
        val masterKey = getKey(masterKeyId, HsmKeyClass.Aes)
        val privateKey = unwrapWithMasterKey(wrappedPrivateKey, masterKey)
        try {
            return signDigest(privateKey, sha256Digest)
        } finally {
            destroyKeysQuietly(privateKey)
        }
    }

    fun signEcdsaSha256(
        key: HsmKeyRef.EcPrivateKeyRef,
        data: ByteArray,
    ): EcdsaSignature = signDigest(key, data.toSha256())

    @Suppress("TooGenericExceptionCaught")
    private fun createKey(): HsmKeyPair =
        try {
            val publicKeyTemplate =
                listOf(
                    Attr(Ck.CKA_CLASS, Ck.CKO_PUBLIC_KEY),
                    Attr(Ck.CKA_KEY_TYPE, Ck.CKK_EC),
                    Attr(Ck.CKA_VERIFY, true),
                    Attr(Ck.CKA_EC_PARAMS, CustomNamedCurves.getOID(HSM_EC_CURVE).encoded),
                )
            val privateKeyTemplate =
                listOf(
                    Attr(Ck.CKA_CLASS, Ck.CKO_PRIVATE_KEY),
                    Attr(Ck.CKA_KEY_TYPE, Ck.CKK_EC),
                    Attr(Ck.CKA_SIGN, true),
                    Attr(Ck.CKA_SENSITIVE, true),
                    Attr(Ck.CKA_EXTRACTABLE, true),
                )
            val (publicKeyHandle, privateKeyHandle) =
                telemetryService.withSpanSync("session.generateKeyPair") {
                    pkcs11.generateKeyPair(sessionHandle, Mechanism.EcKeyPairGen, publicKeyTemplate, privateKeyTemplate)
                }
            try {
                val ecPoint =
                    telemetryService.withSpanSync("session.getAttributeValue (EC point)") {
                        pkcs11.getAttributeValues(sessionHandle, publicKeyHandle, longArrayOf(Ck.CKA_EC_POINT))
                    }.bytes(Ck.CKA_EC_POINT)
                if (ecPoint == null || ecPoint.isEmpty()) {
                    throw HsmException.KeyCreationFailedException(
                        IllegalStateException("HSM returned no EC point for the generated public key"),
                    )
                }
                HsmKeyPair(
                    HsmKeyRef.EcPublicKeyRef(publicKeyHandle, ecPoint),
                    HsmKeyRef.EcPrivateKeyRef(privateKeyHandle),
                )
            } catch (e: Exception) {
                destroyHandlesQuietly(longArrayOf(publicKeyHandle, privateKeyHandle))
                throw e
            }
        } catch (e: Pkcs11Exception) {
            throw HsmException.KeyCreationFailedException(e)
        }

    private fun destroyKeysQuietly(vararg keys: HsmKeyRef) =
        destroyHandlesQuietly(LongArray(keys.size) { keys[it].handle })

    @Suppress("TooGenericExceptionCaught")
    private fun destroyHandlesQuietly(handles: LongArray) =
        handles.forEach { handle ->
            try {
                telemetryService.withSpanSync("session.destroyObject") {
                    pkcs11.destroyObject(sessionHandle, handle)
                }
            } catch (destroyEx: Exception) {
                log.error(destroyEx) { "Failed to destroy key handle $handle" }
            }
        }

    private fun wrapWithMasterKey(
        privateKey: HsmKeyRef.EcPrivateKeyRef,
        masterKey: HsmKeyRef.AesKeyRef,
    ): HsmWrappedPrvk =
        try {
            val bytes =
                telemetryService.withSpanSync("session.wrapKey") {
                    pkcs11.wrapKey(
                        sessionHandle,
                        Mechanism.Plain(wrappingMechanism),
                        masterKey.handle,
                        privateKey.handle,
                    )
                }
            HsmWrappedPrvk(bytes)
        } catch (e: Pkcs11Exception) {
            throw HsmException.KeyWrappingFailedException(e)
        }

    private fun unwrapWithMasterKey(
        hsmWrappedPrvk: HsmWrappedPrvk,
        masterKey: HsmKeyRef.AesKeyRef,
    ): HsmKeyRef.EcPrivateKeyRef =
        try {
            val keyTemplate =
                listOf(
                    Attr(Ck.CKA_CLASS, Ck.CKO_PRIVATE_KEY),
                    Attr(Ck.CKA_KEY_TYPE, Ck.CKK_EC),
                    Attr(Ck.CKA_SIGN, true),
                    Attr(Ck.CKA_SENSITIVE, true),
                    Attr(Ck.CKA_EXTRACTABLE, false),
                )
            val handle =
                telemetryService.withSpanSync("session.unwrapKey") {
                    pkcs11.unwrapKey(
                        sessionHandle,
                        Mechanism.Plain(wrappingMechanism),
                        masterKey.handle,
                        hsmWrappedPrvk.bytes,
                        keyTemplate,
                    )
                }
            HsmKeyRef.EcPrivateKeyRef(handle)
        } catch (e: Pkcs11Exception) {
            throw HsmException.KeyUnwrappingFailedException(e)
        }

    private fun signDigest(
        key: HsmKeyRef.EcPrivateKeyRef,
        digest: ByteArray,
    ): EcdsaSignature =
        try {
            telemetryService.withSpanSync("session.sign (ECDSA)") {
                EcdsaSignature(pkcs11.sign(sessionHandle, Mechanism.Ecdsa, key.handle, digest))
            }
        } catch (e: Pkcs11Exception) {
            throw HsmException.SigningFailedException(e)
        }

    fun signHMAC(
        key: HsmKeyRef.GenericSecretKeyRef,
        data: ByteArray,
    ): ByteArray =
        try {
            telemetryService.withSpanSync("session.sign (generic secret)") {
                pkcs11.sign(sessionHandle, Mechanism.Sha256Hmac, key.handle, data)
            }
        } catch (e: Pkcs11Exception) {
            throw HsmException.SigningFailedException(e)
        }

    fun verifyHMAC(
        key: HsmKeyRef.GenericSecretKeyRef,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean =
        try {
            telemetryService.withSpanSync("session.verify") {
                pkcs11.verify(sessionHandle, Mechanism.Sha256Hmac, key.handle, data, signature)
            }
            true
        } catch (e: Pkcs11Exception) {
            when (e.rv) {
                Ck.CKR_SIGNATURE_INVALID,
                Ck.CKR_SIGNATURE_LEN_RANGE,
                -> false

                else -> throw HsmException.SignatureVerificationException(e)
            }
        }

    fun encrypt(
        key: HsmKeyRef.AesKeyRef,
        data: ByteArray?,
        additionalData: ByteArray?,
    ): EncryptedData =
        try {
            val iv = ByteArray(IV_BYTES).also { secureRandom.nextBytes(it) }
            val cipherData =
                telemetryService.withSpanSync("session.encrypt") {
                    pkcs11.encrypt(
                        sessionHandle,
                        Mechanism.AesGcm(iv, additionalData, AES_TAG_BITS),
                        key.handle,
                        data ?: ByteArray(0),
                    )
                }
            if (iv.all { it == 0.toByte() }) {
                throw HsmException.EncryptionFailedException(IllegalStateException("HSM wrote back an all-zero IV"))
            }
            EncryptedData.fromCipherData(cipherData, iv)
        } catch (e: Pkcs11Exception) {
            throw HsmException.EncryptionFailedException(e)
        }

    fun decrypt(
        key: HsmKeyRef.AesKeyRef,
        cipherData: EncryptedData,
        additionalData: ByteArray?,
    ): ByteArray =
        try {
            telemetryService.withSpanSync("session.decrypt") {
                pkcs11.decrypt(
                    sessionHandle,
                    Mechanism.AesGcm(cipherData.iv, additionalData, AES_TAG_BITS),
                    key.handle,
                    cipherData.cipherText + cipherData.authTag,
                )
            }
        } catch (e: Pkcs11Exception) {
            throw HsmException.DecryptionFailedException(e)
        }

    fun <T : HsmKeyRef> getKey(
        keyId: HsmKeyId,
        keyClass: HsmKeyClass<T>,
    ): T {
        val cached = keyCache[keyId to keyClass] ?: lookupKey(keyId, keyClass)
        telemetryService.traceAttributes(
            buildMap {
                put(HSM_KEY_ID_ATTR, cached.id.value)
                cached.label?.takeIf { it.isNotBlank() }?.let { put(HSM_KEY_LABEL_ATTR, it) }
            },
        )
        @Suppress("UNCHECKED_CAST")
        return cached.ref as T
    }

    private fun <T : HsmKeyRef> lookupKey(
        keyId: HsmKeyId,
        keyClass: HsmKeyClass<T>,
    ): CachedKey {
        val template = keyClass.template() + Attr(Ck.CKA_ID, keyId.byteArrayValue())
        val handle =
            try {
                telemetryService.withSpanSync("session.findObjects (by ID)") {
                    pkcs11.findObjects(sessionHandle, template, limit = 1)
                }
            } catch (ex: Pkcs11Exception) {
                throw HsmException.KeyLookupFailure(keyId.value, ex)
            }.firstOrNull() ?: throw HsmException.KeyNotFoundException(keyId.value)
        val attributes = readAttributes(handle, keyId.value, Ck.CKA_ID, Ck.CKA_LABEL)
        val key =
            CachedKey(
                keyClass.ref(handle),
                attributes.bytes(Ck.CKA_ID)?.let { HsmKeyId.from(it) } ?: keyId,
                attributes.string(Ck.CKA_LABEL),
            )
        keyCache[keyId to keyClass] = key
        return key
    }

    fun <T : HsmKeyRef> findKeysByPrefix(
        keyPrefix: String,
        validityDate: Instant,
        keyClass: HsmKeyClass<T>,
    ): List<HsmKey> {
        val template = keyClass.template() + Attr(Ck.CKA_TOKEN, true)
        val handles =
            try {
                telemetryService.withSpanSync("session.findObjects (by prefix)") {
                    pkcs11.findObjects(sessionHandle, template)
                }
            } catch (ex: Pkcs11Exception) {
                throw HsmException.KeyLookupFailure(keyPrefix, ex)
            }
        val validityDay = validityDate.atZone(ZoneId.systemDefault()).toLocalDate()
        return handles
            .map { readAttributes(it, keyPrefix, Ck.CKA_ID, Ck.CKA_LABEL, Ck.CKA_START_DATE, Ck.CKA_END_DATE) }
            .filter { it.string(Ck.CKA_LABEL).orEmpty().startsWith(keyPrefix) }
            .mapNotNull { HsmKey.from(it) }
            .filter { !it.endDate.isBefore(validityDay) }
    }

    private fun readAttributes(
        handle: Long,
        key: String,
        vararg types: Long,
    ): AttributeValues =
        try {
            telemetryService.withSpanSync("session.getAttributeValue") {
                pkcs11.getAttributeValues(sessionHandle, handle, types)
            }
        } catch (ex: Pkcs11Exception) {
            throw HsmException.KeyLookupFailure(key, ex)
        }

    private fun HsmKeyClass<*>.template(): Template =
        listOf(Attr(Ck.CKA_CLASS, objectClass), Attr(Ck.CKA_KEY_TYPE, keyType))
}
