package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.crypto.toCanonicalP256
import de.eudiwallet.backend.shared.hsm.AES_TAG_BYTES
import de.eudiwallet.backend.shared.hsm.EncryptedData
import de.eudiwallet.backend.shared.hsm.HsmException
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.IV_BYTES
import de.eudiwallet.backend.shared.keyrollover.KeySource
import de.eudiwallet.backend.shared.keyrollover.SymmetricKeySet
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Component
import java.security.interfaces.ECPublicKey

data class EncryptedPinPubk(
    val keyId: HsmKeyId,
    val data: EncryptedData,
)

@Component
class PinPubkCipher(
    @Qualifier("rwscdAccountAeadSymLineage")
    private val lineage: KeySource<SymmetricKeySet>,
    private val hsmProvider: HsmProvider,
    private val rwscaMetrics: RwscaMetrics,
) {
    suspend fun encrypt(
        rwscaAccountId: RwscaAccountId,
        wiMdvmAuthPubk: ECPublicKey,
        pinPubk: ECPublicKey,
    ): EncryptedPinPubk {
        val keyId = lineage.current().primaryId
        val plainText = pinPubk.toCanonicalP256().encoded
        val data =
            hsmProvider.use("Encrypt PIN public key") { hsm ->
                hsm.encrypt(hsm.getKey(keyId, HsmKeyClass.AesGcm), plainText, aad(rwscaAccountId, wiMdvmAuthPubk))
            }
        return EncryptedPinPubk(keyId, data)
    }

    suspend fun decrypt(
        rwscaAccountId: RwscaAccountId,
        wiMdvmAuthPubk: ECPublicKey,
        record: EncryptedPinPubk,
    ): ECPublicKey {
        if (lineage.current().validKeys.none { it.keyId == record.keyId }) {
            rwscaMetrics.countPinPubkRejected(PinPubkRejection.KEY_EXPIRED)
            throw AccountExpiredException(rwscaAccountId, record.keyId)
        }
        if (record.data.iv.size != IV_BYTES || record.data.authTag.size != AES_TAG_BYTES) {
            rejectIntegrity(rwscaAccountId, record.keyId, null)
        }
        val plainText =
            try {
                hsmProvider.use("Decrypt PIN public key") { hsm ->
                    hsm.decrypt(
                        hsm.getKey(record.keyId, HsmKeyClass.AesGcm),
                        record.data,
                        aad(rwscaAccountId, wiMdvmAuthPubk),
                    )
                }
            } catch (e: HsmException.TagMismatchException) {
                rejectIntegrity(rwscaAccountId, record.keyId, e)
            }
        return plainText.ecPublicKeyFromX509()
    }

    private fun rejectIntegrity(
        rwscaAccountId: RwscaAccountId,
        keyId: HsmKeyId,
        cause: Throwable?,
    ): Nothing {
        rwscaMetrics.countPinPubkRejected(PinPubkRejection.INTEGRITY_FAILURE)
        throw AccountIntegrityException(rwscaAccountId, keyId, cause)
    }

    private fun aad(
        rwscaAccountId: RwscaAccountId,
        wiMdvmAuthPubk: ECPublicKey,
    ): ByteArray = rwscaAccountId.id.toString().toByteArray(Charsets.UTF_8) + wiMdvmAuthPubk.jwkThumbprint().decode()
}
