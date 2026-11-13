package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.hsm.EncryptedData
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import org.springframework.data.r2dbc.repository.Modifying
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.UUID

private const val RWSCA_ACCOUNT_TABLE = "rwsca_account"
private const val ID_COLUMN = "id"
private const val RWSCA_ACCOUNT_ID_COLUMN = "rwsca_account_id"
private const val WI_MDVM_AUTH_PUBK_DER_COLUMN = "wi_mdvm_auth_pubk_der"
private const val WI_RWSCA_PIN_PUBK_KEY_ID_COLUMN = "wi_rwsca_pin_pubk_key_id"
private const val WI_RWSCA_PIN_PUBK_IV_COLUMN = "wi_rwsca_pin_pubk_iv"
private const val WI_RWSCA_PIN_PUBK_CT_COLUMN = "wi_rwsca_pin_pubk_ct"
private const val WI_RWSCA_PIN_PUBK_TAG_COLUMN = "wi_rwsca_pin_pubk_tag"
private const val RWSCA_PIN_TRY_COUNTER_COLUMN = "rwsca_pin_try_counter"
private const val RWSCA_PIN_TRY_FAILED_AT_COLUMN = "rwsca_pin_try_failed_at"
private const val REVOKED_AT_COLUMN = "revoked_at"
private const val MDVM_WI_ID_COLUMN = "mdvm_wi_id"

@Table(RWSCA_ACCOUNT_TABLE)
class RwscaAccountEntity(
    @Column(ID_COLUMN)
    val id: UUID,
    @Column(RWSCA_ACCOUNT_ID_COLUMN)
    val rwscaAccountId: UUID,
    @Column(WI_MDVM_AUTH_PUBK_DER_COLUMN)
    val wiMdvmAuthPubkDer: ByteArray,
    @Column(WI_RWSCA_PIN_PUBK_KEY_ID_COLUMN)
    val wiRwscaPinPubkKeyId: String? = null,
    @Column(WI_RWSCA_PIN_PUBK_IV_COLUMN)
    val wiRwscaPinPubkIv: ByteArray? = null,
    @Column(WI_RWSCA_PIN_PUBK_CT_COLUMN)
    val wiRwscaPinPubkCt: ByteArray? = null,
    @Column(WI_RWSCA_PIN_PUBK_TAG_COLUMN)
    val wiRwscaPinPubkTag: ByteArray? = null,
    @Column(RWSCA_PIN_TRY_COUNTER_COLUMN)
    val pinTryCounter: Int?,
    @Column(RWSCA_PIN_TRY_FAILED_AT_COLUMN)
    val pinTryFailedAt: Instant?,
    @Column(REVOKED_AT_COLUMN)
    val revokedAt: Instant? = null,
    @Column(MDVM_WI_ID_COLUMN)
    val mdvmWiId: UUID,
)

@Repository
interface RwscaAccountRepository : CoroutineCrudRepository<RwscaAccountEntity, UUID> {
    @Query("SELECT * FROM $RWSCA_ACCOUNT_TABLE WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId")
    suspend fun findByRwscaAccountId(rwscaAccountId: UUID): RwscaAccountEntity?

    @Query("SELECT * FROM $RWSCA_ACCOUNT_TABLE WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId FOR UPDATE")
    suspend fun findByRwscaAccountIdForUpdate(rwscaAccountId: UUID): RwscaAccountEntity?

    @Query(
        """
            INSERT INTO $RWSCA_ACCOUNT_TABLE ($ID_COLUMN, $RWSCA_ACCOUNT_ID_COLUMN, $WI_MDVM_AUTH_PUBK_DER_COLUMN, $MDVM_WI_ID_COLUMN)
            VALUES (:#{T(java.util.UUID).randomUUID()},:rwscaAccountId, :wiMdvmAuthPubkDer, :mdvmWiId)
            RETURNING *
        """,
    )
    suspend fun create(
        rwscaAccountId: UUID,
        wiMdvmAuthPubkDer: ByteArray,
        mdvmWiId: UUID,
    ): RwscaAccountEntity

    @Modifying
    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE SET $REVOKED_AT_COLUMN = now()
            WHERE $MDVM_WI_ID_COLUMN = :mdvmWiId AND $REVOKED_AT_COLUMN IS NULL
        """,
    )
    suspend fun revokeByMdvmWiId(mdvmWiId: UUID): Long

    suspend fun existsByMdvmWiIdAndRevokedAtIsNotNull(mdvmWiId: UUID): Boolean

    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE
            SET $WI_RWSCA_PIN_PUBK_KEY_ID_COLUMN = :pinPubkKeyId, $WI_RWSCA_PIN_PUBK_IV_COLUMN = :pinPubkIv,
                $WI_RWSCA_PIN_PUBK_CT_COLUMN = :pinPubkCt, $WI_RWSCA_PIN_PUBK_TAG_COLUMN = :pinPubkTag,
                $RWSCA_PIN_TRY_COUNTER_COLUMN = :pinTryCounter
            WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId AND $WI_RWSCA_PIN_PUBK_KEY_ID_COLUMN IS NULL
            RETURNING *
        """,
    )
    suspend fun initializePin(
        rwscaAccountId: UUID,
        pinPubkKeyId: String,
        pinPubkIv: ByteArray,
        pinPubkCt: ByteArray,
        pinPubkTag: ByteArray,
        pinTryCounter: Int,
    ): RwscaAccountEntity?

    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE
            SET $RWSCA_PIN_TRY_COUNTER_COLUMN = :newPinTryCounter, $RWSCA_PIN_TRY_FAILED_AT_COLUMN = :newPinTryFailedAt
            WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId and $RWSCA_PIN_TRY_COUNTER_COLUMN = :existingPinTryCounter and $RWSCA_PIN_TRY_COUNTER_COLUMN > 0 and $WI_RWSCA_PIN_PUBK_KEY_ID_COLUMN IS NOT NULL
            RETURNING *
        """,
    )
    suspend fun updatePinTryCounterAndFailedAt(
        rwscaAccountId: UUID,
        existingPinTryCounter: Int,
        newPinTryCounter: Int,
        newPinTryFailedAt: Instant?,
    ): RwscaAccountEntity?

    @Query("DELETE FROM $RWSCA_ACCOUNT_TABLE WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId")
    suspend fun deleteByRwscaAccountId(rwscaAccountId: UUID)
}

internal fun RwscaAccountEntity.toAccount(): RwscaAccount {
    if (wiRwscaPinPubkKeyId == null) {
        return toAccountWithoutPin()
    }

    return toAccountWithPin()
}

internal fun RwscaAccountEntity.toAccountWithoutPin(): RwscaAccount.WithoutPin =
    RwscaAccount.WithoutPin(
        rwscaAccountId = RwscaAccountId(rwscaAccountId),
    )

internal fun RwscaAccountEntity.toAccountWithPin(): RwscaAccount.WithPin {
    requireNotNull(wiRwscaPinPubkKeyId) { "wiRwscaPinPubkKeyId is null for rwscaAccountId $rwscaAccountId" }
    val tryCounter = requireNotNull(pinTryCounter) { "pinTryCounter is null for rwscaAccountId $rwscaAccountId" }
    return RwscaAccount.WithPin(
        rwscaAccountId = RwscaAccountId(rwscaAccountId),
        pinTryCounter = tryCounter,
        pinTryFailedAt = pinTryFailedAt,
    )
}

internal fun RwscaAccountEntity.toEncryptedPinPubkOrNull(): EncryptedPinPubk? =
    wiRwscaPinPubkKeyId?.let { keyId ->
        EncryptedPinPubk(
            HsmKeyId(keyId),
            EncryptedData(
                cipherText = requireNotNull(wiRwscaPinPubkCt) { "wiRwscaPinPubkCt is null for $rwscaAccountId" },
                authTag = requireNotNull(wiRwscaPinPubkTag) { "wiRwscaPinPubkTag is null for $rwscaAccountId" },
                iv = requireNotNull(wiRwscaPinPubkIv) { "wiRwscaPinPubkIv is null for $rwscaAccountId" },
            ),
        )
    }

internal fun RwscaAccountEntity.verifyAuthPubKey(authPubKey: ECPublicKey): RwscaAccountEntity {
    if (wiMdvmAuthPubkDer.ecPublicKeyFromX509().jwkThumbprint() != authPubKey.jwkThumbprint()) {
        throw AccountNotFoundException()
    }
    return this
}

internal fun RwscaAccountEntity.requireNotRevoked(): RwscaAccountEntity {
    if (revokedAt != null) {
        throw AccountRevokedException()
    }
    return this
}

internal fun RwscaAccountEntity.requireNotLocked(): RwscaAccountEntity {
    if (pinTryCounter != null && pinTryCounter == 0) {
        throw AccountLockedException()
    }
    return this
}
