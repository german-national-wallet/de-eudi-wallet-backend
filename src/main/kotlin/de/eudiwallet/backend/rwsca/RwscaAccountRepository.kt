package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import org.springframework.data.r2dbc.repository.Modifying
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

private const val RWSCA_ACCOUNT_TABLE = "rwsca_account"
private const val ID_COLUMN = "id"
private const val RWSCA_ACCOUNT_ID_COLUMN = "rwsca_account_id"
private const val WI_MDVM_AUTH_PUBK_DER_COLUMN = "wi_mdvm_auth_pubk_der"
private const val WI_RWSCA_PIN_PUBK_DER_COLUMN = "wi_rwsca_pin_pubk_der"
private const val RWSCA_PIN_TRY_COUNTER_COLUMN = "rwsca_pin_try_counter"
private const val RWSCA_PIN_TRY_FAILED_AT_COLUMN = "rwsca_pin_try_failed_at"
private const val WI_HANDLE_COLUMN = "wi_handle"
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
    @Column(WI_RWSCA_PIN_PUBK_DER_COLUMN)
    val wiRwscaPinPubkDer: ByteArray?,
    @Column(RWSCA_PIN_TRY_COUNTER_COLUMN)
    val pinTryCounter: Int?,
    @Column(RWSCA_PIN_TRY_FAILED_AT_COLUMN)
    val pinTryFailedAt: Instant?,
    @Column(WI_HANDLE_COLUMN)
    val wiHandle: String? = null,
    @Column(REVOKED_AT_COLUMN)
    val revokedAt: Instant? = null,
    @Column(MDVM_WI_ID_COLUMN)
    val mdvmWiId: UUID? = null,
)

@Repository
interface RwscaAccountRepository : CoroutineCrudRepository<RwscaAccountEntity, UUID> {
    @Query("SELECT * FROM $RWSCA_ACCOUNT_TABLE WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId")
    suspend fun findByRwscaAccountId(rwscaAccountId: UUID): RwscaAccountEntity?

    @Query("SELECT * FROM $RWSCA_ACCOUNT_TABLE WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId FOR UPDATE")
    suspend fun findByRwscaAccountIdForUpdate(rwscaAccountId: UUID): RwscaAccountEntity?

    @Query(
        """
            INSERT INTO $RWSCA_ACCOUNT_TABLE ($ID_COLUMN, $RWSCA_ACCOUNT_ID_COLUMN, $WI_MDVM_AUTH_PUBK_DER_COLUMN, $WI_RWSCA_PIN_PUBK_DER_COLUMN, $WI_HANDLE_COLUMN, $MDVM_WI_ID_COLUMN)
            VALUES (:#{T(java.util.UUID).randomUUID()},:rwscaAccountId, :wiMdvmAuthPubkDer, null, :wiHandle, :mdvmWiId)
            RETURNING *
        """,
    )
    suspend fun create(
        rwscaAccountId: UUID,
        wiMdvmAuthPubkDer: ByteArray,
        wiHandle: String,
        mdvmWiId: UUID,
    ): RwscaAccountEntity

    @Modifying
    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE SET $REVOKED_AT_COLUMN = now()
            WHERE $WI_HANDLE_COLUMN = :wiHandle AND $REVOKED_AT_COLUMN IS NULL
        """,
    )
    suspend fun revokeByWiHandle(wiHandle: String): Long

    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE
            SET $WI_RWSCA_PIN_PUBK_DER_COLUMN = :pinPubKeyDer, $RWSCA_PIN_TRY_COUNTER_COLUMN = :pinTryCounter
            WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId AND $WI_RWSCA_PIN_PUBK_DER_COLUMN IS NULL
            RETURNING *
        """,
    )
    suspend fun initializePin(
        rwscaAccountId: UUID,
        pinPubKeyDer: ByteArray,
        pinTryCounter: Int,
    ): RwscaAccountEntity?

    @Query(
        """
            UPDATE $RWSCA_ACCOUNT_TABLE
            SET $RWSCA_PIN_TRY_COUNTER_COLUMN = :newPinTryCounter, $RWSCA_PIN_TRY_FAILED_AT_COLUMN = :newPinTryFailedAt
            WHERE $RWSCA_ACCOUNT_ID_COLUMN = :rwscaAccountId and $RWSCA_PIN_TRY_COUNTER_COLUMN = :existingPinTryCounter and $RWSCA_PIN_TRY_COUNTER_COLUMN > 0 and $WI_RWSCA_PIN_PUBK_DER_COLUMN IS NOT NULL
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
    if (wiRwscaPinPubkDer == null) {
        return toAccountWithoutPin()
    }

    return toAccountWithPin()
}

internal fun RwscaAccountEntity.toAccountWithoutPin(): RwscaAccount.WithoutPin =
    RwscaAccount.WithoutPin(
        rwscaAccountId = RwscaAccountId(rwscaAccountId),
    )

internal fun RwscaAccountEntity.toAccountWithPin(): RwscaAccount.WithPin {
    val pubkDer = requireNotNull(wiRwscaPinPubkDer) { "wiRwscaPinPubkDer is null for rwscaAccountId $rwscaAccountId" }
    val tryCounter = requireNotNull(pinTryCounter) { "pinTryCounter is null for rwscaAccountId $rwscaAccountId" }
    return RwscaAccount.WithPin(
        rwscaAccountId = RwscaAccountId(rwscaAccountId),
        pinPubKey = pubkDer.ecPublicKeyFromX509(),
        pinTryCounter = tryCounter,
        pinTryFailedAt = pinTryFailedAt,
    )
}
