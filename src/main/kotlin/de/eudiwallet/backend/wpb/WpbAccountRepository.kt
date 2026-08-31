package de.eudiwallet.backend.wpb

import kotlinx.coroutines.flow.Flow
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

private const val WPB_ACCOUNT_TABLE = "wpb_account"
private const val ID_COLUMN = "id"
private const val WPB_ACCOUNT_ID_COLUMN = "wpb_account_id"
private const val WI_MDVM_AUTH_PUBK_DER_COLUMN = "wi_mdvm_auth_pubk_der"
private const val WPB_WI_REVOCATION_CODE_HASH_COLUMN = "wpb_wi_revocation_hash"
private const val WI_HANDLE_COLUMN = "wi_handle"
private const val REVOKED_AT_COLUMN = "revoked_at"
private const val MDVM_WI_ID_COLUMN = "mdvm_wi_id"

@Table(WPB_ACCOUNT_TABLE)
class WpbAccountEntity(
    @Column(ID_COLUMN)
    val id: UUID,
    @Column(WPB_ACCOUNT_ID_COLUMN)
    val wpbAccountId: UUID,
    @Column(WI_MDVM_AUTH_PUBK_DER_COLUMN)
    val wiMdvmAuthPubkDer: ByteArray,
    @Column(WPB_WI_REVOCATION_CODE_HASH_COLUMN)
    val wpbWiRevocationCodeHash: ByteArray?,
    @Column(WI_HANDLE_COLUMN)
    val wiHandle: String? = null,
    @Column(REVOKED_AT_COLUMN)
    val revokedAt: Instant? = null,
    @Column(MDVM_WI_ID_COLUMN)
    val mdvmWiId: UUID? = null,
)

@Repository
interface WpbAccountRepository : CoroutineCrudRepository<WpbAccountEntity, UUID> {
    @Query("SELECT * FROM $WPB_ACCOUNT_TABLE WHERE $WPB_ACCOUNT_ID_COLUMN = :wpbAccountId")
    suspend fun findByWpbAccountId(wpbAccountId: UUID): WpbAccountEntity?

    @Query("SELECT * FROM $WPB_ACCOUNT_TABLE WHERE $WPB_WI_REVOCATION_CODE_HASH_COLUMN = :revocationHash")
    suspend fun findByRevocationHash(revocationHash: ByteArray): WpbAccountEntity?

    @Query("SELECT * FROM $WPB_ACCOUNT_TABLE WHERE $WPB_ACCOUNT_ID_COLUMN = :wpbAccountId FOR SHARE")
    suspend fun findByWpbAccountIdForShare(wpbAccountId: UUID): WpbAccountEntity?

    @Query("SELECT * FROM $WPB_ACCOUNT_TABLE WHERE $WPB_ACCOUNT_ID_COLUMN = :wpbAccountId FOR UPDATE")
    suspend fun findByWpbAccountIdForUpdate(wpbAccountId: UUID): WpbAccountEntity?

    @Query("DELETE FROM $WPB_ACCOUNT_TABLE WHERE $WPB_ACCOUNT_ID_COLUMN = :wpbAccountId")
    suspend fun deleteByWpbAccountId(wpbAccountId: UUID)

    @Query(
        """
        UPDATE $WPB_ACCOUNT_TABLE SET $REVOKED_AT_COLUMN = now()
        WHERE $WI_HANDLE_COLUMN = :wiHandle AND $REVOKED_AT_COLUMN IS NULL
        RETURNING $WPB_ACCOUNT_ID_COLUMN
        """,
    )
    fun revokeByWiHandleReturningIds(wiHandle: String): Flow<UUID>
}
