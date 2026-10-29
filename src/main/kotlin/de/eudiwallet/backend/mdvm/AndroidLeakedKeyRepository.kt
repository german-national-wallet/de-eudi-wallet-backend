package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.android.AndroidRevocationList.RevocationReason
import at.asitplus.attestation.android.AndroidRevocationList.RevocationStatus
import kotlinx.coroutines.flow.Flow
import org.springframework.data.annotation.Id
import org.springframework.data.r2dbc.repository.Modifying
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import java.time.Instant

private const val ANDROID_LEAKED_KEY_TABLE = "mdvm_android_leaked_key"
private const val SERIAL_COLUMN = "serial"
private const val STATUS_COLUMN = "status"
private const val REASON_COLUMN = "reason"
private const val COMMENT_COLUMN = "comment"
private const val ADDED_BY_COLUMN = "added_by"
private const val CREATED_AT_COLUMN = "created_at"

private const val SERIAL_PARAM = "serial"
private const val STATUS_PARAM = "status"
private const val REASON_PARAM = "reason"
private const val COMMENT_PARAM = "comment"
private const val ADDED_BY_PARAM = "addedBy"

@Table(ANDROID_LEAKED_KEY_TABLE)
data class AndroidLeakedKeyEntity(
    @Id
    @Column(SERIAL_COLUMN)
    val serial: String,
    @Column(STATUS_COLUMN)
    val status: RevocationStatus,
    @Column(REASON_COLUMN)
    val reason: RevocationReason,
    @Column(COMMENT_COLUMN)
    val comment: String?,
    @Column(ADDED_BY_COLUMN)
    val addedBy: String,
    @Column(CREATED_AT_COLUMN)
    val createdAt: Instant,
)

@Repository
interface AndroidLeakedKeyRepository : CoroutineCrudRepository<AndroidLeakedKeyEntity, String> {
    fun findAllByOrderByCreatedAtAscSerialAsc(): Flow<AndroidLeakedKeyEntity>

    @Modifying
    @Query(
        """
        INSERT INTO $ANDROID_LEAKED_KEY_TABLE (
            $SERIAL_COLUMN, $STATUS_COLUMN, $REASON_COLUMN, $COMMENT_COLUMN, $ADDED_BY_COLUMN
        )
        VALUES (:$SERIAL_PARAM, :$STATUS_PARAM, :$REASON_PARAM, :$COMMENT_PARAM, :$ADDED_BY_PARAM)
        ON CONFLICT ($SERIAL_COLUMN) DO NOTHING
    """,
    )
    suspend fun insertIfAbsent(
        @Param(SERIAL_PARAM) serial: String,
        @Param(STATUS_PARAM) status: String,
        @Param(REASON_PARAM) reason: String,
        @Param(COMMENT_PARAM) comment: String?,
        @Param(ADDED_BY_PARAM) addedBy: String,
    ): Long

    @Modifying
    @Query("DELETE FROM $ANDROID_LEAKED_KEY_TABLE WHERE $SERIAL_COLUMN = :$SERIAL_PARAM")
    suspend fun deleteBySerial(
        @Param(SERIAL_PARAM) serial: String,
    ): Long
}
