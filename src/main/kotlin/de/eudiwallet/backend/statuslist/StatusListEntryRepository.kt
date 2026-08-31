package de.eudiwallet.backend.statuslist

import kotlinx.coroutines.flow.Flow
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

const val STATUS_LIST_ENTRY_TABLE = "status_list_entry"

@Table(STATUS_LIST_ENTRY_TABLE)
class StatusListEntryEntity(
    @Column("id")
    val id: UUID,
    @Column("account_id")
    val accountId: UUID,
    @Column("list_id")
    val listId: UUID,
    @Column("idx")
    val idx: Int,
    @Column("exp")
    val exp: Instant,
    @Column("created")
    val created: Instant,
    @Column("client_instance_id")
    val clientInstanceId: UUID?,
)

@Repository
interface StatusListEntryRepository : CoroutineCrudRepository<StatusListEntryEntity, UUID> {
    @Query(
        """
        INSERT INTO $STATUS_LIST_ENTRY_TABLE (account_id, list_id, idx, exp, client_instance_id)
        VALUES (:accountId, :listId, :idx, :exp, :clientInstanceId)
        """,
    )
    suspend fun insert(
        accountId: UUID,
        listId: UUID,
        idx: Int,
        exp: Instant,
        clientInstanceId: UUID,
    )

    @Query(
        """
        SELECT * FROM $STATUS_LIST_ENTRY_TABLE
        WHERE client_instance_id = :clientInstanceId AND account_id = :accountId
        """,
    )
    suspend fun findByAccountAndClientInstanceId(
        accountId: UUID,
        clientInstanceId: UUID,
    ): StatusListEntryEntity?

    @Query("SELECT * FROM $STATUS_LIST_ENTRY_TABLE WHERE account_id = :accountId AND exp > now() ORDER BY list_id, idx")
    fun findLiveByAccountId(accountId: UUID): Flow<StatusListEntryEntity>

    @Query(
        """
        DELETE FROM $STATUS_LIST_ENTRY_TABLE
        WHERE ctid IN (
            SELECT ctid FROM $STATUS_LIST_ENTRY_TABLE
            WHERE exp < now()
            ORDER BY exp
            LIMIT :batchSize
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id
        """,
    )
    fun deleteExpiredBatch(batchSize: Int): Flow<UUID>
}
