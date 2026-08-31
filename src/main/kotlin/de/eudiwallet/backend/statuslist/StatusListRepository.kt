package de.eudiwallet.backend.statuslist

import kotlinx.coroutines.flow.Flow
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

const val STATUS_LIST_TABLE = "status_list"

@Suppress("LongParameterList")
@Table(STATUS_LIST_TABLE)
class StatusListEntity(
    @Column("id")
    val id: UUID,
    @Column("pool")
    val pool: String,
    @Column("bits_per_entry")
    val bitsPerEntry: Int,
    @Column("size")
    val size: Int,
    @Column("cursor")
    val cursor: Int,
    @Column("seed")
    val seed: ByteArray,
    @Column("data")
    val data: ByteArray,
    @Column("version")
    val version: Int,
    @Column("created")
    val created: Instant,
    @Column("exhausted_at")
    val exhaustedAt: Instant?,
)

data class ListShape(
    val bitsPerEntry: Int,
    val size: Int,
)

data class ListHead(
    val pool: String,
    val version: Int,
)

@Repository
interface StatusListRepository : CoroutineCrudRepository<StatusListEntity, UUID> {
    @Query("SELECT * FROM $STATUS_LIST_TABLE WHERE id = :id")
    suspend fun findByIdOrNull(id: UUID): StatusListEntity?

    @Query("SELECT bits_per_entry, size FROM $STATUS_LIST_TABLE WHERE id = :id")
    suspend fun findShapeByIdOrNull(id: UUID): ListShape?

    @Query("SELECT pool, version FROM $STATUS_LIST_TABLE WHERE id = :id")
    suspend fun findHeadByIdOrNull(id: UUID): ListHead?

    @Query("SELECT * FROM $STATUS_LIST_TABLE WHERE pool = :pool AND cursor < size LIMIT 1")
    suspend fun findCurrentList(pool: String): StatusListEntity?

    @Query("SELECT id FROM $STATUS_LIST_TABLE WHERE pool = :pool ORDER BY created")
    fun findListIdsByPool(pool: String): Flow<UUID>

    @Query(
        """
        INSERT INTO $STATUS_LIST_TABLE (pool, bits_per_entry, size, seed, data)
        VALUES (:pool, :bitsPerEntry, :size, :seed, :data)
        ON CONFLICT (pool) WHERE cursor < size DO NOTHING
        RETURNING *
        """,
    )
    suspend fun insertListIfAbsent(
        pool: String,
        bitsPerEntry: Int,
        size: Int,
        seed: ByteArray,
        data: ByteArray,
    ): StatusListEntity?

    @Query(
        """
        UPDATE $STATUS_LIST_TABLE
        SET cursor = cursor + :take,
            exhausted_at = CASE WHEN cursor + :take = size THEN now() ELSE exhausted_at END
        WHERE id = :listId AND cursor + :take <= size
        RETURNING (cursor - :take) AS start_index
        """,
    )
    suspend fun advanceCursor(
        listId: UUID,
        take: Int,
    ): Int?

    @Query(
        """
        UPDATE $STATUS_LIST_TABLE
        SET data = set_byte(data, :byteIndex, (get_byte(data, :byteIndex) & :clearMask) | :setBits),
            version = version + 1
        WHERE id = :listId
        RETURNING version
        """,
    )
    suspend fun updateStatusBit(
        listId: UUID,
        byteIndex: Int,
        clearMask: Int,
        setBits: Int,
    ): Int?

    @Query(
        """
        DELETE FROM $STATUS_LIST_TABLE
        WHERE pool = :pool AND exhausted_at < :cutoff
        RETURNING id
        """,
    )
    fun deleteExhaustedLists(
        pool: String,
        cutoff: Instant,
    ): Flow<UUID>
}
