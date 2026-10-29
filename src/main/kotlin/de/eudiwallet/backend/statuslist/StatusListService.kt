package de.eudiwallet.backend.statuslist

import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

const val STATUS_VALID = 0
const val STATUS_INVALID = 1

data class StatusReference(
    val uri: String,
    val index: Int,
    val expiresAt: Instant,
)

class NoSuchListException : RuntimeException("No such status list")

@Service
@Suppress("TooManyFunctions")
class StatusListService(
    private val config: StatusListConfiguration,
    private val statusListRepository: StatusListRepository,
    private val statusListEntryRepository: StatusListEntryRepository,
    private val telemetryService: TelemetryService,
) {
    private val secureRandom = SecureRandom()
    private val reservations = ConcurrentHashMap<String, PoolReservation>()

    @Transactional(propagation = Propagation.NEVER)
    suspend fun allocate(
        accountId: UUID,
        poolId: String,
    ): StatusReference =
        telemetryService.withSpan("StatusListService.allocate") {
            val pool = config.pool(poolId)
            val reference = reserve(pool)
            val expiresAt = Instant.now().plus(pool.lifetime)
            statusListEntryRepository.insert(accountId, reference.listId, reference.index, expiresAt)
            StatusReference(config.listUri(pool, reference.listId), reference.index, expiresAt)
        }

    suspend fun revokeAccountEntries(accountId: UUID) =
        telemetryService.withSpan("StatusListService.revokeAccountEntries") {
            statusListEntryRepository
                .findLiveByAccountId(accountId)
                .toList()
                .groupBy({ it.listId }, { it.idx })
                .forEach { (listId, indexes) -> updateStatuses(listId, indexes, STATUS_INVALID) }
        }

    suspend fun gcExpiredEntries(batchSize: Int): Int =
        telemetryService.withSpan("StatusListService.gcExpiredEntries") {
            var total = 0
            while (true) {
                val deleted = statusListEntryRepository.deleteExpiredBatch(batchSize).toList().size
                total += deleted
                if (deleted < batchSize) break
            }
            total
        }

    suspend fun gcExhaustedLists(slack: Duration): Int =
        telemetryService.withSpan("StatusListService.gcExhaustedLists") {
            config.pools().sumOf { pool ->
                val cutoff = Instant.now().minus(pool.lifetime).minus(slack)
                statusListRepository.deleteExhaustedLists(pool.id, cutoff).toList().size
            }
        }

    suspend fun updateStatuses(
        listId: UUID,
        indexes: Collection<Int>,
        value: Int,
    ) {
        if (indexes.isEmpty()) return
        val shape = statusListRepository.findShapeByIdOrNull(listId) ?: throw NoSuchListException()
        require(value in 0 until (1 shl shape.bitsPerEntry)) {
            "value $value out of range for ${shape.bitsPerEntry}-bit list"
        }
        indexes.forEach { idx -> require(idx in 0 until shape.size) { "index $idx out of bounds for list $listId" } }
        val updates = StatusListCodec.byteUpdates(indexes, shape.bitsPerEntry, value)
        statusListRepository.updateStatusBytes(
            listId = listId,
            byteIndexes = updates.map { it.byteIndex }.toTypedArray(),
            clearMasks = updates.map { it.clearMask }.toTypedArray(),
            setBits = updates.map { it.setBits }.toTypedArray(),
        ) ?: throw NoSuchListException()
    }

    suspend fun findList(listId: UUID): StatusListEntity? = statusListRepository.findByIdOrNull(listId)

    suspend fun findListHead(listId: UUID): ListHead? = statusListRepository.findHeadByIdOrNull(listId)

    suspend fun listUris(poolId: String): List<String> {
        val pool = config.pool(poolId)
        return statusListRepository.findListIdsByPool(poolId).toList().map { config.listUri(pool, it) }
    }

    private suspend fun reserve(pool: Pool): Reference {
        val reservation = reservations.computeIfAbsent(pool.id) { PoolReservation() }
        return reservation.mutex.withLock {
            val block =
                reservation.block?.takeIf { it.hasNext() && !it.olderThan(config.blockMaxAge) }
                    ?: telemetryService.withSpan("StatusListService.refill") { refill(pool) }
            reservation.block = block
            block.next()
        }
    }

    internal fun dropReservations() = reservations.clear()

    private suspend fun refill(pool: Pool): Block {
        while (true) {
            val list = statusListRepository.findCurrentList(pool.id) ?: createList(pool) ?: continue
            val advance = statusListRepository.advanceCursor(list.id, take = pool.reservationSize)
            if (advance != null) {
                return Block(list.id, FeistelPermutation(list.seed, list.size), advance.startIndex, advance.taken)
            }
        }
    }

    private suspend fun createList(pool: Pool): StatusListEntity? {
        val seed = ByteArray(SEED_BYTES).also(secureRandom::nextBytes)
        val data = ByteArray(StatusListCodec.byteSize(pool.entriesPerList, pool.bitsPerEntry))
        return statusListRepository.insertListIfAbsent(pool.id, pool.bitsPerEntry, pool.entriesPerList, seed, data)
    }

    private class PoolReservation {
        val mutex = Mutex()
        var block: Block? = null
    }

    private class Block(
        val listId: UUID,
        private val permutation: FeistelPermutation,
        private var next: Int,
        count: Int,
    ) {
        private val end = next + count

        private val reservedAt = System.nanoTime()

        fun hasNext() = next < end

        fun olderThan(maxAge: Duration) = System.nanoTime() - reservedAt >= maxAge.toNanos()

        fun next(): Reference = Reference(listId, permutation.permute(next++))
    }

    private data class Reference(
        val listId: UUID,
        val index: Int,
    )

    private companion object {
        const val SEED_BYTES = 32
    }
}
