package de.eudiwallet.backend.statuslist

import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.coroutines.flow.toList
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.UUID

const val STATUS_VALID = 0
const val STATUS_INVALID = 1

data class StatusReference(
    val uri: String,
    val index: Int,
    val expiresAt: Instant,
    val clientInstanceId: UUID,
)

class NoSuchListException : RuntimeException("No such status list")

class StatusListEntryException(
    message: String,
) : RuntimeException(message)

@Service
@Suppress("TooManyFunctions")
class StatusListService(
    private val config: StatusListConfiguration,
    private val statusListRepository: StatusListRepository,
    private val statusListEntryRepository: StatusListEntryRepository,
    private val telemetryService: TelemetryService,
) {
    private val secureRandom = SecureRandom()

    @Transactional
    suspend fun allocate(
        accountId: UUID,
        poolId: String,
    ): StatusReference =
        telemetryService.withSpan("StatusListService.allocate") {
            val pool = config.pool(poolId)
            val reference = allocateOne(pool)
            val expiresAt = Instant.now().plus(pool.lifetime)
            val clientInstanceId = UUID.randomUUID()
            statusListEntryRepository.insert(
                accountId,
                reference.listId,
                reference.index,
                expiresAt,
                clientInstanceId,
            )
            StatusReference(config.listUri(pool, reference.listId), reference.index, expiresAt, clientInstanceId)
        }

    suspend fun reuse(
        clientInstanceId: UUID,
        accountId: UUID,
        poolId: String,
    ): StatusReference =
        telemetryService.withSpan("StatusListService.reuse") {
            val pool = config.pool(poolId)
            val entry =
                verifyStatusListEntry(
                    statusListEntryRepository.findByAccountAndClientInstanceId(accountId, clientInstanceId),
                    pool,
                )
            StatusReference(config.listUri(pool, entry.listId), entry.idx, entry.exp, clientInstanceId)
        }

    @Suppress("ThrowsCount")
    private suspend fun verifyStatusListEntry(
        entry: StatusListEntryEntity?,
        pool: Pool,
    ): StatusListEntryEntity {
        if (entry == null) {
            throw StatusListEntryException("Missing status list entry")
        }
        if (entry.exp < Instant.now()) {
            throw StatusListEntryException("Expired status list entry")
        }
        val list = statusListRepository.findByIdOrNull(entry.listId)
        if (list == null || list.pool != pool.id) {
            throw StatusListEntryException("Wrong status list entry")
        }
        if (StatusListCodec.getStatus(list.data, pool.bitsPerEntry, entry.idx) == STATUS_INVALID) {
            throw StatusListEntryException("Invalid status list entry")
        }
        return entry
    }

    suspend fun revokeAccountEntries(accountId: UUID) =
        telemetryService.withSpan("StatusListService.revokeAccountEntries") {
            statusListEntryRepository.findLiveByAccountId(accountId).toList().forEach { entry ->
                updateStatus(entry.listId, entry.idx, STATUS_INVALID)
            }
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

    suspend fun updateStatus(
        listId: UUID,
        idx: Int,
        value: Int,
    ) {
        val shape = statusListRepository.findShapeByIdOrNull(listId) ?: throw NoSuchListException()
        require(idx in 0 until shape.size) { "index $idx out of bounds for list $listId" }
        require(value in 0 until (1 shl shape.bitsPerEntry)) {
            "value $value out of range for ${shape.bitsPerEntry}-bit list"
        }
        statusListRepository.updateStatusBit(
            listId = listId,
            byteIndex = StatusListCodec.position(idx, shape.bitsPerEntry).byteIndex,
            clearMask = StatusListCodec.clearMask(idx, shape.bitsPerEntry),
            setBits = StatusListCodec.setBits(idx, shape.bitsPerEntry, value),
        ) ?: throw NoSuchListException()
    }

    suspend fun findList(listId: UUID): StatusListEntity? = statusListRepository.findByIdOrNull(listId)

    suspend fun findListHead(listId: UUID): ListHead? = statusListRepository.findHeadByIdOrNull(listId)

    suspend fun listUris(poolId: String): List<String> {
        val pool = config.pool(poolId)
        return statusListRepository.findListIdsByPool(poolId).toList().map { config.listUri(pool, it) }
    }

    private suspend fun allocateOne(pool: Pool): Reference {
        while (true) {
            val list = statusListRepository.findCurrentList(pool.id) ?: createList(pool) ?: continue
            val start = statusListRepository.advanceCursor(list.id, take = 1)
            if (start != null) {
                return Reference(list.id, FeistelPermutation(list.seed, list.size).permute(start))
            }
        }
    }

    private suspend fun createList(pool: Pool): StatusListEntity? {
        val seed = ByteArray(SEED_BYTES).also(secureRandom::nextBytes)
        val data = ByteArray(StatusListCodec.byteSize(pool.entriesPerList, pool.bitsPerEntry))
        return statusListRepository.insertListIfAbsent(pool.id, pool.bitsPerEntry, pool.entriesPerList, seed, data)
    }

    private data class Reference(
        val listId: UUID,
        val index: Int,
    )

    private companion object {
        const val SEED_BYTES = 32
    }
}
