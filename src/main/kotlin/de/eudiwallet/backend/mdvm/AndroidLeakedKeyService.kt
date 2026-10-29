package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.android.AndroidRevocationList.RevocationReason
import at.asitplus.attestation.android.AndroidRevocationList.RevocationStatus
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.math.BigInteger
import java.time.Instant

data class AndroidLeakedKey(
    val serial: String,
    val status: RevocationStatus,
    val reason: RevocationReason,
    val comment: String?,
    val addedBy: String,
    val createdAt: Instant? = null,
)

@Service
class AndroidLeakedKeyService(
    private val repository: AndroidLeakedKeyRepository,
    private val telemetryService: TelemetryService,
) {
    suspend fun findAll(): List<AndroidLeakedKey> =
        telemetryService.withSpan("AndroidLeakedKeyService.findAll") {
            repository.findAllByOrderByCreatedAtAscSerialAsc().map { it.toDomain() }.toList()
        }

    @Transactional
    suspend fun add(keys: List<AndroidLeakedKey>): List<AndroidLeakedKey> =
        telemetryService.withSpan("AndroidLeakedKeyService.add") {
            val normalized = keys.map { it.copy(serial = it.serial.normalizeSerial()) }
            val alreadyStored =
                normalized
                    .filter {
                        repository.insertIfAbsent(
                            it.serial,
                            it.status.name,
                            it.reason.name,
                            it.comment,
                            it.addedBy,
                        ) == 0L
                    }
                    .map { it.serial }
            if (alreadyStored.isNotEmpty()) throw AndroidLeakedKeyConflictException(alreadyStored)

            val stored = repository.findAllById(normalized.map { it.serial }).toList().associateBy { it.serial }
            normalized.map { stored.getValue(it.serial).toDomain() }
        }

    suspend fun remove(serial: String) =
        telemetryService.withSpan("AndroidLeakedKeyService.remove") {
            val normalized = serial.normalizeSerial()
            if (repository.deleteBySerial(normalized) == 0L) throw AndroidLeakedKeyNotFoundException(normalized)
        }
}

@Suppress("MagicNumber")
fun String.normalizeSerial(): String = BigInteger(this, 16).toString(16)

private fun AndroidLeakedKeyEntity.toDomain() = AndroidLeakedKey(serial, status, reason, comment, addedBy, createdAt)
