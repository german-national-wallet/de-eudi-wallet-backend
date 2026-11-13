package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

interface RefreshableLineage {
    val name: String

    fun refresh()
}

data class HeldKey(
    val keyId: HsmKeyId,
    val expiresAt: Instant,
) {
    fun isExpiredAt(now: Instant): Boolean = !now.isBefore(expiresAt)
}

class ExpiredKeyException(
    lineage: String,
    heldKey: HeldKey,
) : RuntimeException("$lineage: key ${heldKey.keyId} expired at ${heldKey.expiresAt}; no valid key has resolved")

private val hsmDateZone: ZoneId get() = ZoneId.systemDefault()

internal fun HsmKey.expiresAt(): Instant = endDate.plusDays(1).atStartOfDay(hsmDateZone).toInstant()

internal fun Instant.lastUsableDay(): LocalDate = minusNanos(1).atZone(hsmDateZone).toLocalDate()
