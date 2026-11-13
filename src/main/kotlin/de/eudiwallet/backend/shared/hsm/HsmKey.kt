package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.AttributeValues
import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import io.github.oshai.kotlinlogging.KotlinLogging
import java.time.Instant
import java.time.LocalDate
import java.util.TimeZone

private val log = KotlinLogging.logger {}

const val HSM_PRIVATE_KEY_LABEL_SUFFIX = "-prvk"

@JvmInline
value class HsmKeyId(
    val value: String,
) {
    override fun toString(): String = "HsmKeyId($value)"

    fun byteArrayValue(): ByteArray = value.hexToByteArray()

    companion object {
        fun from(byteArrayValue: ByteArray) = HsmKeyId(byteArrayValue.toHexString())
    }
}

data class HsmKey(
    val keyId: HsmKeyId,
    val label: String,
    val startDate: LocalDate,
    val endDate: LocalDate,
) {
    companion object {
        internal fun from(attributes: AttributeValues): HsmKey? {
            val id = attributes.bytes(Ck.CKA_ID)?.takeIf { it.isNotEmpty() } ?: return null
            val keyId = HsmKeyId.from(id)
            val label = attributes.string(Ck.CKA_LABEL).orEmpty()
            val startDate = attributes.date(Ck.CKA_START_DATE)
            val endDate = attributes.date(Ck.CKA_END_DATE)
            return if (startDate != null && endDate != null && !endDate.isBefore(startDate)) {
                HsmKey(keyId, label, startDate, endDate)
            } else {
                log.warn { "Key $label (${keyId.value}) ignored: no valid window from $startDate to $endDate" }
                null
            }
        }
    }
}

fun List<HsmKey>.findActiveKeys(validityDate: Instant): List<HsmKey> {
    val on = validityDate.atZone(TimeZone.getDefault().toZoneId()).toLocalDate()
    return this.filter { !it.startDate.isAfter(on) && !it.endDate.isBefore(on) }
        .sortedByDescending { it.startDate }
}

fun List<HsmKey>.findPrimaryKey(validityDate: Instant): HsmKey? = findActiveKeys(validityDate).firstOrNull()

fun List<HsmKey>.findNextKey(validityDate: Instant): HsmKey? {
    val on = validityDate.atZone(TimeZone.getDefault().toZoneId()).toLocalDate()
    return this.filter { it.startDate.isAfter(on) }.minByOrNull { it.startDate }
}

fun HsmKey.certObjectKey(slotLabel: String): String =
    "$slotLabel/${label.removeSuffix(HSM_PRIVATE_KEY_LABEL_SUFFIX)}.pem"
