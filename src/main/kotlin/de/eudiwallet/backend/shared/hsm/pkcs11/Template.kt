package de.eudiwallet.backend.shared.hsm.pkcs11

import java.time.LocalDate
import java.time.format.DateTimeFormatter

internal class Attr(
    val type: Long,
    val value: Any,
) {
    init {
        require(value is Boolean || value is Long || value is ByteArray || value is String) {
            "Unsupported attribute value type ${value::class}"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is Attr && type == other.type &&
            if (value is ByteArray &&
                other.value is ByteArray
            ) {
                value.contentEquals(other.value)
            } else {
                value == other.value
            }

    override fun hashCode(): Int =
        31 * type.hashCode() + if (value is ByteArray) value.contentHashCode() else value.hashCode()

    override fun toString(): String =
        "Attr(type=0x${type.toString(HEX_RADIX)}, value=${if (value is ByteArray) value.toHexString() else value})"
}

private const val HEX_RADIX = 16

internal typealias Template = List<Attr>

internal class AttributeValues(
    private val values: Map<Long, ByteArray?>,
) {
    fun bytes(type: Long): ByteArray? = values[type]

    fun string(type: Long): String? = values[type]?.let { String(it, Charsets.UTF_8) }

    fun date(type: Long): LocalDate? =
        values[type]?.takeIf { it.size == CK_DATE_SIZE && it.all { b -> b in DIGITS } }?.let {
            runCatching { LocalDate.parse(String(it, Charsets.US_ASCII), CK_DATE_FORMAT) }.getOrNull()
        }

    companion object {
        const val CK_DATE_SIZE = 8
        private val DIGITS = '0'.code.toByte()..'9'.code.toByte()
        private val CK_DATE_FORMAT: DateTimeFormatter = DateTimeFormatter.BASIC_ISO_DATE
    }
}
