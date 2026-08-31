package de.eudiwallet.backend.statuslist

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater

@Suppress("TooManyFunctions")
object StatusListCodec {
    private const val BYTE_MASK = 0xFF

    private val base64Url = Base64.getUrlEncoder().withoutPadding()
    private val base64UrlDecoder = Base64.getUrlDecoder()

    @Suppress("MagicNumber")
    val ALLOWED_BITS = setOf(1, 2, 4, 8)

    fun byteSize(
        size: Int,
        bitsPerEntry: Int,
    ): Int {
        require(size > 0) { "size must be positive" }
        require(bitsPerEntry in ALLOWED_BITS) { "bitsPerEntry must be one of $ALLOWED_BITS" }
        require((size.toLong() * bitsPerEntry) % Byte.SIZE_BITS == 0L) {
            "size*bitsPerEntry must be a whole number of bytes"
        }
        return (size.toLong() * bitsPerEntry / Byte.SIZE_BITS).toInt()
    }

    fun pack(
        bitsPerEntry: Int,
        values: IntArray,
    ): ByteArray {
        val data = ByteArray(byteSize(values.size, bitsPerEntry))
        values.forEachIndexed { idx, value -> setStatus(data, bitsPerEntry, idx, value) }
        return data
    }

    fun position(
        idx: Int,
        bitsPerEntry: Int,
    ): BitPosition {
        val bitOffset = idx.toLong() * bitsPerEntry
        return BitPosition((bitOffset / Byte.SIZE_BITS).toInt(), (bitOffset % Byte.SIZE_BITS).toInt())
    }

    fun clearMask(
        idx: Int,
        bitsPerEntry: Int,
    ): Int = (valueMask(bitsPerEntry) shl position(idx, bitsPerEntry).shift).inv() and BYTE_MASK

    fun setBits(
        idx: Int,
        bitsPerEntry: Int,
        value: Int,
    ): Int = (value and valueMask(bitsPerEntry)) shl position(idx, bitsPerEntry).shift

    fun setStatus(
        data: ByteArray,
        bitsPerEntry: Int,
        idx: Int,
        value: Int,
    ) {
        val pos = position(idx, bitsPerEntry)
        val cleared = data[pos.byteIndex].toInt() and clearMask(idx, bitsPerEntry)
        data[pos.byteIndex] = (cleared or setBits(idx, bitsPerEntry, value)).toByte()
    }

    fun getStatus(
        data: ByteArray,
        bitsPerEntry: Int,
        idx: Int,
    ): Int {
        val pos = position(idx, bitsPerEntry)
        return (data[pos.byteIndex].toInt() ushr pos.shift) and valueMask(bitsPerEntry)
    }

    fun encodeLst(data: ByteArray): String = base64Url.encodeToString(deflate(data))

    fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        try {
            deflater.setInput(data)
            deflater.finish()
            return drain { deflater.deflate(it) }
        } finally {
            deflater.end()
        }
    }

    fun decodeLst(lst: String): ByteArray = inflate(base64UrlDecoder.decode(lst))

    fun inflate(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        try {
            inflater.setInput(compressed)
            return drain { if (inflater.finished()) 0 else inflater.inflate(it) }
        } finally {
            inflater.end()
        }
    }

    private inline fun drain(fill: (ByteArray) -> Int): ByteArray {
        val chunk = ByteArray(CHUNK)
        val out = ByteArrayOutputStream()
        while (true) {
            val n = fill(chunk)
            if (n <= 0) break
            out.write(chunk, 0, n)
        }
        return out.toByteArray()
    }

    private fun valueMask(bitsPerEntry: Int) = (1 shl bitsPerEntry) - 1

    private const val CHUNK = 8192
}

data class BitPosition(
    val byteIndex: Int,
    val shift: Int,
)
