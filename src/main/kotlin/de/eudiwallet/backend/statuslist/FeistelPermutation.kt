package de.eudiwallet.backend.statuslist

import org.bouncycastle.crypto.fpe.FPEFF1Engine
import org.bouncycastle.crypto.params.FPEParameters
import org.bouncycastle.crypto.params.KeyParameter

class FeistelPermutation(
    seed: ByteArray,
    private val size: Int,
) {
    init {
        require(size > 0) { "size must be positive" }
    }

    private val engine =
        FPEFF1Engine().apply {
            init(true, FPEParameters(KeyParameter(seed.copyOf()), RADIX, EMPTY_TWEAK))
        }
    private val bits = bitsFor(size)

    fun permute(x: Int): Int {
        require(x in 0..<size) { "x out of range" }
        var y = encrypt(x)
        while (y >= size) y = encrypt(y)
        return y
    }

    private fun encrypt(value: Int): Int {
        val input = ByteArray(bits) { ((value ushr (bits - 1 - it)) and 1).toByte() }
        val output = ByteArray(bits)
        engine.processBlock(input, 0, bits, output, 0)
        return output.fold(0) { acc, bit -> (acc shl 1) or bit.toInt() }
    }

    companion object {
        private const val RADIX = 2

        private const val MIN_BITS = 20

        const val MIN_DOMAIN = 1 shl MIN_BITS

        private val EMPTY_TWEAK = ByteArray(0)

        private fun bitsFor(size: Int): Int {
            val needed = if (size <= 1) 1 else Int.SIZE_BITS - Integer.numberOfLeadingZeros(size - 1)
            return maxOf(needed, MIN_BITS)
        }
    }
}
