package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

enum class WrappingMechanism(
    val mechanism: Long,
) {
    THALES_AES_KWP(Ck.THALES_AES_KWP),
    CKM_AES_KEY_WRAP_PAD(Ck.CKM_AES_KEY_WRAP_PAD),
}

@ConfigurationProperties(prefix = "hsm")
@Suppress("MagicNumber")
class HsmConfiguration(
    val moduleLibrary: String,
    val slotLabel: String,
    val slotPin: String,
    val wrappingMechanism: WrappingMechanism = WrappingMechanism.THALES_AES_KWP,
    val poolSize: Int = 10,
    val poolBorrowTimeout: Duration = Duration.ofSeconds(10),
) {
    val defaultSlot: SlotConfig get() = SlotConfig(slotLabel, slotPin, poolSize)
}

@Suppress("MagicNumber")
data class SlotConfig(
    val label: String,
    val pin: String,
    val poolSize: Int = 10,
    val threadCount: Int? = null,
) {
    val workerCount: Int get() = threadCount ?: poolSize

    init {
        require(poolSize >= 1) { "poolSize must be at least 1" }
        require(workerCount >= 1) { "threadCount must be at least 1" }
    }
}

interface HsmProvider {
    suspend fun <R> use(
        spanName: String,
        borrowTimeout: Duration? = null,
        block: (HsmSession) -> R,
    ): R
}
