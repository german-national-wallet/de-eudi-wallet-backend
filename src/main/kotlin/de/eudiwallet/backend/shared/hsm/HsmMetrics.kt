package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11Exception
import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component

enum class HsmRetryOutcome {
    RECOVERED,
    EXHAUSTED,
    NO_FREE_SESSION,
}

@Component
class HsmMetrics(
    meter: Meter,
) {
    private val hsmPkcs11ErrorCounter by lazy {
        meter.walletCounterBuilder(
            "hsm_pkcs11_errors",
            "Failed PKCS#11 calls, including ones a retry recovered from, by slot, function and rv",
        ).build()
    }

    private val hsmAeadEncryptionCounter by lazy {
        meter.walletCounterBuilder(
            "hsm_aead_encryptions",
            "AES-GCM encryptions by slot and key; SP 800-38D allows 2^32 per key over its lifetime",
        ).build()
    }

    private val hsmSessionRetryCounter by lazy {
        meter.walletCounterBuilder(
            "hsm_session_retries",
            "HSM operations retried on another pooled session after a session-level failure, by outcome",
        ).build()
    }

    internal fun countHsmPkcs11Error(
        slot: String,
        failure: Pkcs11Exception,
    ) = hsmPkcs11ErrorCounter.add(
        1,
        Attributes.of(
            stringKey("slot"),
            slot,
            stringKey("function"),
            failure.function,
            stringKey("rv"),
            Ck.returnValueName(failure.rv),
        ),
    )

    fun countHsmAeadEncryption(
        slot: String,
        keyId: String,
    ) = hsmAeadEncryptionCounter.add(1, Attributes.of(stringKey("slot"), slot, stringKey("key_id"), keyId))

    fun countHsmSessionRetry(
        slot: String,
        outcome: HsmRetryOutcome,
    ) = hsmSessionRetryCounter.add(
        1,
        Attributes.of(stringKey("slot"), slot, stringKey("outcome"), outcome.name.lowercase()),
    )
}
