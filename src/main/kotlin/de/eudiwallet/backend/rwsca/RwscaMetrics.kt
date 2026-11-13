package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component

enum class PinPubkRejection {
    INTEGRITY_FAILURE,
    KEY_EXPIRED,
}

@Component
class RwscaMetrics(
    meter: Meter,
) {
    private val pinPubkRejectedCounter by lazy {
        meter.walletCounterBuilder(
            "rwsca_pin_pubk_rejected",
            "Stored PIN public keys refused at PIN verification, by reason; the retry counter is left untouched",
        ).build()
    }

    private val keyCreatedCounter =
        meter.walletCounterBuilder(
            "rwsca_keys_created",
            "Wallet Instance key pairs created in the HSM by createKeys, which asks for up to 10 per request",
        ).build()

    init {
        keyCreatedCounter.add(0)
    }

    fun countPinPubkRejected(reason: PinPubkRejection) =
        pinPubkRejectedCounter.add(1, Attributes.of(stringKey("reason"), reason.name.lowercase()))

    fun countKeyCreated() = keyCreatedCounter.add(1)
}
