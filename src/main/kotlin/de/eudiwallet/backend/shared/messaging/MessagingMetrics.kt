package de.eudiwallet.backend.shared.messaging

import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component

@Component
class MessagingMetrics(
    meter: Meter,
) {
    private val pushPublishFailureCounter =
        meter.walletCounterBuilder(
            "push_notification_publish_failure",
            "Push notifications dropped because the publish to the topic failed",
        ).build()

    private val walletRevocationConsumedCounter =
        meter.walletCounterBuilder(
            "wallet_revocation_consumed",
            "Wallet Instance revocation events consumed, by module and what they hit",
        ).build()

    init {
        pushPublishFailureCounter.add(0)
        Module.entries.forEach { module ->
            WalletInstanceRevocationOutcome.entries.forEach { outcome ->
                walletRevocationConsumedCounter.add(0, revocationAttributes(module, outcome))
            }
        }
    }

    fun countPushPublishFailure() = pushPublishFailureCounter.add(1)

    internal fun countWalletRevocationConsumed(
        module: Module,
        outcome: WalletInstanceRevocationOutcome,
    ) = walletRevocationConsumedCounter.add(1, revocationAttributes(module, outcome))

    private fun revocationAttributes(
        module: Module,
        outcome: WalletInstanceRevocationOutcome,
    ) = Attributes.of(stringKey("module"), module.name.lowercase(), stringKey("outcome"), outcome.name.lowercase())
}
