package de.eudiwallet.backend.shared.messaging

import io.github.oshai.kotlinlogging.KLogger

enum class WalletInstanceRevocationOutcome {
    APPLIED,

    ALREADY_REVOKED,

    UNKNOWN_HANDLE,
}

internal fun WalletInstanceRevocationOutcome.report(
    module: Module,
    event: WalletInstanceRevocationEvent,
    messagingMetrics: MessagingMetrics,
    log: KLogger,
) {
    messagingMetrics.countWalletRevocationConsumed(module, this)
    when (this) {
        WalletInstanceRevocationOutcome.UNKNOWN_HANDLE -> {
            log.warn { "Revocation ${event.eventId}: $this for WI handle ${event.wiHandle}" }
        }

        else -> {
            log.info { "Revocation ${event.eventId}: $this" }
        }
    }
}
