package de.eudiwallet.backend.shared.messaging

import io.github.oshai.kotlinlogging.KLogger

enum class WalletInstanceRevocationOutcome {
    APPLIED,

    ALREADY_REVOKED,

    UNKNOWN_ACCOUNT,
}

internal fun WalletInstanceRevocationOutcome.report(
    module: Module,
    event: WalletInstanceRevocationEvent,
    messagingMetrics: MessagingMetrics,
    log: KLogger,
) {
    messagingMetrics.countWalletRevocationConsumed(module, this)
    when (this) {
        WalletInstanceRevocationOutcome.UNKNOWN_ACCOUNT -> {
            log.warn { "Revocation ${event.eventId} (${event.reason}): $this for MDVM account ${event.mdvmWiId}" }
        }

        else -> {
            log.info { "Revocation ${event.eventId} (${event.reason}): $this" }
        }
    }
}
