package de.eudiwallet.backend.shared.messaging

import kotlinx.serialization.Serializable

@Serializable
data class WalletInstanceRevocationEvent(
    val eventId: String,
    val wiHandle: String,
    val occurredAt: String,
    val source: String,
)

internal enum class Module { WPB, RWSCA, MDVM }
