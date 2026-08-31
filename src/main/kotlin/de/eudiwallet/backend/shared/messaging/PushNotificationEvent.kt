package de.eudiwallet.backend.shared.messaging

import kotlinx.serialization.Serializable

@Serializable
data class PushNotificationEvent(
    val eventId: String,
    val accountId: String,
    val titleLocKey: String,
    val bodyLocKey: String,
    val data: Map<String, String> = emptyMap(),
    val occurredAt: String,
    val source: String,
)
