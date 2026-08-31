package de.eudiwallet.backend.shared.messaging

fun interface PushNotificationPublisher {
    suspend fun publish(event: PushNotificationEvent)
}
