package de.eudiwallet.backend.shared.messaging

interface WalletInstanceRevocationPublisher {
    suspend fun publish(event: WalletInstanceRevocationEvent)
}
