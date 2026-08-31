package de.eudiwallet.backend.shared.messaging

class MessagingUnavailableException(
    cause: Throwable? = null,
) : RuntimeException("Messaging is unavailable", cause)
