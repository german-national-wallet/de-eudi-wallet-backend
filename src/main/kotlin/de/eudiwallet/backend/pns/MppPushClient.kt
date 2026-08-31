package de.eudiwallet.backend.pns

fun interface MppPushClient {
    suspend fun send(
        mppRegistrationToken: String,
        notification: PushNotification,
    ): PushOutcome
}

data class PushNotification(
    val titleLocKey: String,
    val bodyLocKey: String,
    val data: Map<String, String>,
)

sealed interface PushOutcome {
    data class Delivered(
        val messageId: String?,
    ) : PushOutcome

    data class Terminal(
        val reason: String,
    ) : PushOutcome

    data class Transient(
        val reason: String,
    ) : PushOutcome
}
