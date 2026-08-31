package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.messaging.Module
import de.eudiwallet.backend.shared.messaging.PushNotificationEvent
import java.time.Instant
import java.util.UUID

internal const val USER_REVOKE_TITLE_LOC_KEY = "user_revoke_title"
internal const val USER_REVOKE_BODY_LOC_KEY = "user_revoke_body"
internal const val PUSH_ACTION_DATA_KEY = "action"
internal const val RENEW_MDVM_TOKEN_ACTION = "RENEW_MDVM_TOKEN"

internal fun revocationPushNotification(accountId: MdvmAccountId): PushNotificationEvent =
    PushNotificationEvent(
        eventId = UUID.randomUUID().toString(),
        accountId = accountId.toString(),
        titleLocKey = USER_REVOKE_TITLE_LOC_KEY,
        bodyLocKey = USER_REVOKE_BODY_LOC_KEY,
        data = mapOf(PUSH_ACTION_DATA_KEY to RENEW_MDVM_TOKEN_ACTION),
        occurredAt = Instant.now().toString(),
        source = Module.MDVM.name,
    )
