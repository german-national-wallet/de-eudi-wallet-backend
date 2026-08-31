package de.eudiwallet.backend.pns

import com.google.auth.oauth2.GoogleCredentials
import io.netty.channel.ChannelOption
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatusCode
import org.springframework.http.MediaType
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientRequestException
import org.springframework.web.reactive.function.client.awaitBodyOrNull
import org.springframework.web.reactive.function.client.awaitExchange
import reactor.netty.http.client.HttpClient
import java.io.IOException
import java.time.Duration
import kotlin.time.Duration.Companion.milliseconds

private const val FIREBASE_MESSAGING_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"

private const val DEFAULT_SEND_TIMEOUT_SECONDS = 10L

class FcmPushClient(
    credentials: GoogleCredentials,
    projectId: String,
    baseUrl: String,
    private val json: Json,
    webClientBuilder: WebClient.Builder,
    private val timeout: Duration = Duration.ofSeconds(DEFAULT_SEND_TIMEOUT_SECONDS),
) : MppPushClient,
    AutoCloseable {
    private val webClient =
        webClientBuilder
            .baseUrl(baseUrl)
            .clientConnector(
                ReactorClientHttpConnector(
                    HttpClient.create()
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout.toMillis().toInt())
                        .responseTimeout(timeout),
                ),
            )
            .build()
    private val scopedCredentials = credentials.createScoped(FIREBASE_MESSAGING_SCOPE)
    private val sendPath = "/v1/projects/$projectId/messages:send"

    private val refreshScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun close() = refreshScope.cancel()

    @Suppress("TooGenericExceptionCaught")
    override suspend fun send(
        mppRegistrationToken: String,
        notification: PushNotification,
    ): PushOutcome {
        val accessToken =
            try {
                bearerToken()
            } catch (ex: CancellationException) {
                throw ex
            } catch (ex: Exception) {
                return PushOutcome.Transient("OAuth token refresh failed: ${ex.message}")
            }
        return try {
            webClient
                .post()
                .uri(sendPath)
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(json.encodeToString(FcmSendRequest(fcmMessage(mppRegistrationToken, notification))))
                .awaitExchange { response ->
                    classify(response.statusCode(), response.awaitBodyOrNull<String>().orEmpty())
                }
        } catch (ex: CancellationException) {
            throw ex
        } catch (ex: WebClientRequestException) {
            PushOutcome.Transient("could not reach FCM: ${ex.message}")
        } catch (ex: Exception) {
            PushOutcome.Transient("could not read the FCM response: ${ex.message}")
        }
    }

    private suspend fun bearerToken(): String {
        val refresh =
            refreshScope.async {
                runInterruptible {
                    scopedCredentials.refreshIfExpired()
                    scopedCredentials.accessToken?.tokenValue
                }
            }
        return withTimeoutOrNull(timeout.toMillis().milliseconds) { refresh.await() }
            ?: run {
                refresh.cancel()
                throw IOException("timed out after ${timeout.toMillis()} ms")
            }
    }

    private fun classify(
        status: HttpStatusCode,
        body: String,
    ): PushOutcome {
        if (status.is2xxSuccessful) {
            return PushOutcome.Delivered(messageName(body))
        }
        val error = fcmError(body)
        val errorCode = error?.details?.firstNotNullOfOrNull { it.errorCode }
        return when {
            errorCode in TERMINAL_ERROR_CODES || (errorCode == INVALID_ARGUMENT_CODE && error.indictsToken()) -> {
                PushOutcome.Terminal("$errorCode (HTTP $status)")
            }

            errorCode != null -> {
                PushOutcome.Transient("$errorCode (HTTP $status)")
            }

            else -> {
                PushOutcome.Transient("unclassifiable HTTP $status response")
            }
        }
    }

    private fun messageName(body: String): String? =
        runCatching { json.decodeFromString<FcmSendResponse>(body).name }.getOrNull()

    private fun fcmError(body: String): FcmError? =
        runCatching { json.decodeFromString<FcmErrorResponse>(body).error }.getOrNull()

    private companion object {
        val TERMINAL_ERROR_CODES = setOf("UNREGISTERED", "SENDER_ID_MISMATCH")
        const val INVALID_ARGUMENT_CODE = "INVALID_ARGUMENT"
        const val TOKEN_FIELD = "token"
        const val QUALIFIED_TOKEN_FIELD = "message.token"
    }

    private fun FcmError?.indictsToken(): Boolean =
        this != null &&
            details.any { detail ->
                detail.fieldViolations.any { it.field == TOKEN_FIELD || it.field == QUALIFIED_TOKEN_FIELD }
            }
}

private fun fcmMessage(
    mppRegistrationToken: String,
    notification: PushNotification,
): FcmMessage =
    FcmMessage(
        token = mppRegistrationToken,
        data = notification.data,
        android =
            FcmAndroidConfig(
                priority = "high",
                notification =
                    FcmAndroidNotification(
                        titleLocKey = notification.titleLocKey,
                        bodyLocKey = notification.bodyLocKey,
                    ),
            ),
        apns =
            FcmApnsConfig(
                headers =
                    mapOf(
                        "apns-priority" to "10",
                        "apns-push-type" to "alert",
                    ),
                payload =
                    FcmApnsPayload(
                        aps =
                            FcmAps(
                                alert =
                                    FcmApsAlert(
                                        titleLocKey = notification.titleLocKey,
                                        locKey = notification.bodyLocKey,
                                    ),
                                mutableContent = 1,
                                contentAvailable = 1,
                            ),
                    ),
            ),
    )

@Serializable
data class FcmSendRequest(
    val message: FcmMessage,
)

@Serializable
data class FcmMessage(
    val token: String,
    val data: Map<String, String>,
    val android: FcmAndroidConfig,
    val apns: FcmApnsConfig,
)

@Serializable
data class FcmAndroidConfig(
    val priority: String,
    val notification: FcmAndroidNotification,
)

@Serializable
data class FcmAndroidNotification(
    @SerialName("title_loc_key") val titleLocKey: String,
    @SerialName("body_loc_key") val bodyLocKey: String,
)

@Serializable
data class FcmApnsConfig(
    val headers: Map<String, String>,
    val payload: FcmApnsPayload,
)

@Serializable
data class FcmApnsPayload(
    val aps: FcmAps,
)

@Serializable
data class FcmAps(
    val alert: FcmApsAlert,
    @SerialName("mutable-content") val mutableContent: Int,
    @SerialName("content-available") val contentAvailable: Int,
)

@Serializable
data class FcmApsAlert(
    @SerialName("title-loc-key") val titleLocKey: String,
    @SerialName("loc-key") val locKey: String,
)

@Serializable
data class FcmSendResponse(
    val name: String,
)

@Serializable
data class FcmErrorResponse(
    val error: FcmError,
)

@Serializable
data class FcmError(
    val code: Int = 0,
    val status: String? = null,
    val details: List<FcmErrorDetail> = emptyList(),
)

@Serializable
data class FcmErrorDetail(
    @SerialName("@type") val type: String? = null,
    val errorCode: String? = null,
    val fieldViolations: List<FcmFieldViolation> = emptyList(),
)

@Serializable
data class FcmFieldViolation(
    val field: String? = null,
)
