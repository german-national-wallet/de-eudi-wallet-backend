package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.SerializerRegistry
import at.asitplus.attestation.android.AndroidRevocationList
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import org.springframework.stereotype.Component
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.time.toKotlinDuration

private val RETRY_AFTER_FAILURE = 30.seconds

@Component
class AndroidLeakedKeyLoader(
    private val leakedKeyService: AndroidLeakedKeyService,
    androidConfig: AndroidIntegrityConfig,
) : AndroidRevocationList.CachingLoader() {
    private val log = KotlinLogging.logger {}

    private val refresh = androidConfig.leakedKeyListRefresh.toKotlinDuration()

    private var lastGood: AndroidRevocationList? = null

    override val fallbackRevocationListValiditySeconds: Long = refresh.inWholeSeconds

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(now: Instant): AndroidRevocationList =
        try {
            val entries =
                leakedKeyService.findAll().associate {
                    it.serial to
                        AndroidRevocationList.Entry(status = it.status, reason = it.reason, comment = it.comment)
                }
            AndroidRevocationList(entries = entries, expires = now + refresh).also { lastGood = it }
        } catch (ex: CancellationException) {
            throw ex
        } catch (ex: Exception) {
            val previous = lastGood ?: throw ex
            log.error(ex) { "Failed to reload Android leaked keys, keeping ${previous.entries.size} previous entries" }
            previous.copy(expires = now + RETRY_AFTER_FAILURE)
        }

    @Serializable
    @SerialName("mdvm-leakedkeys-database")
    class Configuration(
        override val fallbackRevocationListValiditySeconds: Long,
    ) : AndroidRevocationList.Loader.Configuration<AndroidLeakedKeyLoader> {
        @Transient
        private var loader: AndroidLeakedKeyLoader? = null

        constructor(loader: AndroidLeakedKeyLoader) : this(loader.fallbackRevocationListValiditySeconds) {
            this.loader = loader
        }

        override fun createLoader() = checkNotNull(loader) { "A deserialized configuration carries no loader" }

        companion object {
            private val log = KotlinLogging.logger {}

            init {
                try {
                    AndroidRevocationList.loaderRegistry.register(Configuration::class)
                } catch (ex: SerializerRegistry.RegistrationException) {
                    log.error(ex) { "Android leaked key loader not registered with Warden" }
                }
            }
        }
    }
}
