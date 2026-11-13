package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.time.Duration
import java.time.Instant
import java.time.Instant.now

@Component
class RwscaPinTransactions(
    private val telemetryService: TelemetryService,
    private val config: RwscaConfiguration,
    private val repository: RwscaAccountRepository,
) {
    init {
        if (config.pinRetry.maxTries - 1 != config.pinRetry.backoffDurations.size) {
            error(
                "backoffDurations should be configured for maxTries-1 (${config.pinRetry.maxTries - 1})",
            )
        }
        if (config.pinRetry.backoffDurations.any { it < Duration.ZERO }) {
            error("all backoffDurations must be non-negative")
        }
    }

    private suspend fun findActiveAccountForUpdate(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccount {
        val entity = repository.findByRwscaAccountIdForUpdate(id.id) ?: throw AccountNotFoundException()
        return entity.verifyAuthPubKey(authPubKey).requireNotRevoked().requireNotLocked().toAccount()
    }

    @Transactional
    suspend fun initializePin(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
        encryptedPinPubk: EncryptedPinPubk,
    ): RwscaAccount.WithPin =
        telemetryService.withSpan("RwscaPinTransactions.initializePin") {
            val account = findActiveAccountForUpdate(id, authPubKey)

            if (account !is RwscaAccount.WithoutPin) {
                throw PinAlreadyInitializedException()
            }

            val savedEntity =
                repository.initializePin(
                    account.rwscaAccountId.id,
                    encryptedPinPubk.keyId.value,
                    encryptedPinPubk.data.iv,
                    encryptedPinPubk.data.cipherText,
                    encryptedPinPubk.data.authTag,
                    config.pinRetry.maxTries,
                ) ?: error("Failed to initialize pin")
            savedEntity.toAccountWithPin()
        }

    fun nextTryAllowed(
        pinTryCounter: Int,
        lastFailedAt: Instant?,
    ): Instant {
        if (pinTryCounter < 0) error("Pin try counter should not be negative")
        if (pinTryCounter == 0) error("Pin try counter should not be 0")
        if (pinTryCounter > config.pinRetry.maxTries) {
            error("Pin try counter ($pinTryCounter) should not exceed maxTries (${config.pinRetry.maxTries})")
        }
        if (pinTryCounter == config.pinRetry.maxTries) {
            if (lastFailedAt != null) error("lastFailedAt should be null when try counter equals maxTries")
            return Instant.EPOCH
        }
        val index = config.pinRetry.maxTries - 1 - pinTryCounter
        val backoff =
            config.pinRetry.backoffDurations.getOrNull(index)
                ?: error("no backOff configured for pinTryCounter ($pinTryCounter)")
        if (lastFailedAt == null) error("lastFailedAt should not be null")
        return lastFailedAt.plus(backoff)
    }

    @Transactional(
        noRollbackFor = [
            PinRetryBlockedException::class,
            PinVerificationFailedException::class,
            AccountLockedException::class,
        ],
    )
    suspend fun verifyPin(
        rwscaAccountId: RwscaAccountId,
        wiMdvmAuthPubk: ECPublicKey,
        verifyPinLambda: suspend () -> Boolean,
    ): Unit =
        telemetryService.withSpan("RwscaPinTransactions.verifyPin") {
            val account = findActiveAccountForUpdate(rwscaAccountId, wiMdvmAuthPubk)

            if (account !is RwscaAccount.WithPin) {
                throw PinNotInitializedException()
            }

            val nextTryAllowed = nextTryAllowed(account.pinTryCounter, account.pinTryFailedAt)
            if (now().isBefore(nextTryAllowed)) {
                throw PinRetryBlockedException(account.pinTryCounter, nextTryAllowed)
            }

            if (verifyPinLambda()) {
                if (account.pinTryCounter < config.pinRetry.maxTries) {
                    repository.updatePinTryCounterAndFailedAt(
                        account.rwscaAccountId.id,
                        account.pinTryCounter,
                        config.pinRetry.maxTries,
                        null,
                    ) ?: error("Failed to reset pin retry counter")
                }
            } else {
                val updatedPinTryCounter = account.pinTryCounter - 1
                val lastFailedAt = now()

                repository.updatePinTryCounterAndFailedAt(
                    account.rwscaAccountId.id,
                    account.pinTryCounter,
                    updatedPinTryCounter,
                    lastFailedAt,
                ) ?: error("Failed to update pin retry counter")

                if (updatedPinTryCounter == 0) {
                    throw AccountLockedException()
                } else {
                    val nextTryAllowed = nextTryAllowed(updatedPinTryCounter, lastFailedAt)
                    throw PinVerificationFailedException(updatedPinTryCounter, nextTryAllowed)
                }
            }
        }
}
