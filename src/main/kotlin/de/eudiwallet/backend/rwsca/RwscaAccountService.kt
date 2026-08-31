package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.crypto.toCanonicalP256
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.dao.DuplicateKeyException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.time.Duration
import java.time.Instant
import java.time.Instant.now
import java.util.UUID

@Service
@Suppress("TooManyFunctions")
class RwscaAccountService(
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

    suspend fun createAccount(
        wiMdvmAuthPubk: ECPublicKey,
        mdvmWiId: MdvmAccountId,
    ): RwscaAccount.WithoutPin =
        telemetryService.withSpan("RwscaService.createAccount") {
            val canonicalPubk = wiMdvmAuthPubk.toCanonicalP256()
            val wiHandle = canonicalPubk.jwkThumbprint().toString()
            val savedEntity =
                try {
                    repository.create(
                        rwscaAccountId = UUID.randomUUID(),
                        wiMdvmAuthPubkDer = canonicalPubk.encoded,
                        wiHandle = wiHandle,
                        mdvmWiId = mdvmWiId.id,
                    )
                } catch (ex: DuplicateKeyException) {
                    throw KeyAlreadyRegisteredException(ex)
                }
            savedEntity.toAccountWithoutPin()
        }

    suspend fun findAccount(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccount =
        telemetryService.withSpan("RwscaService.findAccount") {
            val entity = repository.findByRwscaAccountId(id.id) ?: throw AccountNotFoundException()
            entity.verifyAuthPubKey(authPubKey).toAccount()
        }

    suspend fun findActiveAccount(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccount =
        telemetryService.withSpan("RwscaService.findActiveAccount") {
            val entity = repository.findByRwscaAccountId(id.id) ?: throw AccountNotFoundException()
            entity.verifyAuthPubKey(authPubKey).requireNotRevoked().requireNotLocked().toAccount()
        }

    private suspend fun findActiveAccountForUpdate(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccount {
        val entity = repository.findByRwscaAccountIdForUpdate(id.id) ?: throw AccountNotFoundException()
        return entity.verifyAuthPubKey(authPubKey).requireNotRevoked().requireNotLocked().toAccount()
    }

    private fun RwscaAccountEntity.verifyAuthPubKey(authPubKey: ECPublicKey): RwscaAccountEntity {
        if (wiMdvmAuthPubkDer.ecPublicKeyFromX509().jwkThumbprint() != authPubKey.jwkThumbprint()) {
            throw AccountNotFoundException()
        }
        return this
    }

    private fun RwscaAccountEntity.requireNotRevoked(): RwscaAccountEntity {
        if (revokedAt != null) {
            throw AccountRevokedException()
        }
        return this
    }

    private fun RwscaAccountEntity.requireNotLocked(): RwscaAccountEntity {
        if (pinTryCounter != null && pinTryCounter == 0) {
            throw AccountLockedException()
        }
        return this
    }

    @Transactional
    suspend fun initializePin(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
        initialPinPubk: ECPublicKey,
    ): RwscaAccount.WithPin =
        telemetryService.withSpan("RwscaService.initializePin") {
            val account = findActiveAccountForUpdate(id, authPubKey)

            if (account !is RwscaAccount.WithoutPin) {
                throw PinAlreadyInitializedException()
            }

            val savedEntity =
                repository.initializePin(
                    account.rwscaAccountId.id,
                    initialPinPubk.encoded,
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
        verifyPinLambda: suspend (account: RwscaAccount.WithPin) -> Boolean,
    ): Unit =
        telemetryService.withSpan("RwscaService.verifyPin") {
            val account = findActiveAccountForUpdate(rwscaAccountId, wiMdvmAuthPubk)

            if (account !is RwscaAccount.WithPin) {
                throw PinNotInitializedException()
            }

            val nextTryAllowed = nextTryAllowed(account.pinTryCounter, account.pinTryFailedAt)
            if (now().isBefore(nextTryAllowed)) {
                throw PinRetryBlockedException(account.pinTryCounter, nextTryAllowed)
            }

            if (verifyPinLambda(account)) {
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

    suspend fun deleteAccount(id: RwscaAccountId) =
        telemetryService.withSpan("RwscaService.deleteAccount") {
            repository.deleteByRwscaAccountId(id.id)
        }

    suspend fun revokeByWiHandle(wiHandle: String) =
        telemetryService.withSpan("RwscaService.revokeByWiHandle") {
            repository.revokeByWiHandle(wiHandle)
        }
}
