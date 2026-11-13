package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.crypto.toCanonicalP256
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationOutcome
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.dao.DuplicateKeyException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.util.UUID

@Service
class RwscaAccountService(
    private val telemetryService: TelemetryService,
    private val repository: RwscaAccountRepository,
    private val pinPubkCipher: PinPubkCipher,
    private val pinTransactions: RwscaPinTransactions,
) {
    suspend fun createAccount(
        wiMdvmAuthPubk: ECPublicKey,
        mdvmWiId: MdvmAccountId,
    ): RwscaAccount.WithoutPin =
        telemetryService.withSpan("RwscaService.createAccount") {
            val savedEntity =
                try {
                    repository.create(
                        rwscaAccountId = UUID.randomUUID(),
                        wiMdvmAuthPubkDer = wiMdvmAuthPubk.toCanonicalP256().encoded,
                        mdvmWiId = mdvmWiId.id,
                    )
                } catch (ex: DuplicateKeyException) {
                    throw KeyAlreadyRegisteredException(ex)
                }
            savedEntity.toAccountWithoutPin()
        }

    suspend fun findActiveAccount(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccount =
        telemetryService.withSpan("RwscaService.findActiveAccount") {
            findActiveEntity(id, authPubKey).toAccount()
        }

    private suspend fun findActiveEntity(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ): RwscaAccountEntity {
        val entity = repository.findByRwscaAccountId(id.id) ?: throw AccountNotFoundException()
        return entity.verifyAuthPubKey(authPubKey).requireNotRevoked().requireNotLocked()
    }

    suspend fun initializePin(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
        initialPinPubk: ECPublicKey,
    ): RwscaAccount.WithPin =
        telemetryService.withSpan("RwscaService.initializePin") {
            if (findActiveEntity(id, authPubKey).toEncryptedPinPubkOrNull() != null) {
                throw PinAlreadyInitializedException()
            }
            pinTransactions.initializePin(id, authPubKey, pinPubkCipher.encrypt(id, authPubKey, initialPinPubk))
        }

    suspend fun verifyPin(
        rwscaAccountId: RwscaAccountId,
        wiMdvmAuthPubk: ECPublicKey,
        verifyPinLambda: suspend (pinPubk: ECPublicKey) -> Boolean,
    ): Unit =
        telemetryService.withSpan("RwscaService.verifyPin") {
            val record =
                findActiveEntity(rwscaAccountId, wiMdvmAuthPubk).toEncryptedPinPubkOrNull()
                    ?: throw PinNotInitializedException()
            val pinPubk = pinPubkCipher.decrypt(rwscaAccountId, wiMdvmAuthPubk, record)
            pinTransactions.verifyPin(rwscaAccountId, wiMdvmAuthPubk) { verifyPinLambda(pinPubk) }
        }

    @Transactional
    suspend fun deleteAccount(
        id: RwscaAccountId,
        authPubKey: ECPublicKey,
    ) = telemetryService.withSpan("RwscaService.deleteAccount") {
        val entity = repository.findByRwscaAccountIdForUpdate(id.id) ?: throw AccountNotFoundException()
        entity.verifyAuthPubKey(authPubKey).requireNotRevoked()
        repository.deleteByRwscaAccountId(id.id)
    }

    suspend fun revokeByMdvmWiId(mdvmWiId: MdvmAccountId): WalletInstanceRevocationOutcome =
        telemetryService.withSpan("RwscaService.revokeByMdvmWiId") {
            when {
                repository.revokeByMdvmWiId(mdvmWiId.id) > 0 -> WalletInstanceRevocationOutcome.APPLIED

                repository.existsByMdvmWiIdAndRevokedAtIsNotNull(
                    mdvmWiId.id,
                ) -> WalletInstanceRevocationOutcome.ALREADY_REVOKED

                else -> WalletInstanceRevocationOutcome.UNKNOWN_ACCOUNT
            }
        }
}
