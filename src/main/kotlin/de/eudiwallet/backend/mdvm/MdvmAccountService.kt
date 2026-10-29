package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.mdvm.MdvmAccount.Companion.toStorage
import de.eudiwallet.backend.shared.crypto.toCanonicalP256
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.messaging.MessagingMetrics
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.messaging.PushNotificationPublisher
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationOutcome
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.springframework.beans.factory.ObjectProvider
import org.springframework.dao.DuplicateKeyException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.util.UUID

@Service
class MdvmAccountService(
    private val mdvmAccountRepository: MdvmAccountRepository,
    private val telemetryService: TelemetryService,
    private val mdvmMetrics: MdvmMetrics,
    private val messagingMetrics: MessagingMetrics,
    private val pushNotificationPublisherProvider: ObjectProvider<PushNotificationPublisher>,
) {
    private val log = KotlinLogging.logger {}

    suspend fun createIosAccount(
        authPubk: ECPublicKey,
        deviceClass: IosDeviceInfo,
        deviceAttestation: IosDeviceAttestationData?,
        deviceAssertion: IosDeviceAssertionData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createIosAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk.toCanonicalP256(),
                    deviceType = DeviceType.IOS,
                    deviceClass = deviceClass,
                    iosDeviceAttestation = deviceAttestation?.canonicalAttestation,
                    iosDeviceAssertion = deviceAssertion,
                )
            saveNewAccount(account).also {
                telemetryService.traceAttributes(deviceClass.loggingInfo())
                mdvmMetrics.countDeviceRegistered(deviceClass.metricDimensions())
            }
        }

    suspend fun createAndroidAccount(
        authPubk: ECPublicKey,
        deviceClass: AndroidDeviceInfo,
        attestationData: AndroidDeviceAttestationData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createAndroidAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk.toCanonicalP256(),
                    deviceType = DeviceType.ANDROID,
                    deviceClass = deviceClass,
                    androidDeviceAttestation = attestationData?.attestationDetails,
                )
            saveNewAccount(account).also {
                telemetryService.traceAttributes(attestationData?.attestationDetails?.loggingInfo() ?: emptyMap())
                mdvmMetrics.countDeviceRegistered(attestationData?.attestationDetails.metricDimensions())
            }
        }

    private suspend fun saveNewAccount(account: MdvmAccount): MdvmAccount =
        try {
            mdvmAccountRepository.save(account.toEntity()).toDomain()
        } catch (ex: DuplicateKeyException) {
            throw KeyAlreadyRegisteredException(ex)
        }

    suspend fun findMdvmAccount(accountId: MdvmAccountId): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.findMdvmAccount") {
            mdvmAccountRepository.findByMdvmWiId(accountId.id)?.toDomain() ?: throw AccountNotFound(accountId)
        }

    @Suppress("TooGenericExceptionCaught")
    fun findNonRevokedAccounts(): Flow<Result<MdvmAccount>> =
        mdvmAccountRepository.findAllByRevokedAtIsNull().map { entity ->
            try {
                Result.success(entity.toDomain())
            } catch (ex: Exception) {
                log.warn(ex) { "Unable to decode account ${entity.mdvmWiId}" }
                Result.failure(ex)
            }
        }

    suspend fun revokeByMdvmWiId(mdvmWiId: MdvmAccountId): WalletInstanceRevocationOutcome =
        telemetryService.withSpan("MdvmAccountService.revokeByMdvmWiId") {
            val revoked = mdvmAccountRepository.revokeByMdvmWiId(mdvmWiId.id)
            val account = if (revoked <= 0) mdvmAccountRepository.findByMdvmWiId(mdvmWiId.id) else null
            when {
                revoked > 0 -> {
                    publishRevocationPush(mdvmWiId)
                    WalletInstanceRevocationOutcome.APPLIED
                }

                account?.revokedAt != null -> {
                    publishRevocationPush(mdvmWiId)
                    WalletInstanceRevocationOutcome.ALREADY_REVOKED
                }

                else -> {
                    WalletInstanceRevocationOutcome.UNKNOWN_ACCOUNT
                }
            }
        }

    private suspend fun publishRevocationPush(accountId: MdvmAccountId) {
        val publisher = pushNotificationPublisherProvider.getIfAvailable() ?: return
        try {
            publisher.publish(revocationPushNotification(accountId))
        } catch (ex: MessagingUnavailableException) {
            messagingMetrics.countPushPublishFailure()
            log.error(ex) { "Dropping revocation push for $accountId, the revocation itself stands" }
        }
    }

    @Transactional
    suspend fun saveNonRevokedAccount(
        mdvmAccountId: MdvmAccountId,
        deviceClass: DeviceInfo,
        iosDeviceAssertion: IosDeviceAssertionData? = null,
        androidAttestationDetails: AndroidAttestationDetails? = null,
    ) = telemetryService.withSpan("MdvmAccountService.saveNonRevokedAccount")
        {
            val account =
                mdvmAccountRepository.findByMdvmWiIdWithLockNoWait(mdvmAccountId.id)
                    ?.toDomain() ?: throw AccountNotFound(mdvmAccountId)
            account.requireNotRevoked()
            mdvmAccountRepository.updateAccount(
                mdvmWiId = mdvmAccountId.id,
                deviceClass = deviceClass.toStorage(),
                iosDeviceAssertion = iosDeviceAssertion.toStorage(),
                androidAttestationDetails = androidAttestationDetails.toStorage(),
            ).also {
                telemetryService.traceAttributes(
                    deviceClass.loggingInfo() + (androidAttestationDetails?.loggingInfo() ?: emptyMap()),
                )
                mdvmMetrics.countDeviceRenewed(
                    when (deviceClass) {
                        is IosDeviceInfo -> deviceClass.metricDimensions()
                        is AndroidDeviceInfo -> androidAttestationDetails.metricDimensions()
                    },
                )
            }
        }

    @Transactional
    suspend fun deleteMdvmAccount(accountId: MdvmAccountId) =
        telemetryService.withSpan("MdvmAccountService.deleteMdvmAccount") {
            val account =
                mdvmAccountRepository.findByMdvmWiIdForUpdate(accountId.id)?.toDomain()
                    ?: throw AccountNotFound(accountId)
            account.requireNotRevoked()
            mdvmAccountRepository.deleteByMdvmWiId(accountId.id)
        }
}
