package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.mdvm.MdvmAccount.Companion.toStorage
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.dao.DuplicateKeyException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.util.UUID

@Service
class MdvmAccountService(
    private val mdvmAccountRepository: MdvmAccountRepository,
    private val telemetryService: TelemetryService,
) {
    suspend fun createIosAccount(
        authPubk: ECPublicKey,
        deviceClass: DeviceInfo,
        deviceAttestation: IosDeviceAttestationData?,
        deviceAssertion: IosDeviceAssertionData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createIosAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk,
                    deviceType = DeviceType.IOS,
                    deviceClass = deviceClass,
                    iosDeviceAttestation = deviceAttestation?.canonicalAttestation,
                    iosDeviceAssertion = deviceAssertion,
                )
            saveNewAccount(account)
        }

    suspend fun createAndroidAccount(
        authPubk: ECPublicKey,
        deviceClass: DeviceInfo,
        attestationData: AndroidDeviceAttestationData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createAndroidAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk,
                    deviceType = DeviceType.ANDROID,
                    deviceClass = deviceClass,
                    androidDeviceAttestation = attestationData?.attestationDetails,
                )
            saveNewAccount(account)
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

    suspend fun revokeByWiHandle(wiHandle: String): MdvmAccountId? =
        telemetryService.withSpan("MdvmAccountService.revokeByWiHandle") {
            mdvmAccountRepository.revokeByWiHandleReturningId(wiHandle)?.let { MdvmAccountId(it) }
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
            )
        }

    suspend fun deleteMdvmAccount(accountId: MdvmAccountId) =
        telemetryService.withSpan("MdvmAccountService.deleteMdvmAccount") {
            mdvmAccountRepository.deleteByMdvmWiId(accountId.id)
        }
}
