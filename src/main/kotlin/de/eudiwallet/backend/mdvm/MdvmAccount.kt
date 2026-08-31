package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.CanonicalIosAttestation
import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AuthorizationList
import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.json.fromPostgresJson
import de.eudiwallet.backend.shared.json.toPostgresJson
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import kotlinx.datetime.number
import kotlinx.serialization.Serializable
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.UUID

data class MdvmAccount(
    val mdvmAccountId: MdvmAccountId,
    val authPublicKey: ECPublicKey,
    val deviceType: DeviceType,
    val deviceClass: DeviceInfo,
    val androidDeviceAttestation: AndroidAttestationDetails? = null,
    val iosDeviceAttestation: CanonicalIosAttestation? = null,
    val iosDeviceAssertion: IosDeviceAssertionData? = null,
    val revokedAt: Instant? = null,
    val updatedAt: Instant = Instant.now(),
) {
    fun requireNotRevoked() {
        if (revokedAt != null) {
            throw AccountRevokedException(revokedAt)
        }
    }

    fun verifyDeviceType(deviceType: DeviceType) {
        if (this.deviceType != deviceType) {
            throw WrongDeviceType(this.mdvmAccountId, this.deviceType, deviceType)
        }
    }

    fun toEntity(): MdvmAccountEntity =
        MdvmAccountEntity(
            id = UUID.randomUUID(),
            mdvmWiId = mdvmAccountId.id,
            mdvmAuthPubk = authPublicKey.encoded,
            deviceType = deviceType,
            deviceClass = deviceClass.toStorage(),
            androidAttestationDetails = androidDeviceAttestation.toStorage(),
            iosDeviceAttestation = iosDeviceAttestation.toStorage(),
            iosDeviceAssertion = iosDeviceAssertion.toStorage(),
            wiHandle = authPublicKey.jwkThumbprint().toString(),
            updatedAt = updatedAt,
        )

    companion object {
        fun fromEntity(entity: MdvmAccountEntity): MdvmAccount =
            MdvmAccount(
                mdvmAccountId = MdvmAccountId(entity.mdvmWiId),
                authPublicKey = entity.mdvmAuthPubk.ecPublicKeyFromX509(),
                deviceType = entity.deviceType,
                deviceClass = DeviceInfo(entity.deviceClass.fromPostgresJson()),
                androidDeviceAttestation = entity.androidAttestationDetails?.fromPostgresJson(),
                iosDeviceAttestation = entity.iosDeviceAttestation?.fromPostgresJson(),
                iosDeviceAssertion = entity.iosDeviceAssertion?.fromPostgresJson(),
                revokedAt = entity.revokedAt,
                updatedAt = entity.updatedAt,
            )

        fun DeviceInfo.toStorage() = info.toPostgresJson()

        fun AndroidAttestationDetails?.toStorage() = this?.toPostgresJson()

        fun CanonicalIosAttestation?.toStorage() = this?.toPostgresJson()

        fun IosDeviceAssertionData?.toStorage() = this?.toPostgresJson()
    }
}

@JvmInline
value class DeviceInfo(
    val info: Map<String, String>,
)

@Serializable
data class AndroidPackageInfo(
    val packageName: List<String>? = null,
    val packageVersion: List<UInt>? = null,
    val signatureDigest: List<String>? = null,
)

@Serializable
data class AndroidAttestationDetails(
    val attestationSecurityLevel: AttestationKeyDescription.SecurityLevel,
    val keyMintSecurityLevel: AttestationKeyDescription.SecurityLevel,
    val origin: AuthorizationList.Origin? = null,
    val attestationIdModel: String? = null,
    val attestationIdProduct: String? = null,
    val attestationIdDevice: String? = null,
    val osVersion: String? = null,
    val osPatchLevel: String? = null,
    val deviceLocked: Boolean? = null,
    val verifiedBootState: AuthorizationList.RootOfTrust.VerifiedBootState? = null,
    val verifiedBootKeyDigest: String? = null,
    val packageInfo: AndroidPackageInfo? = null,
) {
    companion object {
        fun AttestationKeyDescription.toAndroidAttestationDetails(
            allowSoftwareAttestation: Boolean,
        ): AndroidAttestationDetails {
            val attestationApplicationId = softwareEnforced.attestationApplicationId?.getOrNull()
            val packageInfo =
                AndroidPackageInfo(
                    packageName = attestationApplicationId?.packageInfos?.map { it.packageName },
                    packageVersion = attestationApplicationId?.packageInfos?.map { it.version },
                    signatureDigest = attestationApplicationId?.signatureDigests?.map { it.toBase64() },
                )
            val softwareEnforceValues = softwareEnforced.takeIf { allowSoftwareAttestation }
            val rootOfTrust = hardwareEnforced.rootOfTrust?.getOrNull()
            return AndroidAttestationDetails(
                attestationSecurityLevel = attestationSecurityLevel,
                keyMintSecurityLevel = keyMintSecurityLevel,
                origin = hardwareEnforced.origin?.getOrNull(),
                attestationIdModel =
                    hardwareEnforced.attestationIdModel?.getOrNull()?.stringValue
                        ?: softwareEnforceValues?.attestationIdModel?.getOrNull()?.stringValue,
                attestationIdProduct =
                    hardwareEnforced.attestationIdProduct?.getOrNull()?.stringValue
                        ?: softwareEnforceValues?.attestationIdProduct?.getOrNull()?.stringValue,
                attestationIdDevice =
                    hardwareEnforced.attestationIdDevice?.getOrNull()?.stringValue
                        ?: softwareEnforceValues?.attestationIdDevice?.getOrNull()?.stringValue,
                osVersion =
                    hardwareEnforced.osVersion?.getOrNull()?.asString()
                        ?: softwareEnforceValues?.osVersion?.getOrNull()?.asString(),
                osPatchLevel =
                    hardwareEnforced.osPatchLevel?.getOrNull()?.asString()
                        ?: softwareEnforceValues?.osPatchLevel?.getOrNull()?.asString(),
                deviceLocked = rootOfTrust?.deviceLocked,
                verifiedBootState = rootOfTrust?.verifiedBootState,
                verifiedBootKeyDigest = rootOfTrust?.verifiedBootKeyDigest?.toBase64(),
                packageInfo = packageInfo,
            )
        }

        private fun AuthorizationList.OsVersion.asString() = "$major.$minor.$sub"

        private fun AuthorizationList.OsPatchLevel.asString() = "$year.${month.number.toString().padStart(2, '0')}"
    }
}

data class AndroidDeviceAttestationData(
    val attestationDetails: AndroidAttestationDetails,
    val publicKey: ECPublicKey,
)

data class IosDeviceAttestationData(
    val canonicalAttestation: CanonicalIosAttestation,
    val publicKey: ECPublicKey,
)

@Serializable
data class IosDeviceAssertionData(
    val counter: Long,
)

fun MdvmAccountEntity.toDomain() = MdvmAccount.fromEntity(this)
