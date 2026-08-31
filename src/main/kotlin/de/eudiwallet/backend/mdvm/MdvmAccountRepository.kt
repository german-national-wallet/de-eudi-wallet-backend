package de.eudiwallet.backend.mdvm

import io.r2dbc.postgresql.codec.Json
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Version
import org.springframework.data.r2dbc.repository.Modifying
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

private const val DEVICE_ACCOUNT_TABLE = "device_account"
private const val ID_COLUMN = "id"
private const val MDVM_WI_ID_COLUMN = "mdvm_wi_id"
private const val WI_MDVM_AUTH_PUBK_COLUMN = "wi_mdvm_auth_pubk_der"
private const val DEVICE_TYPE_COLUMN = "device_type"
private const val DEVICE_CLASS_COLUMN = "device_class"
private const val ANDROID_ATTESTATION_DETAILS_COLUMN = "android_attestation_details"
private const val IOS_DEVICECHECK_ATTESTATION_COLUMN = "ios_devicecheck_attestation"
private const val IOS_DEVICECHECK_ASSERTION_COLUMN = "ios_devicecheck_assertion"
private const val WI_HANDLE_COLUMN = "wi_handle"
private const val REVOKED_AT_COLUMN = "revoked_at"
private const val UPDATED_AT_COLUMN = "updated_at"
private const val VERSION_COLUMN = "version"

private const val MDVM_ACCOUNT_ID_PARAM = "mdvm_account_id"
private const val WI_HANDLE_PARAM = "wi_handle"
private const val DEVICE_CLASS_PARAM = "device_class"
private const val ANDROID_ATTESTATION_DETAILS_PARAM = "android_attestation_details"
private const val IOS_DEVICECHECK_ASSERTION_PARAM = "ios_devicecheck_assertion"

enum class DeviceType {
    ANDROID,
    IOS,
}

@Suppress("ArrayInDataClass")
@Table(DEVICE_ACCOUNT_TABLE)
data class MdvmAccountEntity(
    @Id
    @Column(ID_COLUMN)
    val id: UUID,
    @Column(MDVM_WI_ID_COLUMN)
    val mdvmWiId: UUID,
    @Column(WI_MDVM_AUTH_PUBK_COLUMN)
    val mdvmAuthPubk: ByteArray,
    @Column(DEVICE_TYPE_COLUMN)
    val deviceType: DeviceType,
    @Column(DEVICE_CLASS_COLUMN)
    val deviceClass: Json,
    @Column(UPDATED_AT_COLUMN)
    val updatedAt: Instant,
    @Column(ANDROID_ATTESTATION_DETAILS_COLUMN)
    val androidAttestationDetails: Json? = null,
    @Column(IOS_DEVICECHECK_ATTESTATION_COLUMN)
    val iosDeviceAttestation: Json? = null,
    @Column(IOS_DEVICECHECK_ASSERTION_COLUMN)
    val iosDeviceAssertion: Json? = null,
    @Column(WI_HANDLE_COLUMN)
    val wiHandle: String? = null,
    @Column(REVOKED_AT_COLUMN)
    val revokedAt: Instant? = null,
    @Version
    val version: Long? = null,
)

@Repository
interface MdvmAccountRepository : CoroutineCrudRepository<MdvmAccountEntity, UUID> {
    suspend fun findByMdvmWiId(
        @Param(MDVM_ACCOUNT_ID_PARAM) mdvmWiId: UUID,
    ): MdvmAccountEntity?

    @Query(
        """
        SELECT * FROM $DEVICE_ACCOUNT_TABLE
        WHERE $MDVM_WI_ID_COLUMN = :$MDVM_ACCOUNT_ID_PARAM
        FOR UPDATE NOWAIT
    """,
    )
    suspend fun findByMdvmWiIdWithLockNoWait(
        @Param(MDVM_ACCOUNT_ID_PARAM) mdvmWiId: UUID,
    ): MdvmAccountEntity?

    @Modifying
    @Query("DELETE FROM $DEVICE_ACCOUNT_TABLE WHERE $MDVM_WI_ID_COLUMN = :$MDVM_ACCOUNT_ID_PARAM")
    suspend fun deleteByMdvmWiId(
        @Param(MDVM_ACCOUNT_ID_PARAM) mdvmWiId: UUID,
    )

    @Query(
        """
        UPDATE $DEVICE_ACCOUNT_TABLE
        SET $REVOKED_AT_COLUMN = COALESCE($REVOKED_AT_COLUMN, now()),
            $VERSION_COLUMN = $VERSION_COLUMN + 1
        WHERE $WI_HANDLE_COLUMN = :$WI_HANDLE_PARAM
        RETURNING $MDVM_WI_ID_COLUMN
    """,
    )
    suspend fun revokeByWiHandleReturningId(
        @Param(WI_HANDLE_PARAM) wiHandle: String,
    ): UUID?

    @Modifying
    @Query(
        """
        UPDATE $DEVICE_ACCOUNT_TABLE
        SET $DEVICE_CLASS_COLUMN = :$DEVICE_CLASS_PARAM,
            $IOS_DEVICECHECK_ASSERTION_COLUMN = :$IOS_DEVICECHECK_ASSERTION_PARAM,
            $ANDROID_ATTESTATION_DETAILS_COLUMN = :$ANDROID_ATTESTATION_DETAILS_PARAM,
            $UPDATED_AT_COLUMN = now(),
            $VERSION_COLUMN = $VERSION_COLUMN + 1
        WHERE $MDVM_WI_ID_COLUMN = :$MDVM_ACCOUNT_ID_PARAM
    """,
    )
    suspend fun updateAccount(
        @Param(MDVM_ACCOUNT_ID_PARAM) mdvmWiId: UUID,
        @Param(DEVICE_CLASS_PARAM) deviceClass: Json,
        @Param(IOS_DEVICECHECK_ASSERTION_PARAM) iosDeviceAssertion: Json?,
        @Param(ANDROID_ATTESTATION_DETAILS_PARAM) androidAttestationDetails: Json?,
    )
}
