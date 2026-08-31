package de.eudiwallet.backend.pns

import org.springframework.data.annotation.Id
import org.springframework.data.r2dbc.repository.Modifying
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

private const val NOTIFICATION_REGISTRATION_TABLE = "notification_registration"
private const val ID_COLUMN = "id"
private const val ACCOUNT_ID_COLUMN = "account_id"
private const val MPP_REGISTRATION_TOKEN_COLUMN = "mpp_registration_token"
private const val REGISTERED_AT_COLUMN = "registered_at"

private const val ID_BIND = "id"
private const val ACCOUNT_ID_BIND = "accountId"
private const val MPP_REGISTRATION_TOKEN_BIND = "mppRegistrationToken"

@Table(NOTIFICATION_REGISTRATION_TABLE)
class PnsRegistrationEntity(
    @Id
    @Column(ID_COLUMN)
    val id: UUID,
    @Column(ACCOUNT_ID_COLUMN)
    val accountId: UUID,
    @Column(MPP_REGISTRATION_TOKEN_COLUMN)
    val mppRegistrationToken: String,
    @Column(REGISTERED_AT_COLUMN)
    val registeredAt: Instant,
) {
    override fun toString(): String =
        "PnsRegistrationEntity(id=$id, accountId=$accountId, mppRegistrationToken='<value is hidden>')"
}

@Repository
interface PnsRepository : CoroutineCrudRepository<PnsRegistrationEntity, UUID> {
    @Query("SELECT * FROM $NOTIFICATION_REGISTRATION_TABLE WHERE $ACCOUNT_ID_COLUMN = :$ACCOUNT_ID_BIND")
    suspend fun findByAccountId(
        @Param(ACCOUNT_ID_BIND) accountId: UUID,
    ): PnsRegistrationEntity?

    @Modifying
    @Query(
        """
        INSERT INTO $NOTIFICATION_REGISTRATION_TABLE
            ($ID_COLUMN, $ACCOUNT_ID_COLUMN, $MPP_REGISTRATION_TOKEN_COLUMN, $REGISTERED_AT_COLUMN)
        VALUES (:$ID_BIND, :$ACCOUNT_ID_BIND, :$MPP_REGISTRATION_TOKEN_BIND, now())
        ON CONFLICT ($ACCOUNT_ID_COLUMN)
        DO UPDATE SET
            $MPP_REGISTRATION_TOKEN_COLUMN = :$MPP_REGISTRATION_TOKEN_BIND,
            $REGISTERED_AT_COLUMN = now()
        """,
    )
    suspend fun upsertByAccountId(
        @Param(ID_BIND) id: UUID,
        @Param(ACCOUNT_ID_BIND) accountId: UUID,
        @Param(MPP_REGISTRATION_TOKEN_BIND) mppRegistrationToken: String,
    )

    @Modifying
    @Query("DELETE FROM $NOTIFICATION_REGISTRATION_TABLE WHERE $ACCOUNT_ID_COLUMN = :$ACCOUNT_ID_BIND")
    suspend fun deleteByAccountId(
        @Param(ACCOUNT_ID_BIND) accountId: UUID,
    )
}
