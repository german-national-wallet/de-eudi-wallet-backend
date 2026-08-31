package de.eudiwallet.backend.mdvm

import io.r2dbc.postgresql.codec.Json
import org.springframework.data.annotation.Id
import org.springframework.data.annotation.Version
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import org.springframework.data.repository.kotlin.CoroutineCrudRepository
import org.springframework.stereotype.Repository
import java.util.UUID

private const val MDVM_ANALYTICS_TABLE = "mdvm_analytics"
private const val ANALYTICS_ID_COLUMN = "id"
private const val OPERATION_NAME_COLUMN = "operation_name"
private const val ANALYTICS_AUTH_CHALLENGE_COLUMN = "auth_challenge"
private const val SKIP_INTEGRITY_CHECKS_COLUMN = "skip_integrity_checks"
private const val REQUEST_COLUMN = "request"
private const val EXCEPTION_DETAILS_COLUMN = "exception_details"

@Table(MDVM_ANALYTICS_TABLE)
data class MdvmAnalyticsEntity(
    @Id
    @Column(ANALYTICS_ID_COLUMN)
    val id: UUID,
    @Column(OPERATION_NAME_COLUMN)
    val operationName: String,
    @Column(ANALYTICS_AUTH_CHALLENGE_COLUMN)
    val authChallenge: String,
    @Column(SKIP_INTEGRITY_CHECKS_COLUMN)
    val skipIntegrityChecks: String,
    @Column(REQUEST_COLUMN)
    val request: Json,
    @Column(EXCEPTION_DETAILS_COLUMN)
    val exceptionDetails: Json? = null,
    @Version
    val version: Long? = null,
)

@Repository
interface MdvmAnalyticsRepository : CoroutineCrudRepository<MdvmAnalyticsEntity, UUID>
