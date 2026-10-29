package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.android.AndroidRevocationList
import com.nimbusds.jwt.SignedJWT
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.messaging.Module
import de.eudiwallet.backend.shared.messaging.RevocationReason
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationPublisher
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ServerWebInputException
import java.text.ParseException
import java.time.Instant
import java.util.UUID

const val DRY_RUN_PARAM = "dryRun"
const val ACCOUNTS_CHECKED_FIELD = "accounts_checked"
const val ACCOUNTS_SKIPPED_FIELD = "accounts_skipped"
const val ACCOUNTS_AFFECTED_FIELD = "accounts_affected"
const val ACCOUNTS_AFFECTED_FIXABLE_FIELD = "accounts_affected_fixable"
const val ACCOUNTS_AFFECTED_UNFIXABLE_FIELD = "accounts_affected_unfixable"
const val REVOCATIONS_PUBLISHED_FIELD = "revocations_published"
const val AFFECTED_DEVICE_CLASSES_FIELD = "affected_device_classes"
const val DEVICE_TYPE_FIELD = "device_type"
const val VULNERABILITY_ID_FIELD = "vulnerability_id"
const val CLASSIFICATION_FIELD = "classification"
const val ENTRIES_FIELD = "entries"
const val SERIAL_FIELD = "serial"
const val STATUS_FIELD = "status"
const val REASON_FIELD = "reason"
const val COMMENT_FIELD = "comment"
const val ADDED_BY_FIELD = "added_by"
const val CREATED_AT_FIELD = "created_at"

const val MAX_LEAKED_KEYS_PER_REQUEST = 100
private const val MAX_LEAKED_KEY_COMMENT_LENGTH = 1000

private const val SERIAL_PATTERN = "^[0-9a-fA-F]{1,64}$"
private val SERIAL_REGEX = Regex(SERIAL_PATTERN)

private const val BEARER_PREFIX = "Bearer "
private const val USERNAME_CLAIM = "preferred_username"

@Serializable
data class VulnerableDeviceClassStatistic(
    @SerialName(DEVICE_TYPE_FIELD)
    @Schema(description = "Platform of device class")
    val deviceType: DeviceType,
    @SerialName(VULNERABILITY_ID_FIELD)
    @Schema(description = "Identifier of the vulnerable device class entry", example = "DCVDB-2026-015")
    val vulnerabilityId: String,
    @SerialName(CLASSIFICATION_FIELD)
    @Schema(description = "Whether a system update resolves the vulnerability")
    val classification: VulnerabilityClassification,
    @SerialName(ACCOUNTS_AFFECTED_FIELD)
    @Schema(description = "Number of non-revoked accounts the entry affects")
    val accountsAffected: Int,
)

@Serializable
data class VulnerableDeviceClassRevocationResponse(
    @SerialName(ACCOUNTS_CHECKED_FIELD)
    @Schema(description = "Number of non-revoked accounts scanned")
    val accountsChecked: Int,
    @SerialName(ACCOUNTS_SKIPPED_FIELD)
    @Schema(description = "Accounts without evaluable device data")
    val accountsSkipped: Int,
    @SerialName(ACCOUNTS_AFFECTED_FIXABLE_FIELD)
    @Schema(description = "Accounts affected by fixable vulnerable device class")
    val accountsAffectedFixable: Int,
    @SerialName(ACCOUNTS_AFFECTED_UNFIXABLE_FIELD)
    @Schema(description = "Accounts affected by unfixable vulnerable device class")
    val accountsAffectedUnfixable: Int,
    @SerialName(REVOCATIONS_PUBLISHED_FIELD)
    @Schema(description = "Revocation events published for affected accounts; always 0 for a dry run")
    val revocationsPublished: Int,
    @SerialName(AFFECTED_DEVICE_CLASSES_FIELD)
    @Schema(description = "Affected accounts per vulnerable device class entry")
    val affectedDeviceClasses: List<VulnerableDeviceClassStatistic>,
)

@Serializable
data class AndroidLeakedKeyAddRequest(
    @SerialName(ENTRIES_FIELD)
    @Schema(description = "Keys to revoke, stored all or none")
    @field:Size(
        min = 1,
        max = MAX_LEAKED_KEYS_PER_REQUEST,
        message = "$ENTRIES_FIELD must hold 1 to $MAX_LEAKED_KEYS_PER_REQUEST items",
    )
    @field:Valid
    val entries: List<AndroidLeakedKeyEntry>,
)

@Serializable
data class AndroidLeakedKeyListResponse(
    @SerialName(ENTRIES_FIELD)
    @Schema(description = "Leaked keys, oldest first")
    val entries: List<AndroidLeakedKeyEntry>,
)

@Serializable
data class AndroidLeakedKeyEntry(
    @SerialName(SERIAL_FIELD)
    @Schema(description = "Hexadecimal certificate serial", example = EXAMPLE_SERIAL, pattern = SERIAL_PATTERN)
    @field:Pattern(regexp = SERIAL_PATTERN, message = "$SERIAL_FIELD must be hexadecimal, at most 64 digits")
    val serial: String,
    @SerialName(STATUS_FIELD)
    @Schema(description = "Revocation status", defaultValue = "REVOKED")
    val status: AndroidRevocationList.RevocationStatus = AndroidRevocationList.RevocationStatus.REVOKED,
    @SerialName(REASON_FIELD)
    @Schema(description = "Revocation reason", defaultValue = "UNSPECIFIED")
    val reason: AndroidRevocationList.RevocationReason = AndroidRevocationList.RevocationReason.UNSPECIFIED,
    @SerialName(COMMENT_FIELD)
    @Schema(description = "Free text: source, ticket", maxLength = MAX_LEAKED_KEY_COMMENT_LENGTH)
    @field:Size(
        max = MAX_LEAKED_KEY_COMMENT_LENGTH,
        message = "$COMMENT_FIELD must be at most $MAX_LEAKED_KEY_COMMENT_LENGTH characters",
    )
    val comment: String? = null,
    @SerialName(ADDED_BY_FIELD)
    @Schema(description = "Admin who added the key, from the gateway's ID token; ignored on input")
    val addedBy: String? = null,
    @SerialName(CREATED_AT_FIELD)
    @Schema(description = "When the key was added", format = "date-time", example = EXAMPLE_INSTANT)
    val createdAt: String? = null,
)

@RestController
@RequestMapping("/v1/mdvm/admin")
@Tag(name = "mdvm-admin", description = "MDVM administrative operations")
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmAdminApi(
    private val mdvmService: MdvmService,
    private val mdvmAccountService: MdvmAccountService,
    private val telemetryService: TelemetryService,
    private val revocationPublisherProvider: ObjectProvider<WalletInstanceRevocationPublisher>,
    private val androidLeakedKeyService: AndroidLeakedKeyService,
) {
    private val log = KotlinLogging.logger {}

    @Operation(
        summary = "Revoke accounts of vulnerable device classes",
        description = REVOKE_VULNERABLE_DEVICE_CLASSES_DOCS,
    )
    @PostMapping("/revokeDeviceClasses")
    @ResponseBody
    suspend fun revokeVulnerableDeviceClasses(
        @Parameter(hidden = true) @RequestHeader(HttpHeaders.AUTHORIZATION) authorization: String,
        @Parameter(description = "True (default) - only report; false - revoke")
        @RequestParam(DRY_RUN_PARAM, defaultValue = "true") dryRun: Boolean,
    ): VulnerableDeviceClassRevocationResponse =
        telemetryService.withSpan("MdvmAdminApi.revokeVulnerableDeviceClasses") {
            val revokedBy = authorization.adminUsername()
            val publisher =
                if (dryRun) {
                    null
                } else {
                    revocationPublisherProvider.getIfAvailable() ?: throw MessagingUnavailableException()
                }
            if (!dryRun) log.info { "Device class revocation run started by $revokedBy" }

            val statistics = Statistics()
            mdvmAccountService.findNonRevokedAccounts().collect { decoded ->
                val outcome = decoded.fold(::scanDeviceClass) { DeviceClassScanOutcome.Skipped }
                val published =
                    outcome.needRevocation() && publisher != null && publishRevocation(publisher, decoded.getOrThrow())
                statistics.add(outcome, published)
            }
            statistics.toResponse().also {
                if (!dryRun) log.info { "${it.revocationsPublished} device class revocations published by $revokedBy" }
            }
        }

    @Operation(summary = "List leaked Android keys", description = LIST_ANDROID_LEAKED_KEYS_DOCS)
    @GetMapping("/androidLeakedKeys")
    @ResponseBody
    suspend fun listAndroidLeakedKeys(): AndroidLeakedKeyListResponse =
        telemetryService.withSpan("MdvmAdminApi.listAndroidLeakedKeys") {
            AndroidLeakedKeyListResponse(androidLeakedKeyService.findAll().map { it.toResponse() })
        }

    @Operation(summary = "Add leaked Android keys", description = ADD_ANDROID_LEAKED_KEYS_DOCS)
    @PostMapping("/androidLeakedKeys")
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    suspend fun addAndroidLeakedKeys(
        @Parameter(hidden = true) @RequestHeader(HttpHeaders.AUTHORIZATION) authorization: String,
        @Valid @RequestBody request: AndroidLeakedKeyAddRequest,
    ): AndroidLeakedKeyListResponse =
        telemetryService.withSpan("MdvmAdminApi.addAndroidLeakedKeys") {
            val addedBy = authorization.adminUsername()
            val keys = request.entries.map { AndroidLeakedKey(it.serial, it.status, it.reason, it.comment, addedBy) }
            AndroidLeakedKeyListResponse(androidLeakedKeyService.add(keys).map { it.toResponse() })
        }

    @Operation(summary = "Remove a leaked Android key", description = REMOVE_ANDROID_LEAKED_KEY_DOCS)
    @DeleteMapping("/androidLeakedKeys/{$SERIAL_FIELD}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    suspend fun removeAndroidLeakedKey(
        @Parameter(hidden = true) @RequestHeader(HttpHeaders.AUTHORIZATION) authorization: String,
        @Parameter(description = "Hexadecimal certificate serial, normalized before lookup", example = EXAMPLE_SERIAL)
        @PathVariable(SERIAL_FIELD) serial: String,
    ) = telemetryService.withSpan("MdvmAdminApi.removeAndroidLeakedKey") {
        val removedBy = authorization.adminUsername()
        if (!SERIAL_REGEX.matches(serial)) throw ServerWebInputException("$SERIAL_FIELD must be hexadecimal")
        androidLeakedKeyService.remove(serial)
        log.info { "Leaked Android key ${serial.normalizeSerial()} removed by $removedBy" }
    }

    private fun scanDeviceClass(account: MdvmAccount): DeviceClassScanOutcome =
        try {
            val vulnerability =
                when (account.deviceType) {
                    DeviceType.ANDROID -> {
                        val details = account.androidDeviceAttestation ?: return DeviceClassScanOutcome.Skipped
                        mdvmService.findAndroidVulnerableDeviceClass(details)?.first?.let {
                            VulnerabilityRef(account.deviceType, it.id, it.classification)
                        }
                    }

                    DeviceType.IOS -> {
                        mdvmService.findIosVulnerableDeviceClass(account.iosDeviceClass())?.first?.let {
                            VulnerabilityRef(account.deviceType, it.id, it.classification)
                        }
                    }
                }
            vulnerability?.let { DeviceClassScanOutcome.Affected(it) } ?: DeviceClassScanOutcome.NotAffected
        } catch (ex: MdvmException) {
            log.warn(ex) { "Unable to evaluate the device class of account ${account.mdvmAccountId}" }
            DeviceClassScanOutcome.Skipped
        }

    private suspend fun publishRevocation(
        publisher: WalletInstanceRevocationPublisher,
        account: MdvmAccount,
    ): Boolean =
        try {
            publisher.publish(account.toRevocationEvent())
            true
        } catch (ex: MessagingUnavailableException) {
            log.error(ex) { "Failed to publish account revocation event for ${account.mdvmAccountId}" }
            false
        }
}

private data class VulnerabilityRef(
    val deviceType: DeviceType,
    val vulnerabilityId: String,
    val classification: VulnerabilityClassification,
)

private sealed interface DeviceClassScanOutcome {
    fun needRevocation(): Boolean

    data object Skipped : DeviceClassScanOutcome {
        override fun needRevocation(): Boolean = false
    }

    data object NotAffected : DeviceClassScanOutcome {
        override fun needRevocation(): Boolean = false
    }

    data class Affected(
        val vulnerability: VulnerabilityRef,
    ) : DeviceClassScanOutcome {
        override fun needRevocation(): Boolean = vulnerability.classification == VulnerabilityClassification.UNFIXABLE
    }
}

private class Statistics {
    private var accountsChecked = 0
    private var accountsSkipped = 0
    private var revocationsPublished = 0
    private val affectedAccounts = linkedMapOf<VulnerabilityRef, Int>()

    fun add(
        outcome: DeviceClassScanOutcome,
        published: Boolean,
    ) {
        accountsChecked++
        if (published) revocationsPublished++
        when (outcome) {
            DeviceClassScanOutcome.Skipped -> {
                accountsSkipped++
            }

            DeviceClassScanOutcome.NotAffected -> {
            }

            is DeviceClassScanOutcome.Affected -> {
                affectedAccounts.merge(outcome.vulnerability, 1, Int::plus)
            }
        }
    }

    fun toResponse() =
        VulnerableDeviceClassRevocationResponse(
            accountsChecked = accountsChecked,
            accountsSkipped = accountsSkipped,
            accountsAffectedFixable = accountsAffected(VulnerabilityClassification.FIXABLE),
            accountsAffectedUnfixable = accountsAffected(VulnerabilityClassification.UNFIXABLE),
            revocationsPublished = revocationsPublished,
            affectedDeviceClasses =
                affectedAccounts.map { (vulnerability, count) ->
                    VulnerableDeviceClassStatistic(
                        vulnerability.deviceType,
                        vulnerability.vulnerabilityId,
                        vulnerability.classification,
                        count,
                    )
                },
        )

    private fun accountsAffected(classification: VulnerabilityClassification) =
        affectedAccounts.filterKeys { it.classification == classification }.values.sum()
}

private fun String.adminUsername(): String {
    val username =
        try {
            SignedJWT.parse(removePrefix(BEARER_PREFIX)).jwtClaimsSet.getStringClaim(USERNAME_CLAIM)
        } catch (ex: ParseException) {
            throw ServerWebInputException("${HttpHeaders.AUTHORIZATION} must carry an ID token", null, ex)
        }
    if (username.isNullOrBlank()) {
        throw ServerWebInputException("${HttpHeaders.AUTHORIZATION} ID token lacks $USERNAME_CLAIM")
    }
    return username
}

private fun AndroidLeakedKey.toResponse() =
    AndroidLeakedKeyEntry(
        serial,
        status,
        reason,
        comment,
        addedBy,
        checkNotNull(createdAt) {
            "Unsaved key $serial"
        }.toString(),
    )

private fun MdvmAccount.toRevocationEvent() =
    WalletInstanceRevocationEvent(
        eventId = UUID.randomUUID().toString(),
        mdvmWiId = mdvmAccountId.id,
        occurredAt = Instant.now().toString(),
        source = Module.MDVM.name,
        reason = RevocationReason.MDVM_REVOKE.name,
    )
