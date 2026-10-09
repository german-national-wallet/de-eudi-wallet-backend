package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.messaging.MessagingUnavailableException
import de.eudiwallet.backend.shared.messaging.Module
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationEvent
import de.eudiwallet.backend.shared.messaging.WalletInstanceRevocationPublisher
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.tags.Tag
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.RestController
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

@RestController
@RequestMapping("/v1/mdvm/admin")
@Tag(name = "mdvm-admin", description = "MDVM administrative operations")
@ConditionalOnProperty(prefix = "mdvm", name = ["enabled"], havingValue = "true")
class MdvmAdminApi(
    private val mdvmService: MdvmService,
    private val mdvmAccountService: MdvmAccountService,
    private val telemetryService: TelemetryService,
    private val revocationPublisherProvider: ObjectProvider<WalletInstanceRevocationPublisher>,
) {
    private val log = KotlinLogging.logger {}

    @Operation(
        summary = "Revoke accounts of vulnerable device classes",
        description = REVOKE_VULNERABLE_DEVICE_CLASSES_DOCS,
    )
    @PostMapping("/revokeDeviceClasses")
    @ResponseBody
    suspend fun revokeVulnerableDeviceClasses(
        @Parameter(description = "True (default) - only report; false - revoke")
        @RequestParam(DRY_RUN_PARAM, defaultValue = "true") dryRun: Boolean,
    ): VulnerableDeviceClassRevocationResponse =
        telemetryService.withSpan("MdvmAdminApi.revokeVulnerableDeviceClasses") {
            val publisher =
                if (dryRun) {
                    null
                } else {
                    revocationPublisherProvider.getIfAvailable() ?: throw MessagingUnavailableException()
                }

            val statistics = Statistics()
            mdvmAccountService.findNonRevokedAccounts().collect { account ->
                val outcome = scanDeviceClass(account)
                val published = outcome.needRevocation() && publisher != null && publishRevocation(publisher, account)
                statistics.add(outcome, published)
            }
            statistics.toResponse()
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

private fun MdvmAccount.toRevocationEvent() =
    WalletInstanceRevocationEvent(
        eventId = UUID.randomUUID().toString(),
        wiHandle = authPublicKey.jwkThumbprint().toString(),
        occurredAt = Instant.now().toString(),
        source = Module.MDVM.name,
    )
