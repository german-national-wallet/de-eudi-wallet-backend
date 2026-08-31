package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class PnsService(
    private val repository: PnsRepository,
    private val telemetryService: TelemetryService,
) {
    suspend fun register(
        accountId: MdvmAccountId,
        mppRegistrationToken: String,
    ) = telemetryService.withSpan("PnsService.register") {
        repository.upsertByAccountId(
            id = UUID.randomUUID(),
            accountId = accountId.id,
            mppRegistrationToken = mppRegistrationToken,
        )
    }

    suspend fun delete(accountId: MdvmAccountId) =
        telemetryService.withSpan("PnsService.delete") {
            repository.deleteByAccountId(accountId.id)
        }
}
