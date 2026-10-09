package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.telemetry.walletGaugeBuilder
import io.opentelemetry.api.common.AttributeKey.stringKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.concurrent.ConcurrentHashMap

@Component
class KeyRolloverMetrics(
    meter: Meter,
) {
    private data class DatedKey(
        val keyId: HsmKeyId,
        val keyLabel: String,
        val date: LocalDate,
    )

    private val primaryKeyExpiryByLineage = ConcurrentHashMap<String, DatedKey>()
    private val nextKeyStartByLineage = ConcurrentHashMap<String, DatedKey>()

    init {
        meter.daysUntilGauge(
            "primary_key_time_to_expiry",
            "Days until the primary key of a lineage expires",
            primaryKeyExpiryByLineage,
        )
        meter.daysUntilGauge(
            "next_key_time_to_primary",
            "Days until the next key of a lineage is scheduled to become primary",
            nextKeyStartByLineage,
        )
    }

    fun setPrimaryKeyExpiryDate(
        lineage: String,
        key: HsmKey,
        expiryDate: LocalDate,
    ) {
        if (expiryDate != LocalDate.MAX) {
            primaryKeyExpiryByLineage[lineage] = DatedKey(key.keyId, key.label, expiryDate)
        } else {
            primaryKeyExpiryByLineage.remove(lineage)
        }
    }

    fun setNextKey(
        lineage: String,
        nextKey: HsmKey?,
    ) {
        if (nextKey != null) {
            nextKeyStartByLineage[lineage] = DatedKey(nextKey.keyId, nextKey.label, nextKey.startDate)
        } else {
            nextKeyStartByLineage.remove(lineage)
        }
    }

    private fun Meter.daysUntilGauge(
        name: String,
        description: String,
        keyByLineage: Map<String, DatedKey>,
    ) = walletGaugeBuilder(name, description)
        .ofLongs()
        .setUnit("d")
        .buildWithCallback { measurement ->
            keyByLineage.forEach { (lineage, key) ->
                measurement.record(
                    ChronoUnit.DAYS.between(LocalDate.now(), key.date),
                    Attributes.of(
                        stringKey("lineage"),
                        lineage,
                        stringKey("key_id"),
                        key.keyId.value,
                        stringKey("key_label"),
                        key.keyLabel,
                    ),
                )
            }
        }
}
