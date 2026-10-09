package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.telemetry.walletCounterBuilder
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.metrics.Meter
import org.springframework.stereotype.Component

private val IOS_MODEL_PATTERN = Regex("""(iPhone|iPad|iPod)(\d{1,2},\d{1,2})?""")

private val ANDROID_DEVICE_ID_PATTERN = Regex("""[A-Za-z0-9 ._-]{1,32}""")

private val OS_VERSION_PATTERN = Regex("""\d{1,3}(\.\d{1,4}){0,2}""")

private val OS_PATCH_LEVEL_PATTERN = Regex("""\d{4}\.\d{2}""")

private const val OTHER_DIMENSION_VALUE = "other"
private const val UNKNOWN_DIMENSION_VALUE = "unknown"

sealed interface DeviceMetricDimensions {
    fun toAttributes(): Attributes

    data class Ios(
        val model: String,
        val systemVersion: String,
    ) : DeviceMetricDimensions {
        override fun toAttributes(): Attributes =
            Attributes.builder()
                .put("mdvm.deviceType", "IOS")
                .put("mdvm.model", model.normalizedTo(IOS_MODEL_PATTERN))
                .put("mdvm.systemVersion", systemVersion.normalizedTo(OS_VERSION_PATTERN))
                .build()
    }

    data class Android(
        val attestationIdModel: String?,
        val attestationIdProduct: String?,
        val attestationIdDevice: String?,
        val osVersion: String?,
        val osPatchLevel: String?,
    ) : DeviceMetricDimensions {
        override fun toAttributes(): Attributes =
            Attributes.builder()
                .put("mdvm.deviceType", "ANDROID")
                .put("mdvm.attestationIdModel", attestationIdModel.normalizedTo(ANDROID_DEVICE_ID_PATTERN))
                .put("mdvm.attestationIdProduct", attestationIdProduct.normalizedTo(ANDROID_DEVICE_ID_PATTERN))
                .put("mdvm.attestationIdDevice", attestationIdDevice.normalizedTo(ANDROID_DEVICE_ID_PATTERN))
                .put("mdvm.osVersion", osVersion.normalizedTo(OS_VERSION_PATTERN))
                .put("mdvm.osPatchLevel", osPatchLevel.normalizedTo(OS_PATCH_LEVEL_PATTERN))
                .build()
    }

    fun String?.normalizedTo(pattern: Regex): String =
        when {
            this == null -> UNKNOWN_DIMENSION_VALUE
            pattern.matches(this) -> this
            else -> OTHER_DIMENSION_VALUE
        }
}

@Component
class MdvmMetrics(
    meter: Meter,
) {
    private val deviceRegisteredCounter by lazy {
        meter.walletCounterBuilder("mdvm_device_registered", "Devices registered, by normalized device properties")
            .build()
    }

    private val deviceRenewedCounter by lazy {
        meter.walletCounterBuilder("mdvm_device_renewed", "MDVM token renewals, by normalized device properties")
            .build()
    }

    fun countDeviceRegistered(dimensions: DeviceMetricDimensions) =
        deviceRegisteredCounter.add(1, dimensions.toAttributes())

    fun countDeviceRenewed(dimensions: DeviceMetricDimensions) = deviceRenewedCounter.add(1, dimensions.toAttributes())
}
