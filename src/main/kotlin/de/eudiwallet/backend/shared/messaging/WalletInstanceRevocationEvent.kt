package de.eudiwallet.backend.shared.messaging

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.util.UUID

@Serializable
data class WalletInstanceRevocationEvent(
    val eventId: String,
    @Serializable(with = UuidAsStringSerializer::class)
    val mdvmWiId: UUID,
    val occurredAt: String,
    val source: String,
    val reason: String,
)

internal enum class Module { WPB, RWSCA, MDVM }

internal enum class RevocationReason { USER_REVOKE, MDVM_REVOKE }

internal object UuidAsStringSerializer : KSerializer<UUID> {
    override val descriptor = PrimitiveSerialDescriptor("java.util.UUID", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: UUID,
    ) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): UUID {
        val raw = decoder.decodeString()
        return try {
            UUID.fromString(raw)
        } catch (ex: IllegalArgumentException) {
            throw SerializationException("Not a UUID: $raw", ex)
        }
    }
}
