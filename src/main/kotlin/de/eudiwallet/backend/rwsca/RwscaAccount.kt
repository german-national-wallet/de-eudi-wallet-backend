package de.eudiwallet.backend.rwsca

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.UUID

@Serializable(with = RwscaAccountIdSerializer::class)
@JvmInline
value class RwscaAccountId(
    val id: UUID,
) {
    override fun toString() = id.toString()
}

object RwscaAccountIdSerializer : KSerializer<RwscaAccountId> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("RwscaAccountId", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: RwscaAccountId,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): RwscaAccountId = RwscaAccountId(UUID.fromString(decoder.decodeString()))
}

sealed class RwscaAccount(
    open val rwscaAccountId: RwscaAccountId,
) {
    data class WithoutPin(
        override val rwscaAccountId: RwscaAccountId,
    ) : RwscaAccount(rwscaAccountId)

    data class WithPin(
        override val rwscaAccountId: RwscaAccountId,
        val pinPubKey: ECPublicKey,
        val pinTryCounter: Int,
        val pinTryFailedAt: Instant?,
    ) : RwscaAccount(rwscaAccountId)
}
