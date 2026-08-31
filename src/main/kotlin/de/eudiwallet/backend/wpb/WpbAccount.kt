package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.interfaces.ECPublicKey
import java.util.UUID

@Serializable(with = WpbAccountIdSerializer::class)
@JvmInline
value class WpbAccountId(
    val id: UUID,
) {
    override fun toString() = id.toString()
}

object WpbAccountIdSerializer : KSerializer<WpbAccountId> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("WpbAccountId", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: WpbAccountId,
    ) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): WpbAccountId = WpbAccountId(UUID.fromString(decoder.decodeString()))
}

data class WpbAccount(
    val wpbAccountId: WpbAccountId,
    val wiMdvmAuthPubk: ECPublicKey,
) {
    companion object {
        fun fromEntity(entity: WpbAccountEntity): WpbAccount =
            WpbAccount(
                wpbAccountId = WpbAccountId(entity.wpbAccountId),
                wiMdvmAuthPubk = entity.wiMdvmAuthPubkDer.ecPublicKeyFromX509(),
            )
    }
}
