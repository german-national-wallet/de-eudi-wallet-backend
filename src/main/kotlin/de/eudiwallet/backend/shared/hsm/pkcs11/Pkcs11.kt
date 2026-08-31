package de.eudiwallet.backend.shared.hsm.pkcs11

@Suppress("TooManyFunctions")
internal interface Pkcs11 {
    fun slotList(): LongArray

    fun tokenLabel(slotId: Long): String

    fun openSession(slotId: Long): Long

    fun closeSession(session: Long)

    fun login(
        session: Long,
        pin: CharArray,
    )

    fun logout(session: Long)

    fun sessionInfo(session: Long)

    fun generateKeyPair(
        session: Long,
        mechanism: Mechanism,
        publicKeyTemplate: Template,
        privateKeyTemplate: Template,
    ): Pair<Long, Long>

    fun getAttributeValues(
        session: Long,
        obj: Long,
        types: LongArray,
    ): AttributeValues

    fun destroyObject(
        session: Long,
        obj: Long,
    )

    fun findObjects(
        session: Long,
        template: Template,
        limit: Int = Int.MAX_VALUE,
    ): LongArray

    fun wrapKey(
        session: Long,
        mechanism: Mechanism,
        wrappingKey: Long,
        key: Long,
    ): ByteArray

    fun unwrapKey(
        session: Long,
        mechanism: Mechanism,
        unwrappingKey: Long,
        wrappedKey: ByteArray,
        template: Template,
    ): Long

    fun sign(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray

    fun verify(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
        signature: ByteArray,
    )

    fun encrypt(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray

    fun decrypt(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray
}
