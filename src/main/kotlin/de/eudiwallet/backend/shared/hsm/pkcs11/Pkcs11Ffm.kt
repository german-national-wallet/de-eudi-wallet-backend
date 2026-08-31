package de.eudiwallet.backend.shared.hsm.pkcs11

import java.lang.foreign.AddressLayout
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap

@Suppress("TooManyFunctions", "MagicNumber")
internal class Pkcs11Ffm private constructor(
    libraryPath: String,
) : Pkcs11 {
    private val functionList: MemorySegment

    init {
        val library =
            if (libraryPath.contains('/')) {
                SymbolLookup.libraryLookup(Path.of(libraryPath), Arena.global())
            } else {
                SymbolLookup.libraryLookup(libraryPath, Arena.global())
            }
        val getFunctionList =
            LINKER.downcallHandle(
                library.find("C_GetFunctionList").orElseThrow {
                    IllegalStateException("$libraryPath exports no C_GetFunctionList")
                },
                FunctionDescriptor.of(ULONG, PTR),
            )
        functionList =
            Arena.ofConfined().use { arena ->
                val listPtr = arena.allocate(PTR)
                check("C_GetFunctionList", getFunctionList.invoke(listPtr) as Long)
                listPtr.get(PTR, 0).reinterpret(FUNCTION_LIST_BYTES)
            }
    }

    private fun function(
        index: Int,
        vararg args: MemoryLayout,
    ): MethodHandle =
        LINKER.downcallHandle(
            functionList.get(PTR, FUNCTION_LIST_HEADER_BYTES + index * ULONG.byteSize()),
            FunctionDescriptor.of(ULONG, *args),
        )

    private val cInitialize = function(0, PTR)
    private val cGetSlotList = function(4, BBOOL, PTR, PTR)
    private val cGetTokenInfo = function(6, ULONG, PTR)
    private val cOpenSession = function(12, ULONG, ULONG, PTR, PTR, PTR)
    private val cCloseSession = function(13, ULONG)
    private val cGetSessionInfo = function(15, ULONG, PTR)
    private val cLogin = function(18, ULONG, ULONG, PTR, ULONG)
    private val cLogout = function(19, ULONG)
    private val cDestroyObject = function(22, ULONG, ULONG)
    private val cGetAttributeValue = function(24, ULONG, ULONG, PTR, ULONG)
    private val cFindObjectsInit = function(26, ULONG, PTR, ULONG)
    private val cFindObjects = function(27, ULONG, PTR, ULONG, PTR)
    private val cFindObjectsFinal = function(28, ULONG)
    private val cEncryptInit = function(29, ULONG, PTR, ULONG)
    private val cEncrypt = function(30, ULONG, PTR, ULONG, PTR, PTR)
    private val cDecryptInit = function(33, ULONG, PTR, ULONG)
    private val cDecrypt = function(34, ULONG, PTR, ULONG, PTR, PTR)
    private val cSignInit = function(42, ULONG, PTR, ULONG)
    private val cSign = function(43, ULONG, PTR, ULONG, PTR, PTR)
    private val cVerifyInit = function(48, ULONG, PTR, ULONG)
    private val cVerify = function(49, ULONG, PTR, ULONG, PTR, ULONG)
    private val cGenerateKeyPair = function(59, ULONG, PTR, PTR, ULONG, PTR, ULONG, PTR, PTR)
    private val cWrapKey = function(60, ULONG, PTR, ULONG, ULONG, PTR, PTR)
    private val cUnwrapKey = function(61, ULONG, PTR, ULONG, PTR, ULONG, PTR, ULONG, PTR)

    init {
        initialize()
    }

    private fun initialize() =
        Arena.ofConfined().use { arena ->
            val args = arena.allocate(INITIALIZE_ARGS)
            args.set(ULONG, INITIALIZE_ARGS_FLAGS_OFFSET, Ck.CKF_OS_LOCKING_OK)
            val rv = cInitialize.invoke(args) as Long
            if (rv != Ck.CKR_CRYPTOKI_ALREADY_INITIALIZED) check("C_Initialize", rv)
        }

    override fun slotList(): LongArray =
        Arena.ofConfined().use { arena ->
            val count = arena.allocate(ULONG)
            check("C_GetSlotList", cGetSlotList.invoke(Ck.TRUE, MemorySegment.NULL, count) as Long)
            val slots = arena.allocate(ULONG, count.get(ULONG, 0))
            check("C_GetSlotList", cGetSlotList.invoke(Ck.TRUE, slots, count) as Long)
            slots.asSlice(0, count.get(ULONG, 0) * ULONG.byteSize()).toArray(ULONG)
        }

    override fun tokenLabel(slotId: Long): String =
        Arena.ofConfined().use { arena ->
            val info = arena.allocate(TOKEN_INFO_BYTES)
            check("C_GetTokenInfo", cGetTokenInfo.invoke(slotId, info) as Long)
            String(info.asSlice(0, TOKEN_LABEL_BYTES).toArray(BYTE), Charsets.UTF_8).trimEnd(' ', '\u0000')
        }

    override fun openSession(slotId: Long): Long =
        Arena.ofConfined().use { arena ->
            val handle = arena.allocate(ULONG)
            val flags = Ck.CKF_SERIAL_SESSION or Ck.CKF_RW_SESSION
            check(
                "C_OpenSession",
                cOpenSession.invoke(slotId, flags, MemorySegment.NULL, MemorySegment.NULL, handle) as Long,
            )
            handle.get(ULONG, 0)
        }

    override fun closeSession(session: Long) = check("C_CloseSession", cCloseSession.invoke(session) as Long)

    override fun login(
        session: Long,
        pin: CharArray,
    ) = Arena.ofConfined().use { arena ->
        val pinBytes = String(pin).toByteArray(Charsets.UTF_8)
        val pinSegment = arena.allocateFrom(BYTE, *pinBytes)
        try {
            val rv = cLogin.invoke(session, Ck.CKU_USER, pinSegment, pinBytes.size.toLong()) as Long
            if (rv != Ck.CKR_USER_ALREADY_LOGGED_IN) check("C_Login", rv)
        } finally {
            pinSegment.fill(0)
            pinBytes.fill(0)
        }
    }

    override fun logout(session: Long) = check("C_Logout", cLogout.invoke(session) as Long)

    override fun sessionInfo(session: Long) =
        Arena.ofConfined().use { arena ->
            check("C_GetSessionInfo", cGetSessionInfo.invoke(session, arena.allocate(SESSION_INFO_BYTES)) as Long)
        }

    override fun generateKeyPair(
        session: Long,
        mechanism: Mechanism,
        publicKeyTemplate: Template,
        privateKeyTemplate: Template,
    ): Pair<Long, Long> =
        Arena.ofConfined().use { arena ->
            val handles = arena.allocate(ULONG, 2)
            check(
                "C_GenerateKeyPair",
                cGenerateKeyPair.invoke(
                    session,
                    arena.mechanism(mechanism).segment,
                    arena.template(publicKeyTemplate),
                    publicKeyTemplate.size.toLong(),
                    arena.template(privateKeyTemplate),
                    privateKeyTemplate.size.toLong(),
                    handles,
                    handles.asSlice(ULONG.byteSize()),
                ) as Long,
            )
            handles.getAtIndex(ULONG, 0) to handles.getAtIndex(ULONG, 1)
        }

    override fun getAttributeValues(
        session: Long,
        obj: Long,
        types: LongArray,
    ): AttributeValues =
        Arena.ofConfined().use { arena ->
            val template = arena.allocate(ATTRIBUTE, types.size.toLong())
            var buffers = Array(types.size) { arena.allocate(OUTPUT_CAPACITY) }
            try {
                fillAttributeTemplate(template, types, buffers)
                var rv = cGetAttributeValue.invoke(session, obj, template, types.size.toLong()) as Long
                if (rv == Ck.CKR_BUFFER_TOO_SMALL) {
                    buffers.forEach { it.fill(0) }
                    fillAttributeTemplate(template, types, null)
                    checkAttributeValue(
                        cGetAttributeValue.invoke(session, obj, template, types.size.toLong()) as Long,
                    )
                    buffers =
                        Array(types.size) { i ->
                            val length = template.get(ULONG, i * ATTRIBUTE.byteSize() + ATTRIBUTE_LENGTH_OFFSET)
                            arena.allocate(if (length == Ck.UNAVAILABLE_INFORMATION) 0 else length)
                        }
                    fillAttributeTemplate(template, types, buffers)
                    rv = cGetAttributeValue.invoke(session, obj, template, types.size.toLong()) as Long
                }
                checkAttributeValue(rv)
                AttributeValues(
                    types.indices.associate { i ->
                        val length = template.get(ULONG, i * ATTRIBUTE.byteSize() + ATTRIBUTE_LENGTH_OFFSET)
                        types[i] to
                            if (length ==
                                Ck.UNAVAILABLE_INFORMATION
                            ) {
                                null
                            } else {
                                buffers[i].asSlice(0, minOf(length, buffers[i].byteSize())).toArray(BYTE)
                            }
                    },
                )
            } finally {
                buffers.forEach { it.fill(0) }
            }
        }

    private fun checkAttributeValue(rv: Long) {
        if (rv != Ck.CKR_ATTRIBUTE_SENSITIVE && rv != Ck.CKR_ATTRIBUTE_TYPE_INVALID) {
            check("C_GetAttributeValue", rv)
        }
    }

    private fun fillAttributeTemplate(
        template: MemorySegment,
        types: LongArray,
        buffers: Array<MemorySegment>?,
    ) = types.forEachIndexed { i, type ->
        val offset = i * ATTRIBUTE.byteSize()
        template.set(ULONG, offset, type)
        val buffer = buffers?.get(i)
        template.set(PTR, offset + ATTRIBUTE_VALUE_OFFSET, buffer ?: MemorySegment.NULL)
        template.set(ULONG, offset + ATTRIBUTE_LENGTH_OFFSET, buffer?.byteSize() ?: 0)
    }

    override fun destroyObject(
        session: Long,
        obj: Long,
    ) = check("C_DestroyObject", cDestroyObject.invoke(session, obj) as Long)

    override fun findObjects(
        session: Long,
        template: Template,
        limit: Int,
    ): LongArray =
        Arena.ofConfined().use { arena ->
            check(
                "C_FindObjectsInit",
                cFindObjectsInit.invoke(session, arena.template(template), template.size.toLong()) as Long,
            )
            val found = mutableListOf<Long>()
            var completed = false
            try {
                val pageSize = minOf(limit, FIND_PAGE_SIZE).toLong()
                val page = arena.allocate(ULONG, pageSize)
                val count = arena.allocate(ULONG)
                do {
                    check("C_FindObjects", cFindObjects.invoke(session, page, pageSize, count) as Long)
                    val n = minOf(count.get(ULONG, 0), pageSize)
                    for (i in 0 until n) found.add(page.getAtIndex(ULONG, i))
                } while (n > 0 && found.size < limit)
                completed = true
            } finally {
                val rv = cFindObjectsFinal.invoke(session) as Long
                if (completed) check("C_FindObjectsFinal", rv)
            }
            found.take(limit).toLongArray()
        }

    override fun wrapKey(
        session: Long,
        mechanism: Mechanism,
        wrappingKey: Long,
        key: Long,
    ): ByteArray =
        Arena.ofConfined().use { arena ->
            val mech = arena.mechanism(mechanism).segment
            arena.output("C_WrapKey", OUTPUT_CAPACITY) { out, outLen ->
                cWrapKey.invoke(session, mech, wrappingKey, key, out, outLen) as Long
            }
        }

    override fun unwrapKey(
        session: Long,
        mechanism: Mechanism,
        unwrappingKey: Long,
        wrappedKey: ByteArray,
        template: Template,
    ): Long =
        Arena.ofConfined().use { arena ->
            val handle = arena.allocate(ULONG)
            check(
                "C_UnwrapKey",
                cUnwrapKey.invoke(
                    session,
                    arena.mechanism(mechanism).segment,
                    unwrappingKey,
                    arena.allocateFrom(BYTE, *wrappedKey),
                    wrappedKey.size.toLong(),
                    arena.template(template),
                    template.size.toLong(),
                    handle,
                ) as Long,
            )
            handle.get(ULONG, 0)
        }

    override fun sign(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray =
        Arena.ofConfined().use { arena ->
            check("C_SignInit", cSignInit.invoke(session, arena.mechanism(mechanism).segment, key) as Long)
            val input = arena.allocateFrom(BYTE, *data)
            arena.output("C_Sign", outputCapacity(data)) { out, outLen ->
                cSign.invoke(session, input, data.size.toLong(), out, outLen) as Long
            }
        }

    override fun verify(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
        signature: ByteArray,
    ) = Arena.ofConfined().use { arena ->
        check("C_VerifyInit", cVerifyInit.invoke(session, arena.mechanism(mechanism).segment, key) as Long)
        check(
            "C_Verify",
            cVerify.invoke(
                session,
                arena.allocateFrom(BYTE, *data),
                data.size.toLong(),
                arena.allocateFrom(BYTE, *signature),
                signature.size.toLong(),
            ) as Long,
        )
    }

    override fun encrypt(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray =
        Arena.ofConfined().use { arena ->
            val mech = arena.mechanism(mechanism)
            check("C_EncryptInit", cEncryptInit.invoke(session, mech.segment, key) as Long)
            val input = arena.allocateFrom(BYTE, *data)
            try {
                val output =
                    arena.output("C_Encrypt", outputCapacity(data)) { out, outLen ->
                        cEncrypt.invoke(session, input, data.size.toLong(), out, outLen) as Long
                    }
                mech.readBackIv()
                output
            } finally {
                input.fill(0)
            }
        }

    override fun decrypt(
        session: Long,
        mechanism: Mechanism,
        key: Long,
        data: ByteArray,
    ): ByteArray =
        Arena.ofConfined().use { arena ->
            check("C_DecryptInit", cDecryptInit.invoke(session, arena.mechanism(mechanism).segment, key) as Long)
            val input = arena.allocateFrom(BYTE, *data)
            arena.output("C_Decrypt", outputCapacity(data)) { out, outLen ->
                cDecrypt.invoke(session, input, data.size.toLong(), out, outLen) as Long
            }
        }

    private inline fun Arena.output(
        function: String,
        capacity: Long,
        call: (out: MemorySegment, outLen: MemorySegment) -> Long,
    ): ByteArray {
        var out = allocate(capacity)
        val outLen = allocate(ULONG)
        outLen.set(ULONG, 0, capacity)
        try {
            var rv = call(out, outLen)
            if (rv == Ck.CKR_BUFFER_TOO_SMALL) {
                out.fill(0)
                out = allocate(outLen.get(ULONG, 0))
                outLen.set(ULONG, 0, out.byteSize())
                rv = call(out, outLen)
            }
            check(function, rv)
            return out.asSlice(0, outLen.get(ULONG, 0)).toArray(BYTE)
        } finally {
            out.fill(0)
        }
    }

    private fun Arena.template(template: Template): MemorySegment {
        val segment = allocate(ATTRIBUTE, template.size.toLong())
        template.forEachIndexed { i, attr ->
            val value =
                when (val v = attr.value) {
                    is Boolean -> allocateFrom(BBOOL, if (v) Ck.TRUE else Ck.FALSE)
                    is Long -> allocateFrom(ULONG, v)
                    is ByteArray -> allocateFrom(BYTE, *v)
                    is String -> allocateFrom(BYTE, *v.toByteArray(Charsets.UTF_8))
                    else -> error("Unsupported attribute value type ${v::class}")
                }
            val offset = i * ATTRIBUTE.byteSize()
            segment.set(ULONG, offset, attr.type)
            segment.set(PTR, offset + ATTRIBUTE_VALUE_OFFSET, value)
            segment.set(ULONG, offset + ATTRIBUTE_LENGTH_OFFSET, value.byteSize())
        }
        return segment
    }

    private class NativeMechanism(
        val segment: MemorySegment,
        private val iv: MemorySegment?,
        private val mechanism: Mechanism,
    ) {
        fun readBackIv() {
            if (iv != null && mechanism is Mechanism.AesGcm) {
                MemorySegment.copy(iv, BYTE, 0, mechanism.iv, 0, mechanism.iv.size)
            }
        }
    }

    private fun Arena.mechanism(mechanism: Mechanism): NativeMechanism {
        val segment = allocate(MECHANISM)
        segment.set(ULONG, 0, mechanism.id)
        var iv: MemorySegment? = null
        if (mechanism is Mechanism.AesGcm) {
            iv = allocateFrom(BYTE, *mechanism.iv)
            val params = allocate(GCM_PARAMS)
            params.set(PTR, GCM_IV_OFFSET, iv)
            params.set(ULONG, GCM_IV_LENGTH_OFFSET, mechanism.iv.size.toLong())
            params.set(ULONG, GCM_IV_BITS_OFFSET, mechanism.iv.size * Byte.SIZE_BITS.toLong())
            val aad = mechanism.aad
            params.set(PTR, GCM_AAD_OFFSET, if (aad == null) MemorySegment.NULL else allocateFrom(BYTE, *aad))
            params.set(ULONG, GCM_AAD_LENGTH_OFFSET, aad?.size?.toLong() ?: 0)
            params.set(ULONG, GCM_TAG_BITS_OFFSET, mechanism.tagBits)
            segment.set(PTR, MECHANISM_PARAMETER_OFFSET, params)
            segment.set(ULONG, MECHANISM_PARAMETER_LENGTH_OFFSET, GCM_PARAMS.byteSize())
        } else {
            segment.set(PTR, MECHANISM_PARAMETER_OFFSET, MemorySegment.NULL)
            segment.set(ULONG, MECHANISM_PARAMETER_LENGTH_OFFSET, 0)
        }
        return NativeMechanism(segment, iv, mechanism)
    }

    private fun check(
        function: String,
        rv: Long,
    ) {
        if (rv != Ck.CKR_OK) throw Pkcs11Exception(function, rv)
    }

    companion object {
        private val loaded = ConcurrentHashMap<String, Pkcs11Ffm>()

        fun load(libraryPath: String): Pkcs11 = loaded.computeIfAbsent(libraryPath) { Pkcs11Ffm(it) }

        private val LINKER: Linker = Linker.nativeLinker()
        private val ULONG: ValueLayout.OfLong = ValueLayout.JAVA_LONG
        private val PTR: AddressLayout = ValueLayout.ADDRESS
        private val BYTE: ValueLayout.OfByte = ValueLayout.JAVA_BYTE
        private val BBOOL: ValueLayout.OfByte = ValueLayout.JAVA_BYTE

        private const val FUNCTION_LIST_HEADER_BYTES = 8L
        private const val FUNCTION_LIST_BYTES = FUNCTION_LIST_HEADER_BYTES + 68 * 8L

        private val ATTRIBUTE = MemoryLayout.structLayout(ULONG, PTR, ULONG)
        private const val ATTRIBUTE_VALUE_OFFSET = 8L
        private const val ATTRIBUTE_LENGTH_OFFSET = 16L

        private val MECHANISM = MemoryLayout.structLayout(ULONG, PTR, ULONG)
        private const val MECHANISM_PARAMETER_OFFSET = 8L
        private const val MECHANISM_PARAMETER_LENGTH_OFFSET = 16L

        private val GCM_PARAMS = MemoryLayout.structLayout(PTR, ULONG, ULONG, PTR, ULONG, ULONG)
        private const val GCM_IV_OFFSET = 0L
        private const val GCM_IV_LENGTH_OFFSET = 8L
        private const val GCM_IV_BITS_OFFSET = 16L
        private const val GCM_AAD_OFFSET = 24L
        private const val GCM_AAD_LENGTH_OFFSET = 32L
        private const val GCM_TAG_BITS_OFFSET = 40L

        private val INITIALIZE_ARGS = MemoryLayout.structLayout(PTR, PTR, PTR, PTR, ULONG, PTR)
        private const val INITIALIZE_ARGS_FLAGS_OFFSET = 32L

        private const val TOKEN_INFO_BYTES = 256L
        private const val TOKEN_LABEL_BYTES = 32L
        private const val SESSION_INFO_BYTES = 32L

        private const val OUTPUT_CAPACITY = 512L
        private const val OUTPUT_OVERHEAD = 64L
        private const val FIND_PAGE_SIZE = 200

        private fun outputCapacity(input: ByteArray) = maxOf(OUTPUT_CAPACITY, input.size + OUTPUT_OVERHEAD)
    }
}
