package de.eudiwallet.backend.shared.hsm.pkcs11

@Suppress("MagicNumber")
internal object Ck {
    const val TRUE: Byte = 1
    const val FALSE: Byte = 0
    const val UNAVAILABLE_INFORMATION = -1L

    const val CKF_OS_LOCKING_OK = 0x2L
    const val CKF_RW_SESSION = 0x2L
    const val CKF_SERIAL_SESSION = 0x4L

    const val CKU_USER = 1L

    const val CKO_PUBLIC_KEY = 2L
    const val CKO_PRIVATE_KEY = 3L
    const val CKO_SECRET_KEY = 4L

    const val CKK_EC = 3L
    const val CKK_GENERIC_SECRET = 0x10L
    const val CKK_AES = 0x1fL

    const val CKA_CLASS = 0L
    const val CKA_TOKEN = 1L
    const val CKA_LABEL = 3L
    const val CKA_KEY_TYPE = 0x100L
    const val CKA_ID = 0x102L
    const val CKA_VALUE = 0x11L
    const val CKA_SENSITIVE = 0x103L
    const val CKA_ENCRYPT = 0x104L
    const val CKA_WRAP = 0x106L
    const val CKA_SIGN = 0x108L
    const val CKA_VERIFY = 0x10aL
    const val CKA_START_DATE = 0x110L
    const val CKA_END_DATE = 0x111L
    const val CKA_EXTRACTABLE = 0x162L
    const val CKA_EC_PARAMS = 0x180L
    const val CKA_EC_POINT = 0x181L

    const val CKM_SHA256_HMAC = 0x251L
    const val CKM_EC_KEY_PAIR_GEN = 0x1040L
    const val CKM_ECDSA = 0x1041L
    const val CKM_AES_GCM = 0x1087L
    const val CKM_AES_KEY_WRAP = 0x2109L
    const val CKM_AES_KEY_WRAP_PAD = 0x210aL

    const val CKR_OK = 0L
    const val CKR_BUFFER_TOO_SMALL = 0x150L
    const val CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191L
    const val CKR_SIGNATURE_INVALID = 0xc0L
    const val CKR_SIGNATURE_LEN_RANGE = 0xc1L
    const val CKR_ATTRIBUTE_SENSITIVE = 0x11L
    const val CKR_ATTRIBUTE_TYPE_INVALID = 0x12L
    const val CKR_DEVICE_ERROR = 0x30L
    const val CKR_OBJECT_HANDLE_INVALID = 0x82L
    const val CKR_USER_ALREADY_LOGGED_IN = 0x100L

    private val returnValueNames: Map<Long, String> =
        mapOf(
            0L to "CKR_OK",
            0x100L to "CKR_USER_ALREADY_LOGGED_IN",
            0x101L to "CKR_USER_NOT_LOGGED_IN",
            0x102L to "CKR_USER_PIN_NOT_INITIALIZED",
            0x103L to "CKR_USER_TYPE_INVALID",
            0x104L to "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
            0x105L to "CKR_USER_TOO_MANY_TYPES",
            0x10L to "CKR_ATTRIBUTE_READ_ONLY",
            0x110L to "CKR_WRAPPED_KEY_INVALID",
            0x112L to "CKR_WRAPPED_KEY_LEN_RANGE",
            0x113L to "CKR_WRAPPING_KEY_HANDLE_INVALID",
            0x114L to "CKR_WRAPPING_KEY_SIZE_RANGE",
            0x115L to "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
            0x11L to "CKR_ATTRIBUTE_SENSITIVE",
            0x120L to "CKR_RANDOM_SEED_NOT_SUPPORTED",
            0x121L to "CKR_RANDOM_NO_RNG",
            0x12L to "CKR_ATTRIBUTE_TYPE_INVALID",
            0x130L to "CKR_DOMAIN_PARAMS_INVALID",
            0x13L to "CKR_ATTRIBUTE_VALUE_INVALID",
            0x140L to "CKR_CURVE_NOT_SUPPORTED",
            0x150L to "CKR_BUFFER_TOO_SMALL",
            0x160L to "CKR_SAVED_STATE_INVALID",
            0x170L to "CKR_INFORMATION_SENSITIVE",
            0x180L to "CKR_STATE_UNSAVEABLE",
            0x190L to "CKR_CRYPTOKI_NOT_INITIALIZED",
            0x191L to "CKR_CRYPTOKI_ALREADY_INITIALIZED",
            0x1a0L to "CKR_MUTEX_BAD",
            0x1a1L to "CKR_MUTEX_NOT_LOCKED",
            0x1b0L to "CKR_NEW_PIN_MODE",
            0x1b1L to "CKR_NEXT_OTP",
            0x1bL to "CKR_ACTION_PROHIBITED",
            0x1c0L to "CKR_EXCEEDED_MAX_ITERATIONS",
            0x1c1L to "CKR_FIPS_SELF_TEST_FAILED",
            0x1c2L to "CKR_LIBRARY_LOAD_FAILED",
            0x1c3L to "CKR_PIN_TOO_WEAK",
            0x1c4L to "CKR_PUBLIC_KEY_INVALID",
            0x200L to "CKR_FUNCTION_REJECTED",
            0x201L to "CKR_TOKEN_RESOURCE_EXCEEDED",
            0x202L to "CKR_OPERATION_CANCEL_FAILED",
            0x203L to "CKR_KEY_EXHAUSTED",
            0x204L to "CKR_PENDING",
            0x205L to "CKR_SESSION_ASYNC_NOT_SUPPORTED",
            0x206L to "CKR_SEED_RANDOM_REQUIRED",
            0x207L to "CKR_OPERATION_NOT_VALIDATED",
            0x208L to "CKR_TOKEN_NOT_INITIALIZED",
            0x209L to "CKR_PARAMETER_SET_NOT_SUPPORTED",
            0x20L to "CKR_DATA_INVALID",
            0x21L to "CKR_DATA_LEN_RANGE",
            0x30L to "CKR_DEVICE_ERROR",
            0x31L to "CKR_DEVICE_MEMORY",
            0x32L to "CKR_DEVICE_REMOVED",
            0x40L to "CKR_ENCRYPTED_DATA_INVALID",
            0x41L to "CKR_ENCRYPTED_DATA_LEN_RANGE",
            0x42L to "CKR_AEAD_DECRYPT_FAILED",
            0x50L to "CKR_FUNCTION_CANCELED",
            0x51L to "CKR_FUNCTION_NOT_PARALLEL",
            0x54L to "CKR_FUNCTION_NOT_SUPPORTED",
            0x60L to "CKR_KEY_HANDLE_INVALID",
            0x62L to "CKR_KEY_SIZE_RANGE",
            0x63L to "CKR_KEY_TYPE_INCONSISTENT",
            0x64L to "CKR_KEY_NOT_NEEDED",
            0x65L to "CKR_KEY_CHANGED",
            0x66L to "CKR_KEY_NEEDED",
            0x67L to "CKR_KEY_INDIGESTIBLE",
            0x68L to "CKR_KEY_FUNCTION_NOT_PERMITTED",
            0x69L to "CKR_KEY_NOT_WRAPPABLE",
            0x6aL to "CKR_KEY_UNEXTRACTABLE",
            0x70L to "CKR_MECHANISM_INVALID",
            0x71L to "CKR_MECHANISM_PARAM_INVALID",
            0x82L to "CKR_OBJECT_HANDLE_INVALID",
            0x90L to "CKR_OPERATION_ACTIVE",
            0x91L to "CKR_OPERATION_NOT_INITIALIZED",
            0xa0L to "CKR_PIN_INCORRECT",
            0xa1L to "CKR_PIN_INVALID",
            0xa2L to "CKR_PIN_LEN_RANGE",
            0xa3L to "CKR_PIN_EXPIRED",
            0xa4L to "CKR_PIN_LOCKED",
            0xaL to "CKR_CANT_LOCK",
            0xb0L to "CKR_SESSION_CLOSED",
            0xb1L to "CKR_SESSION_COUNT",
            0xb3L to "CKR_SESSION_HANDLE_INVALID",
            0xb4L to "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
            0xb5L to "CKR_SESSION_READ_ONLY",
            0xb6L to "CKR_SESSION_EXISTS",
            0xb7L to "CKR_SESSION_READ_ONLY_EXISTS",
            0xb8L to "CKR_SESSION_READ_WRITE_SO_EXISTS",
            0xc0L to "CKR_SIGNATURE_INVALID",
            0xc1L to "CKR_SIGNATURE_LEN_RANGE",
            0xd0L to "CKR_TEMPLATE_INCOMPLETE",
            0xd1L to "CKR_TEMPLATE_INCONSISTENT",
            0xe0L to "CKR_TOKEN_NOT_PRESENT",
            0xe1L to "CKR_TOKEN_NOT_RECOGNIZED",
            0xe2L to "CKR_TOKEN_WRITE_PROTECTED",
            0xf0L to "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
            0xf1L to "CKR_UNWRAPPING_KEY_SIZE_RANGE",
            0xf2L to "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
            1L to "CKR_CANCEL",
            2L to "CKR_HOST_MEMORY",
            3L to "CKR_SLOT_ID_INVALID",
            5L to "CKR_GENERAL_ERROR",
            6L to "CKR_FUNCTION_FAILED",
            7L to "CKR_ARGUMENTS_BAD",
            8L to "CKR_NO_EVENT",
            9L to "CKR_NEED_TO_CREATE_THREADS",
        )

    fun returnValueName(rv: Long): String = returnValueNames[rv] ?: "0x%x".format(rv)
}
