package de.eudiwallet.backend.shared.hsm

sealed class HsmException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    class GetSessionFailedException(
        message: String,
    ) : HsmException("Cannot get HSM session from the pool: $message")

    class SessionPoolCreationFailedException(
        cause: Throwable,
    ) : HsmException("Cannot create HSM session pool: ${cause.message}", cause)

    class SlotNotFoundException(
        requiredLabel: String,
        slots: String,
    ) : HsmException(
            "No HSM slot found with label $requiredLabel. Available slots are: $slots",
        )

    class KeyNotFoundException(
        keyId: String,
    ) : HsmException("Key with ID $keyId not found in HSM")

    class KeyLookupFailure(
        key: String?,
        cause: Throwable? = null,
    ) : HsmException("Failed to look up key $key", cause)

    class KeyCreationFailedException(
        cause: Throwable,
    ) : HsmException("HSM key creation failed", cause)

    class KeyWrappingFailedException(
        cause: Throwable,
    ) : HsmException("HSM key wrapping failed", cause)

    class KeyUnwrappingFailedException(
        cause: Throwable,
    ) : HsmException("HSM key unwrapping failed", cause)

    class SigningFailedException(
        cause: Throwable,
    ) : HsmException("HSM signing failed", cause)

    class SignatureVerificationException(
        cause: Throwable,
    ) : HsmException("HSM signature verification failed", cause)

    class EncryptionFailedException(
        cause: Throwable,
    ) : HsmException("HSM encryption failed", cause)

    class DecryptionFailedException(
        cause: Throwable,
    ) : HsmException("HSM decryption failed", cause)
}
