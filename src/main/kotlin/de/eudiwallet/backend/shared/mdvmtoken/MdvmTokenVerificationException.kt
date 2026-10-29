package de.eudiwallet.backend.shared.mdvmtoken

class MdvmTokenVerificationException(
    cause: Throwable,
) : RuntimeException("Malformed MDVM token", cause)

class MdvmTokenExpiredException(
    cause: Throwable,
) : RuntimeException("MDVM token is expired", cause)
