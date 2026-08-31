package de.eudiwallet.backend.shared.hsm.pkcs11

internal class Pkcs11Exception(
    val function: String,
    val rv: Long,
) : RuntimeException("$function returned ${Ck.returnValueName(rv)}")
