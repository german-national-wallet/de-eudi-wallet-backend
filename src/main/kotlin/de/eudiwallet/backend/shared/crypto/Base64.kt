package de.eudiwallet.backend.shared.crypto

import java.util.Base64

fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this)

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)
