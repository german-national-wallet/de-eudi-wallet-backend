package de.eudiwallet.backend.shared.crypto

import java.security.MessageDigest

const val ALGORITHM_SHA256 = "SHA-256"
const val SHA256_DIGEST_SIZE = 32

fun String.toSha256(): ByteArray = toByteArray().toSha256()

fun ByteArray.toSha256(): ByteArray = MessageDigest.getInstance(ALGORITHM_SHA256, BOUNCY_CASTLE_PROVIDER).digest(this)
