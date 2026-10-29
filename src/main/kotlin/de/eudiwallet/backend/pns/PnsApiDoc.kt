@file:Suppress("MaxLineLength")

package de.eudiwallet.backend.pns

private const val CHALLENGE_VERIFICATION_FAILURE =
    """| 400 | `CHALLENGE_VERIFICATION_FAILURE` | Invalid PNS challenge |"""
private const val CHALLENGE_EXPIRED =
    """| 400 | `CHALLENGE_EXPIRED` | Expired PNS challenge |"""
private const val CONTENT_LENGTH_EXCEEDED =
    """| 400 | `CONTENT_LENGTH_EXCEEDED` | Request body is too long |"""
private const val GENERIC_BAD_REQUEST = """| 400 | `BAD_REQUEST` | Bad request |"""
private const val MDVM_TOKEN_VERIFICATION_FAILURE =
    """| 401 | `MDVM_TOKEN_VERIFICATION_FAILURE` | Invalid MDVM token |"""
private const val MDVM_TOKEN_EXPIRED =
    """| 401 | `MDVM_TOKEN_EXPIRED` | Expired MDVM token |"""
private const val SIGNATURE_VERIFICATION_FAILURE =
    """| 401 | `SIGNATURE_VERIFICATION_FAILURE` | HTTP message signature verification failed |"""
private const val WRONG_CONTENT_DIGEST =
    """| 401 | `WRONG_CONTENT_DIGEST` | Content Digest header doesn't correspond to the request body |"""
private const val INTERNAL_SERVER_ERROR = """| 500 | `INTERNAL_SERVER_ERROR` | Generic error |"""
private const val DB_UNAVAILABLE = """| 503 | `DB_UNAVAILABLE` | Database unavailable |"""

internal const val CHALLENGE_DOCS = """
No signatures required.

| HTTP Status | Error Code | Description |
|---|---|---|
$INTERNAL_SERVER_ERROR
"""

internal const val REGISTER_DOCS = """
Requires signature component `pns-auth-sig` containing @method, @path, header(auth-challenge), header(mdvm-token), header(content-digest).

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$GENERIC_BAD_REQUEST
$CONTENT_LENGTH_EXCEEDED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

internal const val DELETE_DOCS = """
Requires signature component `pns-auth-sig` containing: @method, @path, header(auth-challenge), header(mdvm-token)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""
