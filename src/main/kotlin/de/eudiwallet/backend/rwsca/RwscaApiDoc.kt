@file:Suppress("MaxLineLength")

package de.eudiwallet.backend.rwsca

import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder

internal const val CHALLENGE_EXAMPLE =
    "Header {kid, typ: ${ChallengeTokenBuilder.JWT_TYPE}, alg: HS256}; payload {iss, nonce: <UUID>, iat}."
internal const val BASE64_ENCODED_HASH_EXAMPLE = "YTZhMGUzYmYtNDcxYS00NDE3LWIwYTQtODEwZmVjNTBhMjMx"
internal const val BASE64_ENCODED_PUBK_EXAMPLE =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/8x7cG7gGnEOxMjC9D7nxtMzEUJmanPZk5w5A9bY+/iitjD2ymuHG0Vl5Jno08RshEtlL24Xe8Kzq3iothxO9Q=="
internal const val PIN_SESSION_TOKEN_EXAMPLE =
    "Header {kid, typ: ${PinSessionTokenBuilder.JWT_TYPE}, alg: HS256}; payload {iss, rwsca_account_id, iat, exp}."
internal const val EXAMPLE_INSTANT = "2025-01-24T10:00:00Z"
internal const val WRAPPED_PRVK_EXAMPLE =
    "Header {kid, iss, typ: ${RwscaBoundWrappedPrvkBuilder.JWT_TYPE}, enc: A256GCM, alg: dir}; " +
        "ciphertext of the wrapped WI private key."
internal const val WTE_EXAMPLE =
    "Header {typ: ${WalletTrustEvidenceBuilder.JWT_TYPE}, alg: ES256, x5c: [<WTE signing chain>]}; " +
        "payload {iss, attested_keys: [<EC P-256 JWK>], key_storage: [iso_18045_high], " +
        "user_authentication: [iso_18045_high], nonce: <pp_c_nonce>, iat, exp}."
internal const val ENCRYPTED_PIN_VALUE_EXAMPLE =
    "JWE compact serialization: header {typ: $PIN_PUBK_JWE_TYPE, alg: ECDH-ES, enc: A256GCM, " +
        "kid: $PIN_ENCRYPTION_KID, epk}; empty encrypted key."
internal const val PIN_ENCRYPTION_JWK_EXAMPLE =
    """{"kty":"EC","crv":"P-256","x":"qQNMuzMT08YiDVgoayr6glNk_uaIQ2DAJli7ybBOJJA",""" +
        """"y":"kehDTJKvD16PZ4QRE7Te-Ecm99y8plrLaINnqabvjj8","kid":"$PIN_ENCRYPTION_KID","use":"enc","alg":"ECDH-ES"}"""
internal const val BASE64_ENCODED_SIGNATURE_EXAMPLE =
    "MEUCIQC9dIZlclNFVYBmfU9FRNn2dkUQdXiQ9nAYMhBFIwIwAiAm0DQiB5CMaXw2KUXYEiKHA1Z4STAhAjRyYVI0Eg=="

private const val CHALLENGE_VERIFICATION_FAILURE =
    """| 400 | `CHALLENGE_VERIFICATION_FAILURE` | Invalid RWSCA challenge |"""
private const val CHALLENGE_EXPIRED =
    """| 400 | `CHALLENGE_EXPIRED` | Expired RWSCA challenge |"""
private const val MDVM_TOKEN_VERIFICATION_FAILURE =
    """| 401 | `MDVM_TOKEN_VERIFICATION_FAILURE` | Invalid MDVM token |"""
private const val MDVM_TOKEN_EXPIRED =
    """| 401 | `MDVM_TOKEN_EXPIRED` | Expired MDVM token |"""
private const val SIGNATURE_VERIFICATION_FAILURE =
    """| 401 | `SIGNATURE_VERIFICATION_FAILURE` | HTTP message signature verification failed |"""
private const val WRONG_CONTENT_DIGEST =
    """| 401 | `WRONG_CONTENT_DIGEST` | Content Digest header doesn't correspond to the request body |"""
private const val CONTENT_LENGTH_EXCEEDED =
    """| 400 | `CONTENT_LENGTH_EXCEEDED` | Request body is too long |"""
private const val MALFORMED_PIN_PUB_KEY =
    """| 400 | `MALFORMED_PIN_PUB_KEY` | Provided PIN public key is malformed or not a valid EC key |"""
private const val GENERIC_BAD_REQUEST = """| 400 | `BAD_REQUEST` | Bad request |"""
private const val ACCOUNT_LOCKED = """| 403 | `ACCOUNT_LOCKED` | Account is locked |"""
private const val ACCOUNT_REVOKED = """| 403 | `ACCOUNT_REVOKED` | Account revoked |"""
private const val ACCOUNT_NOT_FOUND =
    """| 404 | `ACCOUNT_NOT_FOUND` | Account with provided ID or auth key not found |"""
private const val KEY_ALREADY_REGISTERED =
    """| 409 | `KEY_ALREADY_REGISTERED` | An account already exists for this MDVM account |"""
private const val PIN_NOT_INITIALIZED =
    """| 409 | `PIN_NOT_INITIALIZED` | Account PIN was not initialized |"""
private const val PIN_ALREADY_INITIALIZED =
    """| 409 | `PIN_ALREADY_INITIALIZED` | PIN was already initialized for this account |"""
private const val PIN_VERIFICATION_FAILED =
    """| 401 | `PIN_VERIFICATION_FAILED` | PIN verification failed; check tryCounter and tryAllowedAfter for retry info |"""
private const val PIN_RETRY_BLOCKED =
    """| 429 | `PIN_RETRY_BLOCKED` | PIN retry blocked due to backoff delay; check tryAllowedAfter |"""
private const val PIN_SESSION_TOKEN_VERIFICATION_FAILURE =
    """| 401 | `PIN_SESSION_TOKEN_VERIFICATION_FAILURE` | Invalid or expired pin session token |"""
private const val WRAPPED_PRVK_VERIFICATION_FAILURE =
    """| 401 | `WRAPPED_PRVK_VERIFICATION_FAILURE` | Invalid or malformed wrapped private key |"""
private const val MALFORMED_DATA_HASH =
    """| 400 | `MALFORMED_DATA_HASH` | Provided data hash is malformed or not a valid SHA-256 hash |"""
private const val INTERNAL_SERVER_ERROR = """| 500 | `INTERNAL_SERVER_ERROR` | Generic error |"""
private const val DB_UNAVAILABLE = """| 503 | `DB_UNAVAILABLE` | Database unavailable |"""
private const val HSM_UNAVAILABLE = """| 503 | `HSM_UNAVAILABLE` | HSM unavailable |"""

internal const val CHALLENGE_DOCS = """
No signatures required.

| HTTP Status | Error Code | Description |
|---|---|---|
$INTERNAL_SERVER_ERROR
"""

internal const val REGISTER_DOCS = """
Requires signature component `rwsca-auth-sig` containing @method, @path, header(auth-challenge), header (mdvm-token)

Registration is single-shot per MDVM account. Registering again while an RWSCA account exists for it — active or
revoked — is rejected with 409 `KEY_ALREADY_REGISTERED`. Only deleting a non-revoked account reopens registration; a
revoked one cannot be deleted.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$KEY_ALREADY_REGISTERED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

internal const val INITIALIZE_PIN_AND_START_PIN_SESSION_DOCS = """
Requires signature components `rwsca-auth-sig` and `rwsca-pin-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token), header(content-digest)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$GENERIC_BAD_REQUEST
$MALFORMED_PIN_PUB_KEY
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$PIN_ALREADY_INITIALIZED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

private const val ENCRYPTED_PIN_SIGNATURE =
    """The `rwsca-pin-sig` value in `Signature` is the sf-binary of the UTF-8 bytes of a JWE compact serialization (`typ` "$PIN_SIGNATURE_JWE_TYPE", `alg` ECDH-ES, `enc` A256GCM, `kid` "$PIN_ENCRYPTION_KID", no `zip`, no `crit`) encrypted to `$RWSCA_PIN_ENC_PUBK_FIELD` from `/v2/rwsca/wiMetaData`; its payload is the DER ECDSA signature. A value that does not decrypt is rejected with 401 `SIGNATURE_VERIFICATION_FAILURE` and costs no PIN try."""

internal const val WI_METADATA_DOCS = """
No signatures required.

Returns `$RWSCA_PIN_ENC_PUBK_FIELD`, the P-256 public JWK the WI encrypts its PIN signature and `$WI_RWSCA_PIN_PUBK_FIELD` to.

| HTTP Status | Error Code | Description |
|---|---|---|
$INTERNAL_SERVER_ERROR
"""

internal const val INITIALIZE_PIN_AND_START_PIN_SESSION_V2_DOCS = """
Requires signature components `rwsca-auth-sig` and `rwsca-pin-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token), header(content-digest)

$ENCRYPTED_PIN_SIGNATURE

`$WI_RWSCA_PIN_PUBK_FIELD` is a JWE of the same construction with `typ` "$PIN_PUBK_JWE_TYPE", its payload the DER X.509 public key; one that does not decrypt is rejected with 400 `MALFORMED_PIN_PUB_KEY`.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$GENERIC_BAD_REQUEST
$MALFORMED_PIN_PUB_KEY
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$PIN_ALREADY_INITIALIZED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

internal const val START_PIN_SESSION_V2_DOCS = """
Requires signature components `rwsca-auth-sig` and `rwsca-pin-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token)

$ENCRYPTED_PIN_SIGNATURE

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$PIN_VERIFICATION_FAILED
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$PIN_NOT_INITIALIZED
$PIN_RETRY_BLOCKED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

internal const val START_PIN_SESSION_DOCS = """
Requires signature components `rwsca-auth-sig` and `rwsca-pin-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$PIN_VERIFICATION_FAILED
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$PIN_NOT_INITIALIZED
$PIN_RETRY_BLOCKED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""

internal const val CREATE_KEYS_DOCS = """
Requires signature component `rwsca-auth-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token), header(content-digest)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$GENERIC_BAD_REQUEST
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val SIGN_DATA_DOCS = """
Requires signature component `rwsca-auth-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token), header(pin-session-token), header(content-digest)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$GENERIC_BAD_REQUEST
$MALFORMED_DATA_HASH
$PIN_SESSION_TOKEN_VERIFICATION_FAILURE
$WRAPPED_PRVK_VERIFICATION_FAILURE
$ACCOUNT_REVOKED
$ACCOUNT_LOCKED
$ACCOUNT_NOT_FOUND
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val DELETE_ACCOUNT_DOCS = """
Requires signature component `rwsca-auth-sig` containing: @method, @path, header(rwsca-account-id), header(auth-challenge), header(mdvm-token)

Possession factor only: a locked account can be deleted (delete and re-register is the PIN reset), a revoked account cannot.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MDVM_TOKEN_VERIFICATION_FAILURE
$MDVM_TOKEN_EXPIRED
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$ACCOUNT_REVOKED
$ACCOUNT_NOT_FOUND
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""
