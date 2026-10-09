package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder
import de.eudiwallet.backend.shared.mdvmtoken.MdvmToken

internal const val EXAMPLE_INSTANT = "2025-01-24T10:00:00Z"

internal const val MDVM_AUTH_CHALLENGE_EXAMPLE =
    "Header {kid, typ: ${ChallengeTokenBuilder.JWT_TYPE}, alg: HS256}; payload {iss, nonce: <UUID>, iat}."

internal const val MDVM_TOKEN_EXAMPLE =
    "Header {typ: ${MdvmToken.JWT_TYPE}, alg: ES256, x5c: [<MDVM signing chain>]}; " +
        "payload {iss, mdvm_wi_id, cnf: {jwk: <wallet instance EC P-256 JWK>}, iat, exp}."

const val DEVICECHECK_ATTESTATION_EXAMPLE = "<base64-encoded-devicecheck-attestation>"

const val DEVICECHECK_ASSERTION_EXAMPLE = "<base64-encoded-devicecheck-assertion>"

const val ANDROID_KEY_ATTESTATION_EXAMPLE = """["<base64-encoded-certificate-1>", "<base64-encoded-certificate-2>"]"""

const val IOS_DEVICE_INFO_EXAMPLE = """
    {
        "systemVersion": "26.3",
        "uname": "",
        "model": "iPhone",
        "hardwareModel": "iPhone15,3",
        "osVersion": "Version 26.3 (Build 23D127)"
    }
"""

const val ANDROID_DEVICE_INFO_EXAMPLE = """
    {
        "model": "sdk_gphone64_arm64",
        "device": "emu64a",
        "product": "sdk_gphone64_arm64",
        "hardware": "ranchu",
        "versionPatch": "2026-01-05",
        "versionRelease": "16"
    }
"""

private const val CHALLENGE_VERIFICATION_FAILURE =
    """| 400 | `CHALLENGE_VERIFICATION_FAILURE` | Invalid MDVM challenge |"""
private const val CHALLENGE_EXPIRED =
    """| 400 | `CHALLENGE_EXPIRED` | Expired MDVM challenge |"""
private const val SKIP_INTEGRITY_CHECKS_NOT_ALLOWED =
    """| 400 | `SKIP_INTEGRITY_CHECKS_NOT_ALLOWED` | Skipping integrity checks is not allowed for the environment |"""
private const val MALFORMED_KEY =
    """| 400 | `MALFORMED_KEY` | Provided auth public key is malformed or not a valid EC key |"""
private const val ACCOUNT_REVOKED =
    """| 403 | `ACCOUNT_REVOKED` | Account revoked |"""
private const val SECURITY_VIOLATION =
    """| 403 | `SECURITY_VIOLATION` | Device doesn't meet security requirements |"""
private const val OUTDATED_OS_VERSION =
    """| 403 | `OUTDATED_OS_VERSION` | Device OS version is no longer supported |"""
private const val OUTDATED_PATCH_LEVEL =
    """| 403 | `OUTDATED_PATCH_LEVEL` | Device OS doesn't have required security patches |"""
private const val DEVICE_VULNERABLE_FIXABLE =
    """| 403 | `DEVICE_VULNERABLE_FIXABLE` | Device class is affected by a vulnerability a system update resolves |"""
private const val DEVICE_VULNERABLE_UNFIXABLE =
    """| 403 | `DEVICE_VULNERABLE_UNFIXABLE` | Device class is affected by a vulnerability no system update resolves |"""
private const val OUTDATED_APP_VERSION =
    """| 403 | `OUTDATED_APP_VERSION` | Wallet app version is no longer supported |"""
private const val INVALID_BOOTLOADER_STATE =
    """| 403 | `INVALID_BOOTLOADER_STATE` | Device bootloader is unlocked |"""
private const val ACCOUNT_NOT_FOUND =
    """| 404 | `ACCOUNT_NOT_FOUND` | Account with provided ID not found |"""
private const val KEY_ALREADY_REGISTERED =
    """| 409 | `KEY_ALREADY_REGISTERED` | An account already exists for this auth key |"""
private const val GENERIC_BAD_REQUEST = """| 400 | `BAD_REQUEST` | Bad request |"""
private const val SIGNATURE_VERIFICATION_FAILURE =
    """| 401 | `SIGNATURE_VERIFICATION_FAILURE` | HTTP message signature verification failed |"""
private const val WRONG_CONTENT_DIGEST =
    """| 401 | `WRONG_CONTENT_DIGEST` | Content Digest header doesn't correspond to the request body |"""
private const val CONTENT_LENGTH_EXCEEDED =
    """| 400 | `CONTENT_LENGTH_EXCEEDED` | Request body is too long |"""
private const val INTERNAL_SERVER_ERROR = """| 500 | `INTERNAL_SERVER_ERROR` | Generic error |"""
private const val DB_UNAVAILABLE = """| 503 | `DB_UNAVAILABLE` | Database unavailable |"""
private const val HSM_UNAVAILABLE = """| 503 | `HSM_UNAVAILABLE` | HSM unavailable |"""
private const val MESSAGING_UNAVAILABLE =
    """| 503 | `MESSAGING_UNAVAILABLE` | Messaging is disabled or unavailable |"""

internal const val CHALLENGE_DOCS = """
No signatures required.

| HTTP Status | Error Code | Description |
|---|---|---|
$INTERNAL_SERVER_ERROR
$HSM_UNAVAILABLE
"""

internal const val ANDROID_REGISTER_DOCS = """
Requires signature component `$MDVM_AUTH_SIGNATURE_NAME` containing @method, @path, header(auth-challenge), header (content-digest)

Registration is single-shot per key: the client MUST generate a fresh auth key for every install and MUST NOT
reuse a key it holds no `mdvm_wi_id` for (there is no recovery path). Registering a key that already has an
account — active or revoked — is rejected with 409 `KEY_ALREADY_REGISTERED`.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MALFORMED_KEY
$SECURITY_VIOLATION
$DEVICE_VULNERABLE_FIXABLE
$DEVICE_VULNERABLE_UNFIXABLE
$OUTDATED_OS_VERSION
$OUTDATED_PATCH_LEVEL
$OUTDATED_APP_VERSION
$INVALID_BOOTLOADER_STATE
$SKIP_INTEGRITY_CHECKS_NOT_ALLOWED
$GENERIC_BAD_REQUEST
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$KEY_ALREADY_REGISTERED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val ANDROID_RENEWAL_DOCS = """
Requires signature components `$MDVM_AUTH_SIGNATURE_NAME` and `$MDVM_ANDROID_REATTEST_SIGNATURE_NAME` containing @method, @path, header(auth-challenge), header(mdvm-wi-id),  header (content-digest)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$ACCOUNT_NOT_FOUND
$SECURITY_VIOLATION
$DEVICE_VULNERABLE_FIXABLE
$DEVICE_VULNERABLE_UNFIXABLE
$OUTDATED_OS_VERSION
$OUTDATED_PATCH_LEVEL
$OUTDATED_APP_VERSION
$INVALID_BOOTLOADER_STATE
$ACCOUNT_REVOKED
$SKIP_INTEGRITY_CHECKS_NOT_ALLOWED
$GENERIC_BAD_REQUEST
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val IOS_REGISTER_DOCS = """
Requires signature component `$MDVM_AUTH_SIGNATURE_NAME` containing @method, @path, header(auth-challenge), header (content-digest)

Registration is single-shot per key: the client MUST generate a fresh auth key for every install and MUST NOT
reuse a key it holds no `mdvm_wi_id` for (there is no recovery path). Registering a key that already has an
account — active or revoked — is rejected with 409 `KEY_ALREADY_REGISTERED`.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$MALFORMED_KEY
$SECURITY_VIOLATION
$DEVICE_VULNERABLE_FIXABLE
$DEVICE_VULNERABLE_UNFIXABLE
$OUTDATED_OS_VERSION
$SKIP_INTEGRITY_CHECKS_NOT_ALLOWED
$GENERIC_BAD_REQUEST
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$KEY_ALREADY_REGISTERED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val IOA_RENEWAL_DOCS = """
Requires signature component `$MDVM_AUTH_SIGNATURE_NAME` containing @method, @path, header(auth-challenge), header(mdvm-wi-id), header (content-digest)

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$ACCOUNT_NOT_FOUND
$SECURITY_VIOLATION
$DEVICE_VULNERABLE_FIXABLE
$DEVICE_VULNERABLE_UNFIXABLE
$OUTDATED_OS_VERSION
$ACCOUNT_REVOKED
$SKIP_INTEGRITY_CHECKS_NOT_ALLOWED
$GENERIC_BAD_REQUEST
$SIGNATURE_VERIFICATION_FAILURE
$WRONG_CONTENT_DIGEST
$CONTENT_LENGTH_EXCEEDED
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val DELETE_ACCOUNT_DOCS = """
Requires signature component `$MDVM_AUTH_SIGNATURE_NAME` containing: @method, @path, header(auth-challenge), header(mdvm-wi-id)

Not exposed to Wallet Instances: the gateway does not route it. A revoked account cannot be deleted.

| HTTP Status | Error Code | Description |
|---|---|---|
$CHALLENGE_VERIFICATION_FAILURE
$CHALLENGE_EXPIRED
$ACCOUNT_REVOKED
$ACCOUNT_NOT_FOUND
$SIGNATURE_VERIFICATION_FAILURE
$GENERIC_BAD_REQUEST
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val REVOKE_VULNERABLE_DEVICE_CLASSES_DOCS = """
No signatures required. Not exposed to Wallet Instances: the gateway uses special authentication for it — an operations
endpoint.

Verifies the stored device data of every non-revoked account against the configured vulnerable device class lists and
revokes accounts which have unfixable vulnerabilities.

| HTTP Status | Error Code | Description |
|---|---|---|
$GENERIC_BAD_REQUEST
$MESSAGING_UNAVAILABLE
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
"""
