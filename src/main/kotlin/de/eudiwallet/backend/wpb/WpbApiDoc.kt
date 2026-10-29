package de.eudiwallet.backend.wpb

import de.eudiwallet.backend.shared.challengetoken.ChallengeTokenBuilder

internal const val CHALLENGE_EXAMPLE =
    "Header {kid, typ: ${ChallengeTokenBuilder.JWT_TYPE}, alg: HS256}; payload {iss, nonce: <UUID>, iat}."
internal const val WIA_EXAMPLE =
    "Header {typ: ${WalletInstanceAttestationBuilder.JWT_TYPE}, alg: ES256, x5c: [<WIA signing chain>]}; " +
        "payload {iss, sub: <WPB client id>, cnf: {jwk: <wallet instance EC P-256 JWK>}, " +
        "client_status: {status: {status_list: {uri, idx}}, exp}, " +
        "wallet_name, wallet_link, wallet_version, wallet_solution_certification_information, iat, exp}."
internal const val REVOCATION_CODE_EXAMPLE = "rev1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v"

private const val CHALLENGE_VERIFICATION_FAILURE =
    """| 400 | `CHALLENGE_VERIFICATION_FAILURE` | Invalid WPB challenge |"""
private const val CHALLENGE_EXPIRED =
    """| 400 | `CHALLENGE_EXPIRED` | Expired WPB challenge |"""
private const val MALFORMED_WIA_PUB_KEY =
    """| 400 | `MALFORMED_WIA_PUB_KEY` | Provided WIA public key is malformed or not a valid EC key |"""
private const val MDVM_TOKEN_VERIFICATION_FAILURE =
    """| 401 | `MDVM_TOKEN_VERIFICATION_FAILURE` | Invalid MDVM token |"""
private const val MDVM_TOKEN_EXPIRED =
    """| 401 | `MDVM_TOKEN_EXPIRED` | Expired MDVM token |"""
private const val GENERIC_BAD_REQUEST = """| 400 | `BAD_REQUEST` | Bad request |"""
private const val SIGNATURE_VERIFICATION_FAILURE =
    """| 401 | `SIGNATURE_VERIFICATION_FAILURE` | HTTP message signature verification failed |"""
private const val WRONG_CONTENT_DIGEST =
    """| 401 | `WRONG_CONTENT_DIGEST` | Content Digest header doesn't correspond to the request body |"""
private const val CONTENT_LENGTH_EXCEEDED =
    """| 400 | `CONTENT_LENGTH_EXCEEDED` | Request body is too long |"""
private const val ACCOUNT_REVOKED = """| 403 | `ACCOUNT_REVOKED` | Account revoked |"""
private const val ACCOUNT_NOT_FOUND =
    """| 404 | `ACCOUNT_NOT_FOUND` | Account with provided ID or auth key not found |"""
private const val KEY_ALREADY_REGISTERED =
    """| 409 | `KEY_ALREADY_REGISTERED` | An account already exists for this MDVM account |"""
private const val REVOCATION_CODE_NOT_FOUND =
    """| 404 | `REVOCATION_CODE_NOT_FOUND` | Revocation code is malformed or matches no account |"""
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

internal const val REGISTER_DOCS = """
Requires signature component `wpb-auth-sig` containing @method, @path, header(auth-challenge), header (mdvm-token)

Registration is single-shot per MDVM account. Registering again while a WPB account exists for it — active or
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
$HSM_UNAVAILABLE
"""

internal const val REVOKE_DOCS = """
No signatures required: valid revocation code is sufficient for the authorization. 
Valid code initiates revocation process and returns HTTP 202. Revocation continues in the background."

| HTTP Status | Error Code | Description |
|---|---|---|
$GENERIC_BAD_REQUEST
$REVOCATION_CODE_NOT_FOUND
$INTERNAL_SERVER_ERROR
$MESSAGING_UNAVAILABLE
"""

internal const val ATTESTATION_DOCS = """
Requires signature components `wpb-auth-sig` and `wpb-wia-sig` containing: @method, @path, header(wpb-wi-id), header(auth-challenge), header(mdvm-token), header(content-digest)

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
$MALFORMED_WIA_PUB_KEY
$ACCOUNT_REVOKED
$ACCOUNT_NOT_FOUND
$INTERNAL_SERVER_ERROR
$DB_UNAVAILABLE
$HSM_UNAVAILABLE
"""

internal const val DELETE_ACCOUNT_DOCS = """
Requires signature component `wpb-auth-sig` containing: @method, @path, header(wpb-wi-id), header(auth-challenge), header(mdvm-token)

Not exposed to Wallet Instances: the gateway does not route it. A revoked account cannot be deleted.

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
$HSM_UNAVAILABLE
"""
