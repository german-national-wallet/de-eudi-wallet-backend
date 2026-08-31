package de.eudiwallet.backend.shared.httpsignature

import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.Parameters
import io.swagger.v3.oas.annotations.enums.ParameterIn

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@Parameters(
    Parameter(
        name = SIGNATURE_HEADER,
        `in` = ParameterIn.HEADER,
        required = true,
        description = "RFC 9421 HTTP Message Signature",
    ),
    Parameter(
        name = SIGNATURE_INPUT_HEADER,
        `in` = ParameterIn.HEADER,
        required = true,
        description = "RFC 9421 HTTP Message Signature Input",
    ),
)
annotation class HttpMessageSignatureHeaders

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@Parameters(
    Parameter(
        name = CONTENT_DIGEST_HEADER,
        `in` = ParameterIn.HEADER,
        required = true,
        description = "RFC 9530 Digest of the request body (format: sha-256=:<base64-encoded-digest>:)",
    ),
)
annotation class ContentDigestHeader
