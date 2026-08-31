package de.eudiwallet.backend.shared.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.springframework.core.io.Resource
import java.io.InputStreamReader
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyGenerator

val RECOMMENDED_EC_CURVE: Curve = Curve.P_256
const val ALGORITHM_EC = "EC"
const val ALGORITHM_HMAC_SHA256 = "HmacSHA256"
const val ALGORITHM_AES = "AES"
private const val RECOMMENDED_HMAC_SHA256_KEYSIZE = 256
private const val RECOMMENDED_AES_KEYSIZE = 256
private const val CERTIFICATE_FACTORY_X509 = "X.509"
private const val PEM_CHUNK_SIZE = 64

@Suppress("TooGenericExceptionCaught")
fun ByteArray.ecPublicKeyFromX509(): ECPublicKey =
    try {
        val x509EncodedKeySpec = X509EncodedKeySpec(this)
        val keyFactory = KeyFactory.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER)
        keyFactory.generatePublic(x509EncodedKeySpec) as ECPublicKey
    } catch (ex: InvalidKeySpecException) {
        throw ex
    } catch (ex: Exception) {
        throw InvalidKeySpecException(ex)
    }

fun ByteArray.ecPrivateKeyFromPkcs8(): ECPrivateKey {
    val pkcs8EncodedKeySpec = PKCS8EncodedKeySpec(this)
    val keyFactory = KeyFactory.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER)
    return keyFactory.generatePrivate(pkcs8EncodedKeySpec) as ECPrivateKey
}

fun ECPublicKey.toECJWK(): ECKey = ECKey.Builder(RECOMMENDED_EC_CURVE, this).build()

private val P256_PARAMS: ECParameterSpec =
    AlgorithmParameters.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER).run {
        init(ECGenParameterSpec(RECOMMENDED_EC_CURVE.stdName))
        getParameterSpec(ECParameterSpec::class.java)
    }

fun ECPublicKey.toCanonicalP256(): ECPublicKey {
    require(this.params.curve == P256_PARAMS.curve) { "auth key is not P-256" }
    val spec = ECPublicKeySpec(this.w, P256_PARAMS)
    return KeyFactory.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER)
        .generatePublic(spec) as ECPublicKey
}

fun ECPublicKey.jwkThumbprint(): Base64URL = toECJWK().computeThumbprint()

data class ECKeyPair(
    val private: ECPrivateKey,
    val public: ECPublicKey,
)

fun KeyPair.toECKeyPair() = ECKeyPair(private as ECPrivateKey, public as ECPublicKey)

val x509CertificateFactory: CertificateFactory =
    CertificateFactory.getInstance(
        CERTIFICATE_FACTORY_X509,
        BOUNCY_CASTLE_PROVIDER,
    )

val softwareEcdsaKeyGenerator: KeyPairGenerator =
    KeyPairGenerator.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER).apply {
        initialize(ECGenParameterSpec(RECOMMENDED_EC_CURVE.name))
    }

val softwareHmacKeyGenerator: KeyGenerator =
    KeyGenerator.getInstance(ALGORITHM_HMAC_SHA256, BOUNCY_CASTLE_PROVIDER).apply {
        init(RECOMMENDED_HMAC_SHA256_KEYSIZE)
    }

val softwareAesKeyGenerator: KeyGenerator =
    KeyGenerator.getInstance(ALGORITHM_AES, BOUNCY_CASTLE_PROVIDER).apply {
        init(RECOMMENDED_AES_KEYSIZE)
    }

fun readPKCS8ECPrivateKey(pemPath: Resource): ECPrivateKey =
    PEMParser(InputStreamReader(pemPath.inputStream)).use {
        val pemObject = it.readObject() as PEMKeyPair
        pemObject.privateKeyInfo.encoded.ecPrivateKeyFromPkcs8()
    }

fun readX509Cert(certificateResource: Resource) =
    x509CertificateFactory.generateCertificate(certificateResource.inputStream) as X509Certificate

fun List<String>.toPemChain(): String =
    joinToString(separator = "\n") { base64Der ->
        val lines = base64Der.chunked(PEM_CHUNK_SIZE).joinToString("\n")
        "-----BEGIN CERTIFICATE-----\n$lines\n-----END CERTIFICATE-----"
    }
