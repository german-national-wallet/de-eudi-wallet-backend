"""Generates every SoftHSM fixture under softhsm/generated/ (gitignored); see softhsm/README.md.

A SoftHSM config whose token store lives there too (so each working copy owns its slot), the slot with every key
generated on the token with the attribute template of the real HSM keys, and the dev PKI wrapping the key pairs' public
keys. No key material exists outside the token store: the dev roots sign the leaves and their empty CRLs in this run
only.

usage: HSM_MODULE_LIBRARY=… HSM_SLOT_LABEL=… HSM_SLOT_PIN=… python3 softhsm/gen-keys.py
"""

import datetime
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys

import PyKCS11 as P
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = "softhsm/generated"
P256_OID_DER = bytes.fromhex("06082a8648ce3d030107")
USAGES = [P.CKA_ENCRYPT, P.CKA_DECRYPT, P.CKA_SIGN, P.CKA_VERIFY, P.CKA_WRAP, P.CKA_UNWRAP]
VALIDITY = datetime.timedelta(days=5475)
TODAY = datetime.date.today()

SECRET_KEYS = {
    "rwscd_master_key": (P.CKK_AES, P.CKM_AES_KEY_GEN, {P.CKA_WRAP, P.CKA_UNWRAP}),
    "rwscd_aead_symk": (P.CKK_AES, P.CKM_AES_KEY_GEN, {P.CKA_ENCRYPT, P.CKA_DECRYPT}),
    "rwscd_account_aead_symk": (P.CKK_AES, P.CKM_AES_KEY_GEN, {P.CKA_ENCRYPT, P.CKA_DECRYPT}),
    "rwscd_challenge_symk": (P.CKK_GENERIC_SECRET, P.CKM_GENERIC_SECRET_KEY_GEN, {P.CKA_SIGN, P.CKA_VERIFY}),
    "rwscd_pin_symk": (P.CKK_GENERIC_SECRET, P.CKM_GENERIC_SECRET_KEY_GEN, {P.CKA_SIGN, P.CKA_VERIFY}),
    "mdvm_challenge_symk": (P.CKK_GENERIC_SECRET, P.CKM_GENERIC_SECRET_KEY_GEN, {P.CKA_SIGN, P.CKA_VERIFY}),
    "wpb_challenge_symk": (P.CKK_GENERIC_SECRET, P.CKM_GENERIC_SECRET_KEY_GEN, {P.CKA_SIGN, P.CKA_VERIFY}),
    "pns_challenge_symk": (P.CKK_GENERIC_SECRET, P.CKM_GENERIC_SECRET_KEY_GEN, {P.CKA_SIGN, P.CKA_VERIFY}),
}

KEY_PAIRS = {
    "mdvm_attestation": "mdvm-root",
    "wpb_wia_auth": "nw-root",
    "rwscd_wte_auth": "nw-root",
    "tsl_wia_auth": "nw-root",
}
ROOTS = {"nw-root": "softhsm-nw-root", "mdvm-root": "softhsm-mdvm-attestation-root"}
COMPOSE_CRL_DIR = "/etc/pki-crls"

def common_attributes(label, key_id):
    return [
        (P.CKA_TOKEN, True),
        (P.CKA_LABEL, label),
        (P.CKA_ID, key_id),
        (P.CKA_PRIVATE, False),
        (P.CKA_MODIFIABLE, False),
        (P.CKA_DERIVE, False),
        (P.CKA_START_DATE, (TODAY - datetime.timedelta(days=1)).strftime("%Y%m%d").encode()),
        (P.CKA_END_DATE, (TODAY + VALIDITY).strftime("%Y%m%d").encode()),
    ]

def generate_secret_key(session, name, key_type, mechanism, usages):
    label = f"softhsm-{name}"
    template = common_attributes(label, hashlib.sha256(label.encode()).digest()[:16]) + [
        (P.CKA_CLASS, P.CKO_SECRET_KEY),
        (P.CKA_KEY_TYPE, key_type),
        (P.CKA_VALUE_LEN, 32),
        (P.CKA_SENSITIVE, True),
        (P.CKA_EXTRACTABLE, False),
    ] + [(usage, usage in usages) for usage in USAGES]
    session.generateKey(template, P.Mechanism(mechanism, None))

def generate_key_pair(session, stem):
    key_id = hashlib.sha256(stem.encode()).digest()
    public_template = common_attributes(f"{stem}-pubk", key_id) + [
        (P.CKA_CLASS, P.CKO_PUBLIC_KEY),
        (P.CKA_KEY_TYPE, P.CKK_EC),
        (P.CKA_EC_PARAMS, P256_OID_DER),
        (P.CKA_VERIFY, True),
        (P.CKA_ENCRYPT, False),
        (P.CKA_WRAP, False),
    ]
    private_template = common_attributes(f"{stem}-prvk", key_id) + [
        (P.CKA_CLASS, P.CKO_PRIVATE_KEY),
        (P.CKA_KEY_TYPE, P.CKK_EC),
        (P.CKA_SENSITIVE, True),
        (P.CKA_EXTRACTABLE, False),
        (P.CKA_SIGN, True),
        (P.CKA_DECRYPT, False),
        (P.CKA_UNWRAP, False),
    ]
    public_key, _ = session.generateKeyPair(
        public_template, private_template, P.Mechanism(P.CKM_EC_KEY_PAIR_GEN, None)
    )
    point = bytes(session.getAttributeValue(public_key, [P.CKA_EC_POINT])[0])[2:]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)

def certificate(subject, issuer, issuer_key, public_key, serial, is_ca, now, crl_uris=()):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    )
    if crl_uris:
        distribution_point = x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(uri) for uri in crl_uris],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        builder = builder.add_extension(x509.CRLDistributionPoints([distribution_point]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())

def crl(issuer, issuer_key, now):
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .last_update(now)
        .next_update(now + VALIDITY)
        .add_extension(x509.CRLNumber(1), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
        .sign(issuer_key, hashes.SHA256())
    )

def crl_uris(file_stem):
    return (
        pathlib.Path(f"{OUT}/dev-pki/crls/{file_stem}.crl").resolve().as_uri(),
        f"file://{COMPOSE_CRL_DIR}/{file_stem}.crl",
    )

def write_pem(path, *certificates):
    with open(path, "wb") as f:
        f.write(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates))

def generate(module, token_label, pin):
    os.makedirs(f"{OUT}/tokens")
    with open(f"{OUT}/softhsm2.conf", "w") as f:
        f.write(f"directories.tokendir = {OUT}/tokens/\nobjectstore.backend = file\n")
    os.environ["SOFTHSM2_CONF"] = f"{OUT}/softhsm2.conf"
    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", token_label, "--pin", pin, "--so-pin", "0000"],
        check=True,
    )
    os.makedirs(f"{OUT}/dev-pki/roots")
    os.makedirs(f"{OUT}/dev-pki/chains")
    os.makedirs(f"{OUT}/dev-pki/crls")

    lib = P.PyKCS11Lib()
    lib.load(module)
    slot = next(s for s in lib.getSlotList(tokenPresent=True) if lib.getTokenInfo(s).label.strip() == token_label)
    session = lib.openSession(slot, P.CKF_SERIAL_SESSION | P.CKF_RW_SESSION)
    session.login(pin)
    try:
        for name, (key_type, mechanism, usages) in SECRET_KEYS.items():
            generate_secret_key(session, name, key_type, mechanism, usages)
            print(f"generated softhsm-{name}")

        now = datetime.datetime.now(datetime.timezone.utc)
        roots = {}
        for file_stem, cn in ROOTS.items():
            key = ec.generate_private_key(ec.SECP256R1())
            cert = certificate(cn, cn, key, key.public_key(), x509.random_serial_number(), True, now)
            write_pem(f"{OUT}/dev-pki/roots/{file_stem}.pem", cert)
            with open(f"{OUT}/dev-pki/crls/{file_stem}.crl", "wb") as f:
                f.write(crl(cn, key, now).public_bytes(serialization.Encoding.DER))
            roots[file_stem] = (key, cert)
            print(f"generated dev root {cn}")

        for name, root in KEY_PAIRS.items():
            stem = f"softhsm-{name}"
            public_key = generate_key_pair(session, stem)
            root_key, root_cert = roots[root]
            leaf = certificate(
                stem, ROOTS[root], root_key, public_key, x509.random_serial_number(), False, now, crl_uris(root)
            )
            write_pem(f"{OUT}/dev-pki/chains/{name}.pem", leaf, root_cert)
            print(f"generated {stem}-prvk / -pubk and its chain under {root}")
    finally:
        session.logout()
        session.closeSession()

def main():
    env = {name: os.environ.get(name) for name in ("HSM_MODULE_LIBRARY", "HSM_SLOT_LABEL", "HSM_SLOT_PIN")}
    missing = [name for name, value in env.items() if not value]
    if missing:
        sys.exit(f"Need to set {', '.join(missing)}")
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if os.path.exists(OUT):
        sys.exit(f"{OUT} already holds fixtures - delete it first to regenerate")
    try:
        generate(*env.values())
    except BaseException:
        shutil.rmtree(OUT, ignore_errors=True)
        raise

if __name__ == "__main__":
    main()
