# SoftHSM

Wallet backend services can use [SoftHSM](https://github.com/softhsm/SoftHSMv2) for local development and testing.

## OSX ARM installation

```bash
git clone https://github.com/softhsm/SoftHSMv2
cd SoftHSMv2
brew install automake libtool pkg-config cppunit openssl
./autogen.sh
./configure --with-crypto-backend=openssl --with-openssl="$(brew --prefix openssl)"
make
sudo make install
```

The generator needs Python 3.12+ with PyKCS11 and cryptography; on macOS, install them into a venv:

```bash
python3 -m venv softhsm/.venv
softhsm/.venv/bin/pip install --require-hashes -r softhsm/requirements.txt
```

On Ubuntu, the `python3-pykcs11` and `python3-cryptography` packages do the same.

## Layout

```
softhsm/
  gen-keys.py          # writes everything under generated/
  requirements.txt     # gen-keys.py's dependencies, hash-pinned
  Dockerfile           # compose image: SoftHSM, the token store + the app jar (see docker-compose.yml)
  .gitignore           # ignores generated/ and .venv/
  generated/           # absent in a fresh clone
    softhsm2.conf      # SoftHSM config selecting the token store below; export it as SOFTHSM2_CONF
    tokens/            # this working copy's token store (the TEST_SLOT and its keys live here, not system-wide)
    dev-pki/roots/     # nw-root.pem, mdvm-root.pem: the roots the `dev-pki` profile pins (`DEV_PKI_DIR`)
    dev-pki/chains/    # leaf -> root chains seeded into the simulated S3 bucket: MDVM attestation under
                       # mdvm-root, WIA, WTE and status list under nw-root
```

Nothing under `generated/` is committed, and none of it reaches a deployed stage: those pin the real PKI through the
Helm chart and hold their keys in a real HSM. Only the local compose images bake the generated `tokens/` in.

## Generating the fixtures

```bash
# HSM_MODULE_LIBRARY, HSM_SLOT_LABEL and HSM_SLOT_PIN exported; softhsm/.venv/bin/python on macOS
python3 softhsm/gen-keys.py
```

Writes a SoftHSM config with a private token store, initialises the slot in it and generates the symmetric keys and EC
P-256 keypairs on the token, with the attribute template of the real HSM keys. No key material
exists outside the token. It then mints the two dev roots and the leaf chains that wrap the keypairs' public keys; the
roots' private keys are discarded. It refuses to run while `generated/` exists, and removes it again if it fails: delete
`generated/` to start over (this also drops the slot), run the generator again, then re-run `docker compose up -d s3-init` so the
bucket holds the new chains, and rebuild the compose images (`docker compose up --build`) because they copy
`tokens/`.

Every SoftHSM client — the app, `softhsm2-util`, `pkcs11-tool` — finds the slot only with
`SOFTHSM2_CONF` pointing at the generated config. Both that path and the token store path inside the config are
relative to the repository root, so run the clients from there:

```bash
export SOFTHSM2_CONF=softhsm/generated/softhsm2.conf
softhsm2-util --show-slots
```

The compose image copies the token store into the system-wide location instead: it is private to one container
already. A token store written on macOS loads on Linux and vice versa (SoftHSM 2.6.1, file backend).
