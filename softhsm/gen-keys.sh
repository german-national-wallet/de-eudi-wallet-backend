#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/generated"
KEYS_DIR="$OUT/hsm-keys"
CA_DIR="$OUT/dev-pki/ca"
ROOTS_DIR="$OUT/dev-pki/roots"
CHAINS_DIR="$OUT/dev-pki/chains"

if [ -e "$OUT/softhsm2.conf" ]; then
  echo "$OUT already holds fixtures - delete it first to regenerate" >&2
  exit 1
fi
mkdir -p "$KEYS_DIR" "$CA_DIR" "$ROOTS_DIR" "$CHAINS_DIR" "$OUT/tokens"

cat > "$OUT/softhsm2.conf" <<EOF
directories.tokendir = softhsm/generated/tokens/
objectstore.backend = file
EOF

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

gen_symkey() {
  openssl rand -out "$KEYS_DIR/$1.key" 32
}

gen_keypair() {
  stem="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/$stem.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$TMP/$stem.pem" -outform DER -out "$KEYS_DIR/${stem}_prvk.der"
  openssl pkey -in "$TMP/$stem.pem" -pubout -outform DER -out "$KEYS_DIR/${stem}_pubk.der"
}

gen_root() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1"
  openssl req -x509 -new -key "$1" -sha256 -days 5475 \
    -subj "/CN=$3" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$2"
}

cat > "$TMP/leaf.cnf" <<'EOF'
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
EOF

mint_leaf() {
  stem="$1"; serial="$2"; ca_cert="$3"; ca_key="$4"
  openssl req -new -key "$TMP/$stem.pem" -sha256 -subj "/CN=softhsm-$stem" -out "$TMP/$stem.csr"
  openssl x509 -req -in "$TMP/$stem.csr" -CA "$ca_cert" -CAkey "$ca_key" \
    -set_serial "$serial" -days 5475 -sha256 \
    -extfile "$TMP/leaf.cnf" -extensions leaf -out "$TMP/$stem.crt"
  cat "$TMP/$stem.crt" "$ca_cert" > "$CHAINS_DIR/$stem.pem"
}

gen_symkey rwscd_master_key
gen_symkey rwscd_challenge_symk
gen_symkey mdvm_challenge_symk
gen_symkey wpb_challenge_symk
gen_symkey pns_challenge_symk
gen_symkey rwscd_pin_symk
gen_symkey rwscd_aead_symk

gen_keypair mdvm_attestation
gen_keypair rwscd_wte_auth
gen_keypair tsl_wia_auth
gen_keypair wpb_wia_auth

NW_ROOT_KEY="$CA_DIR/nw-root-key.pem"
NW_ROOT_CERT="$ROOTS_DIR/nw-root.pem"
MDVM_ROOT_KEY="$CA_DIR/mdvm-root-key.pem"
MDVM_ROOT_CERT="$ROOTS_DIR/mdvm-root.pem"

gen_root "$NW_ROOT_KEY" "$NW_ROOT_CERT" "softhsm-nw-root"
gen_root "$MDVM_ROOT_KEY" "$MDVM_ROOT_CERT" "softhsm-mdvm-attestation-root"

mint_leaf mdvm_attestation 2 "$MDVM_ROOT_CERT" "$MDVM_ROOT_KEY"
mint_leaf wpb_wia_auth 2 "$NW_ROOT_CERT" "$NW_ROOT_KEY"
mint_leaf rwscd_wte_auth 3 "$NW_ROOT_CERT" "$NW_ROOT_KEY"
mint_leaf tsl_wia_auth 4 "$NW_ROOT_CERT" "$NW_ROOT_KEY"

echo "Generated under $OUT:"
(cd "$OUT" && find . -type f | sort | sed 's|^\./|  |')
echo
echo "export SOFTHSM2_CONF=softhsm/generated/softhsm2.conf from the repository root before init-slot.sh and the app."
