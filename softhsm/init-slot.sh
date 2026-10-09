#!/bin/sh
set -e

: "${HSM_MODULE_LIBRARY:?Need to set HSM_MODULE_LIBRARY}"
: "${HSM_SLOT_LABEL:?Need to set HSM_SLOT_LABEL}"
: "${HSM_SLOT_PIN:?Need to set HSM_SLOT_PIN}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="${KEYS_DIR:-$SCRIPT_DIR/generated/hsm-keys}"

echo "Token store: SOFTHSM2_CONF=${SOFTHSM2_CONF:-<unset, system default>}"

if softhsm2-util --show-slots | grep -qF "$HSM_SLOT_LABEL"; then
  if [ -t 0 ]; then
    printf 'Slot "%s" already exists. Delete and recreate it? [y/N] ' "$HSM_SLOT_LABEL"
    read -r answer
  else
    answer=n
    echo "Slot $HSM_SLOT_LABEL already exists; reusing it (non-interactive)."
  fi

  case "$answer" in
    [Yy]*)
      echo "Deleting existing token $HSM_SLOT_LABEL..."
      softhsm2-util --delete-token --token "$HSM_SLOT_LABEL"
      ;;
  esac
fi

if ! softhsm2-util --show-slots | grep -qF "$HSM_SLOT_LABEL"; then
  echo "Initializing new slot $HSM_SLOT_LABEL"
  softhsm2-util --init-token --free --label "$HSM_SLOT_LABEL" --pin "$HSM_SLOT_PIN" --so-pin 0000
fi

pkcs11cmd() {
  echo "$@" >&2
  pkcs11-tool --module "$HSM_MODULE_LIBRARY" --token-label "$HSM_SLOT_LABEL" --login --pin "$HSM_SLOT_PIN" "$@"
}

load_key() {
  label="softhsm-$1"
  type="$2"
  file="$3"
  shift 3

  if [ ! -f "$file" ]; then
    echo "Missing $file - run softhsm/gen-keys.sh on a fresh store, or: openssl rand -out $file 32" >&2
    exit 1
  fi
  if pkcs11cmd -O --type "$type" --label "$label" 2>/dev/null | grep -qF "$label"; then
    echo "Deleting existing key with label '$label'"
    pkcs11cmd --delete-object --type "$type" --label "$label"
  fi
  echo "Creating '$label'..."
  id=$( echo -n "$label" | sha256sum | head -c 32 )
  pkcs11cmd --write-object "$file" --type "$type" --label "$label" --id "$id" "$@"
}

load_keypair() {
  stem="softhsm-$1"
  prvk_file="$2"
  pubk_file="$3"
  id=$( echo -n "$stem" | sha256sum | head -c 64 )

  for entry in privkey:prvk pubkey:pubk; do
    type="${entry%%:*}"
    label="$stem-${entry##*:}"
    if pkcs11cmd -O --type "$type" --label "$label" 2>/dev/null | grep -qF "$label"; then
      echo "Deleting existing key with label '$label'"
      pkcs11cmd --delete-object --type "$type" --label "$label"
    fi
  done

  echo "Creating '$stem-prvk' and '$stem-pubk' (shared id $id)..."
  pkcs11cmd --write-object "$prvk_file" --type privkey --label "$stem-prvk" --id "$id" --usage-sign
  pkcs11cmd --write-object "$pubk_file" --type pubkey --label "$stem-pubk" --id "$id"
}

load_key "rwscd_master_key" secrkey "$KEYS_DIR/rwscd_master_key.key" --key-type AES:32 --usage-wrap
load_key "rwscd_challenge_symk" secrkey "$KEYS_DIR/rwscd_challenge_symk.key" --key-type GENERIC:32 --usage-sign
load_key "mdvm_challenge_symk" secrkey "$KEYS_DIR/mdvm_challenge_symk.key" --key-type GENERIC:32 --usage-sign
load_key "wpb_challenge_symk" secrkey "$KEYS_DIR/wpb_challenge_symk.key" --key-type GENERIC:32 --usage-sign
load_key "pns_challenge_symk" secrkey "$KEYS_DIR/pns_challenge_symk.key" --key-type GENERIC:32 --usage-sign
load_key "rwscd_pin_symk" secrkey "$KEYS_DIR/rwscd_pin_symk.key" --key-type GENERIC:32 --usage-sign
load_key "rwscd_aead_symk" secrkey "$KEYS_DIR/rwscd_aead_symk.key" --key-type AES:32 --usage-decrypt
load_keypair "mdvm_attestation" "$KEYS_DIR/mdvm_attestation_prvk.der" "$KEYS_DIR/mdvm_attestation_pubk.der"
load_keypair "wpb_wia_auth" "$KEYS_DIR/wpb_wia_auth_prvk.der" "$KEYS_DIR/wpb_wia_auth_pubk.der"
load_keypair "rwscd_wte_auth" "$KEYS_DIR/rwscd_wte_auth_prvk.der" "$KEYS_DIR/rwscd_wte_auth_pubk.der"
load_keypair "tsl_wia_auth" "$KEYS_DIR/tsl_wia_auth_prvk.der" "$KEYS_DIR/tsl_wia_auth_pubk.der"
