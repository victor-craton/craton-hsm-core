#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# generate-integrity-keypair.sh
# Generates the Ed25519 keypair used to sign Craton HSM binaries
# (see tools/sign-integrity.sh and src/crypto/integrity.rs).
#
# Usage:
#   ./tools/generate-integrity-keypair.sh [--no-encrypt] [output-dir]
#
#   output-dir    Directory for integrity-signing-key.pem
#                 (default: $HOME/.craton_hsm). Created with mode 0700 if it
#                 does not exist; an existing directory must be owned by the
#                 current user and not be accessible by group/other.
#   --no-encrypt  Store the private key unencrypted. NOT recommended; by
#                 default the PEM is encrypted with AES-256 under a
#                 passphrase that openssl prompts for, or that is read from
#                 the 0600 file named by CRATON_HSM_SIGNING_KEY_PASS_FILE.
#
# Outputs:
#   - Private key PEM -> <output-dir>/integrity-signing-key.pem (mode 0600)
#   - The build variable that embeds the public key:
#       CRATON_HSM_INTEGRITY_PUBLIC_KEY=<64 hex chars>
#
# Key custody: the private key anchors binary integrity. Prefer generating
# and using it inside an HSM/KMS. If it must live on disk, keep it encrypted,
# off shared hosts, out of uncontrolled backups and NEVER in VCS.

set -euo pipefail

ENCRYPT=true
OUTPUT_DIR=""
for arg in "$@"; do
    case "$arg" in
        --no-encrypt) ENCRYPT=false ;;
        -h|--help) sed -n '5,28p' "$0"; exit 0 ;;
        -*) echo "ERROR: unknown option $arg" >&2; exit 2 ;;
        *)
            if [ -n "$OUTPUT_DIR" ]; then
                echo "ERROR: more than one output directory given" >&2
                exit 2
            fi
            OUTPUT_DIR="$arg"
            ;;
    esac
done
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/.craton_hsm}"

# Everything this script creates is private to the invoking user.
umask 077

file_owner() { stat -c %u "$1" 2>/dev/null || stat -f %u "$1"; }
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

if [ -e "$OUTPUT_DIR" ] || [ -L "$OUTPUT_DIR" ]; then
    if [ -L "$OUTPUT_DIR" ] || [ ! -d "$OUTPUT_DIR" ]; then
        echo "ERROR: $OUTPUT_DIR exists and is not a plain directory" >&2
        exit 1
    fi
    if [ "$(file_owner "$OUTPUT_DIR")" != "$(id -u)" ]; then
        echo "ERROR: $OUTPUT_DIR is not owned by the current user" >&2
        exit 1
    fi
    # Never chmod a directory this script did not create; refuse if shared.
    PERM=$(file_mode "$OUTPUT_DIR")
    if [ $((8#$PERM & 8#077)) -ne 0 ]; then
        echo "ERROR: $OUTPUT_DIR is accessible by group/other (mode $PERM)." >&2
        echo "       Use a private directory (chmod 700) for the signing key." >&2
        exit 1
    fi
else
    mkdir -p -m 700 "$OUTPUT_DIR"
fi

if git -C "$OUTPUT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: $OUTPUT_DIR is inside a git work tree; refusing to create a signing key there." >&2
    exit 1
fi

PRIVKEY_PATH="$OUTPUT_DIR/integrity-signing-key.pem"

if [ -e "$PRIVKEY_PATH" ] || [ -L "$PRIVKEY_PATH" ]; then
    echo "NOTE: Private key already exists at $PRIVKEY_PATH (not regenerated)."
    echo "      To regenerate, move it away first."
else
    if $ENCRYPT && [ -n "${CRATON_HSM_SIGNING_KEY_PASS_FILE:-}" ]; then
        echo "Generating an encrypted Ed25519 key (passphrase from CRATON_HSM_SIGNING_KEY_PASS_FILE)."
        openssl genpkey -algorithm Ed25519 -aes-256-cbc \
            -pass "file:$CRATON_HSM_SIGNING_KEY_PASS_FILE" -out "$PRIVKEY_PATH"
    elif $ENCRYPT; then
        echo "Generating an encrypted Ed25519 key; openssl will prompt for a passphrase."
        openssl genpkey -algorithm Ed25519 -aes-256-cbc -out "$PRIVKEY_PATH"
    else
        echo "WARNING: generating an UNENCRYPTED private key (--no-encrypt)." >&2
        openssl genpkey -algorithm Ed25519 -out "$PRIVKEY_PATH"
    fi
    chmod 600 "$PRIVKEY_PATH"
    echo "Generated private key: $PRIVKEY_PATH"
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

PASSIN=()
if [ -n "${CRATON_HSM_SIGNING_KEY_PASS_FILE:-}" ]; then
    PASSIN=(-passin "file:$CRATON_HSM_SIGNING_KEY_PASS_FILE")
fi

# Public key: DER written with -out and read as bytes (never via a variable).
openssl pkey -in "$PRIVKEY_PATH" ${PASSIN[@]+"${PASSIN[@]}"} -pubout -out "$WORK_DIR/pub.pem"
openssl pkey -pubin -in "$WORK_DIR/pub.pem" -outform DER -out "$WORK_DIR/pub.der"
DER_LEN=$(wc -c < "$WORK_DIR/pub.der" | tr -d ' ')
if [ "$DER_LEN" -ne 44 ]; then
    echo "ERROR: unexpected Ed25519 SubjectPublicKeyInfo length ($DER_LEN bytes)" >&2
    exit 1
fi
PUBKEY_HEX=$(tail -c 32 "$WORK_DIR/pub.der" | od -An -tx1 | tr -d ' \n')

# Self-check: sign and verify a test message with the keypair.
printf 'craton-hsm integrity self-test' > "$WORK_DIR/msg"
openssl pkeyutl -sign -inkey "$PRIVKEY_PATH" ${PASSIN[@]+"${PASSIN[@]}"} -rawin \
    -in "$WORK_DIR/msg" -out "$WORK_DIR/msg.sig"
if ! openssl pkeyutl -verify -pubin -inkey "$WORK_DIR/pub.pem" -rawin \
        -in "$WORK_DIR/msg" -sigfile "$WORK_DIR/msg.sig" >/dev/null; then
    echo "ERROR: sign/verify self-check failed" >&2
    exit 1
fi

echo ""
echo "=== Public key (hex) ==="
echo "$PUBKEY_HEX"
echo ""
echo "=== Build the library with the public key embedded ==="
echo "CRATON_HSM_INTEGRITY_PUBLIC_KEY=$PUBKEY_HEX cargo build --release --lib"
echo ""
echo "=== SECURITY ==="
echo "Private key: $PRIVKEY_PATH"
echo "  - NEVER commit this to version control"
echo "  - Prefer an HSM/KMS for release signing; keep this file encrypted"
echo "  - Back up securely - losing it requires re-signing all binaries"
