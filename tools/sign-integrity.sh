#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# sign-integrity.sh
# Signs a Craton HSM binary with Ed25519 and writes a .sig sidecar file.
#
# Usage:
#   ./tools/sign-integrity.sh [path-to-library] [private-key-pem]
#
# If path is not specified, defaults to:
#   target/release/libcraton_hsm.so (Linux)
#   target/release/libcraton_hsm.dylib (macOS)
#
# Private key is loaded from (in order):
#   1. Second argument (path to PEM file)
#   2. CRATON_HSM_SIGNING_KEY environment variable (path to PEM file)
#   3. ~/.craton_hsm/integrity-signing-key.pem
#
# An encrypted key (the default of generate-integrity-keypair.sh) makes
# openssl prompt for the passphrase. For unattended signing set
# CRATON_HSM_SIGNING_KEY_PASS_FILE to a 0600 file containing the passphrase
# (passed to openssl as -passin file:<path>; the passphrase itself is never
# on a command line).
#
# The .sig file is written next to the library with the library's extension
# replaced by .sig (e.g. libcraton_hsm.so -> libcraton_hsm.sig), which is
# where the module looks for it.

set -euo pipefail

LIB_PATH="${1:-}"

if [ -z "$LIB_PATH" ]; then
    if [ "$(uname)" = "Darwin" ]; then
        LIB_PATH="target/release/libcraton_hsm.dylib"
    else
        LIB_PATH="target/release/libcraton_hsm.so"
    fi
fi

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at $LIB_PATH" >&2
    echo "Build first: cargo build --release --lib" >&2
    exit 1
fi

# Locate private key
PRIVKEY_PATH="${2:-}"
if [ -z "$PRIVKEY_PATH" ] && [ -n "${CRATON_HSM_SIGNING_KEY:-}" ]; then
    PRIVKEY_PATH="$CRATON_HSM_SIGNING_KEY"
fi
if [ -z "$PRIVKEY_PATH" ]; then
    PRIVKEY_PATH="$HOME/.craton_hsm/integrity-signing-key.pem"
fi

if [ ! -f "$PRIVKEY_PATH" ]; then
    echo "ERROR: Ed25519 private key not found at $PRIVKEY_PATH" >&2
    echo "Generate one with: ./tools/generate-integrity-keypair.sh" >&2
    exit 1
fi

PASSIN=()
if [ -n "${CRATON_HSM_SIGNING_KEY_PASS_FILE:-}" ]; then
    if [ ! -f "$CRATON_HSM_SIGNING_KEY_PASS_FILE" ]; then
        echo "ERROR: CRATON_HSM_SIGNING_KEY_PASS_FILE does not name a file" >&2
        exit 1
    fi
    PASSIN=(-passin "file:$CRATON_HSM_SIGNING_KEY_PASS_FILE")
fi

# All temporary files live in a private directory (mode 0700, files 0600).
umask 077
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# SHA-256 digest of the binary; the module verifies an Ed25519 signature
# over these 32 raw bytes.
openssl dgst -sha256 -binary -out "$WORK_DIR/digest.bin" "$LIB_PATH"
HASH_HEX=$(od -An -tx1 < "$WORK_DIR/digest.bin" | tr -d ' \n')
if [ ${#HASH_HEX} -ne 64 ]; then
    echo "ERROR: Failed to compute the SHA-256 digest of $LIB_PATH." >&2
    exit 1
fi

# openssl diagnostics are shown on failure (not discarded).
if ! openssl pkeyutl -sign \
        -inkey "$PRIVKEY_PATH" ${PASSIN[@]+"${PASSIN[@]}"} \
        -rawin \
        -in "$WORK_DIR/digest.bin" \
        -out "$WORK_DIR/digest.sig"; then
    echo "ERROR: Signing failed (see openssl output above)." >&2
    exit 1
fi

if [ ! -s "$WORK_DIR/digest.sig" ]; then
    echo "ERROR: Signing produced no signature." >&2
    exit 1
fi

# Verify the signature before publishing it.
openssl pkey -in "$PRIVKEY_PATH" ${PASSIN[@]+"${PASSIN[@]}"} -pubout -out "$WORK_DIR/pub.pem"
if ! openssl pkeyutl -verify -pubin -inkey "$WORK_DIR/pub.pem" -rawin \
        -in "$WORK_DIR/digest.bin" -sigfile "$WORK_DIR/digest.sig" >/dev/null; then
    echo "ERROR: Signature self-verification failed." >&2
    exit 1
fi

SIG_HEX=$(od -An -tx1 < "$WORK_DIR/digest.sig" | tr -d ' \n')
if [ ${#SIG_HEX} -ne 128 ]; then
    echo "ERROR: Unexpected signature length (${#SIG_HEX} hex chars, expected 128)." >&2
    exit 1
fi

# Sidecar path = library path with its extension replaced by ".sig"
# (mirrors Path::with_extension in src/crypto/integrity.rs; the directory
# part is never modified).
LIB_DIR=$(dirname -- "$LIB_PATH")
LIB_BASE=$(basename -- "$LIB_PATH")
case "$LIB_BASE" in
    ?*.*) LIB_STEM="${LIB_BASE%.*}" ;;
    *) LIB_STEM="$LIB_BASE" ;;
esac
SIG_PATH="$LIB_DIR/$LIB_STEM.sig"

# The signature is public: it must be readable by whoever loads the module.
printf "%s" "$SIG_HEX" > "$WORK_DIR/out.sig"
chmod 644 "$WORK_DIR/out.sig"
mv -f -- "$WORK_DIR/out.sig" "$SIG_PATH"

echo "Signed:      $LIB_PATH"
echo "Signature:   $SIG_PATH"
echo "Binary size: $(wc -c < "$LIB_PATH" | tr -d ' ') bytes"
echo "SHA-256:     $HASH_HEX"
