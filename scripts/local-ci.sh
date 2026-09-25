#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# local-ci.sh — Run all CI jobs locally (mirrors .github/workflows/ci.yml + security-audit.yml)
#
# Usage:
#   ./scripts/local-ci.sh              # Run all jobs
#   ./scripts/local-ci.sh fmt          # Run a single job
#   ./scripts/local-ci.sh fmt test     # Run specific jobs
#   ./scripts/local-ci.sh quick        # fmt + test + clippy
#   ./scripts/local-ci.sh --allow-skip # Do not fail when a job is skipped
#
# A job that cannot run because a tool is missing (nightly/miri,
# cargo-audit, cargo-deny, cargo-semver-checks, cargo-tarpaulin) is reported
# as SKIPPED and makes the run FAIL unless --allow-skip is given, so a
# missing security tool can never produce "All CI checks passed".
#
# Available jobs:
#   fmt        Format check (cargo fmt --check)
#   test       Build & test (cargo test --workspace)
#   clippy     Clippy (-D correctness -D suspicious, same as CI)
#   semver     Semver compatibility check
#   miri       Miri undefined-behavior check on crypto modules
#   docs       Build rustdoc
#   audit      Security audit (cargo-audit AND cargo-deny; both required)
#   coverage   Code coverage (cargo-tarpaulin; not in the default run)
#   bench      Benchmarks (cargo bench, no SoftHSMv2 comparison)
#
# Prerequisites:
#   - Rust stable + nightly (rustup)
#   - protoc (for gRPC daemon)
#   - cargo-semver-checks:  cargo install cargo-semver-checks
#   - cargo-audit:          cargo install cargo-audit
#   - cargo-deny:           cargo install cargo-deny
#   - cargo-tarpaulin:      cargo install cargo-tarpaulin (coverage job)

set -euo pipefail

# Always run from the repository root, wherever the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd))"
cd "$REPO_ROOT"
AUDIT_IGNORE_FILE="$SCRIPT_DIR/audit-ignore.txt"
ALLOW_SKIP=false

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── State ─────────────────────────────────────────────────────────────────────
PASS=()
FAIL=()
SKIP=()
TOTAL_START=$SECONDS

# ── Helpers ───────────────────────────────────────────────────────────────────
header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  ▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Exit status used by a job function to signal "skipped" (never "passed").
SKIP_RC=200

run_job() {
    local name="$1"
    shift
    local start=$SECONDS
    header "$name"

    local rc=0
    "$@" || rc=$?
    if [[ $rc -eq $SKIP_RC ]]; then
        return 0
    elif [[ $rc -eq 0 ]]; then
        local elapsed=$(( SECONDS - start ))
        echo -e "${GREEN}  ✓ ${name} passed${NC} (${elapsed}s)"
        PASS+=("$name")
        return 0
    else
        local elapsed=$(( SECONDS - start ))
        echo -e "${RED}  ✗ ${name} FAILED${NC} (${elapsed}s)"
        FAIL+=("$name")
        return 1
    fi
}

# Record a skipped job. Job functions must `return $SKIP_RC` right after.
skip_job() {
    echo -e "${YELLOW}  ⊘ $1 skipped ($2)${NC}"
    SKIP+=("$1")
}

has_cmd() {
    command -v "$1" &>/dev/null
}

# ── Job implementations ──────────────────────────────────────────────────────

job_fmt() {
    cargo fmt --check
}

job_test() {
    export CARGO_TERM_COLOR=always
    export RUST_BACKTRACE=1
    cargo test --workspace -- --test-threads=1
}

job_clippy() {
    # Deny correctness and suspicious lints (safety-critical for a crypto project).
    # Other clippy categories remain warnings until pre-existing issues are resolved.
    # -A deprecated: upstream generic-array deprecation from transitive deps
    # clippy::not_unsafe_ptr_arg_deref is deliberately NOT allowed: it flags
    # safe fns that dereference raw pointers (unsound in an FFI crate).
    cargo clippy --workspace --all-targets -- \
        -D clippy::correctness -D clippy::suspicious \
        -A deprecated -A clippy::incompatible_msrv
}

job_semver() {
    if ! has_cmd cargo-semver-checks; then
        skip_job "semver" "cargo-semver-checks not installed (cargo install cargo-semver-checks)"
        return $SKIP_RC
    fi
    # Non-blocking until 1.0 — report but don't fail
    cargo semver-checks check-release --package craton-hsm || true
}

job_miri() {
    # Check nightly is available
    if ! rustup run nightly rustc --version &>/dev/null; then
        skip_job "miri" "Rust nightly not installed (rustup toolchain install nightly)"
        return $SKIP_RC
    fi
    if ! rustup run nightly cargo miri --version &>/dev/null; then
        skip_job "miri" "Miri not installed (rustup +nightly component add miri)"
        return $SKIP_RC
    fi

    export MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-symbolic-alignment-check"
    cargo +nightly miri test --lib -- --test-threads=1 crypto::zeroize crypto::digest crypto::integrity
}

job_docs() {
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps
}

# Print "--ignore <ID>" arguments (one token per line) from the single
# ignore list; fail if an entry is malformed or past its review-by date.
audit_ignore_args() {
    local today id review _
    today=$(date -u +%Y-%m-%d)
    while read -r id review _; do
        [[ -z "$id" || "$id" == \#* ]] && continue
        if [[ ! "$review" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            echo "Malformed entry in $AUDIT_IGNORE_FILE: $id" >&2
            return 1
        fi
        if [[ "$review" < "$today" ]]; then
            echo "Advisory ignore $id expired on $review — re-review it in $AUDIT_IGNORE_FILE" >&2
            return 1
        fi
        printf -- '--ignore\n%s\n' "$id"
    done < "$AUDIT_IGNORE_FILE"
}

job_audit() {
    local audit_ok=true
    local missing=()
    has_cmd cargo-audit || missing+=("cargo-audit")
    has_cmd cargo-deny || missing+=("cargo-deny")

    if [[ ${#missing[@]} -gt 0 ]]; then
        # Both tools are required; a partial audit is not a pass.
        skip_job "audit" "missing: ${missing[*]} (cargo install ${missing[*]})"
        return $SKIP_RC
    fi

    local ignore_list
    ignore_list=$(audit_ignore_args) || return 1
    local -a ignores=()
    if [[ -n "$ignore_list" ]]; then
        mapfile -t ignores <<< "$ignore_list"
    fi

    echo -e "${BOLD}  Running cargo-audit...${NC}"
    cargo audit "${ignores[@]}" || audit_ok=false

    echo -e "${BOLD}  Running cargo-deny...${NC}"
    cargo deny check advisories licenses || audit_ok=false

    $audit_ok
}

job_coverage() {
    if ! has_cmd cargo-tarpaulin; then
        skip_job "coverage" "cargo-tarpaulin not installed (cargo install cargo-tarpaulin)"
        return $SKIP_RC
    fi
    cargo tarpaulin --out xml --out html --skip-clean --timeout 300 \
        --exclude-files 'tests/fips_*' -- --test-threads=1
}

job_bench() {
    cargo bench --bench crypto_bench
}

# ── Job registry ──────────────────────────────────────────────────────────────

ALL_JOBS=(fmt test clippy semver miri docs audit bench)
# Jobs selectable by name but not part of the default run.
EXTRA_JOBS=(coverage)

declare -A JOB_FN
JOB_FN[fmt]=job_fmt
JOB_FN[test]=job_test
JOB_FN[clippy]=job_clippy
JOB_FN[semver]=job_semver
JOB_FN[miri]=job_miri
JOB_FN[docs]=job_docs
JOB_FN[audit]=job_audit
JOB_FN[bench]=job_bench
JOB_FN[coverage]=job_coverage

declare -A JOB_NAME
JOB_NAME[fmt]="Format Check"
JOB_NAME[test]="Build & Test"
JOB_NAME[clippy]="Clippy Lint"
JOB_NAME[semver]="Semver Compliance"
JOB_NAME[miri]="Miri (UB Check)"
JOB_NAME[docs]="Documentation Build"
JOB_NAME[audit]="Security Audit"
JOB_NAME[bench]="Benchmarks"
JOB_NAME[coverage]="Code Coverage"

# ── Main ──────────────────────────────────────────────────────────────────────

echo -e "${BOLD}Craton HSM — Local CI Runner${NC}"
echo -e "Mirrors .github/workflows/ci.yml + security-audit.yml"
echo ""

# Parse args: flags, aliases ("all", "quick") or specific job names
JOBS_TO_RUN=()
for arg in "$@"; do
    case "$arg" in
        --allow-skip) ALLOW_SKIP=true ;;
        quick) JOBS_TO_RUN+=(fmt test clippy) ;;
        all) JOBS_TO_RUN+=("${ALL_JOBS[@]}") ;;
        -h|--help)
            sed -n '5,36p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) JOBS_TO_RUN+=("$arg") ;;
    esac
done
if [[ ${#JOBS_TO_RUN[@]} -eq 0 ]]; then
    JOBS_TO_RUN=("${ALL_JOBS[@]}")
fi

# Validate job names
for job in "${JOBS_TO_RUN[@]}"; do
    if [[ -z "${JOB_FN[$job]+x}" ]]; then
        echo -e "${RED}Unknown job: ${job}${NC}"
        echo "Available jobs: ${ALL_JOBS[*]} ${EXTRA_JOBS[*]} (aliases: all, quick; flag: --allow-skip)"
        exit 1
    fi
done

# Preflight checks
echo -e "${BOLD}Preflight:${NC}"
echo -n "  rustc:    " && rustc --version
echo -n "  cargo:    " && cargo --version
if has_cmd protoc; then
    echo -n "  protoc:   " && protoc --version
else
    echo -e "  protoc:   ${YELLOW}not found (gRPC daemon tests may fail)${NC}"
fi
echo ""

# Run each job — fmt is the fast gate, fail early
CONTINUE=true
for job in "${JOBS_TO_RUN[@]}"; do
    if [[ "$CONTINUE" == false && "$job" != "audit" ]]; then
        skip_job "${JOB_NAME[$job]}" "prior job failed"
        continue
    fi

    run_job "${JOB_NAME[$job]}" "${JOB_FN[$job]}" || {
        # fmt failure is a hard stop (mirrors CI dependency graph)
        if [[ "$job" == "fmt" ]]; then
            echo -e "${RED}  Format check failed — fix with: cargo fmt${NC}"
            CONTINUE=false
        fi
    }
done

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL_ELAPSED=$(( SECONDS - TOTAL_START ))

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  CI Summary  (${TOTAL_ELAPSED}s total)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ ${#PASS[@]} -gt 0 ]]; then
    for j in "${PASS[@]}"; do
        echo -e "  ${GREEN}✓${NC} $j"
    done
fi
if [[ ${#SKIP[@]} -gt 0 ]]; then
    for j in "${SKIP[@]}"; do
        echo -e "  ${YELLOW}⊘${NC} $j (skipped)"
    done
fi
if [[ ${#FAIL[@]} -gt 0 ]]; then
    for j in "${FAIL[@]}"; do
        echo -e "  ${RED}✗${NC} $j"
    done
fi

echo ""
if [[ ${#FAIL[@]} -gt 0 ]]; then
    echo -e "${RED}${BOLD}  ${#FAIL[@]} job(s) failed: ${FAIL[*]}${NC}"
    exit 1
elif [[ ${#SKIP[@]} -gt 0 && "$ALLOW_SKIP" != true ]]; then
    echo -e "${RED}${BOLD}  ${#SKIP[@]} job(s) skipped: ${SKIP[*]} — NOT a pass.${NC}"
    echo -e "  Install the missing tools, or re-run with --allow-skip to accept skips."
    exit 1
elif [[ ${#SKIP[@]} -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}  Passed with ${#SKIP[@]} skipped job(s) (--allow-skip): ${SKIP[*]}${NC}"
    exit 0
else
    echo -e "${GREEN}${BOLD}  All CI checks passed!${NC}"
    exit 0
fi
