#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Craton Software Company
#
# ci-local.sh — DEPRECATED alias for scripts/local-ci.sh.
#
# The two local CI helpers used to diverge (different clippy flags, different
# handling of missing audit tools, wrong semver package name). There is now a
# single implementation; this wrapper only maps the old job names.
#
# Usage (unchanged):
#   ./scripts/ci-local.sh [all|quick|fmt|test|clippy|audit|semver|miri|docs|coverage] [--allow-skip]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Note: scripts/ci-local.sh is deprecated; use scripts/local-ci.sh." >&2

args=()
for a in "$@"; do
    case "$a" in
        all) args+=(fmt test clippy audit semver miri docs coverage) ;;
        *) args+=("$a") ;;
    esac
done

exec bash "$SCRIPT_DIR/local-ci.sh" "${args[@]}"
