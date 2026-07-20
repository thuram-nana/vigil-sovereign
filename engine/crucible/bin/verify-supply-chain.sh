#!/usr/bin/env bash
# bin/verify-supply-chain.sh — sovereign-grade supply-chain verification.
#
# Three checks, run in order; exits non-zero on any failure:
#
#   1. requirements.in resolves cleanly (pip-compile dry-run).
#   2. requirements.lock.txt is up to date with requirements.in
#      (pip-compile --check).
#   3. sbom.json is a valid CycloneDX document and matches the lock.
#
# Sovereign deployments run this from CI on every commit. A lock-file
# drift means an unreviewed dependency change has been merged — fail
# the pipeline rather than ship.
#
# Required tools (install once, then never again):
#   pip install pip-tools cyclonedx-bom
#
# Why these are not in requirements.in: they are *build-time* tooling.
# Adding them to runtime would expand the deployed attack surface
# without expanding the runtime feature set. They are needed only on
# CI / developer machines, not on a sovereign target deployment.

set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "${SCRIPT_DIR}/.."
fi

REQ_IN="framework/v2/requirements.in"
REQ_LOCK="framework/v2/requirements.lock.txt"
SBOM="framework/v2/sbom.json"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        red "ERROR: required tool '$1' not on PATH."
        red "Install with: pip install pip-tools cyclonedx-bom"
        red "These are build-time tools and intentionally NOT in"
        red "framework/v2/requirements.in (would expand runtime"
        red "attack surface). Run this verification on a CI / dev"
        red "host with the tools installed."
        exit 2
    fi
}

require_file() {
    if [[ ! -f "$1" ]]; then
        red "ERROR: required file '$1' is missing."
        exit 3
    fi
}

# ----------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------

require_tool pip-compile
require_tool cyclonedx-py
require_file "${REQ_IN}"

# ----------------------------------------------------------------------
# 1. requirements.in resolves cleanly.
# ----------------------------------------------------------------------

yellow "[1/3] Resolving requirements.in (dry-run)..."
if ! pip-compile --quiet --dry-run "${REQ_IN}" >/dev/null; then
    red "FAIL: requirements.in does not resolve. See pip-compile output."
    exit 4
fi
green "      OK: requirements.in resolves."

# ----------------------------------------------------------------------
# 2. lock file matches the input.
# ----------------------------------------------------------------------

yellow "[2/3] Checking requirements.lock.txt is up-to-date with requirements.in..."
if [[ ! -f "${REQ_LOCK}" ]]; then
    red "FAIL: ${REQ_LOCK} does not exist."
    red "Generate it with:"
    red "  pip-compile --generate-hashes --output-file=${REQ_LOCK} ${REQ_IN}"
    exit 5
fi
TMP_LOCK="$(mktemp -t crucible-lock-check-XXXXXX.txt)"
trap 'rm -f "${TMP_LOCK}"' EXIT
pip-compile --quiet --generate-hashes \
    --output-file="${TMP_LOCK}" "${REQ_IN}" >/dev/null
if ! diff -u "${REQ_LOCK}" "${TMP_LOCK}" >/dev/null; then
    red "FAIL: requirements.lock.txt is stale relative to requirements.in."
    red "Diff (expected vs current):"
    diff -u "${REQ_LOCK}" "${TMP_LOCK}" || true
    red "Regenerate with:"
    red "  pip-compile --generate-hashes --output-file=${REQ_LOCK} ${REQ_IN}"
    exit 6
fi
green "      OK: lock file matches input."

# ----------------------------------------------------------------------
# 3. SBOM is valid and current.
# ----------------------------------------------------------------------

yellow "[3/3] Regenerating SBOM and comparing to ${SBOM}..."
TMP_SBOM="$(mktemp -t crucible-sbom-check-XXXXXX.json)"
trap 'rm -f "${TMP_LOCK}" "${TMP_SBOM}"' EXIT
# cyclonedx-py reads requirements.txt-style files; pass the lock so
# the SBOM reflects pinned versions + hashes.
cyclonedx-py requirements -o "${TMP_SBOM}" \
    --output-format json "${REQ_LOCK}" >/dev/null

if [[ ! -f "${SBOM}" ]]; then
    red "FAIL: ${SBOM} does not exist."
    red "Initialise with: cp ${TMP_SBOM} ${SBOM}"
    exit 7
fi

# Compare top-level component lists (timestamps differ between runs).
PYTHON="${PYTHON:-python3}"
DRIFT="$(${PYTHON} -c '
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
def comps(doc):
    out = []
    for c in doc.get("components", []):
        out.append((c.get("name"), c.get("version")))
    return sorted(out)
ca, cb = comps(a), comps(b)
if ca == cb:
    print("OK")
else:
    print("DRIFT")
    print("expected:", ca)
    print("current:", cb)
' "${SBOM}" "${TMP_SBOM}")"

if [[ "${DRIFT}" != "OK" ]]; then
    red "FAIL: SBOM components diverge from requirements.lock.txt."
    echo "${DRIFT}"
    red "Regenerate with:"
    red "  cyclonedx-py requirements --output-format json -o ${SBOM} ${REQ_LOCK}"
    exit 8
fi
green "      OK: SBOM matches lock."

# ----------------------------------------------------------------------
# Done.
# ----------------------------------------------------------------------

green ""
green "Supply-chain verification PASSED."
green "Inputs match outputs across requirements.in, requirements.lock.txt, sbom.json."
