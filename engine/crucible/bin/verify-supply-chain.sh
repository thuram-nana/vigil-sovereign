#!/usr/bin/env bash
# bin/verify-supply-chain.sh — sovereign-grade supply-chain verification (A14).
#
# Three checks, run in order; exits non-zero on any failure:
#
#   1. requirements.in resolves cleanly (pip-compile dry-run).
#   2. requirements.lock.txt is up to date with requirements.in, AND every pinned
#      requirement in it carries at least one --hash=sha256:.
#   3. A CycloneDX SBOM regenerates from the lock and its component set matches the lock.
#
# Run it from the CRUCIBLE root (engine/crucible), or via the "A14 supply-chain gate" job in
# .github/workflows/supply-chain.yml, which is its caller of record.
#
# Required tools (build-time only — deliberately NOT in requirements.in; adding them there
# would expand the DEPLOYED attack surface without expanding the runtime feature set):
#   pip install pip-tools==7.6.1 cyclonedx-bom==7.3.1
#
# ---------------------------------------------------------------------------------------
# TWO BUGS THIS SCRIPT SHIPPED WITH FOR ITS ENTIRE LIFE, BOTH FIXED HERE (A14)
#
#   (a) It could never pass. Step 2 diffed pip-compile's output against the committed lock,
#       but pip-compile's DEFAULT HEADER embeds the literal --output-file path:
#           # To update, run:
#           #     pip-compile --output-file=/tmp/crucible-lock-check-XXXXXX.txt ...
#       The temp path differs on every run, so the diff ALWAYS differed and step 2 always
#       failed. Fixed with --no-header (and the committed lock is generated the same way, so
#       the two are byte-comparable).
#
#   (b) Its staleness check had the wrong semantics. A bare re-resolve compares the lock
#       against LIVE PyPI, so the gate went red the day any upstream published a release —
#       nothing to do with the change under test, and the only way back to green would have
#       been to bump unrelated dependencies under time pressure. That is how a security gate
#       gets disabled. Fixed by SEEDING the temp file from the committed lock: pip-compile
#       honours existing pins unless --upgrade, so a diff now means exactly "requirements.in
#       changed and the lock was not regenerated". Upgrade availability is reported
#       separately and advisory-only (--report-upgrades).
#
# It was also never called by anything: before this change, grep found zero callers in any
# workflow. A verification script nothing runs verifies nothing.
# ---------------------------------------------------------------------------------------

set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "${0}" && -z "${REQ_IN:-}${REQ_LOCK:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "${SCRIPT_DIR}/.."
fi

# Paths default to CRUCIBLE's own pair, so running this from engine/crucible needs no
# arguments (and the script stays self-contained — engine/crucible is a subtree import and
# must not grow a dependency on the surrounding monorepo). They are env-overridable so the
# SAME implementation verifies the sovereign lock too, rather than a second copy of this
# logic drifting out of sync with this one:
#   REQ_IN=infra/supply-chain/sovereign.in \
#   REQ_LOCK=infra/supply-chain/sovereign.lock.txt \
#     bash engine/crucible/bin/verify-supply-chain.sh
# When either is overridden the script does NOT chdir, so paths are read as given.
REQ_IN="${REQ_IN:-framework/v2/requirements.in}"
REQ_LOCK="${REQ_LOCK:-framework/v2/requirements.lock.txt}"
SBOM_OUT="${SBOM_OUT:-}"          # optional: also keep the generated SBOM at this path
REPORT_UPGRADES=0

for arg in "$@"; do
    case "${arg}" in
        --report-upgrades) REPORT_UPGRADES=1 ;;
        --sbom-out=*)      SBOM_OUT="${arg#*=}" ;;
        *) echo "unknown argument: ${arg}" >&2; exit 64 ;;
    esac
done

# The lock is Python-minor specific (both the marker set and the resolved set depend on it).
# Regenerating under a different minor produces a spurious diff, so say so loudly.
PIN_PY="3.13"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        red "ERROR: required tool '$1' not on PATH."
        red "Install with: pip install pip-tools==7.6.1 cyclonedx-bom==7.3.1"
        red "These are BUILD-TIME tools and intentionally NOT in"
        red "framework/v2/requirements.in (they would expand the deployed"
        red "runtime attack surface). Run this on a CI / dev host."
        exit 2
    fi
}

require_file() {
    if [[ ! -f "$1" ]]; then
        red "ERROR: required file '$1' is missing."
        exit 3
    fi
}

require_tool pip-compile
require_tool cyclonedx-py
require_file "${REQ_IN}"

RUNNING_PY="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if [[ "${RUNNING_PY}" != "${PIN_PY}" ]]; then
    yellow "WARNING: this lock is pinned under Python ${PIN_PY}; you are on ${RUNNING_PY}."
    yellow "         A resolution diff below may be a Python-version artefact, not real drift."
fi

# ----------------------------------------------------------------------
# 1. requirements.in resolves cleanly.
# ----------------------------------------------------------------------

yellow "[1/3] Resolving ${REQ_IN} (dry-run)..."
if ! pip-compile --quiet --dry-run --strip-extras "${REQ_IN}" >/dev/null; then
    red "FAIL: ${REQ_IN} does not resolve. See pip-compile output above."
    exit 4
fi
green "      OK: ${REQ_IN} resolves."

# ----------------------------------------------------------------------
# 2. Lock matches the input, and is genuinely hash-pinned.
# ----------------------------------------------------------------------

yellow "[2/3] Checking ${REQ_LOCK} is current and hash-pinned..."
if [[ ! -f "${REQ_LOCK}" ]]; then
    red "FAIL: ${REQ_LOCK} does not exist. Generate it with:"
    red "  pip-compile --generate-hashes --no-header --strip-extras \\"
    red "              --output-file=${REQ_LOCK} ${REQ_IN}"
    exit 5
fi

# A lock with no `name==version --hash=` lines is not a lock. This repo shipped a 42-line
# comment-only placeholder at this path for its entire history; assert it can never return.
PINNED_COUNT="$(grep -cE '^[A-Za-z0-9._-]+==' "${REQ_LOCK}" || true)"
if [[ "${PINNED_COUNT}" -eq 0 ]]; then
    red "FAIL: ${REQ_LOCK} contains no pinned requirements — it is a placeholder, not a lock."
    exit 5
fi
if ! grep -q -- '--hash=sha256:' "${REQ_LOCK}"; then
    red "FAIL: ${REQ_LOCK} carries no --hash= entries. Regenerate with --generate-hashes."
    exit 5
fi

TMP_LOCK="$(mktemp -t crucible-lock-check-XXXXXX.txt)"
TMP_SBOM="$(mktemp -t crucible-sbom-check-XXXXXX.json)"
TMP_UP="$(mktemp -t crucible-lock-upgrade-XXXXXX.txt)"
trap 'rm -f "${TMP_LOCK}" "${TMP_SBOM}" "${TMP_UP}"' EXIT

# SEED from the committed lock (see bug (b) above): without --upgrade, pip-compile keeps
# pins that already satisfy the input, so a diff means "the .in changed", not "PyPI moved".
cp "${REQ_LOCK}" "${TMP_LOCK}"
pip-compile --quiet --generate-hashes --no-header --strip-extras \
    --output-file="${TMP_LOCK}" "${REQ_IN}" >/dev/null

if ! diff -u "${REQ_LOCK}" "${TMP_LOCK}"; then
    red ""
    red "FAIL: ${REQ_LOCK} is stale relative to ${REQ_IN} (diff above: committed vs regenerated)."
    red "Regenerate under Python ${PIN_PY} with:"
    red "  pip install pip-tools==7.6.1"
    red "  pip-compile --generate-hashes --no-header --strip-extras \\"
    red "              --output-file=${REQ_LOCK} ${REQ_IN}"
    exit 6
fi
green "      OK: lock matches input (${PINNED_COUNT} pinned requirements, all hashed)."

if [[ "${REPORT_UPGRADES}" -eq 1 ]]; then
    yellow "      (advisory) checking whether upstream has newer versions available..."
    pip-compile --quiet --upgrade --generate-hashes --no-header --strip-extras \
        --output-file="${TMP_UP}" "${REQ_IN}" >/dev/null 2>&1 || true
    if diff -q "${REQ_LOCK}" "${TMP_UP}" >/dev/null 2>&1; then
        green "      (advisory) lock is also at the newest resolvable versions."
    else
        yellow "      (advisory) newer versions are available upstream. NOT a failure:"
        diff -u "${REQ_LOCK}" "${TMP_UP}" | grep -E '^[+-][A-Za-z0-9._-]+==' || true
        yellow "      Upgrade deliberately with: pip-compile --upgrade --generate-hashes \\"
        yellow "                                   --no-header --strip-extras \\"
        yellow "                                   --output-file=${REQ_LOCK} ${REQ_IN}"
    fi
fi

# ----------------------------------------------------------------------
# 3. SBOM regenerates from the lock and agrees with it.
# ----------------------------------------------------------------------

yellow "[3/3] Generating a CycloneDX SBOM from the lock and cross-checking it..."
# cyclonedx-py reads requirements.txt-style files; the lock is passed so the SBOM reflects
# pinned versions. The SBOM is DERIVED, so it is not committed — a per-run regenerated
# artifact in git is pure churn, and the lock is the source of truth it is checked against.
cyclonedx-py requirements --output-format JSON --output-reproducible \
    --output-file "${TMP_SBOM}" "${REQ_LOCK}" >/dev/null

PYTHON="${PYTHON:-python3}"
DRIFT="$("${PYTHON}" - "${REQ_LOCK}" "${TMP_SBOM}" <<'PY'
import json, re, sys

lock_path, sbom_path = sys.argv[1], sys.argv[2]

locked = set()
for line in open(lock_path, encoding="utf-8"):
    m = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\;]+)", line)
    if m:
        locked.add((m.group(1).lower().replace("_", "-"), m.group(2)))

doc = json.load(open(sbom_path, encoding="utf-8"))
sbom = {
    (c.get("name", "").lower().replace("_", "-"), c.get("version", ""))
    for c in doc.get("components", [])
}

if not sbom:
    print("DRIFT")
    print("  the generated SBOM has no components at all")
elif locked != sbom:
    print("DRIFT")
    for n, v in sorted(locked - sbom):
        print(f"  in lock but not in SBOM: {n}=={v}")
    for n, v in sorted(sbom - locked):
        print(f"  in SBOM but not in lock: {n}=={v}")
else:
    print(f"OK {len(sbom)}")
PY
)"

if [[ "${DRIFT}" != OK* ]]; then
    red "FAIL: the generated SBOM does not agree with ${REQ_LOCK}."
    echo "${DRIFT}"
    exit 8
fi
green "      OK: SBOM regenerates from the lock and matches it (${DRIFT#OK } components)."

if [[ -n "${SBOM_OUT}" ]]; then
    mkdir -p "$(dirname "${SBOM_OUT}")"
    cp "${TMP_SBOM}" "${SBOM_OUT}"
    green "      SBOM written to ${SBOM_OUT}"
fi

green ""
green "Supply-chain verification PASSED."
green "requirements.in -> requirements.lock.txt (hash-pinned) -> CycloneDX SBOM all agree."
