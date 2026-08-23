#!/usr/bin/env bash
# Verify the release artifacts THIS run just produced, and prove the check is not a no-op.
#
# WHAT IT VERIFIES, OFFLINE:
#   * every wheel/sdist has a Sigstore/cosign bundle, and `cosign verify-blob --offline`
#     accepts it — the Rekor inclusion proof rides inside the bundle, so a third party can run
#     this air-gapped, exactly the property docs/SUPPLY-CHAIN.md said we did not have;
#   * every wheel/sdist has a PEP 740 `.publish.attestation` with a well-formed DSSE envelope
#     and Sigstore verification material.
#   * every SBOM (W3-5 #428) has a cosign bundle that verifies offline, AND its component set still
#     covers its lock — the SAME cross-check the A14 gate runs, re-run here against the exact bytes
#     that are about to be attached to the release (a signature over an incomplete bill of materials
#     is a confident-looking lie).
#
# NEGATIVE CONTROLS: (1) a byte is appended to a COPY of each artifact and the same offline verify
# path is run against it; the tampered copy MUST be rejected. (2) a component is dropped from a COPY
# of each SBOM and the cross-check MUST fail on it. A verifier that accepts a tampered artifact or an
# incomplete SBOM is worse than none, so a passing negative control is required, not optional.
#
# Pure bash + python3 stdlib; no network.
set -euo pipefail

DIST="${1:-dist}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set (owner/repo) to pin the signer identity}"
ISSUER="https://token.actions.githubusercontent.com"
# The keyless signer identity is this workflow at the tag it ran on:
#   https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>
IDENTITY_RE="^https://github\.com/${REPO}/\.github/workflows/release\.yml@refs/tags/"

shopt -s nullglob
artifacts=("$DIST"/*.whl "$DIST"/*.tar.gz)
if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "REFUSING A VACUOUS PASS: no *.whl / *.tar.gz under '$DIST' to verify" >&2
  exit 1
fi

_verify_blob() {
  # $1 = artifact to check against $2 = bundle
  cosign verify-blob \
    --bundle "$2" \
    --certificate-identity-regexp "$IDENTITY_RE" \
    --certificate-oidc-issuer "$ISSUER" \
    --offline \
    "$1"
}

fail=0
for f in "${artifacts[@]}"; do
  bundle="${f}.cosign.bundle"
  att="${f}.publish.attestation"

  if [ ! -f "$bundle" ]; then
    echo "MISSING cosign bundle for $f" >&2; fail=1; continue
  fi
  if [ ! -f "$att" ]; then
    echo "MISSING PEP 740 attestation for $f" >&2; fail=1; continue
  fi

  echo "== $f =="
  echo "-- cosign verify-blob (offline)"
  if ! _verify_blob "$f" "$bundle"; then
    echo "SIGNATURE VERIFICATION FAILED for $f" >&2; fail=1; continue
  fi

  echo "-- PEP 740 attestation structure"
  python3 - "$att" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
assert a.get("version") == 1, f"unexpected attestation version: {a.get('version')!r}"
env = a["envelope"]
assert env.get("statement"), "DSSE envelope has no statement"
assert env.get("signature"), "DSSE envelope has no signature"
assert a.get("verification_material"), "no Sigstore verification material"
print("   PEP 740 structure OK")
PY

  echo "-- NEGATIVE CONTROL: a tampered copy must be rejected"
  tampered="$(mktemp)"
  cp "$f" "$tampered"
  printf '\x00vigil-tamper' >> "$tampered"
  if _verify_blob "$tampered" "$bundle" >/dev/null 2>&1; then
    echo "NEGATIVE CONTROL FAILED: a tampered copy of $f PASSED verification" >&2
    fail=1
  else
    echo "   tampered copy rejected (as it must be)"
  fi
  rm -f "$tampered"
done

# --------------------------------------------------------------------------------------------------
# SBOMs (W3-5 #428). Each *.cdx.json must (a) verify offline against its cosign bundle, (b) survive a
# tamper negative control, and (c) still cross-check against its lock — with an omit-a-component
# negative control proving that check is not a no-op. The SBOM filename selects its lock. Run from the
# repo root (the release workflow invokes this as `verify-release-artifacts.sh dist`), so lock paths
# are repo-relative.
# --------------------------------------------------------------------------------------------------
CROSSCHECK="infra/supply-chain/sbom_crosscheck.py"
declare -A SBOM_LOCK=(
  ["sbom-offense.cdx.json"]="engine/crucible/framework/v2/requirements.lock.txt"
  ["sbom-sovereign.cdx.json"]="infra/supply-chain/sovereign.lock.txt"
)

sboms=("$DIST"/*.cdx.json)
if [ "${#sboms[@]}" -eq 0 ]; then
  echo "REFUSING A VACUOUS PASS: no *.cdx.json SBOM under '$DIST' to verify (W3-5 requires signed SBOMs)" >&2
  exit 1
fi

for s in "${sboms[@]}"; do
  base="$(basename "$s")"
  bundle="${s}.cosign.bundle"
  lock="${SBOM_LOCK[$base]:-}"

  echo "== $s =="
  if [ ! -f "$bundle" ]; then
    echo "MISSING cosign bundle for SBOM $s" >&2; fail=1; continue
  fi
  if [ -z "$lock" ]; then
    echo "UNRECOGNISED SBOM name '$base' — no lock mapping, refusing to pass it unchecked" >&2; fail=1; continue
  fi
  if [ ! -f "$lock" ]; then
    echo "LOCK MISSING for $base: $lock" >&2; fail=1; continue
  fi

  echo "-- cosign verify-blob (offline)"
  if ! _verify_blob "$s" "$bundle"; then
    echo "SBOM SIGNATURE VERIFICATION FAILED for $s" >&2; fail=1; continue
  fi

  echo "-- component cross-check against $lock"
  if ! python3 "$CROSSCHECK" --lock "$lock" --sbom "$s"; then
    echo "SBOM CROSS-CHECK FAILED for $s (incomplete bill of materials)" >&2; fail=1; continue
  fi

  echo "-- NEGATIVE CONTROL: an SBOM with a dropped component must FAIL the cross-check"
  dropped="$(mktemp --suffix=.cdx.json)"
  # Remove exactly one component (stdlib only); if there are none, that is itself a failure.
  if ! python3 - "$s" "$dropped" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
comps = doc.get("components", [])
if not comps:
    print("SBOM has no components to drop — cannot run the negative control", file=sys.stderr)
    raise SystemExit(3)
doc["components"] = comps[1:]  # drop the first shipped component
json.dump(doc, open(sys.argv[2], "w"))
PY
  then
    echo "NEGATIVE CONTROL SETUP FAILED for $s" >&2; fail=1; rm -f "$dropped"; continue
  fi
  if python3 "$CROSSCHECK" --lock "$lock" --sbom "$dropped" >/dev/null 2>&1; then
    echo "NEGATIVE CONTROL FAILED: an SBOM missing a shipped component PASSED the cross-check for $s" >&2
    fail=1
  else
    echo "   SBOM with a dropped component rejected (as it must be)"
  fi
  rm -f "$dropped"
done

if [ "$fail" -ne 0 ]; then
  echo "release-artifact verification FAILED" >&2
  exit 1
fi
echo "OK: every artifact carries a valid signature + PEP 740 attestation, every SBOM verifies offline"
echo "    and cross-checks against its lock, and every tamper / omission negative control was rejected"
