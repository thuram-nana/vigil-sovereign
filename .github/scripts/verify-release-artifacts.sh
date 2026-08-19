#!/usr/bin/env bash
# Verify the release artifacts THIS run just produced, and prove the check is not a no-op.
#
# WHAT IT VERIFIES, OFFLINE:
#   * every wheel/sdist has a Sigstore/cosign bundle, and `cosign verify-blob --offline`
#     accepts it — the Rekor inclusion proof rides inside the bundle, so a third party can run
#     this air-gapped, exactly the property docs/SUPPLY-CHAIN.md said we did not have;
#   * every wheel/sdist has a PEP 740 `.publish.attestation` with a well-formed DSSE envelope
#     and Sigstore verification material.
#
# NEGATIVE CONTROL: a byte is appended to a COPY of each artifact and the same offline verify
# path is run against it; the tampered copy MUST be rejected. A verifier that accepts a
# tampered artifact is worse than none, so a passing negative control is required, not optional.
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

if [ "$fail" -ne 0 ]; then
  echo "release-artifact verification FAILED" >&2
  exit 1
fi
echo "OK: every artifact carries a valid signature + PEP 740 attestation, and tamper was rejected"
