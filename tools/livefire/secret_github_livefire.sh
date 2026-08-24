#!/usr/bin/env bash
# =============================================================================
# VIGIL LIVE-FIRE — exposed-secret VALIDITY (E5, github_pat row) against the
# REAL GitHub API
# =============================================================================
#
# WHAT THIS IS. Every other proof of the exposed-secret validity confirmation
# runs over FIXTURES: evidence we wrote by hand. This script runs it over
# evidence the REAL api.github.com produced, through the real WARDEN-gated
# runner and the real network transport, and it is fully reproducible by anyone
# — a customer, an auditor, or a sceptical evaluator — on their own machine with
# their own GitHub account.
#
# WHY IT IS AUTHORIZED. It uses the OPERATOR'S OWN GitHub credential against the
# OPERATOR'S OWN identity endpoint (`GET /user` — the least-privileged call the
# API offers; it reads who you are and changes nothing). It never touches an
# account it does not own. That is the whole point: unlike the AWS row, this one
# can be re-checked by anyone without borrowing anybody's cloud account.
#
# THE TOKEN NEVER TOUCHES DISK. `gh auth token` is piped straight into the
# harness on stdin. It is never written to a file, never placed in an argv where
# `ps` would show it, and never exported into the environment. The harness
# asserts it does not appear in the capture, the oracle context, or the signed
# certificate.
#
# WHAT IT PROVES, and — just as important — what it proves the system does NOT do:
#
#   1. A genuinely valid credential is CONFIRMED from a real 200 that the real
#      GitHub API returned to a real TLS-verified connection, a signed
#      certificate is minted, and that certificate RE-VERIFIES OFFLINE.
#   2. A bogus token of the same SHAPE, sent LIVE to the same real endpoint, is
#      rejected by GitHub (401) and correctly left a LEAD. Structure is not
#      validity, and this is the difference measured against the real provider.
#   3. The anti-laundering control that matters most: the SAME confirmed capture
#      stops being a fact the instant its confirming endpoint is swapped for an
#      attacker-controlled host (or a suffix-confusion lookalike). If any
#      endpoint could confirm a secret, anyone who controlled one could mint
#      facts at will. The runner's own exfil floor refuses to send the live
#      token there in the first place, which is asserted too.
#   4. The same capture with the credential and the confirming call carrying
#      DIFFERENT fingerprints — "some other secret authenticated" — is likewise
#      not a fact.
#
# A detector that only ever says "found something" is worthless. The controls
# are the product.
#
# WHAT THIS DOES *NOT* PROVE. Only the `github_pat` row. The `aws_access_key`
# row is built and unit-proven but has never been exercised against real AWS —
# it needs a real access key. Nothing here transfers to it.
#
# USAGE:   tools/livefire/secret_github_livefire.sh
#
# REQUIRES: an authenticated `gh` (run `gh auth login`), network egress to
#           api.github.com, and the offense virtualenv at .venv-offense.
#
# NOT RUN IN CI. There are no credentials in CI, and a live-fire that fabricates
# a result when it cannot run is worse than no live-fire. If `gh` is missing or
# unauthenticated this SKIPS cleanly and says so.
# =============================================================================
set -euo pipefail
# No `set -x` anywhere in this script: tracing would print the token.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
skip() { printf '\n\033[1mLIVE-FIRE SKIPPED\033[0m — %s\n' "$*"; exit 0; }

say "1. Checking for an authenticated GitHub credential"
# W11-2: a MISSING TOOL is a hard failure, not a clean skip. gh being absent is exactly the tolerated
# case this workstream removes — the run cannot be proven without it, so fail closed here. (Authentication
# is a CREDENTIAL, not a tool: an unauthenticated gh is still an honest skip below, because there is no
# operator credential in default CI.)
python3 "$HERE/require_tools.py" gh python3
gh auth status >/dev/null 2>&1 || skip "gh is not authenticated. Run 'gh auth login', then re-run this."
gh auth token >/dev/null 2>&1   || skip "gh is authenticated but exposes no token (a GITHUB_TOKEN-less or restricted setup)."
echo "   gh is authenticated — using the operator's own credential against their own /user endpoint."
echo "   the token is piped on stdin: never to disk, never to an argv, never to the environment."

say "2. Checking the offense virtualenv"
# VIGIL_VENV lets this run from a git worktree, whose checkout has no venv of its own.
# VIGIL_LIVEFIRE_NO_VENV=1 lets a CI job that already installed the engine deps into the current
# interpreter proceed without a venv.
VENV="${VIGIL_VENV:-$REPO/.venv-offense}"
if [ -f "$VENV/bin/activate" ]; then
  echo "   using $VENV"
elif [ "${VIGIL_LIVEFIRE_NO_VENV:-0}" != "1" ]; then
  skip "the offense virtualenv is missing at $VENV (set VIGIL_VENV, or VIGIL_LIVEFIRE_NO_VENV=1 if the deps are already installed)."
else
  echo "   no offense venv; using the current interpreter (VIGIL_LIVEFIRE_NO_VENV=1)"
fi

say "3. Driving the real runner against the real api.github.com, then adjudicating"
cd "$REPO"
if [ -f "$VENV/bin/activate" ]; then
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
fi
gh auth token | PYTHONPATH=integration:engine/crucible:gateway \
  python3 "$REPO/tools/livefire/secret_github_livefire.py"

say "LIVE-FIRE COMPLETE"
