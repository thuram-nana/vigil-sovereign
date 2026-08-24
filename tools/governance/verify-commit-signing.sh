#!/usr/bin/env bash
# verify-commit-signing.sh — is THIS working copy configured to sign commits? ([W12-4] #493)
#
# Thin wrapper over tools/governance/commit_signing.py so there is a single source of truth for the
# check (the Python `signing_config_defects`, which the required-CI guard also exercises). Exits 0 when
# the local git config will sign commits, non-zero with guidance when it will not.
#
# This checks the LOCAL side only. The server-side "Require signed commits" rule on main is a separate
# branch-protection admin flip — see docs/decisions/W12-4-enforce-signed-commits.md.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
exec python3 "${here}/commit_signing.py" --verify
