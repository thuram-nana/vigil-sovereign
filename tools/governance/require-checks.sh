#!/usr/bin/env bash
# Bring `main`'s required status checks in line with what CI actually proves. Reviewable and
# reversible, because a branch-protection change is a governance act, not a code change: it is applied
# by a human running this, not silently by a job.
#
# SINGLE SOURCE OF TRUTH. The required-check set is NOT written in this script. It lives in one
# committed file, .github/required-status-checks.txt (one context per line), which this tool reads.
# The offline test docs/tests/test_required_checks_canonical.py proves that file agrees with the
# workflows and the docs, and .github/workflows/branch-protection-verify.yml proves the LIVE settings
# agree with that file. One list, three consumers, nothing to drift.
#
# ORDER MATTERS, AND GETTING IT WRONG LOCKS THE REPOSITORY. A required status check that never reports
# blocks a pull request forever — GitHub waits for a check that no workflow will produce. So a check may
# only be made REQUIRED once its workflow is on `main`, where every future PR will run it. This tool
# refuses to apply while the live-fire workflow (the last one to land) is not yet on the default branch.
#
# LIVE SHAPE THIS TOOL WRITES (matching the audited configuration):
#   - required_status_checks.contexts = the canonical file, strict = true (branch must be up to date);
#   - enforce_admins = false — DELIBERATE: the owner keeps an explicit, attributable admin override;
#     every other contributor and every automated agent is bound unconditionally;
#   - required_pull_request_reviews = none, and signed commits are not required — a scheduled handoff,
#     not a shipped control. This tool does not turn them on;
#   - force-pushes and deletions blocked.
#
#   bash tools/governance/require-checks.sh            # show what would change, change nothing
#   bash tools/governance/require-checks.sh --apply    # apply it
#   bash tools/governance/require-checks.sh --restore <snapshot.json>   # roll back
#
# Requires: gh, authenticated as a user with admin on the repository.
set -euo pipefail

REPO="${VIGIL_REPO:-thuram-nana/vigil-sovereign}"
BRANCH="${VIGIL_BRANCH:-main}"
API="repos/$REPO/branches/$BRANCH/protection"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CANON="${VIGIL_REQUIRED_CHECKS_FILE:-$REPO_ROOT/.github/required-status-checks.txt}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '   \033[31m%s\033[0m\n' "$*" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || die "gh is not installed"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed"
[ -f "$CANON" ] || die "canonical required-checks file not found: $CANON"

# The one source of truth. Blank lines and `#` comments are ignored; everything else is a context.
mapfile -t REQUIRED < <(grep -vE '^[[:space:]]*(#|$)' "$CANON" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
[ "${#REQUIRED[@]}" -gt 0 ] || die "canonical list is empty: $CANON"

if [ "${1:-}" = "--restore" ]; then
  SNAP="${2:-}"
  [ -f "$SNAP" ] || die "usage: $0 --restore <snapshot.json>"
  bold "Restoring $BRANCH protection from $SNAP"
  python3 - "$SNAP" <<'PY' > /tmp/vigil-restore-body.json
import json, sys
d = json.load(open(sys.argv[1]))
rsc = d.get("required_status_checks") or {}
print(json.dumps({
    "required_status_checks": {"strict": rsc.get("strict", False),
                               "contexts": rsc.get("contexts", [])},
    "enforce_admins": bool((d.get("enforce_admins") or {}).get("enabled", False)),
    "required_pull_request_reviews": d.get("required_pull_request_reviews"),
    "restrictions": None,
}))
PY
  gh api -X PUT "$API" --input /tmp/vigil-restore-body.json >/dev/null
  info "restored"
  exit 0
fi

bold "Snapshotting current protection (roll back with --restore)"
SNAP="${VIGIL_SNAPSHOT:-/tmp/vigil-branch-protection-$(date +%Y%m%dT%H%M%S).json}"
gh api "$API" > "$SNAP" || die "could not read protection — are you an admin on $REPO?"
info "saved $SNAP"

bold "Current required checks"
python3 -c "
import json;d=json.load(open('$SNAP'))
[print('   -',c) for c in d['required_status_checks']['contexts']]
print('   strict:', d['required_status_checks']['strict'])
print('   enforce_admins:', d['enforce_admins']['enabled'])
"

bold "Proposed required checks (from $CANON)"
printf '   - %s\n' "${REQUIRED[@]}"
info "strict: True (branch must be up to date)"
info "enforce_admins: False (owner keeps an attributable admin override)"

if [ "${1:-}" != "--apply" ]; then
  bold "DRY RUN — nothing changed"
  info "re-run with --apply to write it"
  exit 0
fi

# A required check that no workflow produces blocks every PR forever. Refuse to apply while the
# live-fire workflow — the last one whose per-PR check this list makes required — is not yet on the
# default branch. The offline test already proves every canonical name is a real PR job in the tree;
# this is the on-`main` version of that guard.
bold "Checking the live-fire workflow is on $BRANCH"
WF="$(gh api "repos/$REPO/contents/.github/workflows?ref=$BRANCH" --jq '.[].name' 2>/dev/null || true)"
case "$WF" in
  *livefire.yml*) info "livefire.yml present on $BRANCH" ;;
  *) die "livefire.yml is NOT on $BRANCH yet. Merge the PR that adds it FIRST — making its
        per-PR check required now would block every pull request." ;;
esac

bold "Applying"
printf '%s\n' "${REQUIRED[@]}" | python3 -c '
import json, sys
contexts = [l.rstrip("\n") for l in sys.stdin if l.strip()]
print(json.dumps({
    "required_status_checks": {"strict": True, "contexts": contexts},
    "enforce_admins": False,
    "required_pull_request_reviews": None,
    "restrictions": None,
}))' > /tmp/vigil-protect-body.json
gh api -X PUT "$API" --input /tmp/vigil-protect-body.json >/dev/null
info "applied"

bold "Verifying against the live API"
gh api "$API" --jq '.required_status_checks.contexts[],
  "strict=\(.required_status_checks.strict)",
  "enforce_admins=\(.enforce_admins.enabled)"'
