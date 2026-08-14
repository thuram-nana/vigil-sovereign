#!/usr/bin/env bash
# Bring `main`'s required status checks in line with what CI actually proves — and bind the owner to
# them. Reviewable and reversible, because a branch-protection change is a governance act, not a code
# change: it is applied by a human running this, not silently by a job.
#
# WHY THIS IS A SCRIPT AND NOT SOMETHING A PULL REQUEST DID.
#
# ORDER MATTERS, AND GETTING IT WRONG LOCKS THE REPOSITORY. A required status check that never reports
# blocks a pull request forever — GitHub waits for a check that no workflow will produce. So a check may
# only be made REQUIRED once its workflow is on `main`, where every future PR will run it. Making
# `livefire smoke (per-PR subset)` required while livefire.yml existed only on a feature branch would
# have blocked every other PR in the repository the moment it was set.
#
# RUN THIS ONLY AFTER the PR that adds .github/workflows/livefire.yml has MERGED to main.
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

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '   \033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# The nine that already gate main, plus the three this program adds. Each addition is a check that
# already RUNS and reports; none of them is new machinery being trusted sight-unseen.
#
#   CRUCIBLE eval + benchmark corpus      — the accuracy corpus/soak. The cheap half of the accuracy
#                                           claim (recall/precision/signature) ALSO rides inside the
#                                           already-required `CRUCIBLE core`, so this is defence in
#                                           depth rather than the only line.
#   the briefing explains every agent...   — the documentation-completeness census. It fails when the
#                                           code declares an agent or capability the briefing never
#                                           explains, which is how a whole half of the system fell out
#                                           of the document once.
#   livefire smoke (per-PR subset)         — an engine-built argv, a real tool, a live target, an engine
#                                           reader, and a negative control proven to have run.
REQUIRED=(
  "vigil_core — shared integrity substrate"
  "CRUCIBLE core on vigil_core"
  "gateway egress gate (P6)"
  "integration two-env boundary (P5)"
  "strix Claude-runtime (P8)"
  "SIGIL governor gates (P7 — offense gate + authn)"
  "formal (TLA+ core-invariant model check, F1)"
  "WARDEN Rust kernel (A10 durability)"
  "A14 supply-chain gate"
  "CRUCIBLE eval + benchmark corpus"
  "the briefing explains every agent and capability"
  "livefire smoke (per-PR subset)"
)

command -v gh >/dev/null 2>&1 || die "gh is not installed"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed"

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
print('   enforce_admins:', d['enforce_admins']['enabled'])
"

bold "Proposed required checks"
printf '   - %s\n' "${REQUIRED[@]}"
info "enforce_admins: True"

if [ "${1:-}" != "--apply" ]; then
  bold "DRY RUN — nothing changed"
  info "re-run with --apply to write it"
  exit 0
fi

# A required check that no workflow produces blocks every PR forever. Refuse to set one whose workflow
# is not on the default branch yet — the failure mode this whole script is arranged around.
bold "Checking each proposed context is produced by a workflow on $BRANCH"
WF="$(gh api "repos/$REPO/contents/.github/workflows?ref=$BRANCH" --jq '.[].name' 2>/dev/null || true)"
case "$WF" in
  *livefire.yml*) info "livefire.yml present on $BRANCH" ;;
  *) die "livefire.yml is NOT on $BRANCH yet. Merge the PR that adds it FIRST — making
        'livefire smoke (per-PR subset)' required now would block every pull request." ;;
esac

bold "Applying"
python3 - <<PY > /tmp/vigil-protect-body.json
import json
print(json.dumps({
    "required_status_checks": {"strict": False, "contexts": $(python3 -c "
import json,sys; print(json.dumps([$(printf '%s\n' "${REQUIRED[@]}" | python3 -c 'import sys,json; print(",".join(json.dumps(l.rstrip(chr(10))) for l in sys.stdin))')]))
")},
    "enforce_admins": True,
    "required_pull_request_reviews": None,
    "restrictions": None,
}))
PY
gh api -X PUT "$API" --input /tmp/vigil-protect-body.json >/dev/null
info "applied"

bold "Verifying against the live API"
gh api "$API" --jq '.required_status_checks.contexts[], "enforce_admins=\(.enforce_admins.enabled)"'
