#!/usr/bin/env bash
# remote-deploy — the BOX side of the opt-in EC2 continuous delivery (docs/runbooks/AWS-EC2-DEPLOY.md).
#
# Runs ON the VIGIL host — invoked by the deploy-ec2 workflow via AWS SSM RunShellScript, or by hand
# (`bash tools/remote-deploy.sh`). It fast-forwards the canonical checkout to origin/<branch> and then
# hands the rollout to the EXISTING, proven primitives:
#
#   1. `make deploy-console`  — mirror the served UI + backend into the running tree and restart the unit
#   2. `make smoke`           — the boundary + provision health gate (no pytest)
#   3. (optional) curl $VIGIL_DEPLOY_HEALTH_URL — a live HTTP check of the restarted edge
#
# It adds NO new deploy logic of its own except the one thing only the box can do: ROLL BACK. It records
# the commit it started from and, if deploy-console / smoke / the health probe fails, resets the checkout
# to that commit, re-runs deploy-console to restore the prior served tree, and exits non-zero so the
# caller (the CI job) fails visibly. The prior good version is restored intact.
#
# Fail-closed by construction: `set -euo pipefail`; a dirty working tree, a missing checkout, or a
# non-fast-forwardable branch aborts BEFORE anything is mirrored or restarted. It only ever deploys the
# configured branch (default main), never force-pushes, never reads or prints a secret.
set -euo pipefail

SRC="${VIGIL_SRC_DIR:-$HOME/vigil}"             # the canonical git checkout on the box
BRANCH="${VIGIL_DEPLOY_BRANCH:-main}"           # the only branch this will ever deploy
UNIT="${VIGIL_DEPLOY_UNIT:-vigil-command.service}"   # the user systemd unit running `vigil up`
HEALTH_URL="${VIGIL_DEPLOY_HEALTH_URL:-}"       # optional live edge check (e.g. http://127.0.0.1:8770/healthz)
LOG="${VIGIL_DEPLOY_LOG:-$HOME/.vigil-deploy.log}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG" >&2; }

[ -d "$SRC/.git" ] || { log "remote-deploy: no git checkout at $SRC (set VIGIL_SRC_DIR); refusing"; exit 2; }
cd "$SRC" || { log "remote-deploy: cannot cd to $SRC"; exit 2; }

# A deploy must be exactly origin/$BRANCH — refuse a dirty tree so nothing local is silently shipped.
if ! git diff --quiet || ! git diff --cached --quiet; then
  log "remote-deploy: working tree at $SRC is dirty — refusing (resolve on the box first)"; exit 3
fi

log "remote-deploy: fetching origin/$BRANCH"
git fetch --quiet origin "$BRANCH"
OLD="$(git rev-parse HEAD)"
NEW="$(git rev-parse "origin/$BRANCH")"
log "remote-deploy: $OLD -> $NEW on $BRANCH"
git checkout --quiet "$BRANCH"
git reset --hard "origin/$BRANCH"

serve() {  # make the current checkout live
  if [ -n "${VIGIL_DEPLOY_DIR:-}" ] && [ "${VIGIL_DEPLOY_DIR}" != "$SRC" ]; then
    make deploy-console            # two-tree: mirror canonical -> running tree, restart the unit, report
  else
    log "remote-deploy: single-tree host — restarting $UNIT in place"
    systemctl --user restart "$UNIT"
  fi
}

rollout() {  # serve + health gate; non-zero on any failure
  serve
  make smoke
  if [ -n "$HEALTH_URL" ]; then
    log "remote-deploy: probing $HEALTH_URL"
    curl -fsS --max-time 20 "$HEALTH_URL" >/dev/null
  fi
}

if rollout; then
  log "remote-deploy: deploy OK at $NEW"
  exit 0
fi

# --- rollback: restore the previous good commit, re-serve it, then fail the job ---
log "remote-deploy: rollout FAILED at $NEW — rolling back to $OLD"
git reset --hard "$OLD"
if serve; then
  log "remote-deploy: rolled back to $OLD (prior version restored)"
else
  log "remote-deploy: ROLLBACK ALSO FAILED — the host needs manual attention at $SRC"
fi
exit 5
