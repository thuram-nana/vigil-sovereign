#!/usr/bin/env bash
# deploy-console — mirror the console UI + backend from THIS (canonical) tree to the running-demo tree and
# restart the unit, then verify. Kills the silent two-tree skew (setback #17): before this existed, an edit
# here reached the running `vigil up` only if someone remembered to hand-copy "the 3 UI files" and restart —
# so every slice was live only by luck, and the docs tests guarded a tree the operator was not looking at.
#
# Safe by construction: it mirrors a FIXED MANIFEST (the served UI, the console backend, the integration
# live engine, the evidence-branch registry) — never the whole tree — and --delete is confined to those
# code subtrees. Configurable: VIGIL_DEPLOY_DIR (default /home/kali/vigil), VIGIL_DEPLOY_UNIT (default
# vigil-command.service). Set VIGIL_DEPLOY_NO_RESTART=1 to mirror without restarting.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${VIGIL_DEPLOY_DIR:-/home/kali/vigil}"
UNIT="${VIGIL_DEPLOY_UNIT:-vigil-command.service}"

if [ ! -d "$DEST" ]; then
  echo "deploy-console: destination tree not found: $DEST (set VIGIL_DEPLOY_DIR)" >&2
  exit 1
fi
if [ "$SRC" = "$DEST" ]; then
  echo "deploy-console: source and destination are the same tree ($SRC) — nothing to mirror" >&2
  exit 1
fi

# THE MANIFEST — the exact code paths the running console serves. Directories are mirrored with --delete
# (they are pure code); single files are copied. Keep this list in lockstep with what the chat/engage path
# actually loads: the UI bundle, the console backend, the live re-drive engine, and the branch registry.
DIRS=(
  "packages/vigil-ui"
  "engine/crucible/framework/v2/console"
  "integration/vigil_integration/live"
)
FILES=(
  "docs/capability-matrix/evidence-branches.json"
)

have_rsync() { command -v rsync >/dev/null 2>&1; }

for d in "${DIRS[@]}"; do
  if [ -d "$SRC/$d" ]; then
    mkdir -p "$DEST/$d"
    if have_rsync; then
      rsync -a --delete --exclude '__pycache__' --exclude '*.pyc' "$SRC/$d/" "$DEST/$d/"
    else
      rm -rf "$DEST/$d" && mkdir -p "$(dirname "$DEST/$d")" && cp -r "$SRC/$d" "$DEST/$d"
    fi
    echo "mirrored dir  $d"
  fi
done

for f in "${FILES[@]}"; do
  if [ -f "$SRC/$f" ]; then
    mkdir -p "$DEST/$(dirname "$f")"
    cp -f "$SRC/$f" "$DEST/$f"
    echo "mirrored file $f"
  fi
done

if [ "${VIGIL_DEPLOY_NO_RESTART:-0}" = "1" ]; then
  echo "deploy-console: mirrored to $DEST (restart skipped — VIGIL_DEPLOY_NO_RESTART=1)"
  exit 0
fi

echo "deploy-console: restarting $UNIT ..."
if systemctl --user restart "$UNIT" 2>/dev/null; then
  # give the unit a moment, then report its state (never fail the deploy on a status hiccup)
  sleep 1 || true
  systemctl --user is-active "$UNIT" >/dev/null 2>&1 \
    && echo "deploy-console: $UNIT is active" \
    || echo "deploy-console: WARN — $UNIT is not active; check 'systemctl --user status $UNIT'"
else
  echo "deploy-console: WARN — could not restart $UNIT (is the user systemd unit installed? 'make systemd')" >&2
fi
echo "deploy-console: done → $DEST"
