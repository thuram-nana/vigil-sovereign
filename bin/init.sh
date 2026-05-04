#!/usr/bin/env bash
#
# bin/init.sh — one-time setup for CRUCIBLE on a fresh host.
#
# What it does (idempotent — safe to re-run):
#   1. Locates CRUCIBLE_ROOT by walking up from this script.
#   2. Rewrites .claude/settings.json so every embedded path matches
#      the actual filesystem location.
#   3. Initializes framework/v2/.intake-authorizations.txt with a header.
#   4. Prints the export line to add to your shell rc file.
#
# What it deliberately does NOT do:
#   - Edit your shell rc files (you do that explicitly).
#   - Install Python dependencies (run requirements.txt yourself).
#   - Touch any v1 canon under framework/{cognitive,playbooks,checklists,
#     knowledge-base,templates}/.
#
# Run it once after you clone or move the repository:
#
#     bash bin/init.sh
#
set -euo pipefail

# ---------- locate CRUCIBLE_ROOT ----------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRUCIBLE_ROOT="$HERE"
while [[ "$CRUCIBLE_ROOT" != "/" && ! -f "$CRUCIBLE_ROOT/CLAUDE.md" ]]; do
  CRUCIBLE_ROOT="$(dirname "$CRUCIBLE_ROOT")"
done

if [[ ! -f "$CRUCIBLE_ROOT/CLAUDE.md" ]]; then
  echo "error: could not find CLAUDE.md walking up from $HERE" >&2
  echo "       are you running this from inside the crucible tree?" >&2
  exit 1
fi

export CRUCIBLE_ROOT
echo "CRUCIBLE_ROOT = $CRUCIBLE_ROOT"

# ---------- patch .claude/settings.json ----------
SETTINGS="$CRUCIBLE_ROOT/.claude/settings.json"
if [[ ! -f "$SETTINGS" ]]; then
  echo "error: $SETTINGS not found" >&2
  exit 1
fi

python3 - <<'PYEOF'
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["CRUCIBLE_ROOT"])
sf = root / ".claude" / "settings.json"
data = json.loads(sf.read_text(encoding="utf-8"))

new_root = str(root)
old_root = data.get("env", {}).get("CRUCIBLE_ROOT", "")

def rewrite(obj):
    if isinstance(obj, str):
        if old_root and old_root != new_root and old_root in obj:
            return obj.replace(old_root, new_root)
        return obj
    if isinstance(obj, list):
        return [rewrite(x) for x in obj]
    if isinstance(obj, dict):
        return {k: rewrite(v) for k, v in obj.items()}
    return obj

if old_root and old_root == new_root:
    print(f"  settings.json already points at {new_root}; no change")
else:
    data = rewrite(data)
    data.setdefault("env", {})["CRUCIBLE_ROOT"] = new_root
    # round-trip through JSON, preserving the leading _comment_purpose key
    sf.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if old_root:
        print(f"  settings.json patched: {old_root!r} -> {new_root!r}")
    else:
        print(f"  settings.json env.CRUCIBLE_ROOT set to {new_root!r}")
PYEOF

# ---------- initialize the v2 authorization ledger ----------
PYTHONPATH="$CRUCIBLE_ROOT" python3 - <<'PYEOF'
import os
import sys
sys.path.insert(0, os.environ["CRUCIBLE_ROOT"])
try:
    from framework.v2.common import ethics
    ethics.init_authorization_ledger()
    print(f"  authorization ledger: {ethics.authorization_ledger()}")
except Exception as e:
    print(f"  warn: could not init authorization ledger ({e.__class__.__name__}: {e})")
PYEOF

# ---------- summary ----------
cat <<EOF

To make CRUCIBLE_ROOT permanent in your shell, add this line to
~/.bashrc or ~/.zshrc:

    export CRUCIBLE_ROOT="$CRUCIBLE_ROOT"

Then verify with:

    python3 -m framework.v2 status
EOF
