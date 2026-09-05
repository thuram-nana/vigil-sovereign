"""Wave 9 — `make deploy-console` mirrors the console UI + backend to the running-demo tree and restarts the
unit, killing the silent two-tree skew (setback #17). Docs-only guard (reads files)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "deploy-console.sh"
MAKEFILE = (REPO / "Makefile").read_text(encoding="utf-8")
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_deploy_script_exists_and_is_executable():
    assert SCRIPT.is_file(), "tools/deploy-console.sh is gone"
    assert os.stat(SCRIPT).st_mode & stat.S_IXUSR, "deploy-console.sh must be executable"


def test_deploy_script_mirrors_the_manifest_and_restarts():
    body = SCRIPT.read_text(encoding="utf-8")
    for path in ("packages/vigil-ui", "engine/crucible/framework/v2/console",
                 "integration/vigil_integration/live", "docs/capability-matrix/evidence-branches.json"):
        assert path in body, f"the deploy manifest is missing {path}"
    assert "VIGIL_DEPLOY_DIR" in body and "systemctl --user restart" in body
    # safe by construction: it must NOT rsync the whole tree, and it refuses src==dest
    assert 'SRC" = "$DEST"' in body


def test_make_has_a_deploy_console_target():
    assert "deploy-console:" in MAKEFILE and "bash tools/deploy-console.sh" in MAKEFILE


def test_slash_verbs_for_a_blocked_run_exist():
    for cmd in ('"/resume"', '"/stop"', '"/approve"', '"/findings"', '"/report"', '"/status"'):
        assert cmd in APPJS, f"slash verb {cmd} is gone"
    # they reuse existing gated actions, never a new power
    assert "pboxRetry();" in APPJS and "pboxCancel();" in APPJS and "offenseApprove(pend[0]" in APPJS
