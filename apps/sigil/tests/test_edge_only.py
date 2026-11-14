"""The edge-only fast path (tools/deploy/edge_only.py): a release qualifies only when every file that differs is a
static file an edge serves (customer_app/ or public_site/) or a file no running process reads (VERSION,
CHANGELOG.md, packages/vigil-brand/, tests/); anything else — code, the console kit, docs/, units, config —
needs the full upgrade. Checked on paths and against a real git history (renames count on both sides).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
TOOL = REPO / "tools" / "deploy" / "edge_only.py"
_spec = importlib.util.spec_from_file_location("edge_only", TOOL)
edge_only = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(edge_only)

CUST = "apps/sigil/sigil/ui/customer_app/"
PUB = "apps/sigil/sigil/ui/public_site/"


@pytest.mark.parametrize("paths,edges", [
    ([CUST + "app.js"], ["customer"]),
    ([PUB + "index.html", PUB + "assets/site.css"], ["public"]),
    ([CUST + "brand/icon-192.png", PUB + "assets/favicon.svg", "packages/vigil-brand/generated/favicon.svg",
      "VERSION", "CHANGELOG.md", "apps/sigil/tests/test_x.py", "docs/tests/test_y.py"], ["customer", "public"]),
])
def test_served_files_and_inert_files_are_edge_only(paths, edges):
    assert edge_only.classify(paths) == (edges, [])


@pytest.mark.parametrize("blocker", [
    "apps/sigil/sigil/ui/custui.py", "apps/sigil/sigil/ui/pubui.py", "apps/sigil/sigil/ui/static_site.py",
    "apps/sigil/sigil/config.py", "packages/vigil-ui/app.js", "integration/vigil_integration/uiproxy.py",
    "docs/capability-matrix/evidence-branches.json", "apps/sigil/deploy/systemd/sigil-customer@.service",
    "apps/sigil/deploy/reverse-proxy/vigil-customer.nginx.conf", "README.md", "apps/sigil/sigil/ui/customer_appx/x",
    "pyproject.toml", "apps/sigil/sigil/bridge/webapp/app.js",
])
def test_anything_else_needs_the_full_upgrade(blocker):
    edges, blockers = edge_only.classify([CUST + "app.js", blocker])
    assert blockers == [blocker]


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@example.test", "PATH": "/usr/bin:/bin", "HOME": str(repo)})


def _commit(repo, files, msg):
    for rel, text in files.items():
        p = repo / rel
        if text is None:
            p.unlink()
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--no-gpg-sign", "-m", msg)
    out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _run(repo, a, b):
    r = subprocess.run([sys.executable, str(TOOL), a, b], cwd=repo, capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout + r.stderr


def test_against_a_git_history(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    base = _commit(repo, {CUST + "app.js": "1", PUB + "index.html": "1", "apps/sigil/sigil/ui/custui.py": "1",
                          "VERSION": "0.1.0\n"}, "base")
    static = _commit(repo, {CUST + "app.js": "2", "VERSION": "0.1.1\n"}, "static")
    assert _run(repo, base, static) == (0, "edge-only: customer\n")
    code = _commit(repo, {PUB + "index.html": "2", "apps/sigil/sigil/ui/custui.py": "2"}, "code")
    rc, out = _run(repo, static, code)
    assert rc == 1 and "apps/sigil/sigil/ui/custui.py" in out
    moved = _commit(repo, {CUST + "app.js": None, "apps/sigil/sigil/ui/app.js": "2"}, "move out of the tree")
    rc, out = _run(repo, code, moved)
    assert rc == 1 and "apps/sigil/sigil/ui/app.js" in out             # the rename's new side counts
    assert _run(repo, moved, moved)[0] == 3                             # nothing differs
    inert = _commit(repo, {"CHANGELOG.md": "x"}, "inert only")
    assert _run(repo, moved, inert)[0] == 3                             # nothing to swap
    assert _run(repo, base, "no-such-ref")[0] == 2                     # a git error
    usage = subprocess.run([sys.executable, str(TOOL), base], cwd=repo, capture_output=True, text=True, timeout=60)
    assert usage.returncode == 2 and "edge_only.py" in usage.stderr
