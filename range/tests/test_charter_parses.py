"""The shipped charter is a real, signed, in-scope authorization VIGIL's own gate accepts.

Two checks: (1) a root-independent structural check of the charter file, and (2) — when the offense engine
is importable — the REAL `framework.v2.common.ethics` parser, run against a temp CRUCIBLE_ROOT holding a
copy of the charter, so the file is proven to satisfy `is_charter_signed` + `parse_scope`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import pytest
from conftest import REPO_ROOT

CHARTER = os.path.join(REPO_ROOT, "targets", "meridian", "charter.md")
# the exact section header ethics.parse_scope keys on (framework/v2/common/ethics.py:_SCOPE_HEADER)
_SCOPE_HEADER = re.compile(r"^##\s*2\.\s*In[- ]scope systems\b", re.MULTILINE | re.IGNORECASE)


def test_charter_has_a_real_signature_and_scope_section():
    text = open(CHARTER, encoding="utf-8").read()
    assert _SCOPE_HEADER.search(text), "missing the numbered `## 2. In-scope systems` header parse_scope needs"
    # a real Signed: line with a non-placeholder name
    m = re.search(r"^Signed:\s*(.+?)\s{2,}", text, re.MULTILINE)
    assert m and "<" not in m.group(1) and m.group(1).strip(), "no real Signed: name"
    assert "`127.0.0.1`" in text


def test_real_ethics_parser_accepts_the_charter(tmp_path):
    # importable only in the offense env; skip elsewhere.
    pytest.importorskip("framework.v2.common.ethics", reason="offense engine not importable in this env")
    root = tmp_path / "root"
    (root / "targets" / "meridian").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# sentinel\n", encoding="utf-8")
    shutil.copy(CHARTER, root / "targets" / "meridian" / "charter.md")

    code = (
        "from framework.v2.common import ethics\n"
        "s,_=ethics.is_charter_signed('meridian')\n"
        "h=ethics.parse_scope('meridian')\n"
        "assert s, 'not signed'\n"
        "assert ethics.host_matches_scope('127.0.0.1', h), h\n"
        "assert ethics.host_matches_scope('localhost', h), h\n"
        "assert not ethics.host_matches_scope('8.8.8.8', h), h\n"
        "print('OK')\n"
    )
    env = {**os.environ, "CRUCIBLE_ROOT": str(root)}
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-1200:]
    assert "OK" in r.stdout
