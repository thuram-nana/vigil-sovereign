"""Fixtures for DAA tests — isolate entitlement so run_analysis's
capability gate is deterministic, and provide a planted source tree."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from ...entitlement import policy as ent_policy


@pytest.fixture(autouse=True)
def _isolated_entitlement(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path) + "/ent")
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    ent_policy.reset_policy()
    yield
    ent_policy.reset_policy()


@pytest.fixture
def planted_tree(tmp_path: Path) -> Path:
    """A small source tree with known dangerous patterns."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "import subprocess, yaml, hashlib\n"
        "def run(user_input):\n"
        "    eval(user_input)\n"
        "    subprocess.run(user_input, shell=True)\n"
        "    yaml.load(user_input)\n"
        "    return hashlib.md5(user_input).hexdigest()\n"
        "API_KEY = \"supersecretvalue123\"\n",
        encoding="utf-8",
    )
    (src / "clean.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )
    (src / "app.js").write_text(
        "function render(x){ document.body.innerHTML = x; }\n",
        encoding="utf-8",
    )
    return src
