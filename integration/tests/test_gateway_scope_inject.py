"""B2 (option c) — the launcher's host-verified signed-scope injection for the stdlib-only egress gateway.

``cli._inject_gateway_scope`` runs in the OFFENSE venv (where the charter + its parser live). It VERIFIES the
SIGNED charter and PARSES its scope host-side, then injects the resolved host list as
``VIGIL_GATEWAY_SCOPE_HOSTS`` so the stdlib-only gateway container enforces exactly that snapshot via
``StaticScopeSource`` — no charter file and no framework parser ever enter the egress container. Fail-closed:
a missing/unsigned charter, or a signed-but-empty scope, RAISES so the ``vigil up`` caller takes its
existing fail-closed branch (never a deny-all/ungated gateway).

Offense leg only (imports framework via the ethics parser) → listed in the ci.yml offense run-list.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("framework.v2.common.ethics", reason="CRUCIBLE (charter parser) not importable in this leg")

from vigil_integration import cli


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _write_charter(tmp_path: Path, slug: str, *, signed: bool = True, hosts=("acme.example.com",)) -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    rows = "".join(f"| `{h}` | Host | Yes |\n" for h in hosts)
    attest = ("## 1. Operator attestation\n\nSigned: `tester`     Date: `2026-08-04`\n\n" if signed
              else "## 1. Operator attestation\n\n(unsigned)\n\n")
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n{attest}"
        f"## 2. In-scope systems\n\n| Host | Notes | Auth |\n|---|---|---|\n{rows}\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def test_signed_charter_injects_the_parsed_scope_hosts(tmp_path: Path):
    _write_charter(tmp_path, "acme", signed=True, hosts=("acme.example.com", "10.0.0.5"))
    env: dict = {}
    cli._inject_gateway_scope("acme", env)
    got = set(env["VIGIL_GATEWAY_SCOPE_HOSTS"].split(","))
    assert {"acme.example.com", "10.0.0.5"} <= got, env


def test_unsigned_charter_is_refused_fail_closed(tmp_path: Path):
    _write_charter(tmp_path, "acme", signed=False)
    env: dict = {}
    with pytest.raises(RuntimeError, match="refusing to bring up the egress gateway"):
        cli._inject_gateway_scope("acme", env)
    assert "VIGIL_GATEWAY_SCOPE_HOSTS" not in env


def test_missing_charter_is_refused_fail_closed(tmp_path: Path):
    env: dict = {}
    with pytest.raises(RuntimeError, match="refusing to bring up the egress gateway"):
        cli._inject_gateway_scope("nonexistent", env)
    assert "VIGIL_GATEWAY_SCOPE_HOSTS" not in env


def test_signed_but_empty_scope_is_refused_fail_closed(tmp_path: Path):
    _write_charter(tmp_path, "acme", signed=True, hosts=())   # signed, but no in-scope host rows
    env: dict = {}
    with pytest.raises(RuntimeError, match="EMPTY in-scope host set"):
        cli._inject_gateway_scope("acme", env)
    assert "VIGIL_GATEWAY_SCOPE_HOSTS" not in env
