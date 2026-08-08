"""PHASE 0.6 — the reusable ToolSpec conformance battery (integration criterion 10), run over a REAL tool.

Proves the acceptance harness itself: nmap's ToolSpec, driven through the real gated runner, passes every
property (positive FACT that re-verifies offline; a deceptive proposal mints NO fact; a tool timeout is the
typed ERROR outcome; a tripped kill-switch and an out-of-scope target each refuse before traffic). This is
the gate a tool must pass before the capability matrix may mark it fact_capable.

Offense-process test (loads framework.*): CI runs it in the offense group (see ci.yml).
"""
from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.conformance import run_toolspec_conformance  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    LocalSubprocessBackend,
    ScopeGate,
    ToolOutcome,
    nmap_service_scan,
)

_SIGNER = generate_keypair()
SIGNERS = [("root0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=_SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-08-08`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


class _DeceptiveNmapBackend:
    """Claims a CLOSED port is open — the runner's own re-drive handshake must fail → NO fact."""
    name = "deceptive"

    def __init__(self, closed_port):
        self._p = closed_port

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, f"Host: 127.0.0.1 ()\tPorts: {self._p}/open/tcp//x///\n", "",
                           self.name)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed (present-tool path)")
def test_nmap_toolspec_passes_the_full_conformance_battery(tmp_path):
    from framework.v2.authority import KillSwitch

    _charter(tmp_path, "127.0.0.1")
    # a real open loopback port (positive) + a definitely-closed port (deceptive)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name="nmap",
            positive_spec=nmap_service_scan(ports=str(open_port)), positive_backend=LocalSubprocessBackend(),
            deceptive_spec=nmap_service_scan(ports=str(closed_port)),
            deceptive_backend=_DeceptiveNmapBackend(closed_port),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=60.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    # every property was actually exercised (no silently-missing check)
    for prop in ("positive_fact", "positive_verified_offline", "deceptive_no_fact", "tool_error_typed",
                 "killswitch_refused_no_traffic", "out_of_scope_refused_no_traffic"):
        assert report.checks.get(prop) is True, f"{prop} not satisfied: {report.summary()}"


def test_conformance_report_non_conformant_when_a_check_fails():
    # a report with a failing check is NOT conformant (the gate a caller uses to withhold fact_capable)
    from vigil_integration.live.conformance import ConformanceReport
    r = ConformanceReport(tool="x", checks={"positive_fact": True, "deceptive_no_fact": False})
    assert r.conformant is False and "deceptive_no_fact" in r.summary()
