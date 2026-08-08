"""BRAIN-SLOT P-a — the hexstrike decision brain is PROPOSE-ONLY, DRIFT-FREE, network-free, and
stdlib-only (loadable in the keyless offense env). This is the reasoning core fitted to VIGIL's empty
agent-body socket; the gate/runner/oracle wiring is tested in test_hexstrike_body.py.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vigil_integration.brains.hexstrike_brain import (
    DriftError,
    HexstrikeBrain,
    TargetType,
    ToolDanger,
)

# tools VIGIL forbids a brain from ever proposing (evasion / poisoning / live-exploit)
_FORBIDDEN = {"responder", "pwntools", "angr", "ropper", "pacu", "netexec", "hydra", "one-gadget"}


def test_propose_is_ordered_leads_no_forbidden_tools():
    b = HexstrikeBrain()
    prof = b.analyze_target("http://127.0.0.1/", open_ports=[80, 443], technologies=[], cms_type="wordpress")
    leads = b.propose(prof, objective="comprehensive")
    assert leads and all(set(l) >= {"tool", "params", "priority", "danger", "effectiveness"} for l in leads)
    tools = {l["tool"] for l in leads}
    assert not (tools & _FORBIDDEN), f"brain proposed a forbidden tool: {tools & _FORBIDDEN}"
    # priorities are a clean 1..N ordering
    assert [l["priority"] for l in leads] == list(range(1, len(leads) + 1))
    # wordpress add-on surfaced (recon/assessment only)
    assert "wpscan" in tools


def test_no_evasion_knob_in_any_proposed_param():
    b = HexstrikeBrain()
    for tt, tgt in [(TargetType.WEB_APPLICATION, "http://127.0.0.1/"),
                    (TargetType.API_ENDPOINT, "http://127.0.0.1/api"),
                    (TargetType.NETWORK_HOST, "127.0.0.1"),
                    (TargetType.CLOUD_SERVICE, "aws://acct")]:
        prof = b.analyze_target(tgt, target_type=tt, open_ports=[80], cloud_provider=("aws" if tt == TargetType.CLOUD_SERVICE else None))
        for obj in ("quick", "comprehensive"):
            for lead in b.propose(prof, obj):
                blob = " ".join(f"{k}={v}".lower() for k, v in lead["params"].items())
                for bad in ("stealth", "tamper", "proxy", "vpn", "rotate", "evade", "space2comment", "blind", "decoy"):
                    assert bad not in blob, f"evasion knob {bad!r} in {lead['tool']} params"


def test_drift_guard_rejects_a_forbidden_knob():
    b = HexstrikeBrain()
    with pytest.raises(DriftError):
        b._assert_drift_free("sqlmap", {"tamper": "space2comment"})
    with pytest.raises(DriftError):
        b._assert_drift_free("nmap", {"timing": "T2", "stealth": True})


def test_recon_vs_active_danger_classes():
    b = HexstrikeBrain()
    prof = b.analyze_target("http://127.0.0.1/", target_type=TargetType.WEB_APPLICATION, open_ports=[80])
    leads = b.propose(prof, "comprehensive")
    dangers = {l["tool"]: l["danger"] for l in leads}
    # sqlmap/nuclei/gobuster are ACTIVE (must be QUEUE on a live target); nmap/httpx are RECON
    assert dangers.get("nmap") == ToolDanger.RECON.value
    assert dangers.get("nuclei") == ToolDanger.ACTIVE.value


def test_analyze_target_does_no_network(monkeypatch):
    import socket
    def _boom(*a, **k):
        raise AssertionError("the brain performed a network call")
    monkeypatch.setattr(socket, "gethostbyname", _boom, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _boom, raising=False)
    b = HexstrikeBrain()
    prof = b.analyze_target("http://example.com/", open_ports=[443])  # a hostname — upstream would resolve it
    assert prof.target_type == TargetType.WEB_APPLICATION
    b.propose(prof, "comprehensive")  # no network


def test_fatal2_brain_imports_no_framework_or_heavy_deps():
    # FATAL-2 / offline: importing the brain must pull NO offense engine (framework) and NONE of the
    # heavy hexstrike deps. vigil_core (the shared sovereign-safe substrate, present in both envs) is
    # allowed — the brain's OWN module imports only stdlib (asserted separately by grepping its imports).
    code = (
        "import sys; import vigil_integration.brains.hexstrike_brain as m; "
        "bad=[k for k in sys.modules if k.split('.')[0] in "
        "{'framework','flask','selenium','mitmproxy','psutil','angr','aiohttp','bs4','mcp','fastmcp'}]; "
        "assert not bad, bad; print('clean')"
    )
    repo = Path(__file__).resolve().parents[1].parent
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd=str(repo), env={"PYTHONPATH": "integration", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout


def test_source_carries_attribution_and_is_stdlib_only():
    src = (Path(__file__).resolve().parents[1] / "vigil_integration" / "brains" / "hexstrike_brain.py").read_text()
    assert "hexstrike-ai" in src and "0x4m4" in src and "MIT" in src
    # the brain module's OWN imports are stdlib only (no framework / vigil_core / heavy deps)
    for line in src.splitlines():
        s = line.strip()
        if s.startswith(("import ", "from ")) and not s.startswith("from __future__"):
            assert not any(tok in s for tok in
                           ("framework", "vigil_core", "flask", "selenium", "mitmproxy", "psutil",
                            "angr", "aiohttp", "bs4", "requests", "mcp")), f"non-stdlib import: {s}"
