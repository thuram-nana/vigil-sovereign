"""Release gate — the DECEPTIVE-TOOL battery, as an honest scoreboard.

WHAT THIS FILE IS. Part III's load-bearing principle: *a scanner's say-so never confirms.* A tool that LIES
— reports a vulnerability or an open service that is not there — must NOT be able to mint a FACT. VIGIL's
own gated re-drive is the authority; the tool is only a proposer. This board drives the REAL gated runner
(``run_external_tool``) with a backend that claims something false and asserts no FACT results, then proves
the same runner mints a FACT when VIGIL's own re-drive reproduces the claim.

HERMETIC BY CONSTRUCTION. The tool binary need not be installed: the backend supplies each tool's
real-format stdout (its proposal), and the FACT — when one is earned — is the runner's OWN scope-gated TCP
handshake against a real loopback port. So a "deceptive nmap" is a canned backend claiming a CLOSED port is
open; the runner's handshake refutes it. No nmap process runs, and no external network is touched.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each row asserts the true bar; a bar the
system does not meet is ``@pytest.mark.xfail(strict=True, reason="<slice>")``. Every deception row has a
negative control proving the SAME tool/runner DOES mint when the claim is real — otherwise "no fact" would
be vacuously true (a runner that never mints anything trivially never mints from a lie).

FRAMEWORK-DEPENDENT. The runner's re-drive is ``framework.v2.verify.capture_handshake``; this file
``importorskip``s ``framework`` and therefore MUST be listed in the ci.yml offense-leg run-list (enforced by
``test_ci_framework_tests_run_in_offense_leg``). It skips cleanly in the sovereign leg.
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE (framework) not importable in this leg")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    ScopeGate,
    ToolOutcome,
    nmap_service_scan,
    run_external_tool,
    tls_scan,
)

_SIGNER = generate_keypair()
SIGNERS = [("root0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=_SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2 import entitlement
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-08-08`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


class _LyingBackend:
    """Reports a port as ``open`` regardless of reality — the deceptive proposer under test."""
    name = "lying-nmap"

    def __init__(self, claimed_port: int) -> None:
        self._p = claimed_port

    def available(self):
        return True, "lying"

    def run(self, argv, *, timeout=0):
        return ToolOutcome(
            list(argv), 0, f"Host: 127.0.0.1 ()\tPorts: {self._p}/open/tcp//x///\n", "", self.name)


def _gate_in():
    return ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True)


def _open_and_closed_ports():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    return srv, open_port, closed_port


def _run(spec, backend, tmp_path):
    _charter(tmp_path, "127.0.0.1")
    return run_external_tool(spec, "127.0.0.1", scope_gate=_gate_in(), backend=backend,
                             engagement_slug="alpha", signers=SIGNERS, timeout=30.0)


# =========================================================================================================
# The deception: a tool claims a CLOSED port is open. VIGIL's own handshake refutes it → NO fact.
# =========================================================================================================
def test_a_lying_tool_cannot_mint_a_fact(tmp_path):
    srv, _open_port, closed_port = _open_and_closed_ports()
    try:
        res = _run(nmap_service_scan(ports=str(closed_port)), _LyingBackend(closed_port), tmp_path)
    finally:
        srv.close()
    proposed = list(getattr(res, "proposed", []) or [])
    facts = list(getattr(res, "facts", []) or [])
    assert proposed, (
        "the lying backend proposed NOTHING — the deception was never exercised (the re-drive firewall was "
        "not tested)"
    )
    assert not facts, (
        "a tool that LIED (claimed a closed port open) minted a FACT — the runner trusted the tool's say-so "
        "instead of its own re-drive"
    )


def test_negative_control_the_same_runner_mints_when_the_claim_is_REAL(tmp_path):
    """Non-vacuity: the identical runner + backend format against a genuinely OPEN loopback port DOES mint a
    signed FACT (VIGIL's handshake reproduces the claim). So 'no fact from a lie' is a real refutation, not a
    runner that never mints anything."""
    srv, open_port, _closed = _open_and_closed_ports()
    try:
        res = _run(nmap_service_scan(ports=str(open_port)), _LyingBackend(open_port), tmp_path)
    finally:
        srv.close()
    facts = list(getattr(res, "facts", []) or [])
    assert facts, "a REAL open port did not mint — the deception control would be vacuous"


def test_the_minted_fact_re_verifies_offline(tmp_path):
    """The earned FACT is not just present — it re-verifies offline against its retained oracle context, so
    the negative control is a real signed, reproducible FACT (the property the deception must never reach)."""
    from framework.v2.evidence.certify import verify_certificate

    srv, open_port, _closed = _open_and_closed_ports()
    try:
        res = _run(nmap_service_scan(ports=str(open_port)), _LyingBackend(open_port), tmp_path)
    finally:
        srv.close()
    facts = list(getattr(res, "facts", []) or [])
    assert facts, "no fact to re-verify (the runner minted nothing on a real open port)"
    f = facts[0]
    ctx = (res.contexts or {}).get(f.finding_ref, {})
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=TRUST).ok, (
        "the earned FACT did not re-verify offline"
    )


def test_the_deception_is_selected_by_the_runners_own_probe_not_the_tools_stdout(tmp_path):
    """The distinction that makes this sound: the ONLY thing that differs between the deception and the
    control is whether VIGIL's re-drive reproduces the claim. Same tool, same output format, same argv shape
    — a closed port yields no fact, an open port yields a fact. The tool's stdout never decides."""
    srv, open_port, closed_port = _open_and_closed_ports()
    try:
        lie = _run(nmap_service_scan(ports=str(closed_port)), _LyingBackend(closed_port), tmp_path)
        truth = _run(nmap_service_scan(ports=str(open_port)), _LyingBackend(open_port), tmp_path)
    finally:
        srv.close()
    assert not (getattr(lie, "facts", []) or []) and (getattr(truth, "facts", []) or []), (
        "the runner's verdict did not track its OWN re-drive — a lie and a truth in the same tool format were "
        "adjudicated the same way"
    )


# =========================================================================================================
# The conformance harness carries the same property as a gate on `fact_capable` — pin it here too.
# =========================================================================================================
def test_the_conformance_battery_encodes_the_deceptive_property_as_a_hard_requirement():
    """A tool cannot be marked ``fact_capable`` unless it passes ``deceptive_no_fact`` (and actually PROPOSED
    something — a backend that proposes nothing makes 'no fact' vacuous). This pins that the required-property
    set the capability matrix gates on still contains both halves of the crit-6 firewall property."""
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES
    assert {"deceptive_proposed", "deceptive_no_fact"} <= set(REQUIRED_PROPERTIES), (
        "the conformance battery no longer requires the deceptive-no-fact property — a lying tool could be "
        "certified fact_capable"
    )


def test_negative_control_a_report_missing_the_deceptive_property_is_non_conformant():
    """Proves the requirement is enforced, not decorative: a conformance report that omits the deceptive
    property is NON-conformant (so the capability matrix would withhold ``fact_capable``)."""
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES, ConformanceReport
    checks = {p: True for p in REQUIRED_PROPERTIES if p != "deceptive_no_fact"}
    assert ConformanceReport(tool="x", checks=checks).conformant is False


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"


# =========================================================================================================
# The TLS deception (C1): an sslscan-shaped tool CLAIMS a weakness (SSLv2 / RC4 / an MD5-signed, expired
# cert) in its stdout. VIGIL never trusts those rows — it re-negotiates its OWN gated handshake and lets the
# deterministic TLS oracle judge the cert IT retrieved. Against a STRONG (SHA-256) endpoint the lie is
# refuted → no FACT; against a genuinely WEAK (SHA-1) endpoint the SAME lying tool's finding is CONFIRMED by
# VIGIL's own cert → a FACT. So the FACT tracks VIGIL's handshake, never the tool's say-so.
# =========================================================================================================
class _LyingSslscanBackend:
    """An sslscan-shaped backend whose ROWS lie about a weakness (SSLv2 + RC4 + an MD5-signed, expired cert).
    Those rows are never adjudicated — the runner re-drives its own handshake and judges the cert it gets."""
    name = "lying-sslscan"

    def available(self):
        return True, "lying"

    def run(self, argv, *, timeout=0):
        stdout = ("Connected to 127.0.0.1\nTesting SSL server 127.0.0.1 on port 443\n"
                  "Accepted  SSLv2  256 bits  RC4-MD5\n  SSL Certificate:\n"
                  "Signature Algorithm: md5WithRSAEncryption\n"
                  "Not valid after: Jan  1 00:00:00 2015 GMT  (EXPIRED)\n")
        return ToolOutcome(list(argv), 0, stdout, "", self.name)


def _selfsigned(sha: str):
    """A self-signed 2048-bit RSA cert signed with ``sha`` (``-sha1`` weak / ``-sha256`` strong) via the
    openssl CLI (modern ``cryptography`` refuses to SIGN with SHA-1). Skips (never fakes) if openssl can't."""
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    cert_p, key_p = Path(d) / "c.pem", Path(d) / "k.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", sha, "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key_p), "-out", str(cert_p), "-days", "3650",
         "-subj", "/CN=vigil-tls-deception.local"], capture_output=True, text=True)
    if proc.returncode != 0 or not cert_p.is_file():
        pytest.skip(f"openssl could not mint a {sha} cert here (rc={proc.returncode}): {proc.stderr[:200]}")
    return cert_p.read_bytes(), key_p.read_bytes()


class _TLSServer:
    """A minimal threaded loopback TLS server that completes handshakes presenting the given cert."""

    def __init__(self, cert_pem: bytes, key_pem: bytes):
        import ssl
        import tempfile
        import threading
        d = tempfile.mkdtemp()
        cf, kf = Path(d) / "c.pem", Path(d) / "k.pem"
        cf.write_bytes(cert_pem)
        kf.write_bytes(key_pem)
        self._ssl = ssl
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(cf), str(kf))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                raw, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(16)
            except (self._ssl.SSLError, OSError):
                pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


def test_a_lying_tls_tool_cannot_mint_a_fact_over_a_strong_endpoint(tmp_path):
    """The TLS deception: a lying sslscan claims SSLv2/RC4/MD5 weaknesses, but VIGIL's OWN handshake reaches a
    STRONG (SHA-256) cert and the TLS oracle refutes every claim → no FACT. The runner trusted its own
    re-drive, not the tool's rows."""
    cert, key = _selfsigned("-sha256")
    srv = _TLSServer(cert, key)
    try:
        res = _run(tls_scan(port=srv.port), _LyingSslscanBackend(), tmp_path)
    finally:
        srv.close()
    assert list(getattr(res, "proposed", []) or []), (
        "the lying sslscan proposed NOTHING — the deception was never exercised")
    assert not [f for f in (getattr(res, "facts", []) or [])
                if getattr(f, "confirmed_by", "") == "tls_weakness"], (
        "a LYING sslscan minted a TLS FACT over a STRONG endpoint — the runner trusted its rows, not its own "
        "handshake")


def test_negative_control_the_same_lying_tls_tool_mints_when_the_weakness_is_REAL(tmp_path):
    """Non-vacuity: the IDENTICAL lying backend against a genuinely WEAK (SHA-1-signed) cert DOES mint a
    signed TLS_WEAKNESS FACT — VIGIL's own retrieved cert confirms it. So 'no fact from a lie' is a real
    refutation drawn by the handshake, not a probe that never fires."""
    from framework.v2.evidence.certify import verify_certificate
    cert, key = _selfsigned("-sha1")
    srv = _TLSServer(cert, key)
    try:
        res = _run(tls_scan(port=srv.port), _LyingSslscanBackend(), tmp_path)
    finally:
        srv.close()
    facts = [f for f in (res.facts or []) if getattr(f, "confirmed_by", "") == "tls_weakness"]
    assert facts, f"a REAL SHA-1 cert must mint a TLS_WEAKNESS FACT; facts={res.facts} leads={res.leads}"
    ctx = res.contexts[facts[0].finding_ref]
    assert verify_certificate(facts[0].signed, oracle_context=ctx, trust_root=TRUST).ok is True
