"""C4 — the web-FACT runner leg: the web_discovery family's FACT column + the scanners bug-class dispatcher.

A discovery tool (katana / gobuster) PROPOSES a URL and a scanner (nuclei) PROPOSES a URL + a class; the
runner re-drives each through VIGIL's OWN gated ACHIEVED_STATE web re-drive (``live.web_redrive.web_redrive``
— the shipped open_redirect / cors / host_header / graphql_introspection checks judged by the deterministic
predicate_oracle over VIGIL's own no-redirect capture). The headline proofs are genuinely LIVE: a real
loopback HTTP server serves a vulnerable open-redirect + a credential-reflecting CORS; the runner mints a
signed FACT that re-verifies OFFLINE. No external tool binary is installed or run — a canned backend supplies
each tool's real-format PROPOSAL, and the FACT is VIGIL's own gated capture, never the tool's bytes or label.

THE INVARIANT under test (no downgrade): a tool result mints a FACT ONLY via a VIGIL-owned gated capture that
crosses ``verdict.admit()``; the SAME tool result with no established channel (or on a safe endpoint) mints
NOTHING and stays a LEAD. A scanner's classification is never trusted — it selects WHICH re-drive to
attribute, and the oracle over VIGIL's own capture is the sole authority.

Offense-process test (loads framework.* + vigil_integration.live.*): CI runs it in the offense group.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")
pytest.importorskip("vigil_gateway", reason="vigil_gateway (gated transport) not importable here")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.conformance import REQUIRED_PROPERTIES, run_toolspec_conformance  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    ScopeGate,
    ToolOutcome,
    dirsearch_web_scan,
    feroxbuster_web_scan,
    gau_web_scan,
    gobuster_web_scan,
    katana_web_scan,
    nuclei_web_redrive,
    run_external_tool,
    waybackurls_web_scan,
)


# ---- gate isolation + charter (mirrors test_web_redrive / test_conformance) -------------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-09-29`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers_and_trust():
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


SIGNERS, TRUST = _signers_and_trust()


# ---- a loopback web app: a REAL open-redirect + a REAL credential-reflecting CORS + a SAFE endpoint --
_HITS = {"n": 0}


class _WebApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: D401 — silence
        return

    def do_GET(self):  # noqa: N802
        _HITS["n"] += 1
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/redirect":                      # VULNERABLE: reflects `next` into Location
            self.send_response(302)
            self.send_header("Location", (q.get("next") or [""])[0])
            self.end_headers()
        elif parts.path == "/api":                         # VULNERABLE: reflects Origin + allows creds
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"{}")
        elif parts.path == "/safe":                        # SAFE: reflects the value in plain text only
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"you requested: {(q.get('next') or [''])[0]}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def _serve():
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _WebApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _CannedBackend:
    """Returns a fixed stdout for ANY argv — supplies a tool's real-format proposal with no binary present."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self):
        return True, "canned"

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, self._stdout, "", self.name)


def _katana_jsonl(url: str) -> str:
    return json.dumps({"timestamp": "t", "url": url, "method": "GET"}) + "\n"


def _gobuster_line(url: str) -> str:
    # gobuster `-e` (expanded) prints the FULL URL of each hit; the parser host-pins it, keeping the port.
    return f"{url} (Status: 200) [Size: 42]\n"


def _plain_url_line(url: str) -> str:
    # gau / waybackurls / feroxbuster --silent print ONE full URL per line.
    return f"{url}\n"


def _dirsearch_line(url: str) -> str:
    # dirsearch --full-url decorates each hit with a timestamp + status + size; the URL is a LATER token.
    return f"[12:00:00] 200 -   42B - {url}\n"


def _nuclei_jsonl(url: str, template_id: str, cwe: str) -> str:
    return json.dumps({
        "template-id": template_id,
        "info": {"name": template_id, "severity": "medium",
                 "classification": {"cwe-id": [cwe]}},
        "type": "http", "host": urlsplit(url).netloc, "matched-at": url,
    }) + "\n"


def _scope_gate(hosts):
    return ScopeGate(scope=StaticScopeSource(list(hosts)), loopback_allowed_if_scoped=True)


def _run(spec, backend, *, target="127.0.0.1", scope=("127.0.0.1",)):
    return run_external_tool(spec, target, scope_gate=_scope_gate(scope), backend=backend,
                             engagement_slug="alpha", signers=SIGNERS, timeout=30.0)


# ===================================================================================================
# (1) web_discovery FACT: a tool-proposed URL → VIGIL's OWN gated capture → an ACHIEVED_STATE FACT.
# ===================================================================================================
def test_katana_proposed_open_redirect_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    """katana PROPOSES a URL; VIGIL re-drives it through its own gated web capture and the achieved_state
    oracle mints a signed open_redirect FACT that re-verifies OFFLINE. The tool's URL row was never the
    authority — VIGIL's own capture is."""
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(katana_web_scan(scheme="http"),
                   _CannedBackend(_katana_jsonl(f"http://127.0.0.1:{port}/redirect?next=orig")))
    finally:
        srv.shutdown()
    assert res.status == "ran", res.reason
    assert res.proposed, "katana must have proposed the URL (grounding intel)"
    assert res.facts, f"expected an ACHIEVED_STATE FACT; leads={res.leads} detail={res.reason}"
    f = next(x for x in res.facts if "open_redirect" in x.finding_ref)
    ctx = res.contexts[f.finding_ref]
    # re-verifies OFFLINE from the retained JSON-safe capture — no network, no runner
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=TRUST).ok is True
    assert _HITS["n"] > 0, "VIGIL's own gated capture must actually contact the server"


def test_gobuster_proposed_cors_endpoint_mints_a_fact(monkeypatch, tmp_path):
    """gobuster PROPOSES a discovered path; VIGIL re-drives the joined URL and mints a cors FACT over its own
    capture (the credential-reflecting CORS at /api)."""
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    srv = _serve()
    port = srv.server_address[1]
    try:
        # gobuster (expanded) reports the FULL URL of each hit; host-pinned to the scope target (port kept)
        res = _run(gobuster_web_scan(scheme="http"),
                   _CannedBackend(_gobuster_line(f"http://127.0.0.1:{port}/api")))
    finally:
        srv.shutdown()
    assert res.status == "ran", res.reason
    facts = [x for x in res.facts if "cors" in x.finding_ref]
    assert facts, f"expected a cors FACT; proposed={res.proposed} leads={res.leads}"
    ctx = res.contexts[facts[0].finding_ref]
    assert verify_certificate(facts[0].signed, oracle_context=ctx, trust_root=TRUST).ok is True


# ===================================================================================================
# (2) the SAME tool result WITHOUT a VIGIL capture (or on a safe endpoint) mints NOTHING (stays LEAD).
# ===================================================================================================
def test_a_web_discovery_proposal_on_a_safe_endpoint_mints_nothing(monkeypatch, tmp_path):
    """The server reflects the value in plain text but never redirects to the canary — VIGIL's OWN re-drive
    refutes any would-be finding, so NOTHING is minted even though the tool proposed the URL."""
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(katana_web_scan(scheme="http"),
                   _CannedBackend(_katana_jsonl(f"http://127.0.0.1:{port}/safe?next=orig")))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, "the tool DID propose the URL"
    assert _HITS["n"] > 0, "VIGIL genuinely re-drove it (not a vacuous gated refusal)"
    assert res.facts == [], f"a safe endpoint must mint NO fact: {[x.finding_ref for x in res.facts]}"


def test_a_truly_vulnerable_url_mints_nothing_without_a_vigil_channel(monkeypatch, tmp_path):
    """THE core soundness property: a tool proposing a genuinely-shaped vulnerable URL (``/redirect?next=``)
    mints NOTHING when VIGIL's OWN gated capture cannot reach a channel (here: a closed port). The tool's
    say-so is never a FACT — only VIGIL's own successful gated capture + oracle mints. proposed>0, facts==0."""
    _charter(tmp_path, "127.0.0.1")
    dead = _closed_port()   # nothing listens here
    res = _run(katana_web_scan(scheme="http"),
               _CannedBackend(_katana_jsonl(f"http://127.0.0.1:{dead}/redirect?next=orig")))
    assert res.status == "ran"
    assert res.proposed, "the tool proposed the vulnerable-shaped URL"
    assert res.facts == [], "no VIGIL channel ⇒ no FACT, however vulnerable the tool CLAIMED the URL to be"


# ===================================================================================================
# (3) the conformance battery — the gate each newly-fact_capable web_discovery tool passed.
# ===================================================================================================
@pytest.mark.parametrize("tool,ctor", [("katana", katana_web_scan), ("gobuster", gobuster_web_scan)])
def test_web_discovery_tool_passes_the_full_conformance_battery(tool, ctor, monkeypatch, tmp_path):
    """Each newly-fact_capable web_discovery tool PASSES ``run_toolspec_conformance`` through the REAL gated
    runner: a positive FACT that re-verifies offline; a deceptive proposal (a safe endpoint) mints NO fact; a
    tool timeout is the typed ERROR; a tripped kill-switch and an out-of-scope target each refuse before
    traffic. This is the gate ``docs/capability-matrix`` required before ``fact_capable=true`` was set."""
    from framework.v2.authority import KillSwitch
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    vuln = f"http://127.0.0.1:{port}/redirect?next=orig"   # a real open redirect
    safe = f"http://127.0.0.1:{port}/safe?next=orig"       # reflects in plain text; no redirect
    target = "127.0.0.1"
    if tool == "katana":
        pos_backend = _CannedBackend(_katana_jsonl(vuln))
        dec_backend = _CannedBackend(_katana_jsonl(safe))
    else:  # gobuster (expanded) reports the full URL of each hit, host-pinned by the parser
        pos_backend = _CannedBackend(_gobuster_line(vuln))
        dec_backend = _CannedBackend(_gobuster_line(safe))
    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=ctor(scheme="http"), positive_backend=pos_backend,
            deceptive_spec=ctor(scheme="http"), deceptive_backend=dec_backend,
            target=target,
            scope_gate_in=_scope_gate(["127.0.0.1"]),
            scope_gate_out=_scope_gate(["10.99.99.99"]),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.shutdown()
    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# (3b) M1.2 — the rest of the web_discovery FACT column: gau / waybackurls (passive archive URL
#      proposers) + feroxbuster / dirsearch (content-discovery brute). Each PROPOSES a URL the runner
#      re-drives through the SAME gated ACHIEVED_STATE web re-drive; the FACT is VIGIL's own capture.
# ===================================================================================================
_M12_CTORS = {
    "gau": gau_web_scan,
    "waybackurls": waybackurls_web_scan,
    "feroxbuster": feroxbuster_web_scan,
    "dirsearch": dirsearch_web_scan,
}


def _m12_canned(tool: str, url: str) -> str:
    """The real-format proposal each M1.2 tool emits for ``url`` (no binary run — a canned backend)."""
    return _dirsearch_line(url) if tool == "dirsearch" else _plain_url_line(url)


@pytest.mark.parametrize("tool", sorted(_M12_CTORS))
def test_m12_web_discovery_tool_proposed_url_mints_a_fact_over_vigils_own_capture(tool, monkeypatch, tmp_path):
    """Each M1.2 web_discovery tool PROPOSES a URL; VIGIL re-drives it through its OWN gated web capture and
    the achieved_state oracle mints a signed open_redirect FACT that re-verifies OFFLINE. The tool's row
    (an archive hit or a brute path) was never the authority — VIGIL's own no-redirect capture is."""
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(_M12_CTORS[tool](),
                   _CannedBackend(_m12_canned(tool, f"http://127.0.0.1:{port}/redirect?next=orig")))
    finally:
        srv.shutdown()
    assert res.status == "ran", res.reason
    assert res.proposed, f"{tool} must have proposed the URL (grounding intel)"
    f = next((x for x in res.facts if "open_redirect" in x.finding_ref), None)
    assert f is not None, f"expected an ACHIEVED_STATE FACT; leads={res.leads} detail={res.reason}"
    ctx = res.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=TRUST).ok is True
    assert _HITS["n"] > 0, "VIGIL's own gated capture must actually contact the server"


@pytest.mark.parametrize("tool", sorted(_M12_CTORS))
def test_m12_proposal_that_does_not_reconfirm_stays_a_lead(tool, monkeypatch, tmp_path):
    """THE soundness property for the inflation guard: a surfaced URL that VIGIL's OWN re-drive cannot
    reproduce as a finding (a SAFE endpoint that only reflects in plain text) mints NOTHING — the tool
    proposed it, VIGIL genuinely re-drove it, and it stays a LEAD."""
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(_M12_CTORS[tool](),
                   _CannedBackend(_m12_canned(tool, f"http://127.0.0.1:{port}/safe?next=orig")))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, f"{tool} DID propose the URL"
    assert _HITS["n"] > 0, "VIGIL genuinely re-drove it (not a vacuous gated refusal)"
    assert res.facts == [], f"a safe endpoint must mint NO fact: {[x.finding_ref for x in res.facts]}"


@pytest.mark.parametrize("tool", sorted(_M12_CTORS))
def test_m12_web_discovery_tool_passes_the_full_conformance_battery(tool, monkeypatch, tmp_path):
    """Each newly-fact_capable M1.2 web_discovery tool PASSES ``run_toolspec_conformance`` through the REAL
    gated runner: a positive FACT that re-verifies offline; a deceptive proposal (a safe endpoint) mints NO
    fact; a tool timeout is the typed ERROR; a tripped kill-switch and an out-of-scope target each refuse
    before traffic. This is the gate ``docs/capability-matrix`` required before ``fact_capable=true`` was
    set."""
    from framework.v2.authority import KillSwitch
    ctor = _M12_CTORS[tool]
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    vuln = f"http://127.0.0.1:{port}/redirect?next=orig"   # a real open redirect
    safe = f"http://127.0.0.1:{port}/safe?next=orig"       # reflects in plain text; no redirect
    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=ctor(), positive_backend=_CannedBackend(_m12_canned(tool, vuln)),
            deceptive_spec=ctor(), deceptive_backend=_CannedBackend(_m12_canned(tool, safe)),
            target="127.0.0.1",
            scope_gate_in=_scope_gate(["127.0.0.1"]),
            scope_gate_out=_scope_gate(["10.99.99.99"]),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.shutdown()
    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# (4) the scanners bug-class DISPATCHER: nuclei's web-class finding → web_redrive → FACT, but only when
#     VIGIL independently confirms the CLAIMED class (criterion-6 firewall for a scanner's say-so).
# ===================================================================================================
def test_nuclei_confirmed_web_class_mints_a_fact_via_the_dispatcher(monkeypatch, tmp_path):
    """nuclei labels an open-redirect at a URL that REALLY redirects; the dispatcher re-drives it through
    web_redrive and VIGIL's own oracle confirms → a signed FACT (attributed to ACHIEVED_STATE, not nuclei)."""
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(nuclei_web_redrive(scheme="http"),
                   _CannedBackend(_nuclei_jsonl(f"http://127.0.0.1:{port}/redirect?next=orig",
                                                "open-redirect", "CWE-601")))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed and res.proposed[0].claimed_class == "open_redirect"
    f = next((x for x in res.facts if "open_redirect" in x.finding_ref), None)
    assert f is not None, f"nuclei's confirmed web finding must mint a FACT; leads={res.leads}"
    ctx = res.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=TRUST).ok is True


def test_nuclei_unconfirmed_web_class_is_a_lead_not_a_fact(monkeypatch, tmp_path):
    """nuclei labels an open-redirect at a SAFE endpoint (it does not redirect). The dispatcher re-drives it,
    VIGIL's own oracle does NOT fire, so the scanner's say-so stays a LEAD — never a FACT (criterion-6)."""
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    try:
        res = _run(nuclei_web_redrive(scheme="http"),
                   _CannedBackend(_nuclei_jsonl(f"http://127.0.0.1:{port}/safe?next=orig",
                                                "open-redirect", "CWE-601")))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, "the nuclei finding WAS proposed (grounding intel)"
    assert _HITS["n"] > 0, "VIGIL genuinely re-drove nuclei's URL"
    assert res.facts == [], f"an unconfirmed scanner label must NOT mint a FACT: {[x.finding_ref for x in res.facts]}"


def test_nuclei_non_web_class_is_not_proposed_by_the_web_dispatcher(monkeypatch, tmp_path):
    """A nuclei finding whose class is not web-re-drivable (e.g. sqli, CWE-89) is not proposed by the web
    dispatcher at all — it stays a LEAD on the ingest path, and this leg mints nothing from it."""
    _charter(tmp_path, "127.0.0.1")
    srv = _serve()
    port = srv.server_address[1]
    vuln = f"http://127.0.0.1:{port}/redirect?next=orig"
    try:
        sqli = _run(nuclei_web_redrive(scheme="http"),
                    _CannedBackend(_nuclei_jsonl(vuln, "sqli-detect", "CWE-89")))
    finally:
        srv.shutdown()
    assert sqli.proposed == [], "a non-web nuclei class must not be proposed by the web dispatcher"
    assert sqli.facts == []


def test_a_scanner_label_can_never_reach_the_oidc_fact_class():
    """A scanner's label can never obtain the higher-severity A07 ``oidc_redirect_uri`` certificate: its live
    evidence is byte-identical to a plain open_redirect, so the OIDC classification would rest entirely on the
    scanner's say-so. ``web_fact_class_for`` excludes oidc (mirrors LLM_CLAIM_WEB_FACT_CLASSES), so any
    oidc-ish label maps to None (or, via CWE-601, to the conservative open_redirect — never oidc)."""
    from vigil_integration.live.web_redrive import SCANNER_CLAIM_WEB_FACT_CLASSES, web_fact_class_for
    assert web_fact_class_for("oidc_redirect_uri") is None
    assert web_fact_class_for("oidc-redirect") is None
    assert "oidc_redirect_uri" not in SCANNER_CLAIM_WEB_FACT_CLASSES
    # the four classes a scanner label MAY select are exactly the header/body ACHIEVED_STATE web classes
    assert set(SCANNER_CLAIM_WEB_FACT_CLASSES) == {
        "open_redirect", "cors", "host_header_injection", "graphql_introspection"}


# ===================================================================================================
# (5) the gate refuses BEFORE any traffic — kill-switch and out-of-scope (mirrors the ProposedService leg).
# ===================================================================================================
def test_web_fact_leg_refuses_out_of_scope_before_any_traffic(monkeypatch, tmp_path):
    _charter(tmp_path, "127.0.0.1")

    class _Spy(_CannedBackend):
        def __init__(self):
            super().__init__("")
            self.runs = []

        def run(self, argv, *, timeout=0):
            self.runs.append(list(argv))
            return super().run(argv, timeout=timeout)

    spy = _Spy()
    res = run_external_tool(katana_web_scan(scheme="http"), "10.1.2.3",
                            scope_gate=_scope_gate(["127.0.0.1"]), backend=spy,
                            engagement_slug="alpha", signers=SIGNERS, timeout=30.0)
    assert res.refused and spy.runs == [], "an out-of-scope target must refuse before the tool runs"


def test_web_fact_leg_refuses_when_killswitch_tripped_before_any_traffic(monkeypatch, tmp_path):
    from framework.v2.authority import KillSwitch
    _charter(tmp_path, "127.0.0.1")
    KillSwitch("alpha").trip("halt")

    class _Spy(_CannedBackend):
        def __init__(self):
            super().__init__("")
            self.runs = []

        def run(self, argv, *, timeout=0):
            self.runs.append(list(argv))
            return super().run(argv, timeout=timeout)

    spy = _Spy()
    res = run_external_tool(nuclei_web_redrive(scheme="http"), "127.0.0.1",
                            scope_gate=_scope_gate(["127.0.0.1"]), backend=spy,
                            engagement_slug="alpha", signers=SIGNERS, timeout=30.0)
    assert res.refused and spy.runs == [], "a tripped kill-switch must refuse before the tool runs"


# ===================================================================================================
# (6) OPSEC: the ENFORCED gated-request budget (C4 red-pen BLOCK). A crafted high-complexity URL cannot drive
#     more than the enforced per-URL / per-run request cap — measured by an external counting server (spy).
# ===================================================================================================
class _CountingApp(http.server.BaseHTTPRequestHandler):
    """Counts EVERY request it receives (GET and POST) — the external spy on VIGIL's actual gated traffic. It
    404s everything (so nothing mints), so the count is a clean measurement of requests issued, not findings."""
    hits = {"n": 0}

    def log_message(self, *a):  # noqa: D401
        return

    def do_GET(self):  # noqa: N802
        _CountingApp.hits["n"] += 1
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        _CountingApp.hits["n"] += 1
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        self.send_response(404)
        self.end_headers()


def _serve_counting():
    _CountingApp.hits["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _CountingApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _high_complexity_url(port: int, n_params: int = 200) -> str:
    """An in-scope URL whose open-redirect insertion-point count (one gated request per query param) FAR
    exceeds any cap — the crafted, attacker-influenced input the red-pen used to drive ~220 requests/URL."""
    qs = "&".join(f"p{i}=v{i}" for i in range(n_params))
    return f"http://127.0.0.1:{port}/a/b/c/d/e?{qs}"


def test_a_crafted_high_complexity_url_cannot_exceed_the_enforced_per_url_request_cap(monkeypatch, tmp_path):
    """C4 red-pen BLOCK closed (per-URL). A single crafted URL with 200 query params would, uncapped, drive
    200+ gated requests through web_redrive's open-redirect leg. With the ENFORCED per-URL cap, VIGIL's own
    gated send refuses once the cap is hit — MID-URL — so the counting server (the external spy) receives no
    more than the cap, regardless of the URL's param count. The detail's spent number matches the observed
    traffic (no overclaim)."""
    from vigil_integration.live import external_tool
    _charter(tmp_path, "127.0.0.1")
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_REQUEST_BUDGET", 1000)  # run cap high: per-URL binds
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_MAX_REQUESTS_PER_URL", 8)
    srv = _serve_counting()
    port = srv.server_address[1]
    try:
        res = _run(katana_web_scan(scheme="http"),
                   _CannedBackend(_katana_jsonl(_high_complexity_url(port, n_params=200))))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    assert res.proposed, "the crafted URL was proposed"
    hits = _CountingApp.hits["n"]
    assert hits <= 8, f"per-URL request cap NOT enforced: server received {hits} requests for one URL (cap 8)"
    assert hits > 0, "VIGIL did genuinely re-drive (not a vacuous refusal)"
    # the detail's spent count matches the ACTUAL traffic — no overclaim
    assert f"spent {hits}/1000 gated requests" in res.reason, res.reason
    assert res.facts == []


def test_a_single_pathological_url_cannot_exceed_the_enforced_per_run_request_cap(monkeypatch, tmp_path):
    """C4 red-pen BLOCK closed (per-run, mid-URL). Even with a HIGH per-URL cap, a single crafted URL cannot
    exceed the per-RUN gated-request budget: the shared counter hard-stops MID-URL. The counting server
    receives no more than the run cap, and the detail reports the true spent count."""
    from vigil_integration.live import external_tool
    _charter(tmp_path, "127.0.0.1")
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_REQUEST_BUDGET", 20)     # run cap binds
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_MAX_REQUESTS_PER_URL", 1000)
    srv = _serve_counting()
    port = srv.server_address[1]
    try:
        res = _run(katana_web_scan(scheme="http"),
                   _CannedBackend(_katana_jsonl(_high_complexity_url(port, n_params=200))))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    hits = _CountingApp.hits["n"]
    assert hits <= 20, f"per-run request cap NOT enforced: server received {hits} requests (cap 20)"
    assert hits > 0
    assert f"spent {hits}/20 gated requests" in res.reason, res.reason
    assert res.facts == []


def test_many_high_complexity_urls_stay_within_the_per_run_request_cap(monkeypatch, tmp_path):
    """C4 red-pen BLOCK closed (per-run across URLs). Several crafted high-complexity URLs together cannot
    exceed the per-run cap: once spent, further URLs are budget-SKIPPED (loud, never silent), and the total
    traffic the counting server sees stays within the cap."""
    from vigil_integration.live import external_tool
    _charter(tmp_path, "127.0.0.1")
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_REQUEST_BUDGET", 40)
    monkeypatch.setattr(external_tool, "_WEB_REDRIVE_MAX_REQUESTS_PER_URL", 8)
    # findings pre-filter = 40 // 8 = 5; each URL uses its 8 → 5 x 8 = 40 = the run cap exactly.
    srv = _serve_counting()
    port = srv.server_address[1]
    try:
        stdout = "".join(_katana_jsonl(_high_complexity_url(port, n_params=50) + f"&u={i}") for i in range(12))
        res = _run(katana_web_scan(scheme="http"), _CannedBackend(stdout))
    finally:
        srv.shutdown()
    assert res.status == "ran"
    hits = _CountingApp.hits["n"]
    assert hits <= 40, f"per-run cap NOT enforced across URLs: server received {hits} requests (cap 40)"
    assert res.truncated_proposals > 0, "the surplus URLs must be SKIPPED, and that truncation must be recorded"
    assert "OPSEC CAP" in res.budget_note and "ENFORCED" in res.budget_note
    assert res.facts == []


def test_web_fact_leg_caps_redriven_findings_against_the_request_budget(monkeypatch, tmp_path):
    from vigil_integration.live.external_tool import _max_web_redriven_findings
    _charter(tmp_path, "127.0.0.1")
    cap = _max_web_redriven_findings()
    # propose cap+5 distinct URLs on a CLOSED port (no channel, so each re-drive is cheap and mints nothing);
    # the point is the truncation accounting, not a fact.
    dead = _closed_port()
    stdout = "".join(_katana_jsonl(f"http://127.0.0.1:{dead}/p{i}?next=x") for i in range(cap + 5))
    res = _run(katana_web_scan(scheme="http"), _CannedBackend(stdout))
    assert res.status == "ran"
    assert len(res.proposed) == cap + 5, "every proposal is recorded on the Observation (nothing hidden)"
    assert res.truncated_proposals == 5, f"expected 5 skipped, got {res.truncated_proposals}"
    assert "OPSEC CAP" in res.budget_note and "SKIPPED 5" in res.budget_note
    assert res.facts == []
