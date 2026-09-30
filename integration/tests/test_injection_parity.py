"""Slice B2 — governed-engage re-drive for nosqli / ldap_injection / xpath_injection (LEAD-only).

These three classes are now DRIVEN through the governed-engage seam
(engine._redrive_spec → wiring._live_injection_redrive_fact → runtime_redrive.injection_redrive): VIGIL sends
its OWN gated class-specific error probe + a benign control twin, so the operator's lead has a VIGIL-owned
capture behind it instead of the model's assertion.

They are LEAD-ONLY. A RED-PEN BLOCKED the first (fact_capable) attempt with four durable false FACTs: the
error_signature oracle is a STRING MATCH and re-verifies only CONDITIONAL EMISSION of a datastore-error-shaped
string — a WAF block page, an input-validator rejection, or an unrelated 500 whose stack trace merely names
the driver package all emit one conditionally on the metacharacter and pass the benign-control-twin guard.
Conditional emission is necessary but NOT sufficient for a query break. The sound FACT path (a break-vs-repair
parser-state-toggle causation oracle re-executed offline) needs a new OracleKind, out of this slice's scope,
so the branches are honest LEAD-only ladder targets (see docs/capability-matrix/evidence-branches.json
blocking_work + V2-LIMITATIONS §31).

This file pins: the _redrive_spec routing; that the arm DRIVES a VIGIL-owned capture and admits a LEAD but
mints NO FACT (no signed certificate) on a genuine error surface; and that the whole red-pen decoy battery —
a WAF block, a validator rejection, an unrelated-500-naming-the-package, plus benign twin / bare differential
/ mismatched engine — stays LEAD (assert facts == []).
"""
from __future__ import annotations

import http.server
import json
import threading
import types
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# hermetic: _redrive_spec routing
# ---------------------------------------------------------------------------------------------------

def _decision(bug_class: str, *, url: str) -> types.SimpleNamespace:
    analysis = types.SimpleNamespace(exploit_succeeded=True, extracted_info={"bug_class": bug_class})
    tool = types.SimpleNamespace(tool_args={"url": url})
    return types.SimpleNamespace(tool=tool, output_analysis=analysis)


# Only the aliases the AUTHORITATIVE verifier (normalize_bug_class) folds are exercised here — the seam and
# the router normalize via the verifier, never a hand-rolled map (landmine 2).
@pytest.mark.parametrize("claimed,norm", [
    ("nosqli", "nosqli"), ("nosql_injection", "nosqli"), ("no_sqli", "nosqli"),
    ("ldap_injection", "ldap_injection"), ("ldap", "ldap_injection"), ("ldapi", "ldap_injection"),
    ("xpath_injection", "xpath_injection"), ("xpath", "xpath_injection"), ("xpathi", "xpath_injection"),
])
def test_redrive_spec_emits_an_injection_spec_for_the_three_classes(claimed, norm):
    from vigil_integration.live.engine import VigilEngine
    spec = VigilEngine._redrive_spec(
        _decision(claimed, url="http://127.0.0.1:19010/api/search?q=x"), None)
    assert spec is not None, f"{claimed} should be re-drivable"
    assert spec["kind"] == "injection"
    assert spec["bug_class"] == norm
    assert spec["url"].endswith("/api/search?q=x")


def test_redrive_spec_needs_exploit_succeeded_for_injection():
    from vigil_integration.live.engine import VigilEngine
    d = _decision("nosqli", url="http://127.0.0.1:19010/api/search?q=x")
    d.output_analysis.exploit_succeeded = False
    assert VigilEngine._redrive_spec(d, None) is None


# ---------------------------------------------------------------------------------------------------
# gate isolation + charter (mirrors test_engine_runtime_redrive_seam)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _prov(signers, slug: str = "alpha"):
    # The injection seam reads only ``prov.slug`` (gate + cert binding) and ``prov.signers`` (cert signers);
    # keypair/trust_root are unused on this path, so a minimal Provisioned is sufficient.
    from vigil_integration.live.wiring import Provisioned
    return Provisioned(keypair=None, trust_root=None, signers=signers, authority_path="", slug=slug)


# ---------------------------------------------------------------------------------------------------
# a loopback app: genuine error surfaces + the red-pen false-FACT decoys
# ---------------------------------------------------------------------------------------------------
# The RUNNER's injection payloads carry syntax metacharacters; the benign control twin carries a
# metacharacter-free "vfctl…" marker. The genuine surfaces emit the engine error ONLY when a metacharacter is
# present; the decoys emit a datastore-error-SHAPED string CONDITIONALLY on the metacharacter from a
# NON-datastore source — the exact class of false FACT the red-pen reproduced.
_META = set("'\"(){}[]|&*/;$`\\<>")

_REAL_ENGINE_ERROR = {
    "/real-mongo": "MongoError: unknown top level operator near ",
    "/real-ldap": "javax.naming.directory.InvalidSearchFilterException: bad filter near ",
    "/real-xpath": "XPathException: invalid expression near ",
}


def _has_meta(values) -> bool:
    return any(c in _META for v in values for c in v)


class _App(http.server.BaseHTTPRequestHandler):
    hits = 0

    def _text(self, code: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")   # declared → body is adjudicable
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        type(self).hits += 1
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        values = [v for vs in q.values() for v in vs]
        meta = _has_meta(values)

        if parts.path in _REAL_ENGINE_ERROR:
            # A genuine error-based sink: a metacharacter breaks the query and the backend emits its engine
            # error; a benign value renders a clean row.
            if meta:
                self._text(500, _REAL_ENGINE_ERROR[parts.path] + repr(values))
            else:
                self._text(200, json.dumps({"rows": [], "echo": values}))
            return

        # --- the red-pen false-FACT battery: a datastore-error-shaped string emitted CONDITIONALLY on the
        #     metacharacter by a NON-datastore source. Each MUST stay a LEAD (no FACT). ---
        if parts.path == "/waf-mongo":
            if meta:
                self._text(403, "Request blocked by WAF: possible MongoError NoSQL injection attempt rejected")
            else:
                self._text(200, json.dumps({"rows": [1, 2, 3]}))
            return
        if parts.path == "/valid-ldap":
            if meta:
                self._text(400, "Invalid input rejected by request validator: LDAPException-style characters "
                                "are not allowed")
            else:
                self._text(200, "ok")
            return
        if parts.path == "/stacktrace-mongo":
            # unrelated 500 whose stack trace merely NAMES the driver package (com.mongodb frames); the root
            # cause is a number parse, not a query break. A metacharacter routinely triggers some 500, so this
            # is a high-frequency real-world false positive.
            if meta:
                self._text(500, "java.lang.NumberFormatException: For input string\n"
                                "  at app.Handler.parseId(Handler.java:42)\n"
                                "  at com.mongodb.client.internal.MongoClientDelegate.<init>"
                                "(MongoClientDelegate.java:10)\n")
            else:
                self._text(200, "ok")
            return
        if parts.path == "/waf-xpath":
            if meta:
                self._text(403, "Blocked: Expression must evaluate to a node-set — injection filter tripped")
            else:
                self._text(200, "ok")
            return

        # --- other negative controls ---
        if parts.path == "/always-error":
            self._text(500, "MongoError: unknown top level operator (static banner)")   # control errors too
            return
        if parts.path == "/reflect":
            self._text(200, f"MongoError: unknown top level operator near {values!r}")  # chrome, control too
            return
        if parts.path == "/bare-diff":
            # a BARE benign-vs-payload DIFFERENTIAL: the body varies with the input (distinct status/length)
            # but there is NO datastore/parser error signature at all.
            if meta:
                self._text(418, f"filtered request rejected: {len(values[0]) if values else 0} chars")
            else:
                self._text(200, f"results for {values!r}: 3 items")
            return
        if parts.path == "/sql-on-mongo":
            # emits a MySQL error on a metacharacter → a nosqli claim matches the mysql engine, not mongodb.
            if meta:
                self._text(500, "You have an error in your SQL syntax; check the manual near " + repr(values))
            else:
                self._text(200, "ok")
            return
        if parts.path == "/clean":
            self._text(200, json.dumps({"rows": [1, 2, 3], "echo": values}))   # benign twin: never errors
            return

        self._text(404, "not found")

    def log_message(self, *a):  # silence
        return


def _serve():
    _App.hits = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _drive(url: str, claimed: str, signers):
    from vigil_integration.live.runtime_redrive import injection_redrive
    return injection_redrive(url, slug="alpha", engagement_slug="alpha", signers=signers, claimed_class=claimed)


def _drive_on(monkeypatch, tmp_path, path: str, claimed: str):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers = _signers()
    srv = _serve(); port = srv.server_address[1]
    try:
        return _drive(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------------------------------
# the arm DRIVES a VIGIL-owned capture and admits a LEAD, but mints NO FACT
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed", [
    ("/real-mongo", "nosqli"), ("/real-ldap", "ldap_injection"), ("/real-xpath", "xpath_injection"),
])
def test_genuine_error_surface_is_driven_but_mints_no_fact(monkeypatch, tmp_path, path, claimed):
    rr = _drive_on(monkeypatch, tmp_path, path, claimed)
    assert _App.hits >= 2, "the arm must send BOTH the probe AND the benign control twin (not a vacuous pass)"
    assert rr.n_facts == 0, f"{claimed}: LEAD-only — no FACT may be minted through governed engage"
    # the fired oracle was ADMITTED and DEMOTED to a LEAD (the demotion, not an absent arm, is doing the work)
    assert rr.leads, f"{claimed}: the driven capture must be recorded as an admitted LEAD"
    assert all(getattr(f, "signed", None) is None for f in rr.leads), "a LEAD carries no signed certificate"
    assert all(getattr(f, "is_fact", False) is False for f in rr.leads)


# ---------------------------------------------------------------------------------------------------
# THE RED-PEN BLOCK: the four reproduced false FACTs must each stay a LEAD (facts == [])
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed,why", [
    ("/waf-mongo", "nosqli", "a WAF block page that names MongoError is not a datastore query break"),
    ("/valid-ldap", "ldap_injection", "an input-validator rejection naming LDAPException is not a query break"),
    ("/stacktrace-mongo", "nosqli", "an unrelated 500 whose stack trace names com.mongodb is not a query break"),
    ("/waf-xpath", "xpath_injection", "an xpath WAF block echoing the node-set phrase is not a query break"),
])
def test_conditional_non_datastore_emitter_stays_lead(monkeypatch, tmp_path, path, claimed, why):
    rr = _drive_on(monkeypatch, tmp_path, path, claimed)
    assert _App.hits >= 2, "the arm must actually contact the server (a refusal would be a vacuous pass)"
    assert rr.n_facts == 0, f"BLOCK regression: {why} — minted a FALSE FACT"


# ---------------------------------------------------------------------------------------------------
# the rest of the false-FACT battery — all LEAD
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed", [
    ("/clean", "nosqli"),            # benign twin — never errors
    ("/bare-diff", "nosqli"),        # a bare benign-vs-payload differential, no datastore error
    ("/always-error", "nosqli"),     # control errors too → not attributable
    ("/reflect", "nosqli"),          # verbatim-reflected static error template → control carries it
])
def test_other_negative_controls_stay_lead(monkeypatch, tmp_path, path, claimed):
    rr = _drive_on(monkeypatch, tmp_path, path, claimed)
    assert _App.hits >= 2
    assert rr.n_facts == 0, f"{path} must not mint a FACT"


def test_mismatched_engine_is_not_admitted_for_the_class(monkeypatch, tmp_path):
    """A nosqli claim whose probe provokes a SQL (mysql) engine error is not admitted under nosqli — the
    evidence names a different class, so even the LEAD stays class-appropriate (and no FACT, since LEAD-only)."""
    rr = _drive_on(monkeypatch, tmp_path, "/sql-on-mongo", "nosqli")
    assert _App.hits >= 2
    assert rr.n_facts == 0
    assert any("different class" in n for n in rr.notes), "the engine mismatch must be recorded honestly"


# ---------------------------------------------------------------------------------------------------
# the governed-engage SEAM: _live_injection_redrive_fact returns None (LEAD-only) but DRIVES the probe
# ---------------------------------------------------------------------------------------------------

def _seam(url: str, claimed: str, signers):
    from vigil_integration.live.wiring import _live_injection_redrive_fact
    return _live_injection_redrive_fact(
        _prov(signers), {}, {"kind": "injection", "url": url, "bug_class": claimed})


def test_seam_returns_none_and_drives_the_probe_on_a_genuine_surface(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers = _signers()
    for path, claimed in [("/real-mongo", "nosqli"), ("/real-ldap", "ldap_injection"),
                          ("/real-xpath", "xpath_injection")]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
        finally:
            srv.shutdown()
        assert ref is None, f"{claimed} is LEAD-only through governed engage — the seam must not mint a FACT"
        assert _App.hits >= 2, "the seam must still DRIVE VIGIL's own probe (a VIGIL-owned capture)"


def test_seam_stays_none_on_the_whole_decoy_battery(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers = _signers()
    for path in ["/waf-mongo", "/valid-ldap", "/stacktrace-mongo", "/waf-xpath",
                 "/clean", "/bare-diff", "/always-error", "/reflect", "/sql-on-mongo"]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", "nosqli", signers)
        finally:
            srv.shutdown()
        assert ref is None, f"the seam must return None (LEAD) on {path}"


def test_seam_ignores_a_non_injection_class(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers = _signers()
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _seam(f"http://127.0.0.1:{port}/real-mongo?q=hello", "open_redirect", signers)
    finally:
        srv.shutdown()
    assert ref is None, "a non-injection class is not handled by this seam"


def test_seam_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    signers = _signers()
    ref = _seam("http://10.99.99.99/real-mongo?q=hello", "nosqli", signers)
    assert ref is None, "an out-of-scope target must never mint a FACT"


# ---------------------------------------------------------------------------------------------------
# the registry: both branch families for these classes are LEAD-only (no FACT-capable nlx branch)
# ---------------------------------------------------------------------------------------------------

def test_all_nlx_branches_are_lead_only_in_the_registry():
    root = Path(__file__).resolve().parents[2]
    reg = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text("utf-8"))
    by = {b["id"]: b for b in reg["branches"]}
    for cls in ("nosqli", "ldap_injection", "xpath_injection"):
        for suffix in ("datastore_error", "sprt_inference"):
            b = by[f"{cls}.{suffix}"]
            assert b["fact_capable"] is False, f"{cls}.{suffix} must be LEAD-only (no false FACT path)"
            assert b["clean_capable"] is False
            assert b["oracle_version"] == "", f"{cls}.{suffix} LEAD-only ⇒ no oracle_version"
            assert len(b.get("blocking_work", "")) > 40, f"{cls}.{suffix} must name the sound FACT path"
