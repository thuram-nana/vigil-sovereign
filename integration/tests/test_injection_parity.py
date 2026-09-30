"""Slice B2 — governed-engage FACT parity for nosqli / ldap_injection / xpath_injection.

Before this slice these three classes could mint a FACT ONLY on the Strix proof rail
(proof.run._strix_errsig_redrive); through governed engage they were structurally LEAD-only (no dedicated
evidence branch, so the oracle seam fell through to the LLM-provenanced LEAD). This file pins the sound FACT
path built here:

  * ``VigilEngine._redrive_spec`` emits a ``{"kind": "injection", ...}`` spec for each class (+ aliases).
  * ``runtime_redrive.injection_redrive`` mints a signed FACT ONLY when the deterministic
    ``error_signature`` oracle fires ATTRIBUTABLY (VIGIL's OWN class-specific error probe provoked a
    datastore/parser error a benign CONTROL twin did NOT) AND the matched ENGINE is the one that NAMES the
    claimed class. The FACT re-verifies OFFLINE and a tamper is rejected.
  * ``wiring._live_injection_redrive_fact`` returns a signed FACT's ref on the sound path and NOTHING on the
    negative controls (benign twin, always-erroring page, verbatim reflection, a BARE benign-vs-payload
    DIFFERENTIAL with no datastore error, a mismatched engine, a non-injection class, an out-of-scope URL).

Every live proof drives a REAL loopback origin through the REAL gated send (mirrors
test_strix_errsig_redrive / test_engine_runtime_redrive_seam). The RUNNER crafts the injection payload; the
Strix/LLM value is never trusted.
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


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def _prov(signers, slug: str = "alpha"):
    # The injection seam reads only ``prov.slug`` (gate + cert binding) and ``prov.signers`` (cert signers);
    # keypair/trust_root are unused on this path, so a minimal Provisioned is sufficient.
    from vigil_integration.live.wiring import Provisioned
    return Provisioned(keypair=None, trust_root=None, signers=signers, authority_path="", slug=slug)


# ---------------------------------------------------------------------------------------------------
# a loopback app: a REAL error-based injection surface per class + the false-FACT decoys
# ---------------------------------------------------------------------------------------------------
# The RUNNER's injection payloads carry syntax metacharacters; the benign control twin carries a
# metacharacter-free "vfctl…" marker. A REAL surface emits its engine's error ONLY when a metacharacter is
# present; the decoys emit the SAME datastore string regardless (so the control twin ALSO carries it → not
# attributable → the mint refuses).
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

        if parts.path in _REAL_ENGINE_ERROR:
            # A genuine error-based sink: a metacharacter breaks the query and the backend emits its engine
            # error; a benign value renders a clean row.
            if _has_meta(values):
                self._text(500, _REAL_ENGINE_ERROR[parts.path] + repr(values))
            else:
                self._text(200, json.dumps({"rows": [], "echo": values}))
            return

        if parts.path == "/always-error":
            # DECOY: ALWAYS emits the Mongo error, even for the benign control → present in BOTH → refused.
            self._text(500, "MongoError: unknown top level operator (static banner)")
            return

        if parts.path == "/reflect":
            # DECOY: reflects the value verbatim inside a static datastore-error TEMPLATE → the phrase is
            # chrome (present for the benign control too), NOT engine-emitted → the control twin catches it.
            self._text(200, f"MongoError: unknown top level operator near {values!r}")
            return

        if parts.path == "/bare-diff":
            # DECOY (THE B2 SOUNDNESS CASE): a BARE benign-vs-payload DIFFERENTIAL — the body VARIES with the
            # input (echoes it, distinct lengths/status) but there is NO datastore/parser error signature at
            # all. A differential is a LEAD for these classes; the error_signature oracle must not fire.
            if _has_meta(values):
                self._text(418, f"filtered request rejected: {len(values[0]) if values else 0} chars")
            else:
                self._text(200, f"results for {values!r}: 3 items")
            return

        if parts.path == "/sql-on-mongo":
            # DECOY: emits a MySQL error on a metacharacter. A nosqli CLAIM re-drives here and the oracle
            # matches the mysql engine, NOT mongodb → mismatched engine → refused (the evidence proves SQLi,
            # not nosqli; never mislabel it).
            if _has_meta(values):
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
    """Call the runner-owned injection_redrive engine directly (like test_runtime_redrive_soundness) so we can
    inspect the RuntimeRedriveResult (.facts / .contexts / .leads) for the offline-verify + tamper proofs."""
    from vigil_integration.live.runtime_redrive import injection_redrive
    return injection_redrive(url, slug="alpha", engagement_slug="alpha", signers=signers, claimed_class=claimed)


# ---------------------------------------------------------------------------------------------------
# live positives — each class mints a signed FACT that re-verifies OFFLINE, and a tamper is rejected
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed,engine", [
    ("/real-mongo", "nosqli", "mongodb"),
    ("/real-ldap", "ldap_injection", "ldap"),
    ("/real-xpath", "xpath_injection", "xpath"),
])
def test_each_class_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path, path, claimed, engine):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        rr = _drive(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
    finally:
        srv.shutdown()
    assert _App.hits >= 2, "the arm must send BOTH the injection probe AND the benign control twin"
    assert rr.n_facts == 1, f"{claimed}: expected exactly one signed FACT; notes={rr.notes}"
    fact = rr.facts[0]
    assert fact.is_fact and fact.bug_class == claimed, f"the FACT must name the claimed class {claimed}"
    ctx = rr.contexts[fact.finding_ref]

    # (1) the signed cert re-verifies OFFLINE from the retained JSON-safe context — no network, no runner.
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True

    # (2) a TAMPER is rejected: strip the datastore-error signature from the retained observed body → the
    #     oracle no longer fires over the reproduced context.
    tampered = json.loads(json.dumps(ctx))
    assert "error_observed" in tampered, "the error_signature context must carry the observed body"
    tampered["error_observed"] = "clean OK\n{\"rows\": []}"
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False


def test_offline_reverify_rejects_a_tampered_control(monkeypatch, tmp_path):
    """A second tamper direction: injecting the SAME datastore error into the retained CONTROL body makes the
    error non-attributable, so the oracle refuses over the reproduced context (fail-closed)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        rr = _drive(f"http://127.0.0.1:{port}/real-mongo?q=hello", "nosqli", signers)
    finally:
        srv.shutdown()
    assert rr.n_facts == 1
    fact = rr.facts[0]
    ctx = rr.contexts[fact.finding_ref]
    tampered = json.loads(json.dumps(ctx))
    tampered["error_control"] = tampered["error_observed"]     # the error now rides the control too
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False


# ---------------------------------------------------------------------------------------------------
# the false-FACT battery — each drives the REAL arm and must yield NO fact (a LEAD)
# ---------------------------------------------------------------------------------------------------

def _no_fact(monkeypatch, tmp_path, path: str, claimed: str = "nosqli"):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        rr = _drive(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
    finally:
        srv.shutdown()
    return rr


def test_benign_twin_mints_nothing(monkeypatch, tmp_path):
    rr = _no_fact(monkeypatch, tmp_path, "/clean")
    assert _App.hits >= 2, "the arm must actually contact the server (a refusal would be a vacuous pass)"
    assert rr.n_facts == 0, "an endpoint that never emits a datastore error must not mint a FACT"


def test_bare_differential_mints_nothing(monkeypatch, tmp_path):
    """THE B2 soundness case: a bare benign-vs-payload DIFFERENTIAL (the body varies with the input, distinct
    status/length) but with NO datastore error is a LEAD for these classes, never a FACT."""
    rr = _no_fact(monkeypatch, tmp_path, "/bare-diff")
    assert _App.hits >= 2
    assert rr.n_facts == 0, "a bare differential masquerading as evidence must not mint a datastore-error FACT"


def test_always_erroring_page_mints_nothing(monkeypatch, tmp_path):
    """The benign control twin errors too → the error is not attributable → refused."""
    rr = _no_fact(monkeypatch, tmp_path, "/always-error")
    assert _App.hits >= 2
    assert rr.n_facts == 0, "an always-erroring page must not mint a FACT"


def test_verbatim_reflection_of_a_static_error_template_mints_nothing(monkeypatch, tmp_path):
    rr = _no_fact(monkeypatch, tmp_path, "/reflect")
    assert _App.hits >= 2
    assert rr.n_facts == 0, "a verbatim-reflected static datastore-error template must not mint a FACT"


def test_mismatched_engine_mints_nothing(monkeypatch, tmp_path):
    """A nosqli claim whose probe provokes a SQL (mysql) engine error must NOT mint under nosqli — the
    evidence proves a different class, so the arm refuses rather than mislabel it."""
    rr = _no_fact(monkeypatch, tmp_path, "/sql-on-mongo", "nosqli")
    assert _App.hits >= 2
    assert rr.n_facts == 0, "a mysql error under a nosqli claim must not mint a nosqli FACT"
    assert any("different class" in n for n in rr.notes), "the mismatch must be recorded honestly"


# ---------------------------------------------------------------------------------------------------
# the governed-engage SEAM: _live_injection_redrive_fact returns a ref on the sound path, None otherwise
# ---------------------------------------------------------------------------------------------------

def _seam(url: str, claimed: str, signers):
    from vigil_integration.live.wiring import _live_injection_redrive_fact
    return _live_injection_redrive_fact(
        _prov(signers), {}, {"kind": "injection", "url": url, "bug_class": claimed})


def test_seam_mints_a_fact_for_each_class(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    for path, claimed in [("/real-mongo", "nosqli"), ("/real-ldap", "ldap_injection"),
                          ("/real-xpath", "xpath_injection")]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
        finally:
            srv.shutdown()
        assert ref, f"the governed-engage seam must mint a signed FACT for {claimed}"


def test_seam_stays_lead_on_the_negative_controls(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    for path, claimed in [("/clean", "nosqli"), ("/bare-diff", "nosqli"), ("/always-error", "nosqli"),
                          ("/reflect", "nosqli"), ("/sql-on-mongo", "nosqli")]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
        finally:
            srv.shutdown()
        assert ref is None, f"the seam must stay a LEAD on {path} (got a FACT ref)"


def test_seam_ignores_a_non_injection_class(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _seam(f"http://127.0.0.1:{port}/real-mongo?q=hello", "open_redirect", signers)
    finally:
        srv.shutdown()
    assert ref is None, "a non-injection class is not handled by this seam"


def test_seam_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    signers, _ = _signers_and_trust()
    ref = _seam("http://10.99.99.99/real-mongo?q=hello", "nosqli", signers)
    assert ref is None, "an out-of-scope target must never mint a FACT"
