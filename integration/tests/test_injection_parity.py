"""Slice: governed-engage re-drive for nosqli / ldap_injection / xpath_injection — a PROVEN query break.

These three classes are DRIVEN through the governed-engage seam
(engine._redrive_spec → wiring._live_injection_redrive_fact → runtime_redrive.injection_redrive): VIGIL sends
its OWN gated THREE-leg probe (a benign CONTROL, an UNBALANCED metacharacter BREAK, and a RE-BALANCED
BALANCED payload carrying the SAME metacharacter set) and the deterministic parser_state_toggle_oracle mints a
signed FACT ONLY when the datastore parser errored on the BREAK leg ALONE — a genuine QUERY BREAK, re-derived
OFFLINE over the frozen capture.

This CLOSES the earlier red-pen BLOCK. The old error_signature form was a STRING MATCH that re-verified only
CONDITIONAL EMISSION of a datastore-error-shaped string — a WAF block page, an input-validator rejection, or
an unrelated 500 whose stack trace merely names the driver PACKAGE all emit one conditionally on the
metacharacter and passed the benign-control-twin guard (four durable false FACTs at rate 1.0). The parser-
state-toggle defeats every one of them: a source keying on metacharacter PRESENCE errors on BOTH break and
balanced (same metacharacters) and so cannot produce the toggle; a static banner fires on all three; a bare
package name is not a parser-break message; a block/rejection response is refused.

This file pins: the _redrive_spec routing; that a GENUINE query break mints a signed FACT that re-verifies
OFFLINE; that the whole red-pen decoy battery (metacharacter-presence filter, WAF block, validator rejection,
unrelated-500-naming-the-package, static banner, bare differential, verbatim reflection, mismatched engine)
mints NO FACT; and that the datastore_error branches are FACT-capable while the sprt_inference branches stay
honest LEAD-only (no offline NoSQL/LDAP/XPath engine ships to build truth-correct clause families).
"""
from __future__ import annotations

import http.server
import json
import re
import threading
import types
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

# Two-env faithfulness: the FACT here is minted by framework.v2.verify.oracles.parser_state_toggle_oracle,
# which this slice ADDS to engine/crucible. If the loaded framework is the installed/main-clone copy (its
# engine/crucible is NOT ahead of this worktree's on PYTHONPATH), that symbol is absent, injection_redrive's
# import of it fails closed, and every server-driving assertion below would cascade. SKIP honestly in that
# case (the oracle under test is not loaded) rather than report a spurious failure — run via tw.sh's `off`
# leg, or put THIS worktree's engine/crucible first on PYTHONPATH, to exercise it.
_oracles = pytest.importorskip("framework.v2.verify.oracles", reason="CRUCIBLE not importable here")
if not hasattr(_oracles, "parser_state_toggle_oracle"):
    pytest.skip(
        "the loaded framework.v2.verify.oracles has no parser_state_toggle_oracle — this worktree's "
        "engine/crucible is not ahead of the installed framework on PYTHONPATH, so the oracle under test is "
        "not loaded (put <worktree>/engine/crucible first on PYTHONPATH, e.g. tw.sh's `off` leg)",
        allow_module_level=True)


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
    from vigil_integration.live.wiring import Provisioned
    return Provisioned(keypair=None, trust_root=None, signers=signers, authority_path="", slug=slug)


# ---------------------------------------------------------------------------------------------------
# a loopback app: GENUINE parser breaks (balance-keyed) + the red-pen false-FACT decoys (presence-keyed)
# ---------------------------------------------------------------------------------------------------
# A GENUINE error-based sink errors on an UNBALANCED query and renders cleanly on a balanced one — it reacts
# to the ARRANGEMENT of the metacharacters, as a real parser does. The DECOYS react to metacharacter PRESENCE
# (error on ANY metacharacter) from a NON-datastore source — the exact class of false FACT the red-pen
# reproduced; under the parser-state toggle (break vs re-balanced) every one stays a LEAD (no FACT).
_META = set("'\"(){}[]|&*/;$`\\<>")

_BREAK_MSG = {
    "mongodb": "FailedToParse: Expecting '}' or ',' but found end of input near ",
    "ldap": "LDAP: error code 87 - Bad search filter near ",
    "xpath": "XPathException: Invalid XPath expression: unexpected token near ",
}
_CLEAN_BODY = json.dumps({"rows": [1, 2, 3], "ok": True})


def _balanced(s: str, opener: str, closer: str) -> bool:
    depth = 0
    for ch in s:
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _mongo_unbalanced(v: str) -> bool:
    return bool(v.count('"') % 2 or v.count("'") % 2
                or not _balanced(v, '{', '}') or not _balanced(v, '[', ']'))


def _ldap_unbalanced(v: str) -> bool:
    wrapped = "(uid=" + v + ")"
    return (not _balanced(wrapped, '(', ')')) or bool(re.search(r"\([|&!]\)", wrapped))


def _xpath_unbalanced(v: str) -> bool:
    wrapped = "//user[name='" + v + "']"
    return bool(wrapped.count("'") % 2 or not _balanced(wrapped, '[', ']'))


_UNBALANCED = {"mongodb": _mongo_unbalanced, "ldap": _ldap_unbalanced, "xpath": _xpath_unbalanced}


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

        # --- GENUINE parser breaks: error on an UNBALANCED query, clean on a balanced one -------------
        for engine, path in (("mongodb", "/break-mongo"), ("ldap", "/break-ldap"), ("xpath", "/break-xpath")):
            if parts.path == path:
                if any(_UNBALANCED[engine](v) for v in values):
                    self._text(500, _BREAK_MSG[engine] + repr(values))
                else:
                    self._text(200, _CLEAN_BODY)
                return
        # a genuine break whose engine is NOT the one that names the claimed class (mongo break payload →
        # an LDAP parser error): the toggle FIRES but the engine mismatches, so the arm refuses it.
        if parts.path == "/cross-engine":
            if any(_mongo_unbalanced(v) for v in values):
                self._text(500, _BREAK_MSG["ldap"] + repr(values))
            else:
                self._text(200, _CLEAN_BODY)
            return

        # --- the red-pen false-FACT battery: a datastore-error-shaped string from a NON-datastore source,
        #     emitted on metacharacter PRESENCE. Each MUST stay a LEAD (no FACT). ---
        if parts.path in ("/real-mongo", "/real-ldap", "/real-xpath"):
            # a PRESENCE emitter: errors on ANY metacharacter (so break AND balanced both error) → the
            # toggle cannot fire. This is the same-shape negative the toggle exists to defeat.
            engine = {"/real-mongo": "mongodb", "/real-ldap": "ldap", "/real-xpath": "xpath"}[parts.path]
            self._text(500 if meta else 200, _BREAK_MSG[engine] + repr(values) if meta else _CLEAN_BODY)
            return
        if parts.path == "/waf-mongo":
            self._text(403, "Request blocked by WAF: possible NoSQL injection attempt rejected") if meta \
                else self._text(200, _CLEAN_BODY)
            return
        if parts.path == "/valid-ldap":
            self._text(400, "Invalid input rejected by request validator: LDAPException-style characters "
                            "are not allowed") if meta else self._text(200, "ok")
            return
        if parts.path == "/stacktrace-mongo":
            # unrelated 500 whose stack trace merely NAMES the driver package (com.mongodb); a number parse,
            # not a query break. A metacharacter routinely triggers some 500, so this is high-frequency.
            self._text(500, "java.lang.NumberFormatException: For input string\n"
                            "  at com.mongodb.client.internal.MongoClientDelegate.<init>"
                            "(MongoClientDelegate.java:10)\n") if meta else self._text(200, "ok")
            return
        if parts.path == "/always-error":
            self._text(500, _BREAK_MSG["mongodb"] + "(static banner)")   # control + balanced error too
            return
        if parts.path == "/reflect":
            self._text(200, _BREAK_MSG["mongodb"] + repr(values))   # verbatim echo → every leg carries it
            return
        if parts.path == "/bare-diff":
            # a BARE benign-vs-payload DIFFERENTIAL: body varies with the input but NO parser error at all.
            self._text(418, f"filtered: {len(values[0]) if values else 0} chars") if meta \
                else self._text(200, f"results for {values!r}: 3 items")
            return
        if parts.path == "/sql-on-mongo":
            # a genuine break that emits a SQL error (this oracle carries no SQL signatures → never fires).
            if any(_mongo_unbalanced(v) for v in values):
                self._text(500, "You have an error in your SQL syntax; check the manual near " + repr(values))
            else:
                self._text(200, "ok")
            return
        if parts.path == "/clean":
            self._text(200, _CLEAN_BODY)   # benign: never errors
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


def _drive_on(monkeypatch, tmp_path, path: str, claimed: str, signers=None):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers = signers or [("gov0", _signers_and_trust()[0][0][1])]
    srv = _serve(); port = srv.server_address[1]
    try:
        return _drive(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------------------------------
# a GENUINE query break mints a signed FACT that re-verifies OFFLINE
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed", [
    ("/break-mongo", "nosqli"), ("/break-ldap", "ldap_injection"), ("/break-xpath", "xpath_injection"),
])
def test_a_genuine_query_break_mints_a_fact_that_reverifies_offline(monkeypatch, tmp_path, path, claimed):
    from framework.v2.evidence.certify import verify_certificate
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        rr = _drive(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
    finally:
        srv.shutdown()
    assert _App.hits >= 3, "the arm must send all THREE legs (control + break + balanced)"
    assert rr.n_facts == 1, f"{claimed}: a genuine query break must mint exactly one FACT; notes={rr.notes}"
    f = rr.facts[0]
    assert f.is_fact and getattr(f, "signed", None) is not None
    from framework.v2.verify.verifier import normalize_bug_class
    assert normalize_bug_class(f.bug_class) == claimed, "the FACT is tied to the claimed class"
    # OFFLINE re-verification over the FROZEN retained context — the sound-FACT guarantee.
    ctx = rr.contexts[f.finding_ref]
    assert verify_certificate(f.signed, oracle_context=ctx, trust_root=tr).ok is True


# ---------------------------------------------------------------------------------------------------
# the same-shape negative: a metacharacter-PRESENCE emitter (errors on break AND balanced) mints NO FACT
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed", [
    ("/real-mongo", "nosqli"), ("/real-ldap", "ldap_injection"), ("/real-xpath", "xpath_injection"),
])
def test_a_presence_only_emitter_mints_no_fact(monkeypatch, tmp_path, path, claimed):
    rr = _drive_on(monkeypatch, tmp_path, path, claimed)
    assert _App.hits >= 3, "the arm must send all three legs (not a vacuous pass)"
    assert rr.n_facts == 0, (
        f"{claimed}: a metacharacter-PRESENCE emitter errors on break AND balanced — the toggle must NOT fire")


# ---------------------------------------------------------------------------------------------------
# the red-pen decoy battery — each reproduced false FACT must stay a LEAD (facts == [])
# ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,claimed,why", [
    ("/waf-mongo", "nosqli", "a WAF block page that names the engine is not a datastore query break"),
    ("/valid-ldap", "ldap_injection", "an input-validator rejection is not a query break"),
    ("/stacktrace-mongo", "nosqli", "an unrelated 500 whose stack trace names com.mongodb is not a query break"),
    ("/always-error", "nosqli", "a static banner errors on every leg, including the benign control"),
    ("/reflect", "nosqli", "a verbatim-reflected error template rides every leg"),
    ("/bare-diff", "nosqli", "a bare benign-vs-payload differential has no parser-break message"),
    ("/clean", "nosqli", "a benign endpoint never errors"),
])
def test_the_red_pen_decoy_battery_mints_no_fact(monkeypatch, tmp_path, path, claimed, why):
    rr = _drive_on(monkeypatch, tmp_path, path, claimed)
    assert _App.hits >= 3, "the arm must actually contact the server (a refusal would be a vacuous pass)"
    assert rr.n_facts == 0, f"BLOCK regression: {why} — minted a FALSE FACT"


def test_a_sql_error_under_a_nosqli_claim_mints_no_fact(monkeypatch, tmp_path):
    """A genuine break that emits a SQL error is SQLi, not nosqli — this oracle carries no SQL parser-break
    signatures, so the toggle never fires and no nosqli FACT is minted."""
    rr = _drive_on(monkeypatch, tmp_path, "/sql-on-mongo", "nosqli")
    assert _App.hits >= 3
    assert rr.n_facts == 0


def test_a_mismatched_engine_break_is_not_admitted_for_the_class(monkeypatch, tmp_path):
    """A genuine query break whose engine is NOT the one that names the claimed class (a nosqli probe that
    provokes an LDAP parser error) fires the toggle but is REFUSED — the evidence proves a DIFFERENT class."""
    rr = _drive_on(monkeypatch, tmp_path, "/cross-engine", "nosqli")
    assert _App.hits >= 3
    assert rr.n_facts == 0
    assert any("different class" in n for n in rr.notes), f"the engine mismatch must be recorded: {rr.notes}"


# ---------------------------------------------------------------------------------------------------
# the governed-engage SEAM: _live_injection_redrive_fact mints on a genuine break, None on the decoys
# ---------------------------------------------------------------------------------------------------

def _seam(url: str, claimed: str, signers):
    from vigil_integration.live.wiring import _live_injection_redrive_fact
    return _live_injection_redrive_fact(
        _prov(signers), {}, {"kind": "injection", "url": url, "bug_class": claimed})


def test_seam_mints_a_fact_on_a_genuine_break(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    for path, claimed in [("/break-mongo", "nosqli"), ("/break-ldap", "ldap_injection"),
                          ("/break-xpath", "xpath_injection")]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", claimed, signers)
        finally:
            srv.shutdown()
        assert ref, f"{claimed}: a genuine query break must surface a signed FACT finding_ref through the seam"
        assert _App.hits >= 3


def test_seam_stays_none_on_the_whole_decoy_battery(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    for path in ["/real-mongo", "/waf-mongo", "/valid-ldap", "/stacktrace-mongo",
                 "/clean", "/bare-diff", "/always-error", "/reflect", "/sql-on-mongo", "/cross-engine"]:
        srv = _serve(); port = srv.server_address[1]
        try:
            ref = _seam(f"http://127.0.0.1:{port}{path}?q=hello", "nosqli", signers)
        finally:
            srv.shutdown()
        assert ref is None, f"the seam must return None (no FACT) on {path}"


def test_seam_ignores_a_non_injection_class(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _tr = _signers_and_trust()
    srv = _serve(); port = srv.server_address[1]
    try:
        ref = _seam(f"http://127.0.0.1:{port}/break-mongo?q=hello", "open_redirect", signers)
    finally:
        srv.shutdown()
    assert ref is None, "a non-injection class is not handled by this seam"


def test_seam_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    signers, _tr = _signers_and_trust()
    ref = _seam("http://10.99.99.99/break-mongo?q=hello", "nosqli", signers)
    assert ref is None, "an out-of-scope target must never mint a FACT"


# ---------------------------------------------------------------------------------------------------
# the registry: datastore_error is FACT-capable (toggle); sprt_inference stays honest LEAD-only
# ---------------------------------------------------------------------------------------------------

def test_datastore_error_branches_are_fact_capable_via_the_toggle():
    root = Path(__file__).resolve().parents[2]
    reg = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text("utf-8"))
    by = {b["id"]: b for b in reg["branches"]}
    for cls in ("nosqli", "ldap_injection", "xpath_injection"):
        b = by[f"{cls}.datastore_error"]
        assert b["fact_capable"] is True, f"{cls}.datastore_error must be FACT-capable (parser-state toggle)"
        assert b["clean_capable"] is False, "a positive-only toggle is not clean-capable"
        assert b["oracle_version"] == "error_signature", "adjudicated by the ERROR_SIGNATURE kind (reuse)"
        assert "blocking_work" not in b, "a FACT-capable branch names no blocking_work"
        assert "lead-only" not in b["limitation"].lower()


def test_sprt_inference_branches_stay_lead_only():
    """No offline NoSQL/LDAP/XPath injection engine ships, so a truth-correct machine-verified clause family
    cannot be built — these stay honest LEAD-only ladder targets."""
    root = Path(__file__).resolve().parents[2]
    reg = json.loads((root / "docs" / "capability-matrix" / "evidence-branches.json").read_text("utf-8"))
    by = {b["id"]: b for b in reg["branches"]}
    for cls in ("nosqli", "ldap_injection", "xpath_injection"):
        b = by[f"{cls}.sprt_inference"]
        assert b["fact_capable"] is False, f"{cls}.sprt_inference must stay LEAD-only"
        assert b["clean_capable"] is False
        assert b["oracle_version"] == "", f"{cls}.sprt_inference LEAD-only ⇒ no oracle_version"
        assert len(b.get("blocking_work", "")) > 40, f"{cls}.sprt_inference must name the blocker"
