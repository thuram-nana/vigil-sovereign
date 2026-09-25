"""WAVE #1a — the error-signature RE-DRIVE rail: a Strix injection LEAD → an oracle-confirmed FACT.

The headline proofs are genuinely live: a real loopback HTTP app serves an error-based injection surface for
each of the four injection classes (error_based_sqli / nosqli / ldap_injection / xpath_injection). The proof
sink's ``_strix_errsig_redrive`` re-drives the finding's {endpoint, param} through the SAME charter-gated,
DNS-pinned, proxy-free transport the web re-drive uses (``web_redrive._gated_web_send``) — the RUNNER crafts
the injection payload, never the Strix report — fetches a benign CONTROL twin via the production
``bootstrap._live_control_fetch`` seam, and the deterministic ``error_signature_oracle`` mints a signed FACT
that re-verifies OFFLINE. The engine the oracle matches OVERRIDES the Strix-claimed class.

The false-FACT battery is the point: an always-erroring page, a soft-404/WAF page echoing a SQL-ish string,
and a verbatim-reflecting page each present the SAME datastore-error string in the benign control twin, so the
control-comparison guard REFUSES the mint (LEAD). No external tool is installed or run — the transport is
VIGIL's own, gated.
"""
from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---- gate isolation + charter (mirrors the reachability_cloud / web-redrive live-capture tests) ----
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


# ---- a loopback app: a REAL error-based injection surface per class + the false-FACT decoys ----------
# The RUNNER's injection payloads carry syntax metacharacters; the benign control twin carries a
# metacharacter-free "vfctl…" marker. A REAL surface emits its engine's error ONLY when a metacharacter is
# present (a genuine error-based injection); the decoys emit the SAME datastore string regardless (so the
# control twin ALSO carries it → not attributable → the mint refuses).
_META = set("'\"(){}[]|&*/;$`\\<>")
_HITS = {"n": 0}

# path -> the engine-specific error string emitted when a metacharacter is present (a real error-based injection)
_REAL_ENGINE_ERROR = {
    "/real-sql": "You have an error in your SQL syntax; check the manual near ",
    "/real-mongo": "MongoError: unknown top level operator near ",
    "/real-ldap": "javax.naming.directory.InvalidSearchFilterException: bad filter near ",
    "/real-xpath": "XPathException: invalid expression near ",
    # RELABEL: the finding will CLAIM error_based_sqli, but THIS endpoint is a Mongo backend — the oracle
    # matches the mongodb engine, so the FACT must mint under nosqli, not the claim.
    "/relabel-mongo": "MongoError: unknown top level operator near ",
}


def _has_meta(value: str) -> bool:
    return any(c in _META for c in value)


class _App(http.server.BaseHTTPRequestHandler):
    def _count(self):
        _HITS["n"] += 1

    def _text(self, code: int, body: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")   # declared → body is adjudicable
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):  # noqa: N802
        self._count()
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        value = (q.get("q") or [""])[0]

        if parts.path in _REAL_ENGINE_ERROR:
            # A genuine error-based sink: a metacharacter breaks the query and the backend emits its engine
            # error; a benign value renders a clean row. So observed(payload)=error, control(benign)=clean.
            if _has_meta(value):
                self._text(500, _REAL_ENGINE_ERROR[parts.path] + repr(value))
            else:
                self._text(200, json.dumps({"rows": [], "echo": value}))
            return

        if parts.path == "/always-error":
            # DECOY (false-FACT a): ALWAYS emits the SQL error, even for the benign control → present in BOTH
            # observed and control → the oracle's control-comparison guard suppresses the fire → LEAD.
            self._text(500, "You have an error in your SQL syntax; check the manual (static banner)")
            return

        if parts.path == "/soft404":
            # DECOY (false-FACT b): a WAF/soft-404 page that echoes a SQL-ish string as canned chrome for ANY
            # request (200) → the signature is value-independent → present in the control twin → LEAD.
            self._text(200, "Request blocked. check the manual that corresponds to your MySQL server version.")
            return

        if parts.path == "/reflect":
            # DECOY (false-FACT c): reflects the param value VERBATIM inside a static error-message TEMPLATE.
            # The datastore-error phrase is chrome (present for the benign control too), NOT engine-emitted, so
            # the control twin carries it and the mint refuses. VIGIL's runner-crafted metacharacters are not
            # themselves a signature, so reflection alone never fabricates one.
            self._text(200, f"You have an error in your SQL syntax near '{value}'")
            return

        self._text(404, "not found")

    def log_message(self, *a):  # silence
        return


def _serve():
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _App)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _mint(tmp_path: Path, signers, slug: str = "alpha"):
    """Build the proof-sink mint callback wired to the PRODUCTION control-fetch seam (bootstrap)."""
    from vigil_integration.proof.bootstrap import _live_control_fetch
    from vigil_integration.proof.run import build_report_mint
    return build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug=slug,
                             control_fetch=_live_control_fetch(slug))


def _report(check_id: str, path: str, port: int, bug_class: str, param: str = "q") -> dict:
    return {"id": check_id, "bug_class": bug_class, "param": param,
            "endpoint": f"http://127.0.0.1:{port}{path}"}


# ---- the live proofs ------------------------------------------------------------------------------

def test_real_error_based_sqli_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("sqli-1", "/real-sql", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert _HITS["n"] >= 2, "the rail must send BOTH the injection probe AND the benign control twin"
    assert mr is not None and mr.is_fact, f"expected a signed FACT; got {mr}"
    assert mr.engine == "mysql" and mr.engine_class == "error_based_sqli"
    assert mr.result.bug_class == "error_based_sqli"

    # (1) the signed cert re-verifies OFFLINE from the retained JSON-safe context — no network, no runner.
    assert verify_certificate(mr.result.signed, oracle_context=mr.oracle_context, trust_root=tr).ok is True

    # (2) a TAMPER is rejected: flip a byte in the retained observed body → the oracle no longer fires.
    tampered = json.loads(json.dumps(mr.oracle_context))
    tampered["error_observed"] = "clean OK\n{\"rows\": []}"    # strip the datastore-error signature
    assert verify_certificate(mr.result.signed, oracle_context=tampered, trust_root=tr).ok is False


def test_offline_cli_reverify_of_the_persisted_reverifiable_report(monkeypatch, tmp_path):
    """`python3 -m framework.v2 verify <report.json>` re-fires the persisted proofs/reverifiable.json (the
    exact CLI code path is reverify.main). A tamper of the retained context makes the CLI fail closed."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.verify import reverify
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("sqli-cli", "/real-sql", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert mr is not None and mr.is_fact
    report_path = tmp_path / "proofs" / "reverifiable.json"
    assert report_path.is_file(), "the FACT must persist a re-verifiable report for offline CLI verify"

    # exit 0 ⇒ every certificate reproduced offline and matched its claim.
    assert reverify.main([str(report_path)]) == 0

    # tamper the retained oracle_context → the oracle cannot re-fire → the CLI fails closed (non-zero).
    doc = json.loads(report_path.read_text(encoding="utf-8"))
    for f in doc["active_findings"]:
        oc = f.get("oracle_context") or {}
        if "error_observed" in oc:
            oc["error_observed"] = "benign OK, no datastore error here"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tampered_path)]) != 0, "a tampered context must not re-verify"


@pytest.mark.parametrize(
    "path,bug_class,expected_engine,expected_class",
    [
        ("/real-sql", "error_based_sqli", "mysql", "error_based_sqli"),
        ("/real-mongo", "nosqli", "mongodb", "nosqli"),
        ("/real-ldap", "ldap_injection", "ldap", "ldap_injection"),
        ("/real-xpath", "xpath_injection", "xpath", "xpath_injection"),
    ],
)
def test_all_four_injection_classes_mint_under_the_matched_engine(
        monkeypatch, tmp_path, path, bug_class, expected_engine, expected_class):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report(f"inj-{bug_class}", path, port, bug_class))
    finally:
        srv.shutdown()
    assert mr is not None and mr.is_fact, f"{bug_class}: expected a FACT; got {mr}"
    assert mr.engine == expected_engine, f"{bug_class}: matched engine {mr.engine!r}"
    assert mr.engine_class == expected_class and mr.result.bug_class == expected_class
    assert verify_certificate(mr.result.signed, oracle_context=mr.oracle_context, trust_root=tr).ok is True


def test_oracle_authoritative_relabel_mints_under_the_engine_not_the_claim(monkeypatch, tmp_path):
    """A finding whose Strix-claimed class (error_based_sqli) DISAGREES with the datastore the oracle matched
    (mongodb) mints under the ENGINE's class (nosqli), never the claim."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.evidence.certify import verify_certificate
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("relabel-1", "/relabel-mongo", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert mr is not None and mr.is_fact
    assert mr.claimed_class == "error_based_sqli", "the Strix claim is preserved for the audit trail"
    assert mr.engine == "mongodb" and mr.engine_class == "nosqli", "the oracle's engine must WIN over the claim"
    assert mr.result.bug_class == "nosqli", "the certificate must name the class the EVIDENCE proves"
    assert verify_certificate(mr.result.signed, oracle_context=mr.oracle_context, trust_root=tr).ok is True


# ---- the false-FACT battery: each must yield NO mint / LEAD ---------------------------------------

def test_always_erroring_page_where_the_control_also_errors_is_refused(monkeypatch, tmp_path):
    """False-FACT (a): a page that ALWAYS emits the datastore error — the benign control twin errors too, so
    the error is NOT attributable to the payload → the control-comparison guard refuses the mint."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("always-1", "/always-error", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert _HITS["n"] >= 2, "the rail must actually contact the server (a refusal would be a vacuous pass)"
    assert mr is None or not mr.is_fact, "an always-erroring page must NOT mint a FACT"


def test_soft404_waf_page_echoing_a_sql_string_is_refused(monkeypatch, tmp_path):
    """False-FACT (b): a WAF/soft-404 page echoes a SQL-ish string as canned chrome for ANY request — present
    in the benign control twin → refused."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("soft404-1", "/soft404", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert _HITS["n"] >= 2
    assert mr is None or not mr.is_fact, "a soft-404 WAF banner must NOT mint a FACT"


def test_verbatim_reflection_of_a_static_error_template_is_refused(monkeypatch, tmp_path):
    """False-FACT (c): a page that reflects user input inside a STATIC datastore-error template — the phrase is
    chrome, present for the benign control twin too (not engine-emitted), so the control twin catches it."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("reflect-1", "/reflect", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert _HITS["n"] >= 2
    assert mr is None or not mr.is_fact, "a verbatim-reflected static error template must NOT mint a FACT"


def test_missing_control_fetch_seam_stays_a_lead(monkeypatch, tmp_path):
    """Fail-closed: with NO control-fetch seam wired, the control-comparison guard cannot be made live, so
    even a genuinely erroring surface stays a LEAD (a control that cannot be captured never mints)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.proof.run import build_report_mint
    signers, _ = _signers_and_trust()
    mint = build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug="alpha")  # control_fetch=None
    srv = _serve()
    port = srv.server_address[1]
    try:
        mr = mint(_report("nocontrol-1", "/real-sql", port, "error_based_sqli"))
    finally:
        srv.shutdown()
    assert mr is None or not mr.is_fact, "no control seam ⇒ no attributable error ⇒ LEAD (fail-closed)"


def test_out_of_scope_endpoint_is_refused_before_a_fact(monkeypatch, tmp_path):
    """A gate refusal (the target host is not in the charter scope) yields NO channel → LEAD, never a FACT
    over traffic VIGIL was not authorized to send."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")            # charter authorizes 127.0.0.1 only
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    # 127.0.0.2 is loopback but NOT in the charter scope → the gate refuses before any probe.
    mr = mint({"id": "oos-1", "bug_class": "error_based_sqli", "param": "q",
               "endpoint": "http://127.0.0.2:1/real-sql"})
    assert mr is None or not mr.is_fact, "an out-of-scope target must never mint a FACT"


def test_a_report_with_a_capture_still_uses_the_capture_path(monkeypatch, tmp_path):
    """A capture-bearing injection report is left for the executor-capture mint (the errsig re-drive rail is
    the primary ONLY for a captureless Strix LEAD); the rail must not hijack it. The capture carries the
    bound request + a benign control exchange, so the capture path mints a FACT — and it is a MintResult
    (``.reproduced``), NEVER the rail's ``_ErrsigMintResult`` (``.engine_class``)."""
    from vigil_integration.proof.run import build_report_mint
    from vigil_integration.proof.sink import CAPTURE_KEY
    signers, _ = _signers_and_trust()
    mint = build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug="alpha")
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "bug_class": "error_based_sqli"},
                         {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended",
                     "ctrl": b"HTTP/1.1 200 OK\r\n\r\n{\"items\": []}",
                     "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    res = mint({"id": "cap-1", "bug_class": "error_based_sqli", CAPTURE_KEY: cap})
    assert res is not None and getattr(res, "is_fact", False), "the capture path must still mint from bytes"
    assert hasattr(res, "reproduced"), "a capture-bearing report must take the executor-capture MintResult path"
    assert not hasattr(res, "engine_class"), "the live re-drive rail must NOT hijack a capture-bearing report"
