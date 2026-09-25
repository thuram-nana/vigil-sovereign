"""WAVE #2 — four HTTP-response-derived re-drive arms on the Strix proof-sink rail: a Strix LEAD → an
oracle-confirmed FACT VIGIL mints by re-firing its OWN gated probe.

Each arm is genuinely LIVE against a loopback app that serves a real surface for its class:

  * reflected XSS (CWE-79) — ``runtime_redrive(claimed_class="xss")`` / reflection_context oracle (html_tag).
  * SSTI            — ``ssti_redrive`` / evaluation oracle (per-probe random product, raw absent, control lacks it).
  * boolean_sqli    — ``boolean_redrive`` / boolean_inference SPRT (true!=false, within-pair false stable).
  * time_based_sqli — ``timing_redrive`` / timing oracle (Mann-Whitney U + effect floor + dose-response).

Per arm: a REAL positive mints a signed FACT that re-verifies OFFLINE (verify_certificate + the
``framework.v2 verify`` CLI over the persisted proofs/reverifiable.json) and whose TAMPER is rejected; and the
false-FACT battery each yields a LEAD (no mint). Plus the W1a red-pen disjointness pin: every re-drive arm's
class set / CWE map is pairwise DISJOINT, so arm order can never route a report to the wrong arm.

The RUNNER crafts every probe; the Strix report is never proof. No browser, no OOB collector — the transport is
VIGIL's OWN charter-gated, DNS-pinned, proxy-free send (``web_redrive._gated_web_send``), reused by every arm.
"""
from __future__ import annotations

import http.server
import json
import re
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---- gate isolation + charter (mirrors test_strix_errsig_redrive) --------------------------------------
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


def _mint(tmp_path: Path, signers, slug: str = "alpha"):
    """The proof-sink mint callback. The W2 arms craft their OWN gated controls, so NO control_fetch seam is
    needed (unlike the errsig arm)."""
    from vigil_integration.proof.run import build_report_mint
    return build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug=slug)


def _report(check_id: str, path: str, port: int, bug_class: str, param: str = "q") -> dict:
    return {"id": check_id, "bug_class": bug_class, "param": param,
            "endpoint": f"http://127.0.0.1:{port}{path}?{param}=seed"}


# ---- a loopback app: a REAL surface per class + the false-FACT decoys ----------------------------------

_SLEEP_RE = re.compile(r"(?:pg_)?sleep\(\s*(\d*\.?\d+)\s*\)", re.IGNORECASE)
_ARITH_RE = re.compile(r"(\d{4,})\s*\*\s*(\d{4,})")
_HITS = {"n": 0}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class _App(http.server.BaseHTTPRequestHandler):
    def _html(self, body: str, code: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")   # declared → body is adjudicable
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        _HITS["n"] += 1
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        value = (q.get("q") or [""])[0]
        path = parts.path

        # ----- reflected XSS -----
        if path == "/xss":                       # VULNERABLE: reflects q UNSANITISED into an element context
            return self._html(f"<html><body><h1>Results</h1><div>{value}</div></body></html>")
        if path == "/xss-encoded":               # BENIGN: HTML-escaped reflection (inert, never a live element)
            return self._html(f"<html><body><h1>Results</h1><div>{_esc(value)}</div></body></html>")
        if path == "/xss-static":                # BENIGN: input ignored (not reflected)
            return self._html("<html><body><h1>Results</h1><div>none</div></body></html>")

        # ----- SSTI (template / EL evaluation) -----
        if path == "/ssti":                      # VULNERABLE: EVALUATES the arithmetic, emits ONLY the product
            m = _ARITH_RE.search(value)
            if m:
                return self._html(f"<html><body><p>{int(m.group(1)) * int(m.group(2))}</p></body></html>")
            return self._html(f"<html><body><p>{_esc(value)}</p></body></html>")   # benign: echo, no product
        if path == "/ssti-reflect":              # BENIGN: reflects the RAW expression verbatim (not evaluated)
            return self._html(f"<html><body><p>{value}</p></body></html>")
        if path == "/ssti-static":               # BENIGN: input ignored (product never appears)
            return self._html("<html><body><p>welcome</p></body></html>")

        # ----- boolean-blind SQLi (name = '<value>') -----
        if path == "/bool":                      # VULNERABLE: OR-tautology selects every row; false selects none
            true = ("'1'='1" in value) or ("1=1" in value)
            return self._html("<html><body>alice bob carol dave erin frank grace heidi</body></html>"
                              if true else "<html><body>no results found for your query</body></html>")
        if path == "/bool-random":               # DECOY: a purely-dynamic page — a long per-request RANDOM token
            # dominates the body, so ANY two responses (incl. two identical repeats) diverge lexically well past
            # the differential threshold → the same-request STABILITY control trips EVERY round → SPRT refutes.
            return self._html(f"<html><body>session {secrets.token_hex(64)} — no results</body></html>")
        if path == "/bool-dynamic":              # DECOY (DETERMINISTIC always-varies, no RNG): the body LENGTH
            # steps by a large fixed amount per request (mod-cycled so it never converges). Any 4 consecutive
            # requests in a round have 4 distinct lengths → every control (across/within_same/stable) sees a
            # differential → signal 0 EVERY round → the SPRT refutes DETERMINISTICALLY (0 false FACTs, always).
            pad = "=" * (40 + (_HITS["n"] % 5) * 90)
            return self._html(f"<html><body>catalogue {pad} listing</body></html>")
        if path == "/bool-static":               # DECOY: identical body for ANY input → no across differential
            return self._html("<html><body>welcome to the catalogue, browse our products</body></html>")

        # ----- time-based blind SQLi -----
        if path == "/time":                      # VULNERABLE: sleeps the injected duration (dose-responsive)
            m = _SLEEP_RE.search(value)
            if m:
                time.sleep(min(float(m.group(1)), 2.0))
            return self._html("<html><body>ok</body></html>")
        if path == "/time-slow":                 # DECOY: UNIFORMLY slow — sleeps a fixed amount for EVERY req
            time.sleep(0.05)
            return self._html("<html><body>ok</body></html>")
        if path == "/time-offset":               # DECOY: CONSTANT offset for any sleep payload (no dose scaling)
            if _SLEEP_RE.search(value):
                time.sleep(0.2)
            return self._html("<html><body>ok</body></html>")

        return self._html("not found", code=404)

    def log_message(self, *a):  # silence
        return


def _serve():
    _HITS["n"] = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_mint(tmp_path, signers, check_id, path, bug_class, param="q"):
    srv = _serve()
    port = srv.server_address[1]
    try:
        return _mint(tmp_path, signers)(_report(check_id, path, port, bug_class, param)), port
    finally:
        srv.shutdown()


def _assert_fact_reverifies(mr, tr, tmp_path):
    """A minted FACT: signed cert re-verifies OFFLINE over its retained context, a TAMPER is rejected, and the
    persisted proofs/reverifiable.json re-fires (and fails closed on tamper) via the `framework.v2 verify` CLI."""
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.verify import reverify

    assert mr is not None and mr.is_fact, f"expected a signed FACT; got {mr}"
    res = mr.result
    assert res.n_facts >= 1
    fact = res.facts[0]
    ctx = res.contexts[fact.finding_ref]

    # (1) the signed cert re-verifies OFFLINE from the retained JSON-safe context — no network, no runner.
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True

    # (2) a TAMPER of the retained context is rejected (the oracle no longer re-fires over the altered bytes).
    tampered = json.loads(json.dumps(ctx))
    _corrupt_context(tampered)
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False

    # (3) the offline CLI (`python3 -m framework.v2 verify <report>`) re-fires the persisted reverifiable.json.
    report_path = tmp_path / "proofs" / "reverifiable.json"
    assert report_path.is_file(), "a FACT must persist a re-verifiable report for offline CLI verify"
    assert reverify.main([str(report_path)]) == 0, "the persisted FACT must re-verify offline"

    doc = json.loads(report_path.read_text(encoding="utf-8"))
    for f in doc["active_findings"]:
        _corrupt_context(f.get("oracle_context") or {})
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tampered_path)]) != 0, "a tampered context must not re-verify"


def _corrupt_context(oc: dict) -> None:
    """Strip the evidence of the fire from a retained oracle_context, so the deterministic oracle can no longer
    re-fire over it (used for the tamper-rejection half of every positive)."""
    if "eval_observed" in oc:                    # SSTI: remove the evaluated product from the observed body
        oc["eval_observed"] = "<html><body><p>welcome</p></body></html>"
    if "observed_sink" in oc:                    # reflected XSS: neutralise the live element
        oc["observed_sink"] = "<html><body>nothing reflected here</body></html>"
    if "probe_rounds" in oc:                     # boolean: make every true/false pair identical (no signal)
        for r in oc["probe_rounds"]:
            if isinstance(r, dict):
                r["true"] = r["false_a"] = r["false_b"] = {"status": 200, "body": "same"}
                if "false_a_repeat" in r:
                    r["false_a_repeat"] = {"status": 200, "body": "same"}
    if "treatment_latencies" in oc:              # timing: flatten the treatment to the baseline (no shift)
        oc["treatment_latencies"] = list(oc.get("baseline_latencies") or [1.0, 1.1, 1.0, 1.2, 1.1, 1.0])
        oc.pop("timing_dose", None)


# =======================================================================================================
# reflected XSS (CWE-79)
# =======================================================================================================

def test_reflected_xss_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "xss-1", "/xss", "xss")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "xss"


def test_reflected_xss_encoded_reflection_is_refused(monkeypatch, tmp_path):
    """FP: an HTML-escaped (inert) reflection — the canary is present but not in an executable context → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "xss-enc", "/xss-encoded", "xss")
    assert mr is None or not mr.is_fact, "an HTML-escaped reflection must NOT mint an XSS FACT"


def test_reflected_xss_not_reflected_is_refused(monkeypatch, tmp_path):
    """FP: a substring/no reflection with no executable context → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "xss-none", "/xss-static", "xss")
    assert mr is None or not mr.is_fact, "an endpoint that never reflects the canary must NOT mint an XSS FACT"


# =======================================================================================================
# SSTI
# =======================================================================================================

def test_ssti_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "ssti-1", "/ssti", "ssti")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "ssti"


def test_ssti_reflected_but_unevaluated_is_refused(monkeypatch, tmp_path):
    """FP: the raw expression survives verbatim (reflected == sent) → reflected, not evaluated → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "ssti-refl", "/ssti-reflect", "ssti")
    assert mr is None or not mr.is_fact, "a verbatim-reflected (unevaluated) expression must NOT mint an SSTI FACT"


def test_ssti_static_page_is_refused(monkeypatch, tmp_path):
    """FP: the product never appears (no evaluation, no coincidence) → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "ssti-static", "/ssti-static", "ssti")
    assert mr is None or not mr.is_fact, "a page that never evaluates the expression must NOT mint an SSTI FACT"


# =======================================================================================================
# boolean-blind SQLi
# =======================================================================================================

def test_boolean_sqli_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "bool-1", "/bool", "boolean_sqli")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "boolean_sqli"


def test_boolean_sqli_dynamic_page_is_refused(monkeypatch, tmp_path):
    """FP (randomized endpoint): a page whose response varies with ANY input — a long per-request random token
    dominates the body, so the same-request STABILITY control (an identical false repeat must be non-differential)
    trips EVERY round; the SPRT signal is 0 every round and it refutes → LEAD. Was ~40% false-FACT before the fix."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "bool-rand", "/bool-random", "boolean_sqli")
    assert mr is None or not mr.is_fact, "a dynamic page (varies with any input) must NOT mint a boolean FACT"


def test_boolean_sqli_deterministic_dynamic_page_is_refused(monkeypatch, tmp_path):
    """FP (DETERMINISTIC always-varies endpoint, no RNG): the body length steps by a large fixed amount per
    request, so every control (across / within_same / stability) sees a differential — signal 0 EVERY round,
    the SPRT refutes DETERMINISTICALLY. A non-flaky regression that pins the fix without relying on randomness."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "bool-dyn", "/bool-dynamic", "boolean_sqli")
    assert mr is None or not mr.is_fact, "a deterministic always-varies page must NOT mint a boolean FACT"


def test_boolean_sqli_static_page_is_refused(monkeypatch, tmp_path):
    """FP: an endpoint with no differential at all (true == false) — no boolean channel → LEAD (no SPRT flip)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "bool-static", "/bool-static", "boolean_sqli")
    assert mr is None or not mr.is_fact, "a static page (no true/false differential) must NOT mint a boolean FACT"


# =======================================================================================================
# time-based blind SQLi
# =======================================================================================================

def test_time_based_sqli_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "time-1", "/time", "time_based_sqli")
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "time_based_sqli"


def test_time_based_sqli_uniformly_slow_page_is_refused(monkeypatch, tmp_path):
    """FP: a uniformly slow/loaded endpoint — no distribution shift between benign and injected, and a one-off
    spike cannot fake the rank-sum → the test fails to reject → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "time-slow", "/time-slow", "time_based_sqli")
    assert mr is None or not mr.is_fact, "a uniformly slow endpoint must NOT mint a time-based FACT"


def test_time_based_sqli_constant_offset_without_dose_response_is_refused(monkeypatch, tmp_path):
    """FP: a constant extra delay that does NOT scale with the injected delay — the dose-response ratio stays
    ~1.0 → the timing oracle refuses (a constant offset cannot fake dose scaling) → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, _ = _signers_and_trust()
    mr, _ = _run_mint(tmp_path, signers, "time-offset", "/time-offset", "time_based_sqli")
    assert mr is None or not mr.is_fact, "a constant offset with no dose-response must NOT mint a time-based FACT"


# =======================================================================================================
# out-of-scope + capture-path guards (shared soundness, per arm the same shape as the errsig rail)
# =======================================================================================================

def test_out_of_scope_endpoint_is_refused_before_a_fact(monkeypatch, tmp_path):
    """A gate refusal (target host not in the charter scope) yields NO channel → LEAD, for a W2 arm too."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")            # charter authorizes 127.0.0.1 only
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "oos-xss", "bug_class": "xss", "param": "q",
               "endpoint": "http://127.0.0.2:1/xss?q=seed"})
    assert mr is None or not mr.is_fact, "an out-of-scope target must never mint a FACT"


def test_a_capture_bearing_report_is_not_hijacked_by_a_w2_arm(monkeypatch, tmp_path):
    """A capture-bearing report is left for the executor-capture mint (every W2 arm is requires_no_capture)."""
    from vigil_integration.proof.sink import CAPTURE_KEY
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "bug_class": "error_based_sqli"},
                         {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended",
                     "ctrl": b"HTTP/1.1 200 OK\r\n\r\n{\"items\": []}",
                     "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    # bug_class xss would classify to the reflection arm, BUT the capture forces the executor-capture path.
    res = mint({"id": "cap-xss", "bug_class": "xss", CAPTURE_KEY: cap})
    assert not hasattr(res, "result") or getattr(res, "result", None) is None or hasattr(res, "reproduced"), (
        "a capture-bearing report must not be hijacked by a W2 runtime arm")


# =======================================================================================================
# W1a red-pen pin: the re-drive arms are PAIRWISE class-disjoint (arm order can never mis-route a report).
# =======================================================================================================

def test_redrive_arm_class_sets_are_disjoint():
    """Every re-drive arm's class set AND CWE map is pairwise DISJOINT (web / errsig / xss / ssti / boolean /
    timing / dom_xss / prototype_pollution). Even were it violated, no false FACT could result (each arm mints
    only over its own oracle), but pinning it now that eight arms exist keeps arm ORDER from ever routing a
    report to the wrong arm — in particular reflected xss (CWE-79, server-response reflection) vs dom_xss
    (bug_class dom_xss, DOM execution) stay distinct."""
    from vigil_integration.proof import run
    from vigil_integration.live.web_redrive import WEB_FACT_CLASSES

    class_sets = {
        "web": set(WEB_FACT_CLASSES) | set(run._WEB_CWE_TO_CLASS.values()),
        "errsig": set(run._ERRSIG_REDRIVE_CLASSES) | set(run._ERRSIG_CWE_TO_CLASS.values()),
        "xss": (set(run._REFLECTION_REDRIVE_CLASSES) | set(run._REFLECTION_ALIASES.values())
                | set(run._REFLECTION_CWE_TO_CLASS.values())),
        "ssti": (set(run._SSTI_REDRIVE_CLASSES) | set(run._SSTI_ALIASES.values())
                 | set(run._SSTI_CWE_TO_CLASS.values())),
        "boolean": set(run._BOOLEAN_REDRIVE_CLASSES) | set(run._BOOLEAN_ALIASES.values()),
        "timing": set(run._TIMING_REDRIVE_CLASSES) | set(run._TIMING_ALIASES.values()),
        "dom_xss": (set(run._DOM_XSS_REDRIVE_CLASSES) | set(run._DOM_XSS_ALIASES.values())
                    | set(run._DOM_XSS_CWE_TO_CLASS.values())),
        "prototype_pollution": (set(run._PROTO_POLLUTION_REDRIVE_CLASSES)
                                | set(run._PROTO_POLLUTION_ALIASES.values())
                                | set(run._PROTO_POLLUTION_CWE_TO_CLASS.values())),
    }
    cwe_maps = {
        "web": set(run._WEB_CWE_TO_CLASS),
        "errsig": set(run._ERRSIG_CWE_TO_CLASS),
        "xss": set(run._REFLECTION_CWE_TO_CLASS),
        "ssti": set(run._SSTI_CWE_TO_CLASS),
        "boolean": set(run._BOOLEAN_CWE_TO_CLASS),
        "timing": set(run._TIMING_CWE_TO_CLASS),
        "dom_xss": set(run._DOM_XSS_CWE_TO_CLASS),
        "prototype_pollution": set(run._PROTO_POLLUTION_CWE_TO_CLASS),
    }
    names = list(class_sets)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            overlap = class_sets[a] & class_sets[b]
            assert not overlap, f"arm class sets {a!r} and {b!r} overlap on {sorted(overlap)}"
            cwe_overlap = cwe_maps[a] & cwe_maps[b]
            assert not cwe_overlap, f"arm CWE maps {a!r} and {b!r} overlap on {sorted(cwe_overlap)}"

    # and each arm's classifier actually returns its own class (the sets are load-bearing, not decorative).
    assert run._reflection_redrive_class({"bug_class": "xss"}) == "xss"
    assert run._ssti_redrive_class({"bug_class": "ssti"}) == "ssti"
    assert run._boolean_redrive_class({"bug_class": "boolean_sqli"}) == "boolean_sqli"
    assert run._timing_redrive_class({"bug_class": "time_based_sqli"}) == "time_based_sqli"
    assert run._dom_xss_redrive_class({"bug_class": "dom_xss"}) == "dom_xss"
    assert run._prototype_pollution_redrive_class({"bug_class": "prototype_pollution"}) == "prototype_pollution"
    assert run._prototype_pollution_redrive_class({"cwe": "CWE-1321"}) == "prototype_pollution"
    # a cross-class report is NOT claimed by a foreign arm (order-independence in practice).
    assert run._boolean_redrive_class({"bug_class": "error_based_sqli"}) is None
    assert run._errsig_redrive_class({"bug_class": "boolean_sqli"}) is None
    # reflected xss vs dom_xss stay distinct: a bare CWE-79 is reflected's (not dom_xss's); an explicit
    # dom_xss is NOT claimed by the reflected-xss arm.
    assert run._dom_xss_redrive_class({"cwe": "CWE-79"}) is None
    assert run._reflection_redrive_class({"bug_class": "dom_xss"}) is None
    assert run._dom_xss_redrive_class({"bug_class": "xss"}) is None
