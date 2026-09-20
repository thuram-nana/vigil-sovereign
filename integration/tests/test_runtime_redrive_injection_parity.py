"""FACT-coverage Wave 1.1 — governed-FACT PARITY for the injection classes via ``live.runtime_redrive``.

The deterministic scanner already CONFIRMS boolean_sqli / nosqli / ldap_injection / xpath_injection (SPRT),
time_based_sqli (timing) and ssti (computed evaluation); this pins that the GOVERNED runtime re-drive now
mints the SAME FACTs from its OWN gated live capture, and — critically — that:

  * a vulnerable fixture mints a signed FACT (n_facts >= 1);
  * a SAFE twin (no channel) and a DYNAMIC/reflecting page mint NOTHING and are INCONCLUSIVE, never CLEAN or
    LEAD — the SPRT's false_a==false_b dynamic-page control, the timing effect-floor, and the evaluation
    computed-result control each refuse the near-miss;
  * the minted FACT's RETAINED oracle_context re-adjudicates OFFLINE through the SAME OracleKind
    (BOOLEAN_INFERENCE / TIMING / EVALUATION) — never silently downgraded to the single-shot
    DIFFERENTIAL_RESPONSE oracle (the correctness trap this slice exists to avoid).

Drives ``runtime_redrive()`` DIRECTLY (not only the wiring seam) so LEAD vs INCONCLUSIVE is observable.
Reuses the reviewed gated send + charter/active-recon/kill-switch gate exactly as the seam test does.
"""
from __future__ import annotations

import http.server
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# -- isolation + authorization (mirrors test_engine_runtime_redrive_seam) ---------------------------

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


def _signers(slug: str = "alpha"):
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(monkeypatch, tmp_path, handler, url_tmpl: str, claimed: str):
    from vigil_integration.live.runtime_redrive import runtime_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve(handler); port = srv.server_address[1]
    try:
        return runtime_redrive(url_tmpl.format(port=port), slug="alpha", engagement_slug="alpha",
                               signers=_signers(), claimed_class=claimed)
    finally:
        srv.shutdown()


def _reverify_kind(res, expected_kind_value: str) -> None:
    """The minted FACT's retained context must re-fire the SAME OracleKind offline — the downgrade guard."""
    from framework.v2.verify.verifier import OracleVerifier
    assert res.facts, "expected a minted FACT to re-verify"
    fact = res.facts[0]
    ctx = res.contexts[fact.finding_ref]
    result = OracleVerifier().confirm(ctx)
    assert result.confirmed, "the retained oracle_context did not re-confirm offline"
    fired = {s.kind.value for s in result.signals if s.fired and s.confidence >= 0.7}
    assert expected_kind_value in fired, (
        f"offline re-verify fired {fired}, expected the {expected_kind_value} oracle")
    assert "differential_response" not in fired, (
        "a boolean-blind FACT re-verified via the SINGLE-SHOT differential oracle — the SPRT context was "
        "downgraded (the exact trap this slice avoids)")


# ---------------------------------------------------------------------------------------------------
# boolean-blind SPRT: boolean_sqli / nosqli / ldap_injection / xpath_injection
# ---------------------------------------------------------------------------------------------------

def _bool_app(true_clause: str, false_clause: str):
    """A clean boolean channel keyed on ``id``: the TRUE clause returns a long stable record set, the FALSE
    clause an empty one (they differ), and every FALSE response is byte-identical (the dynamic-page control
    the SPRT requires holds)."""
    long_body = "records: " + " ".join(f"row{i}" for i in range(40))
    short_body = "records: none"

    class _App(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            from urllib.parse import parse_qs, urlsplit
            v = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
            body = long_body if v == true_clause else short_body if v == false_clause else "records: 1"
            self._text(body)

        def _text(self, body: str):
            raw = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw)

        def log_message(self, *a):
            return
    return _App


class _BoolSafeApp(http.server.BaseHTTPRequestHandler):
    """SAFE twin: identical body for every input — no boolean channel, so the SPRT refutes."""
    def do_GET(self):  # noqa: N802
        raw = b"records: 1 (constant)"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _BoolDynApp(http.server.BaseHTTPRequestHandler):
    """DYNAMIC page: a fresh token every request, so the two FALSE responses DISAGREE — the SPRT
    dynamic-page control trips and no round produces a signal."""
    _n = 0

    def do_GET(self):  # noqa: N802
        type(self)._n += 1
        raw = (f"records: 1 nonce={type(self)._n}-{time.time_ns()} " + "x" * (type(self)._n % 17)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


_SPRT_CASES = ["boolean_sqli", "nosqli", "ldap_injection", "xpath_injection"]


@pytest.mark.parametrize("cls", _SPRT_CASES)
def test_sprt_class_mints_a_fact_and_reverifies_via_boolean_inference(monkeypatch, tmp_path, cls):
    from vigil_integration.live.runtime_redrive import _SPRT_CLAUSES
    t, f = _SPRT_CLAUSES[cls]
    res = _run(monkeypatch, tmp_path, _bool_app(t, f), "http://127.0.0.1:{port}/q?id=1", cls)
    assert res.n_facts >= 1, f"{cls}: a clean boolean channel must mint a signed FACT via the SPRT"
    _reverify_kind(res, "boolean_inference")


@pytest.mark.parametrize("cls", _SPRT_CASES)
def test_sprt_class_safe_twin_is_inconclusive_never_fact_or_lead(monkeypatch, tmp_path, cls):
    res = _run(monkeypatch, tmp_path, _BoolSafeApp, "http://127.0.0.1:{port}/q?id=1", cls)
    assert res.n_facts == 0, f"{cls}: a constant-body endpoint must not mint a FACT"
    assert not res.leads, f"{cls}: a refuted SPRT is INCONCLUSIVE, not a LEAD"
    assert res.family_verdict(cls) == "INCONCLUSIVE", f"{cls}: no channel != CLEAN"


@pytest.mark.parametrize("cls", _SPRT_CASES)
def test_sprt_class_dynamic_page_is_inconclusive(monkeypatch, tmp_path, cls):
    res = _run(monkeypatch, tmp_path, _BoolDynApp, "http://127.0.0.1:{port}/q?id=1", cls)
    assert res.n_facts == 0, f"{cls}: a page that changes every request must not mint (dynamic-page control)"
    assert res.family_verdict(cls) != "CLEAN"


# ---------------------------------------------------------------------------------------------------
# time-based blind: time_based_sqli
# ---------------------------------------------------------------------------------------------------

class _TimeApp(http.server.BaseHTTPRequestHandler):
    """VULNERABLE: the SLEEP payload induces a real ~2s delay > the timing oracle's effect floor
    (0.5 * injected_ms = 1500ms); the benign value returns fast."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
        if "sleep" in v.lower():
            time.sleep(2.0)
        raw = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _TimeSafeApp(http.server.BaseHTTPRequestHandler):
    """SAFE twin: never sleeps — no timing shift, so the timing oracle does not fire."""
    def do_GET(self):  # noqa: N802
        raw = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


def test_time_based_sqli_mints_a_fact_and_reverifies_via_timing(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, _TimeApp, "http://127.0.0.1:{port}/q?id=1", "time_based_sqli")
    assert res.n_facts >= 1, "a real delay above the effect floor must mint a timing FACT"
    _reverify_kind(res, "timing")


def test_time_based_sqli_safe_twin_is_inconclusive(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, _TimeSafeApp, "http://127.0.0.1:{port}/q?id=1", "time_based_sqli")
    assert res.n_facts == 0, "a constant-latency endpoint must not mint a timing FACT"
    assert res.family_verdict("time_based_sqli") != "CLEAN"


# ---------------------------------------------------------------------------------------------------
# ssti: computed evaluation
# ---------------------------------------------------------------------------------------------------

class _SstiApp(http.server.BaseHTTPRequestHandler):
    """VULNERABLE: evaluates a ``{{a*b}}`` product server-side and renders ONLY the computed result (the raw
    template text never survives), so the evaluation oracle fires. The benign control never carries a product."""
    def do_GET(self):  # noqa: N802
        import re
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
        m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", v)
        rendered = str(int(m.group(1)) * int(m.group(2))) if m else v
        raw = f"<html><body>Hello {rendered}</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


class _SstiReflectApp(http.server.BaseHTTPRequestHandler):
    """SAFE twin: reflects the RAW payload verbatim (no evaluation) — the oracle sees the raw template text
    present and returns a conclusive 'reflected, not evaluated' negative → INCONCLUSIVE for this branch."""
    def do_GET(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
        raw = f"<html><body>Hello {v}</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


def test_ssti_mints_a_fact_and_reverifies_via_evaluation(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, _SstiApp, "http://127.0.0.1:{port}/q?id=1", "ssti")
    assert res.n_facts >= 1, "a server that COMPUTES {{a*b}} must mint an evaluation FACT"
    _reverify_kind(res, "evaluation")


def test_ssti_safe_twin_reflection_is_inconclusive_never_fact(monkeypatch, tmp_path):
    res = _run(monkeypatch, tmp_path, _SstiReflectApp, "http://127.0.0.1:{port}/q?id=1", "ssti")
    assert res.n_facts == 0, "a page that only REFLECTS the raw template must not mint an SSTI FACT"
    assert not res.leads, "a reflected-not-evaluated conclusive negative is INCONCLUSIVE, not a LEAD"
    assert res.family_verdict("ssti") != "CLEAN", "a body-derived branch may never assert CLEAN"


def test_ssti_out_of_scope_url_mints_nothing(monkeypatch, tmp_path):
    from vigil_integration.live.runtime_redrive import runtime_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")   # only 127.0.0.1 is in scope
    res = runtime_redrive("http://10.99.99.99/q?id=1", slug="alpha", engagement_slug="alpha",
                          signers=_signers(), claimed_class="ssti")
    assert res.refused and res.n_facts == 0, "an out-of-scope target must be refused before any traffic"


# ---------------------------------------------------------------------------------------------------
# REGRESSION (red-pen BLOCK): a PURE input-reflecting endpoint must NOT mint a boolean-blind FACT.
#
# Before the reflection-stripping fix, an endpoint that merely ECHOED the injected value back into its
# body (NO backend boolean evaluation) made the TRUE-clause and FALSE-clause responses differ ONLY by
# the reflected clause string — so the SPRT `across` differential fired every round and a signed
# boolean_sqli/xpath_injection FACT was minted on a page with no injection channel at all. The fix
# strips every reflected payload (raw + encoded forms) from the bodies BEFORE the differential, applied
# IDENTICALLY live (checks.py) and offline (boolean_inference_oracle over the retained rounds), so a
# pure echo collapses to identical stripped bodies ⇒ INCONCLUSIVE, while real backend content survives.
# ---------------------------------------------------------------------------------------------------

class _ReflectApp(http.server.BaseHTTPRequestHandler):
    """PURE input reflection: echoes the injected value into MULTIPLE body fields (title, breadcrumb,
    echo — as a real search page reflects a query term), with NO backend query. The two FALSE responses
    are byte-identical (the dynamic-page control holds), and true vs false differ ONLY by the reflected
    clause — the exact false-positive the stripping fix must refuse."""
    def do_GET(self):  # noqa: N802
        import json
        from urllib.parse import parse_qs, urlsplit
        v = (parse_qs(urlsplit(self.path).query).get("id") or [""])[0]
        raw = json.dumps({"title": f"Search results for {v}",
                          "breadcrumb": f"Home / Search / {v}",
                          "q": v, "echo": v, "results": []}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def log_message(self, *a):
        return


@pytest.mark.parametrize("cls", ["boolean_sqli", "xpath_injection"])
def test_pure_input_reflection_mints_no_fact_live(monkeypatch, tmp_path, cls):
    """LIVE: a pure-echo endpoint must be INCONCLUSIVE, never a FACT or a LEAD — reflection is not a channel."""
    res = _run(monkeypatch, tmp_path, _ReflectApp, "http://127.0.0.1:{port}/q?id=1", cls)
    assert res.n_facts == 0, f"{cls}: a pure input-reflecting endpoint must NOT mint a boolean-blind FACT"
    assert not res.leads, f"{cls}: reflected-only differential is INCONCLUSIVE, not a LEAD"
    assert res.family_verdict(cls) == "INCONCLUSIVE", f"{cls}: pure reflection != CLEAN and != FACT"


@pytest.mark.parametrize("cls", ["boolean_sqli", "xpath_injection"])
def test_pure_input_reflection_is_inconclusive_offline(monkeypatch, tmp_path, cls):
    """OFFLINE: capture the SPRT rounds against the pure-echo endpoint exactly as the runner would, then
    re-adjudicate through the SAME deterministic boolean_inference oracle — it must NOT fire (the retained
    rounds carry true_payload/false_payload so the offline strip matches the live strip byte-for-byte)."""
    from framework.v2.scanner.checks import BooleanInferenceCheck
    from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
    from framework.v2.verify.oracles import boolean_inference_oracle
    from vigil_integration.live.runtime_redrive import _SPRT_CLAUSES

    t, f = _SPRT_CLAUSES[cls]
    srv = _serve(_ReflectApp); port = srv.server_address[1]
    try:
        import urllib.request

        def send(req):
            r = req  # RequestTemplate.render returns an HttpRequest
            with urllib.request.urlopen(r.url, timeout=5) as resp:  # noqa: S310  (loopback test fixture)
                return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}

        tmpl = RequestTemplate(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/q?id=1"))
        point = next(p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                     if p.name.lower() == "id")
        chk = BooleanInferenceCheck(id=f"rt-{cls}", bug_class=cls, true_clause=t, false_clause=f, n_max=12)
        ctx = chk.probe(tmpl, point, send)
        assert ctx is not None
        rounds = ctx.to_verifier_context().get("probe_rounds")
        assert rounds and all("true_payload" in r and "false_payload" in r for r in rounds), (
            "retained rounds must carry the payloads so the offline oracle strips identically")
        signal = boolean_inference_oracle(rounds)
        assert not signal.fired, (
            f"{cls}: offline boolean_inference oracle must NOT fire on a pure-reflection capture")
    finally:
        srv.shutdown()


def test_reflection_strip_is_a_noop_without_payloads_and_defends_only_echo():
    """Unit guard for the load-bearing helper: (1) NO-payload rounds are byte-identical to the pre-fix
    behaviour (every non-SPRT caller stays unchanged); (2) a pure-echo round is refused; (3) a REAL
    backend-content channel (rows vs empty, payload NOT in the body) still fires."""
    from framework.v2.verify.oracles import _strip_reflections, boolean_inference_oracle

    # (1) no-op: empty payloads leave the body (and length) untouched.
    r = {"body": "abc' OR '1'='1 xyz", "length": 18}
    assert _strip_reflections(r, []) == r
    assert _strip_reflections(r, [""]) == r

    # (1b) a round WITHOUT *_payload keys must produce exactly the pre-fix decision (no-op strip). A pure
    # echo without retained payloads therefore STILL fires — proving the strip, not some other change, is
    # what defends the channel, and that legacy/other callers are byte-identical.
    echo_no_payload = [{"true": {"body": "q=TRUECLAUSE " * 4},
                        "false_a": {"body": "q=FALSECLAUSE " * 4},
                        "false_b": {"body": "q=FALSECLAUSE " * 4}} for _ in range(6)]
    assert boolean_inference_oracle(echo_no_payload).fired, (
        "no-payload rounds must be byte-identical to pre-fix (strip is additive/opt-in)")

    # (2) same echo, now WITH retained payloads → stripped identical → refused.
    echo_with_payload = [{**rd, "true_payload": "TRUECLAUSE", "false_payload": "FALSECLAUSE"}
                         for rd in echo_no_payload]
    assert not boolean_inference_oracle(echo_with_payload).fired, (
        "a pure-echo capture with retained payloads must be refused (stripped bodies are identical)")

    # (3) a REAL boolean channel: backend content differs (rows vs empty) and does NOT contain the payload,
    # so stripping is a no-op on it → the differential still fires → FACT survives the fix.
    real = [{"true": {"body": "records: " + " ".join(f"row{i}" for i in range(40))},
             "false_a": {"body": "records: none"},
             "false_b": {"body": "records: none"},
             "true_payload": "TRUECLAUSE", "false_payload": "FALSECLAUSE"} for _ in range(6)]
    assert boolean_inference_oracle(real).fired, (
        "a real backend-content boolean channel must survive stripping and still mint")
