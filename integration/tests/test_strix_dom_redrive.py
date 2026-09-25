"""WAVE #3 (browser-backed) — two DOM ACHIEVED-STATE re-drive arms on the Strix proof-sink rail: a Strix
LEAD → an oracle-confirmed FACT VIGIL mints by driving its OWN egress-gated headless-Chromium/CDP harness.

  * dom_xss            — ``dom_redrive.dom_xss_redrive`` / dom_execution oracle: VIGIL's canary EXECUTED in a
                         real DOM (a ``__crucible_xss`` binding call) — never a reflected-but-inert payload.
  * prototype_pollution — ``dom_redrive.proto_pollution_redrive`` / prototype_pollution oracle: the achieved
                         ``Object.prototype[cpp_…] === ppv_…`` state, benign-key control undefined.

The deterministic battery drives the FULL proof-sink path (``build_report_mint`` → ``_dispatch_redrive`` →
the arm → VIGIL's gated harness → the oracle → admit()+certify_admitted) with the real Chromium subprocess
replaced by a STUB CDP browser, so it runs everywhere (browserless CI included) and still exercises the mint,
the offline re-verify (``verify_certificate`` + the ``framework.v2 verify`` CLI over proofs/reverifiable.json),
and TAMPER rejection. The false-FACT battery (reflected-but-inert, browserless, a Strix-supplied readback, an
app-set wrong-shape key, the benign-key control) each yields a LEAD/INCONCLUSIVE — never a FACT, never a
CLEAN. A separate skip-gated pair drives the SAME path against a REAL headless Chromium.

The RUNNER crafts every probe; the unforgeable canary is VIGIL-generated (secrets); the Strix report is never
proof.
"""
from __future__ import annotations

import contextlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

_XSS_CANARY_RE = re.compile(r"cxss[0-9]{2}[0-9a-f]{8}")
_PP_KEY_RE = re.compile(r"cpp_[0-9a-f]{12}")


# ---- gate isolation + charter (mirrors test_strix_http_redrive) ----------------------------------------
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
    from vigil_integration.proof.run import build_report_mint
    return build_report_mint(run_dir=tmp_path, signers=signers, engagement_slug=slug)


# ---- stub CDP browser (replaces the real Chromium subprocess deterministically) ------------------------
class _DomXssStubSession:
    """Models a page for the dom_xss driver: when ``vulnerable``, an injected execution payload 'executes' —
    it echoes back the ``__crucible_xss`` canary embedded in the navigated URL; when safe, no binding call
    (an inert / encoded reflection)."""

    def __init__(self, *, vulnerable: bool) -> None:
        self._vulnerable = vulnerable
        self._url = ""

    def add_binding(self, name: str) -> None:
        return None

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        self._url = url

    def binding_calls(self, name: str) -> list[str]:
        if not self._vulnerable:
            return []
        m = _XSS_CANARY_RE.search(self._url)
        return [m.group(0)] if m else []


class _ProtoStubSession:
    """Models a page for the prototype_pollution driver. On ``evaluate`` of the readback snippet it extracts
    the probe's cpp_/benign_ keys and reports a JSON blob via the ``__crucible_pp`` binding per ``mode``:
      * 'pollute'   → Object.prototype[cpp_…] === ppv_… (benign key undefined) = FACT
      * 'reflect'   → the page reflected the key but did NOT pollute (polluted_val null)
      * 'ambient'   → polluted BUT the benign key is also polluted (cannot attribute)
      * 'mismatch'  → polluted to a wrong (app-set) value, not VIGIL's ppv_
      * 'forged'    → an attacker/page-controlled readback claiming a NON-canary key (a Strix-supplied
                      readback) — the arm asks about VIGIL's cpp_ key, this reports a different one, so the
                      readback is filtered out (never mints)."""

    def __init__(self, mode: str) -> None:
        self._mode = mode
        self._calls: list[str] = []

    def add_binding(self, name: str) -> None:
        return None

    def navigate(self, url: str, *, settle: float = 0.4, timeout: float = 15.0) -> None:
        return None

    def drain_events(self, *, timeout: float = 1.0) -> list:
        return []

    def evaluate(self, expression: str, **_kw):
        keys = re.findall(r'"(cpp_[0-9a-f]{12}|benign_[0-9a-f]{12})"', expression)
        if len(keys) < 2:
            return None
        key, benign = keys[0], keys[1]
        tag = key[len("cpp_"):]
        val = f"ppv_{tag}"
        if self._mode == "forged":
            # An attacker-controlled readback that names a DIFFERENT (non-VIGIL) key. The scanner filters the
            # readback to calls carrying VIGIL's own key, so this is dropped entirely.
            blob = {"polluted_key": "isAdmin", "polluted_val": "true",
                    "benign_key": "x", "benign_key_undefined": True}
        else:
            blob = {"pollute": {"polluted_key": key, "polluted_val": val, "benign_key": benign,
                                "benign_key_undefined": True},
                    "reflect": {"polluted_key": key, "polluted_val": None, "benign_key": benign,
                                "benign_key_undefined": True},
                    "ambient": {"polluted_key": key, "polluted_val": val, "benign_key": benign,
                                "benign_key_undefined": False},
                    "mismatch": {"polluted_key": key, "polluted_val": "app_default_value", "benign_key": benign,
                                 "benign_key_undefined": True}}[self._mode]
        self._calls.append(json.dumps(blob))
        return None

    def binding_calls(self, name: str) -> list[str]:
        return list(self._calls) if name == "__crucible_pp" else []


class _StubBrowser:
    def __init__(self, *, session_factory, **_kw) -> None:  # accepts allowed_hosts=... etc.
        self._session_factory = session_factory

    def start(self) -> "_StubBrowser":
        return self

    def session(self):
        return self._session_factory()

    def stop(self) -> None:
        return None


def _install_stub_browser(monkeypatch, session_factory) -> None:
    """Patch the CDP harness so ``dom_redrive`` builds our STUB browser (no real Chromium) and reports it
    usable. The framework imports in ``dom_redrive`` are function-local, so patching the module attributes
    takes effect at call time."""
    from framework.v2.scanner import cdp
    monkeypatch.setattr(cdp, "cdp_available", lambda: True)
    monkeypatch.setattr(cdp, "CdpBrowser", lambda **kw: _StubBrowser(session_factory=session_factory, **kw))


# ---- offline re-verify + tamper helpers ----------------------------------------------------------------
def _assert_fact_reverifies(mr, tr, tmp_path):
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.verify import reverify

    assert mr is not None and mr.is_fact, f"expected a signed FACT; got {mr}"
    res = mr.result
    assert res.n_facts >= 1
    fact = res.facts[0]
    ctx = res.contexts[fact.finding_ref]

    # (1) the signed cert re-verifies OFFLINE from the retained JSON-safe context.
    assert verify_certificate(fact.signed, oracle_context=ctx, trust_root=tr).ok is True

    # (2) a TAMPER of the retained context is rejected (the oracle no longer re-fires over the altered bytes).
    tampered = json.loads(json.dumps(ctx))
    _corrupt(tampered)
    assert verify_certificate(fact.signed, oracle_context=tampered, trust_root=tr).ok is False

    # (3) the offline CLI (`python3 -m framework.v2 verify <report>`) re-fires the persisted reverifiable.json.
    report_path = tmp_path / "proofs" / "reverifiable.json"
    assert report_path.is_file(), "a FACT must persist a re-verifiable report for offline CLI verify"
    assert reverify.main([str(report_path)]) == 0, "the persisted FACT must re-verify offline"

    doc = json.loads(report_path.read_text(encoding="utf-8"))
    for f in doc["active_findings"]:
        _corrupt(f.get("oracle_context") or {})
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tampered_path)]) != 0, "a tampered context must not re-verify"


def _corrupt(oc: dict) -> None:
    """Strip the evidence of the fire from a retained DOM oracle_context, so the deterministic oracle can no
    longer re-fire over it."""
    if "dom_binding_calls" in oc:                # dom_xss: drop the execution callback that carried the canary
        oc["dom_binding_calls"] = []
    if "proto_pollution" in oc:                  # prototype_pollution: break the achieved-state value
        oc["proto_pollution"]["polluted_val"] = "ppv_000000000000"


# =======================================================================================================
# dom_xss (CWE-79-DOM) — DOM execution
# =======================================================================================================
def test_dom_xss_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _DomXssStubSession(vulnerable=True))
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "dom-1", "bug_class": "dom_xss", "param": "q",
               "endpoint": "http://127.0.0.1:9/echo?q=seed"})
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "dom_xss"


def test_dom_xss_reflected_but_inert_is_refused(monkeypatch, tmp_path):
    """FP: a safe page — the payload is reflected but never EXECUTES, so no __crucible_xss binding call → the
    dom_execution oracle does not fire → LEAD (never a FACT)."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _DomXssStubSession(vulnerable=False))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "dom-inert", "bug_class": "dom_xss", "param": "q",
               "endpoint": "http://127.0.0.1:9/echo?q=seed"})
    assert mr is None or not mr.is_fact, "a reflected-but-inert payload must NOT mint a DOM-XSS FACT"
    # and it is INCONCLUSIVE, never CLEAN (this branch cannot assert absence).
    assert mr.result.family_verdict("dom_xss") != "CLEAN"


def test_dom_xss_browserless_is_a_lead_never_clean(monkeypatch, tmp_path):
    """Browserless (no usable CDP harness) → INCONCLUSIVE (a LEAD), never CLEAN — grounded in cdp_available()."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.scanner import cdp
    monkeypatch.setattr(cdp, "cdp_available", lambda: False)
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "dom-nobrowser", "bug_class": "dom_xss", "param": "q",
               "endpoint": "http://127.0.0.1:9/echo?q=seed"})
    assert mr is not None and not mr.is_fact, "a browserless DOM re-drive must NOT mint a FACT"
    assert mr.result.family_verdict("dom_xss") == "INCONCLUSIVE", "browserless must be INCONCLUSIVE, not CLEAN"
    assert mr.result.inconclusive, "a browserless re-drive records an INCONCLUSIVE, never a CLEAN"


# =======================================================================================================
# prototype_pollution (CWE-1321) — achieved Object.prototype state
# =======================================================================================================
def test_prototype_pollution_mints_a_signed_fact_that_reverifies_offline(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _ProtoStubSession("pollute"))
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-1", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "prototype_pollution"


def test_prototype_pollution_benign_key_control_undefined_is_refused(monkeypatch, tmp_path):
    """FP: the benign-key control was NOT undefined (ambient / indiscriminate pollution) — the oracle cannot
    attribute the polluted state to THIS probe → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _ProtoStubSession("ambient"))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-ambient", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    assert mr is None or not mr.is_fact, "an ambient-pollution page (benign key not undefined) must NOT mint"


def test_prototype_pollution_app_set_wrong_shape_value_is_refused(monkeypatch, tmp_path):
    """FP: the prototype carries an app-set value that is NOT VIGIL's per-probe ppv_ canary → the oracle
    refuses (the value did not reproduce the driven-in marker) → LEAD."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _ProtoStubSession("mismatch"))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-mismatch", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    assert mr is None or not mr.is_fact, "an app-set wrong-shape value must NOT mint a prototype-pollution FACT"


def test_prototype_pollution_reflected_without_polluting_is_refused(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _ProtoStubSession("reflect"))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-reflect", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    assert mr is None or not mr.is_fact, "a page that reflects the gadget without polluting must NOT mint"


def test_prototype_pollution_strix_supplied_readback_cannot_mint(monkeypatch, tmp_path):
    """THE canary-SHAPE guard: a Strix-supplied (attacker/page-controlled) readback can NEVER mint. The arm
    drives VIGIL's OWN gadget and reads back through VIGIL's OWN binding keyed on a secrets-derived cpp_ key;
    a readback naming any other key is filtered out (nothing minted). And directly: the oracle refuses any
    key/value that is not VIGIL's cpp_<hex>/ppv_<hex> canary shape, so even a hand-crafted 'isAdmin=true'
    achieved-state context cannot be laundered into a FACT."""
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    _install_stub_browser(monkeypatch, lambda: _ProtoStubSession("forged"))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-forged", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    assert mr is None or not mr.is_fact, "a Strix-supplied readback must NOT mint a prototype-pollution FACT"

    # the oracle-level guarantee: a non-canary achieved-state context does not fire (shape guard).
    from framework.v2.verify.oracles import prototype_pollution_oracle
    sig = prototype_pollution_oracle({"polluted_key": "isAdmin", "expected_val": "true",
                                      "polluted_val": "true", "benign_key": "x",
                                      "benign_key_undefined": True})
    assert not sig.fired, "an arbitrary (non-cpp_/ppv_) key must never satisfy the prototype-pollution oracle"


def test_prototype_pollution_browserless_is_a_lead_never_clean(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from framework.v2.scanner import cdp
    monkeypatch.setattr(cdp, "cdp_available", lambda: False)
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "pp-nobrowser", "bug_class": "prototype_pollution",
               "endpoint": "http://127.0.0.1:9/proto"})
    assert mr is not None and not mr.is_fact
    assert mr.result.family_verdict("prototype_pollution") == "INCONCLUSIVE"


# =======================================================================================================
# wiring + shared soundness (mirrors the W2 rail guards)
# =======================================================================================================
def test_both_dom_classes_are_redrivable_at_the_sink_gate():
    from vigil_integration.proof.sink import _dom_xss_redrivable, _prototype_pollution_redrivable
    assert _dom_xss_redrivable({"bug_class": "dom_xss"}) is True
    assert _prototype_pollution_redrivable({"bug_class": "prototype_pollution"}) is True
    assert _prototype_pollution_redrivable({"cwe": "CWE-1321"}) is True
    # a foreign class is not claimed
    assert _dom_xss_redrivable({"bug_class": "xss"}) is False
    assert _prototype_pollution_redrivable({"bug_class": "dom_xss"}) is False


def test_the_dom_branches_are_registered_and_fact_capable():
    from vigil_integration.live.verdict import branch_ids
    ids = branch_ids()
    assert "dom_xss.dom_execution" in ids
    assert "prototype_pollution.achieved_state" in ids


def test_out_of_scope_dom_target_is_refused_before_a_fact(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")               # charter authorizes 127.0.0.1 only
    _install_stub_browser(monkeypatch, lambda: _DomXssStubSession(vulnerable=True))
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    mr = mint({"id": "oos-dom", "bug_class": "dom_xss", "param": "q",
               "endpoint": "http://127.0.0.2:1/echo?q=seed"})
    assert mr is None or not mr.is_fact, "an out-of-scope DOM target must never mint a FACT"
    assert mr.result.refused is True, "the charter gate must refuse before any browser is launched"


def test_a_capture_bearing_report_is_not_hijacked_by_a_dom_arm(monkeypatch, tmp_path):
    """A capture-bearing report is left for the executor-capture mint (both W3 arms are requires_no_capture)."""
    from vigil_integration.proof.sink import CAPTURE_KEY
    signers, _ = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    cap = {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                          "request_bytes_ref": "req", "status": 500, "bug_class": "error_based_sqli"},
                         {"channel": "error_signature", "role": "control", "response_bytes_ref": "ctrl"}],
           "blobs": {"resp": b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended",
                     "ctrl": b"HTTP/1.1 200 OK\r\n\r\n{\"items\": []}",
                     "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}}
    # bug_class dom_xss would classify to the dom arm, BUT the capture forces the executor-capture path.
    res = mint({"id": "cap-dom", "bug_class": "dom_xss", CAPTURE_KEY: cap})
    assert not hasattr(res, "result") or getattr(res, "result", None) is None or hasattr(res, "reproduced"), (
        "a capture-bearing report must not be hijacked by a W3 DOM arm")


# =======================================================================================================
# REAL headless Chromium — the same proof-sink path end to end (skip-gated on a usable CDP harness)
# =======================================================================================================
class _VulnDom(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = ("<div id=o></div><script>document.getElementById('o').innerHTML="
                "new URLSearchParams(location.search).get('q')||''</script>").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _serve(handler) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _cdp_ok() -> bool:
    try:
        from framework.v2.scanner.cdp import cdp_available
        return cdp_available()
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _cdp_ok(), reason="no usable headless Chromium for the CDP driver")
def test_dom_xss_against_a_real_browser_mints_via_the_proof_sink(monkeypatch, tmp_path):
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    signers, tr = _signers_and_trust()
    mint = _mint(tmp_path, signers)
    with _serve(_VulnDom) as base:
        mr = mint({"id": "dom-real", "bug_class": "dom_xss", "param": "q", "endpoint": f"{base}?q=seed"})
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "dom_xss"


@pytest.mark.skipif(not _cdp_ok(), reason="no usable headless Chromium for the CDP driver")
def test_prototype_pollution_against_a_real_browser_mints_via_the_proof_sink(monkeypatch, tmp_path):
    from framework.v2.eval.benchmark_app import serve
    _grant_active_recon(monkeypatch)
    signers, tr = _signers_and_trust()
    with serve() as base:
        from urllib.parse import urlsplit
        _charter(tmp_path, urlsplit(base).hostname or "127.0.0.1")
        mint = _mint(tmp_path, signers)
        mr = mint({"id": "pp-real", "bug_class": "prototype_pollution", "endpoint": f"{base}/proto"})
    _assert_fact_reverifies(mr, tr, tmp_path)
    assert mr.result.bug_class == "prototype_pollution"
