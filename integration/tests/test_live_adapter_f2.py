"""VF-1a.3 — genuine F2 (nonce THROUGH the exploit path) + the LIVE positive control, end-to-end against a
GENUINE loopback server, with the honest residual made explicit.

This extends test_live_adapter.py (the four states) with the VF-1a.3 soundness properties, each driven against
a real stdlib ``ThreadingHTTPServer`` on 127.0.0.1 through the gated :class:`HttpExecutor`:

  * GENUINE F2 for STILL_VULNERABLE — with a ``payload_template`` the run challenge rides the exploit payload;
    a VULNERABLE build reflects the injected data (challenge included) INSIDE the firing SQL error, so the
    fresh nonce comes back through the SINK → the driver credits F2 (unforgeable: an edge that cannot execute
    the injection cannot fabricate a firing DB error wrapping a fresh, unpredictable nonce).
  * REMEDIATED CAPS AT F1 even when the nonce is reflected — a PATCHED build that echoes the payload back into a
    SILENT response does NOT reach F2: reflection is not sink-traversal (the reclassification, live).
  * LIVE positive control closes PARAM-STRIPPING — with ``require_injectable_param_live`` an edge that drops the
    injectable param cannot yield REMEDIATED (the benign marker is never reflected → CONTROL_FAILED).
  * The SEMANTIC-WAF RESIDUAL is stated, not hidden — a payload-discriminating WAF (blocks the exploit's
    metacharacters, passes the benign marker) over a still-vulnerable origin reads as REMEDIATED@F1; an
    F2-demanding verifier gets INCONCLUSIVE (never a falsely-strong REMEDIATED@F2). This is the honest limit.

Needs framework (reverify + the translator) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from vigil_core import (  # noqa: E402
    generate_keypair, identity_digest, prove_wielder, sign_capability, sign_identity_attestation,
)
from vigil_integration.live.wiring import provision_authority  # noqa: E402
from vigil_integration.remediation.live_adapter import LiveHttpAdapter  # noqa: E402
from vigil_integration.remediation.prove_driver import (  # noqa: E402
    Freshness, ProvePolicy, Reason, State, prove_remediation, verify_prove_certificate,
)

from framework.v2.agents import HttpExecutor  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402

ENG = "remediate-live-f2"
NOW = 1_000
BUG = "error_based_sqli"
WIELDER = generate_keypair()

# The RETAINED original firing bytes (the harness-capability positive control): a real error-based-SQLi sig.
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"
# An error-based-SQLi payload TEMPLATE weaving the run challenge into a data position the sink reflects (an
# extractvalue marker); the vulnerable build echoes it back INSIDE the DB error → the fresh nonce traverses the
# sink. Contains SQL metacharacters (' and -) so a payload-discriminating WAF blocks it (see the residual test).
_F2_TEMPLATE = "' AND extractvalue(1,concat(0x7e,'{challenge}'))-- -"


def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# A richer loopback target: vulnerable/patched × reflects-input × payload-discriminating-WAF × param-stripping.
# --------------------------------------------------------------------------------------------------------
_METACHARS = "'\";-"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        raw_val = (q.get(srv.exploit_param) or [""])[0]
        nonce = (q.get(srv.nonce_param) or [""])[0]
        # A param-stripping edge drops the injectable param before it reaches the app logic.
        val = "" if srv.strip_param else raw_val
        has_metachar = any(c in val for c in _METACHARS)
        # A payload-discriminating WAF blocks metacharacter-bearing values (the exploit) but passes benign ones.
        blocked = srv.waf_block and has_metachar
        fires = (not srv.patched) and bool(val) and not blocked
        if fires:
            # error-based SQLi: the DB error REFLECTS the injected data — so a challenge woven into the payload
            # comes back INSIDE the firing signature (genuine F2).
            body = f"HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '{val}' at line 1\n"
        else:
            body = '{"results": [], "ok": true}\n'
            # a normal app reflects the (benign or patched) search term; a stripping edge / blocked payload does not.
            if srv.reflect_param and val and not blocked:
                body += f"\nYou searched for: {val}\n"
        if srv.echo_nonce and nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(*, patched: bool, reflect_param: bool = False, waf_block: bool = False, strip_param: bool = False,
           echo_nonce: bool = True, exploit_param: str = "q", nonce_param: str = "rc") -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = patched                # type: ignore[attr-defined]
    srv.reflect_param = reflect_param    # type: ignore[attr-defined]
    srv.waf_block = waf_block            # type: ignore[attr-defined]
    srv.strip_param = strip_param        # type: ignore[attr-defined]
    srv.echo_nonce = echo_nonce          # type: ignore[attr-defined]
    srv.exploit_param = exploit_param    # type: ignore[attr-defined]
    srv.nonce_param = nonce_param        # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


@pytest.fixture()
def gated_root(tmp_path, monkeypatch):
    targets = tmp_path / "targets"
    (targets / ENG).mkdir(parents=True)
    (targets / ENG / "charter.md").write_text(_CHARTER.format(slug=ENG), encoding="utf-8")
    authdir = tmp_path / "authority"
    authdir.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: authdir / f"{s}.authority.json")
    return tmp_path


def _executor(base_url: str) -> HttpExecutor:
    return HttpExecutor(engagement_slug=ENG, base_url=base_url, prompt_callback=lambda *_a: False)


def _adapter(srv: _Server, *, payload_template: str = "") -> LiveHttpAdapter:
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    return LiveHttpAdapter(
        executor=_executor(base), base_url=base, endpoint_path="/search", param="q",
        payload="x' OR '1'='1", nonce_param="rc", payload_template=payload_template,
        original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)


def _drive(adapter, *, policy=ProvePolicy(), now=NOW, not_after=9_000):
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    owner = prov.keypair
    ident = sign_identity_attestation(owner, engagement=ENG, policy={"host": ["127.0.0.1"]}, not_after=9_000)
    cap = sign_capability(owner, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=not_after,
                          rate_limit=10, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wproof = prove_wielder(WIELDER, challenge="pop-1", capability=cap)
    out = prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
        trusted_owner_pubkey=owner.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=prov.signers, now=now, run_id="run-1",
        pop_challenge="pop-1", freshness_nonce="fresh-nonce-xyz", revoked_ids=frozenset(), policy=policy)
    return out, {prov.signers[0][0]: owner.public_key_b64}


# ============================ genuine F2 (nonce through the exploit path) ============================
def test_genuine_f2_vulnerable_reflects_nonce_inside_firing_error(gated_root):
    # the challenge rides the exploit payload; the VULNERABLE sink reflects it INSIDE the firing DB error →
    # the fresh nonce provably traversed the sink → STILL_VULNERABLE at genuine F2.
    srv = _start(patched=False, reflect_param=True)
    try:
        out, pubkeys = _drive(_adapter(srv, payload_template=_F2_TEMPLATE))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.STILL_VULNERABLE and out.reason_code == Reason.ORACLE_FIRED
    assert out.achieved_freshness == Freshness.F2_PATH_TRAVERSED, out
    ok, _ = verify_prove_certificate(out.certificate, signer_pubkeys=pubkeys)
    assert ok and out.certificate["verdict"]["oracle_fired"] is True


def test_remediated_reflecting_patched_caps_at_f1_not_f2(gated_root):
    # a PATCHED build that echoes the payload (challenge included) into a SILENT response does NOT reach F2:
    # reflection into a silent body is not sink-traversal. REMEDIATED, but honestly at F1.
    srv = _start(patched=True, reflect_param=True)
    try:
        out, _ = _drive(_adapter(srv, payload_template=_F2_TEMPLATE))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REMEDIATED and out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS
    assert out.achieved_freshness == Freshness.F1_TARGET_ECHOES, out


def test_remediated_reflecting_patched_under_f2_floor_is_inconclusive(gated_root):
    # the same patched+reflecting build under an F2 floor → INCONCLUSIVE (a remediation can never earn F2).
    srv = _start(patched=True, reflect_param=True)
    try:
        out, _ = _drive(_adapter(srv, payload_template=_F2_TEMPLATE),
                        policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


# ============================ the LIVE positive control ============================
def test_live_control_confirms_injectable_param_live_on_reflecting_patched(gated_root):
    # require_injectable_param_live: a genuinely-patched build that reflects the benign marker → the control
    # confirms the injectable param reaches the app this run → REMEDIATED (the closure does not over-reject).
    srv = _start(patched=True, reflect_param=True)
    try:
        out, _ = _drive(_adapter(srv),
                        policy=ProvePolicy(require_injectable_param_live=True))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REMEDIATED and out.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS


def test_live_control_param_stripping_edge_is_inconclusive(gated_root):
    # a param-stripping edge drops the injectable param → the benign marker is never reflected →
    # injectable_param_live is False → under the policy the run is INCONCLUSIVE, NOT a false REMEDIATED.
    srv = _start(patched=True, reflect_param=True, strip_param=True)
    try:
        out, _ = _drive(_adapter(srv),
                        policy=ProvePolicy(require_injectable_param_live=True))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.CONTROL_FAILED


# ============================ the HONEST residual (payload-discriminating WAF) ============================
def test_semantic_waf_residual_reads_as_f1_never_false_strong_f2(gated_root):
    # HONEST LIMIT: a payload-discriminating WAF blocks the exploit's metacharacters while passing the benign
    # marker, over a still-vulnerable origin. The live control PASSES (marker reflected → param_live), the
    # exploit is silent (blocked) → REMEDIATED@F1. This is the residual the docs disclose: F1 cannot tell a
    # WAF-block from a fix. Crucially it is NEVER a falsely-strong REMEDIATED@F2 — an F2 verifier gets
    # INCONCLUSIVE (below), so no over-claim escapes.
    srv = _start(patched=False, reflect_param=True, waf_block=True)
    try:
        out, _ = _drive(_adapter(srv, payload_template=_F2_TEMPLATE),
                        policy=ProvePolicy(require_injectable_param_live=True))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.REMEDIATED and out.achieved_freshness == Freshness.F1_TARGET_ECHOES, out


def test_semantic_waf_under_f2_floor_is_inconclusive_no_overclaim(gated_root):
    srv = _start(patched=False, reflect_param=True, waf_block=True)
    try:
        out, _ = _drive(_adapter(srv, payload_template=_F2_TEMPLATE),
                        policy=ProvePolicy(minimum_freshness_level=Freshness.F2_PATH_TRAVERSED,
                                           require_injectable_param_live=True))
    finally:
        srv.shutdown(); srv.server_close()
    assert out.state == State.INCONCLUSIVE and out.reason_code == Reason.INSUFFICIENT_FRESHNESS


def test_payload_template_without_challenge_slot_is_refused_at_construction(gated_root):
    # fail-closed: a template that forgets the {challenge} slot would silently degrade to F1 while claiming F2.
    srv = _start(patched=True)
    try:
        with pytest.raises(ValueError, match="challenge"):
            _adapter(srv, payload_template="' OR 1=1-- -")
    finally:
        srv.shutdown(); srv.server_close()
