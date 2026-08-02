"""VF-3 (A) — the WHOLE Verifiable-Fact remediation lifecycle, end-to-end, in ONE test.

This is the capstone demonstration of the Verifiable-Fact program: it chains EVERY merged VF stage into a
single runnable lifecycle against a REAL loopback HTTP target and, at the end, hands every produced artifact
to the STANDALONE, VIGIL-free verifier (``docs/proof-carrying-finding/verify_vf.py``) and to a tamper matrix.
It composes the merged modules — it never re-implements or modifies them:

  * VF-1a.2 :class:`LiveHttpAdapter` re-drives the ORIGINAL exploit through CRUCIBLE's gated
    :class:`HttpExecutor` against a genuine stdlib ``ThreadingHTTPServer`` on 127.0.0.1 (real sockets, real
    HTTP, the real ``error_signature`` oracle re-firing over the freshly-captured bytes).
  * VF-1a :func:`prove_remediation` classifies each re-drive into the four states over that fresh evidence.
  * VF-1b :func:`append_tick` / :func:`verify_log` build a signed, hash-chained, anti-rollback monotonic
    series of re-proof ticks and derive the VISION drift vocabulary.
  * VF-1c :func:`witness_attestation_head` / :func:`verify_timed_witnessed_checkpoint` put a strict-majority,
    time-bounded INDEPENDENT witness quorum over the attestation head.
  * VF-1d ``verify_vf`` re-derives the ENTIRE lifecycle — prove-cert authenticity, the attestation series +
    drift, and the witnessed no-later-than bound — with ZERO VIGIL code, and REJECTS every tamper.

The world-first world this one test walks through, concretely:
  vulnerable → proven-fixed → still-proven, witnessed (no-later-than T), standalone-verified, every tamper
  rejected.

Runs in the framework-INCLUSIVE integration CI job (it needs the real oracle re-fire + the REMEDIATED
embedded re-execute): ``PYTHONPATH=integration:engine/crucible:gateway``.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from vigil_core import (  # noqa: E402
    AuthorizerKey, TrustRoot, generate_keypair, identity_digest, prove_wielder, sign_capability,
    sign_identity_attestation,
)
from vigil_integration.live.wiring import provision_authority  # noqa: E402
from vigil_integration.remediation import attestation_log as al  # noqa: E402
from vigil_integration.remediation.attestation_log import append_tick, verify_log  # noqa: E402
from vigil_integration.remediation.attestation_witness import (  # noqa: E402
    verify_timed_witnessed_checkpoint, witness_attestation_head,
)
from vigil_integration.remediation.live_adapter import LiveHttpAdapter  # noqa: E402
from vigil_integration.remediation.prove_driver import (  # noqa: E402
    Freshness, ProvePolicy, Reason, State, prove_remediation, verify_prove_certificate,
)

from framework.v2.agents import HttpExecutor  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402


# --- load the STANDALONE verifier BY FILE PATH. It lives under docs/ (not a package), and imports ONLY
#     stdlib + cryptography, so loading it in-process pulls in no VIGIL code. Importing by path is the
#     option the VF-1d spec calls out; the --prove-standalone subprocess (test_vf_differential.py) proves
#     the stronger property that no VIGIL module is even importable in a clean interpreter. ---
_PCF_DIR = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding"
_VERIFIER = _PCF_DIR / "verify_vf.py"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_vf_e2e", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()

ENG = "remediate-e2e"
NOW = 1_000
BUG = "error_based_sqli"
WIELDER = generate_keypair()
# Three INDEPENDENTLY-keyed witnesses → a strict-majority 2-of-3 (split-view-resistant) quorum.
W0, W1, W2 = generate_keypair(), generate_keypair(), generate_keypair()

# The RETAINED original firing bytes (the positive control): a real MySQL error-based-SQLi signature.
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"


def _error_context(body: bytes) -> dict:
    """Build the error_signature oracle_context the original oracle re-fires over — the SAME translator the
    adapter and the base RemediationCertificate use."""
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# A genuine loopback HTTP target (stdlib only — mirrors test_live_adapter.py). Toggled patched/vulnerable.
# --------------------------------------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the test output quiet
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler contract
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        exploit_present = any(v for v in q.get(srv.exploit_param, []))    # the injectable param carried a value
        nonce = (q.get(srv.nonce_param) or [""])[0]
        if (not srv.patched) and exploit_present:
            # the VULNERABLE build leaks a datastore parser error the error_signature oracle fires on.
            body = "HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '' at line 1\n"
        else:
            # the PATCHED build (or a benign request) answers cleanly — the oracle stays silent.
            body = '{"results": [], "ok": true}\n'
        if srv.echo_nonce and nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"                    # freshness: echo the run challenge
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(*, patched: bool, echo_nonce: bool = True,
           exploit_param: str = "q", nonce_param: str = "rc") -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = patched            # type: ignore[attr-defined]
    srv.echo_nonce = echo_nonce      # type: ignore[attr-defined]
    srv.exploit_param = exploit_param  # type: ignore[attr-defined]
    srv.nonce_param = nonce_param    # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------------------------------------
# hermetic CRUCIBLE paths — a signed charter so the HttpExecutor scope gate ADMITS loopback (127.0.0.1).
# --------------------------------------------------------------------------------------------------------
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
    """Point the framework path helpers at a throwaway tree: the signed charter (so the executor's scope gate
    admits 127.0.0.1), the kill-switch, per-target evidence, and the provisioned authority all land under
    tmp_path — hermetic, and independent of the cached CRUCIBLE_ROOT (mirrors test_live_adapter.py)."""
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


def _adapter(srv: _Server) -> LiveHttpAdapter:
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    return LiveHttpAdapter(
        executor=_executor(base), base_url=base, endpoint_path="/search", param="q",
        payload="x' OR '1'='1", nonce_param="rc",
        original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)


def _drive(adapter, prov, *, run_id, freshness_nonce, now=NOW, not_after=9_000, rate_limit=10):
    """Compose the owner-attested identity + capability + wielder proof (over the ONE provisioned governance
    keypair) and run the gated four-state flow. ``run_id`` / ``freshness_nonce`` vary per re-proof so each
    tick has a distinct digest (a realistic re-proof series over the SAME finding)."""
    owner = prov.keypair
    ident = sign_identity_attestation(owner, engagement=ENG, policy={"host": ["127.0.0.1"]}, not_after=9_000)
    cap = sign_capability(owner, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=not_after,
                          rate_limit=rate_limit, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wproof = prove_wielder(WIELDER, challenge="pop-1", capability=cap)
    return prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wproof,
        trusted_owner_pubkey=owner.public_key_b64, engagement=ENG, finding_id="errsqli-1",
        original_certificate_digest="sha256:orig", signers=prov.signers, now=now, run_id=run_id,
        pop_challenge="pop-1", freshness_nonce=freshness_nonce, policy=ProvePolicy())


def _append(log, cert, prov, trust_root, signer_pubkeys):
    return append_tick(log, cert, engagement_slug=ENG, signers=prov.signers,
                       trust_root=trust_root, signer_pubkeys=signer_pubkeys)


def _load_log(log: Path):
    """Load the persisted attestation artifacts as the plain dicts a third party would ship in a bundle."""
    ticks = [json.loads(x) for x in (log / al._TICKS_FILE).read_text(encoding="utf-8").splitlines()
             if x.strip()]
    head = json.loads((log / al._HEAD_FILE).read_text(encoding="utf-8"))
    floor = json.loads((log / al._HIGHWATER_FILE).read_text(encoding="utf-8"))
    return ticks, head, floor


# ========================================================================================================
# THE ONE end-to-end lifecycle test.
# ========================================================================================================
def test_vf_end_to_end_lifecycle_and_standalone_verification(gated_root):
    # ONE provisioned governance authority reused across EVERY re-proof so all ticks + the chain head are
    # signed by ONE key — append_tick admits, and verify_log re-verifies, every tick against ONE signer set.
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    owner = prov.keypair
    key_id = prov.signers[0][0]
    signer_pubkeys = {key_id: owner.public_key_b64}
    trust_root = prov.trust_root                       # threshold=1 over the owner key
    trust_root_d = trust_root.model_dump(mode="json")  # the standalone verifier takes the dict form
    log = gated_root / "attlog"
    print("\n===== VF-3 END-TO-END LIFECYCLE (real loopback target) =====")

    # ---- STAGE 1: server VULNERABLE → STILL_VULNERABLE (the "presence" proof) → append as tick 0 --------
    srv = _start(patched=False)
    try:
        out0 = _drive(_adapter(srv), prov, run_id="run-0", freshness_nonce="nonce-0")
    finally:
        srv.shutdown(); srv.server_close()
    assert out0.state == State.STILL_VULNERABLE and out0.reason_code == Reason.ORACLE_FIRED, out0
    ok, _ = verify_prove_certificate(out0.certificate, signer_pubkeys=signer_pubkeys)
    assert ok and out0.certificate["verdict"]["oracle_fired"] is True
    res0 = _append(log, out0.certificate, prov, trust_root, signer_pubkeys)
    assert res0.seq == 0 and res0.state == State.STILL_VULNERABLE
    print("  [1] VULNERABLE   -> STILL_VULNERABLE (oracle fired over fresh evidence); appended tick 0")

    # ---- STAGE 2: server PATCHED → REMEDIATED (live re-drive, oracle silent, cert verifies) → tick 1 ----
    srv = _start(patched=True)
    try:
        out1 = _drive(_adapter(srv), prov, run_id="run-1", freshness_nonce="nonce-1")
    finally:
        srv.shutdown(); srv.server_close()
    assert out1.state == State.REMEDIATED and out1.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS, out1
    # HONEST: a separate-param nonce echo establishes F1 (target responsive THIS run), NOT F2 (exploit-path
    # traversal). The adapter never claims more than it proves — the exact limit stated in TRUST-GRADIENT.md.
    assert out1.trials_valid == 3 and out1.achieved_freshness == Freshness.F1_TARGET_ECHOES
    ok, reason = verify_prove_certificate(out1.certificate, signer_pubkeys=signer_pubkeys)
    assert ok and "cross-bound" in reason, reason
    assert out1.certificate["evidence"]["embedded_remediation_cert"] is not None
    res1 = _append(log, out1.certificate, prov, trust_root, signer_pubkeys)
    assert res1.seq == 1 and res1.state == State.REMEDIATED
    print("  [2] PATCHED      -> REMEDIATED (live re-drive, oracle silent, F1, cert cross-bound); tick 1")

    # ---- STAGE 3: PATCHED again (another day / another re-proof) → REMEDIATED → append as tick 2 --------
    srv = _start(patched=True)
    try:
        out2 = _drive(_adapter(srv), prov, run_id="run-2", freshness_nonce="nonce-2")
    finally:
        srv.shutdown(); srv.server_close()
    assert out2.state == State.REMEDIATED and out2.reason_code == Reason.ORACLE_SILENT_ACROSS_TRIALS, out2
    res2 = _append(log, out2.certificate, prov, trust_root, signer_pubkeys)
    assert res2.seq == 2 and res2.state == State.REMEDIATED
    print("  [3] PATCHED      -> REMEDIATED (re-proved another day); appended tick 2")

    # ---- the anti-rollback attestation series: present → proven-fixed → still-proven -------------------
    ok, reason, series = verify_log(log, trust_root=trust_root, signer_pubkeys=signer_pubkeys)
    assert ok, reason
    assert [s.label for s in series] == [al.LABEL_PRESENT, al.LABEL_PROVEN_FIXED, al.LABEL_STILL_PROVEN]
    assert [s.state for s in series] == [State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED]
    print("      attestation series (VIGIL verify_log): " + " -> ".join(s.label for s in series))

    # ---- STAGE 4: witness the attestation HEAD with a strict-majority 2-of-3 quorum + observed_times ----
    quorum = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64),
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=W2.public_key_b64)])
    quorum_d = quorum.model_dump(mode="json")
    twc = witness_attestation_head(log, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                   observed_times=[1000, 2000, 3000])
    # Demand the FULL roster (min_distinct_signers=3) — the strong tier that blunts producer curation.
    wok, T, wreason = verify_timed_witnessed_checkpoint(twc, witness_trust_root=quorum, min_distinct_signers=3)
    assert wok and T == 2000, wreason          # (n//2)-th of sorted [1000,2000,3000] = the exact median
    print(f"  [4] WITNESSED    -> strict-majority 3-of-3 quorum; no-later-than T={T}")

    # ---- STAGE 5: hand ALL artifacts to the STANDALONE, VIGIL-free verifier, OOB-pinned trust roots -----
    ticks, head, floor = _load_log(log)
    wit_sig_dicts = [s.model_dump(mode="json") for s in twc.witness_signatures]
    bundle = {
        "prove_cert": out2.certificate,                              # a REMEDIATED prove-cert
        "attestation": {"ticks": ticks, "head": head, "floor": floor},
        "witnessed": {"checkpoint": twc.checkpoint, "witness_signatures": wit_sig_dicts},
    }
    # Out-of-band-pinned trust roots (exactly as an external party would obtain them independent of the bundle).
    pin = "sha256:" + VF.digest_payload(trust_root_d)
    wit_pin = "sha256:" + VF.digest_payload(quorum_d)
    sound, slog = VF.verify_bundle(
        bundle, signer_pubkeys=signer_pubkeys, trust_root=trust_root_d, witness_trust_root=quorum_d,
        pin=pin, witness_pin=wit_pin, min_distinct_signers=3)
    assert sound, "the standalone verifier must CONFIRM the whole lifecycle:\n" + "\n".join(slog)

    # …and each standalone layer independently, with the drift series re-derived with ZERO VIGIL code:
    s_ok, s_reason = VF.verify_prove_cert(out2.certificate, signer_pubkeys=signer_pubkeys)
    assert s_ok, s_reason
    s_ok, s_reason, s_series = VF.verify_attestation_series(
        ticks, head, floor, trust_root=trust_root_d, signer_pubkeys=signer_pubkeys)
    assert s_ok, s_reason
    assert [s["label"] for s in s_series] == [VF.LABEL_PRESENT, VF.LABEL_PROVEN_FIXED, VF.LABEL_STILL_PROVEN]
    s_ok, s_T, s_reason = VF.verify_timed_witnessed(
        twc.checkpoint, wit_sig_dicts, witness_trust_root=quorum_d, min_distinct_signers=3)
    assert s_ok and s_T == 2000, s_reason

    # ---- STAGE 6: TAMPER each layer in turn → the STANDALONE verifier REJECTS each --------------------
    # (a) prove-cert: flip the state without re-signing → the whole-cert signature no longer verifies.
    t_cert = copy.deepcopy(out2.certificate)
    t_cert["state"] = State.STILL_VULNERABLE
    assert VF.verify_prove_cert(t_cert, signer_pubkeys=signer_pubkeys)[0] is False
    # and the whole bundle flips to NOT SOUND.
    tampered_bundle = {**bundle, "prove_cert": t_cert}
    assert VF.verify_bundle(
        tampered_bundle, signer_pubkeys=signer_pubkeys, trust_root=trust_root_d, witness_trust_root=quorum_d,
        pin=pin, witness_pin=wit_pin, min_distinct_signers=3)[0] is False

    # (b) attestation: truncate a tick — drop the last tick while the head still commits all three, so the
    #     head↔chain binding (and, redundantly, the durable floor) rejects it.
    s_ok, _r, _s = VF.verify_attestation_series(
        ticks[:-1], head, floor, trust_root=trust_root_d, signer_pubkeys=signer_pubkeys)
    assert s_ok is False

    # (c) witness: drop a co-signature below the strict-majority quorum (present only 1 of the required 2).
    s_ok, s_T, _r = VF.verify_timed_witnessed(
        twc.checkpoint, wit_sig_dicts[:1], witness_trust_root=quorum_d)
    assert s_ok is False and s_T is None
