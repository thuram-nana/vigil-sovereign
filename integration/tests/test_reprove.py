"""TRUTHENOVATION A2 — the continuous RE-PROOF SERVICE, offline + deterministic.

Proves the operating property, not just the primitives: :func:`remediation.reprove.run_reprove` LOOPS a
cadence over a retained corpus and, each cycle, RE-PROVES the corpus against a real loopback target (a
genuine live re-drive — the ``error_signature`` oracle re-firing over fresh wire bytes), APPENDS a signed
four-state tick, and has an independent witness quorum time-co-sign the new head. It asserts:

  * EXACTLY N ticks appended for N cycles (one per corpus item per cycle);
  * ``verify_log`` passes end-to-end over the whole N-tick series (chain + head + per-tick re-verify);
  * every tick's head is WITNESSED (a strict-majority 2-of-3 quorum co-signature that verifies + a
    no-later-than bound), and the checkpoints are durably persisted;
  * the cadence ``sleep`` is INJECTED (no real time passes — it is called N-1 times with the interval);
  * DETERMINISM — two identical N-cycle runs (injected clock + deterministic nonces) produce identical
    chain head digests, so the signed tick math carries no wallclock/rng.

Reuses the exact loopback + governance fixtures the VF end-to-end capstone uses. Runs in the
framework-INCLUSIVE integration CI leg (the re-proof needs the real oracle re-fire + the REMEDIATED
embedded re-execute): ``PYTHONPATH=integration:engine/crucible:gateway``.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_integration.live.wiring import provision_authority  # noqa: E402
from vigil_integration.remediation import attestation_log as al  # noqa: E402
from vigil_integration.remediation.attestation_log import verify_log  # noqa: E402
from vigil_integration.remediation.attestation_witness import (  # noqa: E402
    verify_timed_witnessed_checkpoint,
)
from vigil_integration.remediation.live_adapter import LiveHttpAdapter  # noqa: E402
from vigil_integration.remediation.prove_driver import State  # noqa: E402
from vigil_integration.remediation.reprove import (  # noqa: E402
    ReproveConfig, build_live_prove_target, deterministic_nonce, load_witnessed, run_reprove,
)

from framework.v2.agents import HttpExecutor  # noqa: E402
from framework.v2.common import paths as _paths  # noqa: E402

ENG = "reprove-e2e"
NOW = 1_000
BUG = "error_based_sqli"
# Three INDEPENDENTLY-keyed witnesses → a strict-majority 2-of-3 (split-view-resistant) quorum.
W0, W1, W2 = generate_keypair(), generate_keypair(), generate_keypair()
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"


def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --- a genuine loopback target (stdlib only), always PATCHED so each re-proof is REMEDIATED --------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        nonce = (q.get(srv.nonce_param) or [""])[0]
        body = '{"results": [], "ok": true}\n'          # PATCHED build — the oracle stays silent
        if nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"   # freshness: echo the run challenge (F1)
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(nonce_param: str = "rc") -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.nonce_param = nonce_param  # type: ignore[attr-defined]
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
"""


@pytest.fixture()
def gated_root(tmp_path, monkeypatch):
    """A throwaway CRUCIBLE tree: the signed charter (so the executor scope gate admits 127.0.0.1), the
    kill-switch, and the provisioned authority all land under tmp_path (mirrors test_vf_end_to_end.py)."""
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


def _adapter_factory(base_url: str):
    def make():
        return LiveHttpAdapter(
            executor=_executor(base_url), base_url=base_url, endpoint_path="/search", param="q",
            payload="x' OR '1'='1", nonce_param="rc",
            original_firing_context=_error_context(_ORIG_SQL_ERROR), bug_class=BUG)
    return make


def _quorum() -> TrustRoot:
    return TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64),
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=W2.public_key_b64)])


def _config(*, log_dir, prov, base_url, wielder):
    signer_pubkeys = {prov.signers[0][0]: prov.keypair.public_key_b64}
    target = build_live_prove_target(
        finding_id="errsqli-1", engagement=ENG, prov=prov, scope_host="127.0.0.1",
        adapter_factory=_adapter_factory(base_url), wielder=wielder, bug_class=BUG)
    return ReproveConfig(
        log_dir=log_dir, engagement_slug=ENG, signers=prov.signers, trust_root=prov.trust_root,
        signer_pubkeys=signer_pubkeys, corpus=[target], witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")])


def test_reprove_service_appends_n_witnessed_ticks_verifies_and_is_deterministic(gated_root):
    N = 3
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    signer_pubkeys = {prov.signers[0][0]: prov.keypair.public_key_b64}
    trust_root = prov.trust_root
    wielder = generate_keypair()                 # ONE wielder reused so re-proofs are byte-reproducible
    log = gated_root / "attlog"

    srv = _start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}/"

        # ---- run N cycles with an INJECTED no-op sleep + injected clock + deterministic nonces ----------
        slept: list[float] = []
        cfg = _config(log_dir=log, prov=prov, base_url=base, wielder=wielder)
        res = run_reprove(cfg, cycles=N, interval=99.0, sleep=lambda s: slept.append(s),
                          clock=lambda: NOW, nonce_fn=deterministic_nonce)

        # (1) EXACTLY N ticks, each a REMEDIATED re-proof, seq 0..N-1.
        assert res.cycles_run == N
        assert len(res.ticks) == N
        assert [t.append.seq for t in res.ticks] == list(range(N))
        assert all(t.append.state == State.REMEDIATED for t in res.ticks)
        # the cadence sleep was INJECTED (no real time passed) and fired only BETWEEN cycles (N-1 times).
        assert slept == [99.0] * (N - 1)

        # (2) verify_log passes end-to-end over the whole N-tick series; drift labels are the re-proof story.
        ok, reason, series = verify_log(log, trust_root=trust_root, signer_pubkeys=signer_pubkeys)
        assert ok, reason
        assert len(series) == N
        assert [s.label for s in series] == [al.LABEL_PROVEN_FIXED] + [al.LABEL_STILL_PROVEN] * (N - 1)

        # (3) every tick's head is WITNESSED — a 2-of-3 strict-majority quorum co-signature that verifies,
        #     with a no-later-than T == the injected observed_time; and each is durably persisted.
        quorum = _quorum()
        persisted = load_witnessed(log)
        assert len(persisted) == N
        for t in res.ticks:
            assert t.witnessed is not None
            wok, T, wreason = verify_timed_witnessed_checkpoint(
                t.witnessed, witness_trust_root=quorum, min_distinct_signers=3)
            assert wok and T == NOW, wreason

        # (4) DETERMINISM — two identical N-cycle runs (same target, injected clock, deterministic nonces,
        #     the SAME reused wielder) produce identical chain head digests. Nothing wallclock/rng leaks
        #     into the signed tick math.
        def _digests(dirname: str) -> list[str]:
            d = gated_root / dirname
            cfg_d = _config(log_dir=d, prov=prov, base_url=base, wielder=wielder)
            r = run_reprove(cfg_d, cycles=N, interval=0.0, sleep=lambda _s: None,
                            clock=lambda: NOW, nonce_fn=deterministic_nonce)
            return [t.append.head.head_hash for t in r.ticks]

        d1, d2 = _digests("det1"), _digests("det2")
        assert d1 == d2
        assert len(d1) == N and len(set(d1)) == N        # N distinct heads (a growing chain), reproducible
    finally:
        srv.shutdown(); srv.server_close()


def test_reprove_once_appends_exactly_one_tick(gated_root):
    """The systemd oneshot path: cycles=1 appends exactly one witnessed tick and never sleeps."""
    prov = provision_authority(slug=ENG, scope=["127.0.0.1"])
    signer_pubkeys = {prov.signers[0][0]: prov.keypair.public_key_b64}
    wielder = generate_keypair()
    log = gated_root / "attlog-once"
    srv = _start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}/"
        slept: list[float] = []
        cfg = _config(log_dir=log, prov=prov, base_url=base, wielder=wielder)
        res = run_reprove(cfg, cycles=1, interval=99.0, sleep=lambda s: slept.append(s),
                          clock=lambda: NOW, nonce_fn=deterministic_nonce)
        assert res.cycles_run == 1 and len(res.ticks) == 1
        assert res.ticks[0].append.seq == 0 and res.ticks[0].append.state == State.REMEDIATED
        assert slept == []                                # --once never sleeps
        ok, reason, series = verify_log(log, trust_root=prov.trust_root, signer_pubkeys=signer_pubkeys)
        assert ok and len(series) == 1, reason
    finally:
        srv.shutdown(); srv.server_close()
