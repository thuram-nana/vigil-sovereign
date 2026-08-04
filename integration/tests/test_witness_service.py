"""TRUTHENOVATION A3 — the DEPLOYABLE witness co-sign SERVICE, offline + deterministic.

Proves the co-sign TRANSPORT that was deferred (``apps/sigil/spine/witness.py:37-39``): N independently-keyed
witness PROCESSES co-sign a real checkpoint series over a real loopback socket, and a third party can run one.
It asserts:

  * HAPPY PATH — 3 witnesses, each its OWN key + injected clock, behind loopback HTTP servers; the submit
    client fans a REAL append-only checkpoint SERIES (cp0→cp1→cp2) at each of them; a strict-majority 2-of-3
    quorum co-signs and :func:`verify_timed_witnessed` passes with a no-later-than bound (the median clock).
  * THE MONEY TEST (anti-equivocation) — after the quorum co-signs branch ``cp1``, a FORK / split-view
    ``cp1b`` (a divergent checkpoint extending the SAME prior cp0) is submitted; every witness that already
    co-signed cp1 REFUSES cp1b (409 ConsistencyError, surfaced in ``refusals``, never swallowed), so its
    signature is ABSENT and the quorum for the fork FAILS CLOSED. Equivocation is refused, not co-signed.
  * A THIRD PARTY CAN RUN ONE STANDALONE — a witness launched as a real ``python -m
    vigil_integration.witness_service serve`` subprocess co-signs over its loopback socket and the
    co-signature verifies. (Self-contained process; no in-repo wiring needed to run it.)
  * DETERMINISM — every ``observed_time`` is an INJECTED clock reading (in-process) or ``--fixed-time``
    (subprocess); nothing wallclock/rng enters the signed co-signature bytes, so T is exact.
  * SOVEREIGN-SAFE (FATAL-2) — importing the service with ``framework`` blocked still succeeds and loads
    ZERO ``framework`` modules; the witness never co-loads the offense engine.

Sovereign-safe by construction (vigil_core + stdlib only) → runs in BOTH CI legs; no ``importorskip``.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from urllib import error as _urlerror
from urllib import request as _urlrequest

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_integration.remediation.attestation_witness import verify_timed_witnessed
from vigil_integration.transparency import Checkpoint, checkpoint_hash
from vigil_integration.witness_service import (
    WitnessService,
    fetch_pubkey,
    load_or_create_witness_key,
    serve_witness,
    submit_checkpoint,
)

# Three independently-keyed witnesses + their injected clocks (w0<w1<w2 → the 3-quorum median is w1's 200).
_CLOCKS = {"w0": 100, "w1": 200, "w2": 300}


def _mk_cp(prev: Checkpoint | None, *, seq: int, count: int, head: str) -> Checkpoint:
    return Checkpoint(last_seq=seq, entry_count=count, head_hash=head, merkle_root=f"m-{head}",
                      prev_checkpoint_hash="" if prev is None else checkpoint_hash(prev))


@pytest.fixture
def witnesses():
    """Spin up 3 in-process loopback witness servers, each its own key + a fixed injected clock. Yields
    ``(endpoints, trust_root_2of3)`` and tears the servers down after."""
    servers, threads, endpoints, auths = [], [], [], []
    for kid, tval in _CLOCKS.items():
        kp = generate_keypair()
        svc = WitnessService(kid, kp, clock=lambda t=tval: t)      # INJECTED clock — deterministic observed_time
        srv = serve_witness("127.0.0.1", 0, svc)                   # ephemeral port on loopback
        th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        servers.append(srv)
        threads.append(th)
        endpoints.append(f"http://127.0.0.1:{srv.server_address[1]}")
        auths.append(AuthorizerKey(key_id=kid, name=kid, public_key_b64=kp.public_key_b64))
    tr = TrustRoot(threshold=2, authorizers=auths)                 # strict-majority 2-of-3 (split-view resistant)
    try:
        yield endpoints, tr
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


def test_quorum_cosigns_a_real_series_over_the_wire(witnesses):
    endpoints, tr = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    cp1 = _mk_cp(cp0, seq=3, count=4, head="h1")
    cp2 = _mk_cp(cp1, seq=5, count=6, head="h2")

    prev_T = None
    for cp in (cp0, cp1, cp2):
        res = submit_checkpoint(cp, endpoints)
        assert not res.refusals, res.refusals
        assert not res.errors, res.errors
        assert len(res.signatures) == 3                             # all three co-signed over the wire
        ok, T, reason = verify_timed_witnessed(cp, res.signatures, witness_trust_root=tr)
        assert ok, reason
        assert T == 200, reason                                     # median of {100,200,300} = w1's clock
        assert "no-later-than T=200" in reason
        prev_T = T
    assert prev_T == 200


def test_fork_is_refused_and_the_quorum_fails_closed(witnesses):
    """THE MONEY TEST: after the quorum co-signs cp1, a divergent cp1b (extends the same prior cp0) is
    submitted. Each witness already committed to cp1 REFUSES cp1b (anti-equivocation), so the fork gathers
    NO quorum and the verify fails closed. Equivocation is detected + refused, never co-signed."""
    endpoints, tr = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    cp1a = _mk_cp(cp0, seq=3, count=4, head="h1-A")                 # branch A
    cp1b = _mk_cp(cp0, seq=3, count=4, head="h1-B-FORK")            # branch B: SAME height + prior, different head

    # (1) branch A: the full quorum co-signs and verifies.
    ra = submit_checkpoint(cp1a, endpoints)
    assert len(ra.signatures) == 3 and not ra.refusals
    ok_a, T_a, _ = verify_timed_witnessed(cp1a, ra.signatures, witness_trust_root=tr)
    assert ok_a and T_a == 200

    # (2) branch B (the fork): every witness that co-signed A REFUSES it — surfaced as refusals, not errors.
    rb = submit_checkpoint(cp1b, endpoints)
    assert rb.signatures == [], "a witness co-signed a fork — anti-equivocation BROKEN"
    assert len(rb.refusals) == 3, rb.refusals
    for _ep, why in rb.refusals:
        assert "refuses to co-sign" in why and ("chain broken" in why or "different head" in why), why

    # (3) the fork's quorum FAILS CLOSED (no signatures gathered → quorum not met).
    ok_b, T_b, reason_b = verify_timed_witnessed(cp1b, rb.signatures, witness_trust_root=tr)
    assert not ok_b and T_b is None and "quorum not met" in reason_b


def test_exact_replay_of_the_tip_is_idempotent_not_a_fork(witnesses):
    """Re-submitting the EXACT head a witness just signed is not equivocation — it returns the same
    co-signature (same observed_time), so a client retry never trips the fork refusal."""
    endpoints, tr = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    first = submit_checkpoint(cp0, endpoints)
    second = submit_checkpoint(cp0, endpoints)
    assert not first.refusals and not second.refusals
    assert len(second.signatures) == 3
    a = {s.key_id: (s.observed_time, s.signature_b64) for s in first.signatures}
    b = {s.key_id: (s.observed_time, s.signature_b64) for s in second.signatures}
    assert a == b                                                   # byte-identical co-signatures on replay
    ok, T, _ = verify_timed_witnessed(cp0, second.signatures, witness_trust_root=tr)
    assert ok and T == 200


def test_a_third_party_can_run_a_witness_standalone(tmp_path):
    """A witness is a self-contained process: launch it as a real ``python -m
    vigil_integration.witness_service serve`` subprocess (its own key, --fixed-time for determinism), co-sign
    over its loopback socket, and verify the co-signature. This is the "a third party runs one" proof."""
    import socket

    # A free loopback port.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    keyfile = tmp_path / "third-party-witness.key"
    proc = subprocess.Popen(
        [sys.executable, "-m", "vigil_integration.witness_service", "serve",
         "--host", "127.0.0.1", "--port", str(port), "--key", str(keyfile),
         "--key-id", "third-party", "--fixed-time", "4242"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        endpoint = f"http://127.0.0.1:{port}"
        # Poll /health until the standalone process has bound the socket (fail if it never comes up).
        deadline = time.time() + 15.0
        up = False
        while time.time() < deadline:
            if proc.poll() is not None:
                raise AssertionError(f"witness subprocess exited early: {proc.communicate()[0]}")
            try:
                with _urlrequest.urlopen(endpoint + "/health", timeout=1.0) as r:
                    up = r.status == 200
                    break
            except (_urlerror.URLError, OSError):
                time.sleep(0.1)
        assert up, "standalone witness never came up on its loopback socket"

        kid, pub = fetch_pubkey(endpoint)
        assert kid == "third-party"
        tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id=kid, name=kid, public_key_b64=pub)])

        cp = _mk_cp(None, seq=1, count=1, head="standalone-head")
        res = submit_checkpoint(cp, [endpoint])
        assert not res.refusals and not res.errors and len(res.signatures) == 1
        ok, T, reason = verify_timed_witnessed(cp, res.signatures, witness_trust_root=tr)
        assert ok, reason
        assert T == 4242, reason                                    # the --fixed-time the standalone folded in
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_persistent_key_is_stable_across_restart(tmp_path):
    """A witness's key is PERSISTENT — the same public key + id every load, so a verifier's out-of-band
    roster stays valid across restarts. (A co-sign key is never freshly minted per request.)"""
    kf = tmp_path / "w.key"
    kid1, kp1 = load_or_create_witness_key(kf, key_id="w0")
    kid2, kp2 = load_or_create_witness_key(kf)
    assert kid1 == kid2 == "w0"
    assert kp1.public_key_b64 == kp2.public_key_b64
    assert kp1.private_key_b64 == kp2.private_key_b64


def test_public_bind_is_refused():
    """The witness never becomes a public listener — a public / unspecified bind fails closed (bind_ok)."""
    svc = WitnessService("w0", generate_keypair(), clock=lambda: 1)
    for bad in ("0.0.0.0", "8.8.8.8", "::"):
        with pytest.raises(ValueError, match="refusing to bind"):
            serve_witness(bad, 0, svc)


def test_service_is_sovereign_safe_with_framework_blocked():
    """FATAL-2: importing the witness service with ``framework`` import forcibly blocked still succeeds and
    pulls in ZERO ``framework`` modules — a witness process never co-loads the offense engine.

    Run in a CLEAN subprocess: a meta-path finder blocks any ``framework`` import; then import the service +
    submit client and assert its own ``sys.modules`` holds no ``framework``. (An in-process check would be
    polluted by sibling tests that legitimately load the offense engine into the shared interpreter.)"""
    probe = (
        "import sys\n"
        "class _Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'framework' or name.startswith('framework.'):\n"
        "            raise ImportError('framework blocked (FATAL-2 probe): ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n"
        "import vigil_integration.witness_service as ws\n"
        "assert hasattr(ws, 'WitnessService') and hasattr(ws, 'submit_checkpoint')\n"
        "bad = [m for m in sys.modules if m == 'framework' or m.startswith('framework.')]\n"
        "assert not bad, 'co-loaded framework: ' + repr(bad)\n"
        "print('SOVEREIGN-SAFE')\n"
    )
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert proc.returncode == 0, f"FATAL-2 probe failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    assert "SOVEREIGN-SAFE" in proc.stdout
