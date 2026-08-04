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

import http.client
import json
import socket
import subprocess
import sys
import threading
import time
from urllib import error as _urlerror
from urllib import request as _urlrequest

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair, sign
from vigil_integration.remediation.attestation_witness import verify_timed_witnessed
from vigil_integration.transparency import Checkpoint, checkpoint_hash
from vigil_integration.witness_service import (
    WitnessService,
    fetch_pubkey,
    load_or_create_witness_key,
    producer_sign,
    producer_signing_bytes,
    serve_witness,
    submit_checkpoint,
)

# Three independently-keyed witnesses + their injected clocks (w0<w1<w2 → the 3-quorum median is w1's 200).
_CLOCKS = {"w0": 100, "w1": 200, "w2": 300}

# A single trusted PRODUCER shared across the witness fixture: its PUBLIC key is pinned on every witness,
# its PRIVATE key authorises each submission. (In a real deploy this is the attestation-log producer.)
_PRODUCER = generate_keypair()


def _mk_cp(prev: Checkpoint | None, *, seq: int, count: int, head: str) -> Checkpoint:
    return Checkpoint(last_seq=seq, entry_count=count, head_hash=head, merkle_root=f"m-{head}",
                      prev_checkpoint_hash="" if prev is None else checkpoint_hash(prev))


@pytest.fixture
def witnesses():
    """Spin up 3 in-process loopback witness servers, each its own key + a fixed injected clock, all pinning
    the shared ``_PRODUCER`` public key. Yields ``(endpoints, trust_root_2of3, producer_keypair)`` and tears
    the servers down after."""
    servers, threads, endpoints, auths = [], [], [], []
    for kid, tval in _CLOCKS.items():
        kp = generate_keypair()
        svc = WitnessService(kid, kp, producer_pubkeys=[_PRODUCER.public_key_b64],
                             clock=lambda t=tval: t)               # INJECTED clock — deterministic observed_time
        srv = serve_witness("127.0.0.1", 0, svc)                   # ephemeral port on loopback
        th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        servers.append(srv)
        threads.append(th)
        endpoints.append(f"http://127.0.0.1:{srv.server_address[1]}")
        auths.append(AuthorizerKey(key_id=kid, name=kid, public_key_b64=kp.public_key_b64))
    tr = TrustRoot(threshold=2, authorizers=auths)                 # strict-majority 2-of-3 (split-view resistant)
    try:
        yield endpoints, tr, _PRODUCER
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def one_witness():
    """A single loopback witness pinning ``_PRODUCER``, with a SHORT read timeout (for the slow-loris test).
    Yields ``(host, port, service, producer_keypair)`` and tears the server down after."""
    kp = generate_keypair()
    svc = WitnessService("w-solo", kp, producer_pubkeys=[_PRODUCER.public_key_b64], clock=lambda: 1234)
    srv = serve_witness("127.0.0.1", 0, svc, read_timeout=1.0)
    th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    th.start()
    host, port = "127.0.0.1", srv.server_address[1]
    try:
        yield host, port, svc, _PRODUCER
    finally:
        srv.shutdown()
        srv.server_close()


def _post_raw(host: str, port: int, body: bytes, headers: dict, *, path: str = "/cosign",
              timeout: float = 6.0) -> "tuple[int, bytes]":
    """Send a fully hand-crafted POST (so a test controls every header — Host, X-Requested-With, Origin,
    Content-Type) and return ``(status, body)``. Uses http.client so Host can be overridden precisely."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _good_headers(host: str, port: int) -> dict:
    return {"Host": f"{host}:{port}", "X-Requested-With": "vigil-witness-submit",
            "Content-Type": "application/json"}


def _signed_body(cp: Checkpoint, producer, *, scope: str = "") -> bytes:
    return json.dumps({"checkpoint": cp.to_dict(), "scope": scope,
                       "producer_sig_b64": producer_sign(cp, producer_keypair=producer, scope=scope)}).encode()


def test_quorum_cosigns_a_real_series_over_the_wire(witnesses):
    endpoints, tr, producer = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    cp1 = _mk_cp(cp0, seq=3, count=4, head="h1")
    cp2 = _mk_cp(cp1, seq=5, count=6, head="h2")

    prev_T = None
    for cp in (cp0, cp1, cp2):
        res = submit_checkpoint(cp, endpoints, producer_keypair=producer)
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
    endpoints, tr, producer = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    cp1a = _mk_cp(cp0, seq=3, count=4, head="h1-A")                 # branch A
    cp1b = _mk_cp(cp0, seq=3, count=4, head="h1-B-FORK")            # branch B: SAME height + prior, different head

    # (1) branch A: the full quorum co-signs and verifies.
    ra = submit_checkpoint(cp1a, endpoints, producer_keypair=producer)
    assert len(ra.signatures) == 3 and not ra.refusals
    ok_a, T_a, _ = verify_timed_witnessed(cp1a, ra.signatures, witness_trust_root=tr)
    assert ok_a and T_a == 200

    # (2) branch B (the fork): the SAME trusted producer signs the fork too (a compromised/equivocating
    #     producer) — it clears the producer-pin gate, so the ANTI-EQUIVOCATION consistency check is what
    #     must refuse it. Every witness that co-signed A REFUSES it — surfaced as refusals, not errors.
    rb = submit_checkpoint(cp1b, endpoints, producer_keypair=producer)
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
    endpoints, tr, producer = witnesses
    cp0 = _mk_cp(None, seq=1, count=2, head="h0")
    first = submit_checkpoint(cp0, endpoints, producer_keypair=producer)
    second = submit_checkpoint(cp0, endpoints, producer_keypair=producer)
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
    producer = generate_keypair()                                   # the producer this witness will pin
    proc = subprocess.Popen(
        [sys.executable, "-m", "vigil_integration.witness_service", "serve",
         "--host", "127.0.0.1", "--port", str(port), "--key", str(keyfile),
         "--key-id", "third-party", "--producer-pubkey", producer.public_key_b64,
         "--fixed-time", "4242"],
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
        res = submit_checkpoint(cp, [endpoint], producer_keypair=producer)
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
    svc = WitnessService("w0", generate_keypair(), producer_pubkeys=[_PRODUCER.public_key_b64],
                         clock=lambda: 1)
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


# --------------------------------------------------------------------------------------------------------
# FINDING 1 (Content-Length DoS) — bounded + timed body read
# --------------------------------------------------------------------------------------------------------
def test_oversized_content_length_is_rejected_413_before_reading(one_witness):
    """A Content-Length above the MAX_BODY cap is 413-rejected AT THE HEADER — the huge body is never read
    into memory (no memory-exhaustion), and the response is immediate (deterministic, no waiting)."""
    host, port, _svc, producer = one_witness
    huge = 10 * 1024 * 1024                                          # 10 MiB > 256 KiB cap
    conn = http.client.HTTPConnection(host, port, timeout=6.0)
    try:
        conn.putrequest("POST", "/cosign", skip_host=True, skip_accept_encoding=True)
        for k, v in _good_headers(host, port).items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(huge))
        conn.endheaders()
        conn.send(b"{}")                                            # only 2 bytes actually sent — never read
        t0 = time.time()
        resp = conn.getresponse()
        elapsed = time.time() - t0
        assert resp.status == 413, resp.status
        assert elapsed < 3.0, f"413 should be immediate, took {elapsed:.1f}s"
    finally:
        conn.close()


def test_slow_loris_body_does_not_hang_the_thread(one_witness):
    """A lying Content-Length (declare 100000, dribble 5 bytes, keep the socket open) must NOT hang the
    serving thread: the handler read timeout (1.0s here) fails it closed FAST instead of blocking forever."""
    host, port, _svc, _producer = one_witness
    raw = socket.create_connection((host, port), timeout=6.0)
    try:
        req = (f"POST /cosign HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"X-Requested-With: vigil-witness-submit\r\nContent-Type: application/json\r\n"
               f"Content-Length: 100000\r\n\r\n").encode()
        raw.sendall(req + b"12345")                                 # 5 of the promised 100000 body bytes
        raw.settimeout(6.0)                                         # generous ceiling; server times out at 1.0s
        t0 = time.time()
        data = raw.recv(4096)                                       # server should respond (408) or close, FAST
        elapsed = time.time() - t0
        # Either a 408 response arrives, or the peer closes (b"") — either way NOT a hang past the ceiling.
        assert elapsed < 5.0, f"slow-loris hung the thread for {elapsed:.1f}s"
        if data:
            assert b" 408 " in data or b" 400 " in data, data[:80]
    finally:
        raw.close()


# --------------------------------------------------------------------------------------------------------
# FINDING 2 — producer-pin (tip-poisoning) + anti-CSRF / DNS-rebind guard
# --------------------------------------------------------------------------------------------------------
def test_unpinned_witness_is_refused_at_construction():
    """Root fix: a witness with NO pinned producer key is refused at construction — an unpinned witness
    would co-sign an arbitrary caller's first checkpoint and let its tip be poisoned."""
    with pytest.raises(ValueError, match="pinned producer public key"):
        WitnessService("w0", generate_keypair(), producer_pubkeys=[], clock=lambda: 1)


def test_bogus_first_checkpoint_is_rejected_tip_not_poisoned(witnesses):
    """FINDING 2 (a): an UNAUTHENTICATED peer submits a bogus first checkpoint signed by an ATTACKER key
    (not the pinned producer). Every witness rejects it (403 producer_unauthorised) → the tip is NEVER
    advanced → the legit producer's real cp0 still gets its full quorum. Poisoning is impossible."""
    endpoints, tr, producer = witnesses
    attacker = generate_keypair()                                   # NOT pinned on any witness

    # (1) attacker's bogus first checkpoint (attacker-signed) — rejected at the door on every witness.
    bogus = _mk_cp(None, seq=99, count=99, head="ATTACKER-POISON")
    host_port = [(e.split("//", 1)[1].split(":")[0], int(e.rsplit(":", 1)[1])) for e in endpoints]
    for host, port in host_port:
        status, _b = _post_raw(host, port, _signed_body(bogus, attacker), _good_headers(host, port))
        assert status == 403, f"attacker checkpoint was NOT rejected: {status}"

    # (2) the legit producer's real cp0 now still gets the full quorum — the tip was never poisoned.
    cp0 = _mk_cp(None, seq=1, count=2, head="h0-legit")
    res = submit_checkpoint(cp0, endpoints, producer_keypair=producer)
    assert not res.refusals and not res.errors and len(res.signatures) == 3, (res.refusals, res.errors)
    ok, T, reason = verify_timed_witnessed(cp0, res.signatures, witness_trust_root=tr)
    assert ok and T == 200, reason


def test_anti_csrf_and_dns_rebind_guards(one_witness):
    """FINDING 2 (b): each of a missing custom header, a wrong Content-Type, a rebinding Host, and a
    cross-site Origin is 403-refused — even with a VALID producer signature in the body."""
    host, port, _svc, producer = one_witness
    cp = _mk_cp(None, seq=1, count=1, head="h0")
    body = _signed_body(cp, producer)

    # missing X-Requested-With (a cross-site simple form cannot set it)
    h = _good_headers(host, port); h.pop("X-Requested-With")
    assert _post_raw(host, port, body, h)[0] == 403

    # wrong Content-Type (never json.loads an arbitrary form body)
    h = _good_headers(host, port); h["Content-Type"] = "text/plain"
    assert _post_raw(host, port, body, h)[0] == 403

    # DNS-rebinding Host (a domain resolving to loopback carries its NAME in Host, not the resolved IP)
    h = _good_headers(host, port); h["Host"] = f"evil.example.com:{port}"
    assert _post_raw(host, port, body, h)[0] == 403

    # wrong-port Host (another local service's authority)
    h = _good_headers(host, port); h["Host"] = f"127.0.0.1:{port + 1}"
    assert _post_raw(host, port, body, h)[0] == 403

    # cross-site Origin (a modern browser sends it on every cross-origin POST)
    h = _good_headers(host, port); h["Origin"] = "https://evil.example.com"
    assert _post_raw(host, port, body, h)[0] == 403

    # control: all-correct headers + a valid producer sig → 200 (the guard does not over-block)
    assert _post_raw(host, port, body, _good_headers(host, port))[0] == 200


# --------------------------------------------------------------------------------------------------------
# FINDING 3 — scope is genuinely BOUND into the submission (the producer signs (checkpoint, scope))
# --------------------------------------------------------------------------------------------------------
def test_scope_is_bound_into_the_producer_signature(one_witness):
    """The producer signs ``(checkpoint, scope)``; a witness verifies that binding. A signature made over
    scope 'A' does NOT authorise a submission that claims scope 'B' — proving scope is genuinely bound, not
    silently ignored."""
    host, port, _svc, producer = one_witness
    cp = _mk_cp(None, seq=1, count=1, head="h0")

    # correct scope → co-signed
    assert _post_raw(host, port, _signed_body(cp, producer, scope="prod-A"),
                     _good_headers(host, port))[0] == 200

    # a body that claims scope 'B' but carries a signature over scope 'A' → producer verify fails → 403.
    sig_over_A = producer_sign(cp, producer_keypair=producer, scope="prod-A")
    tampered = json.dumps({"checkpoint": cp.to_dict(), "scope": "prod-B",
                           "producer_sig_b64": sig_over_A}).encode()
    assert _post_raw(host, port, tampered, _good_headers(host, port))[0] == 403


def test_producer_signing_bytes_are_domain_separated():
    """The producer submission domain is distinct from the witness co-sign domains — a producer signature
    can never be a valid witness co-signature (and vice-versa)."""
    cp = _mk_cp(None, seq=1, count=1, head="h0")
    pb = producer_signing_bytes(cp, "s")
    assert pb.startswith(b"vigil-witness-producer-submit-v1\x00")
    # a producer sig verifies as a producer sig...
    from vigil_core import verify_one
    sig = sign(_PRODUCER.private_key_b64, pb)
    assert verify_one(_PRODUCER.public_key_b64, pb, sig)
    # ...but NOT over the transparency (timeless witness) bytes for the same checkpoint.
    from vigil_integration.transparency import _signing_bytes as _wtns_bytes
    assert not verify_one(_PRODUCER.public_key_b64, _wtns_bytes(cp), sig)
