"""SIGIL Phase 9 W1-B — the WireGuard-bound bridge HTTP transport: the bind guard, the device-envelope
auth (per-request Ed25519 signature, no wire secret), the endpoint<->action binding, the timestamp
freshness window (injected deterministic clock), the effectful-nonce replay gate, the anti-rebind
Host/Origin gate, and the minimal-frame (no-subject/no-secret) invariant on the phone-facing surface.

Deterministic by construction: temp spines, port=0 (ephemeral), a FIXED clock, fixed nonces. The
phone path uses ONLY owner-authorized DEVICE keys — the owner trust-root is never needed to drive it.
Run: ~/.sigil/venv/bin/python tests/test_bridge_server.py"""
import base64
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.agents.approvals import _approval_message
from sigil.agents.base import Agent, Proposal, Tier
from sigil.bridge import BridgeDaemon
from sigil.bridge.envelope import build_core, sign_envelope
from sigil.bridge.server import build_server
from sigil.governor import Governor
from sigil.governor.killswitch import KillSwitch
from sigil.mesh import authorize_device
from sigil.reuse import canonical_json, generate_keypair, sign
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
NOW = 1_000_000.0                                  # the fixed "server clock" every test shares
CLOCK = lambda: NOW                                # noqa: E731 — injected so freshness is deterministic


# ---- an agent that queues an A2/A3 with a SECRET subject (mirrors test_mobile._Emitter) -----------
class _Emitter(Agent):
    name = "TESTER"
    ceiling = Tier.A2

    def __init__(self, store):
        super().__init__(store, governor=Governor(store, owner_key=OWNER, trusted_pubkey=OP))

    def run(self, tier, kind="draft"):
        return self._dispatch([Proposal(kind, {"subject": "TOP SECRET wire $1M"}, tier)])


# ---- harness --------------------------------------------------------------------------------------
def _spine():
    return tempfile.mktemp(suffix=".jsonl")


def _serve(spine_path):
    srv = build_server(addr="127.0.0.1", port=0, spine_path=spine_path, trusted_pubkey=OP, clock=CLOCK)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _authorize(spine_path):
    """Owner-side (desktop) setup: mint an authorized device key. Uses the OWNER key ONCE, here —
    never on the phone request path below."""
    dev = generate_keypair()
    authorize_device(SpineStore(spine_path), "phone-1", dev.public_key_b64, OWNER)
    return dev


def _env(device_key, action, args, nonce, ts=NOW):
    """The phone side: build + device-sign the envelope, encode it base64url-of-canonical-JSON for the
    wire. Touches ONLY the device key — no owner key."""
    core = build_core(device_key.public_key_b64, action, args, nonce, ts)
    payload = sign_envelope(device_key, core)
    raw = canonical_json(payload)
    raw = raw if isinstance(raw, bytes) else raw.encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _approval_body(device_key, target_seq, decision="approved", approver="phone"):
    """The phone's OWN device-signed `governor.approval` payload (what it POSTs to /api/action). Built
    with ONLY the device key — the server verifies, it does not sign."""
    msg = _approval_message(target_seq, decision, approver)
    return {"signal": "governor.approval", "approval": decision, "target_seq": target_seq,
            "approver": approver, "pubkey": device_key.public_key_b64,
            "sig": sign(device_key.private_key_b64, msg)}


def _get(port, path, *, env=None, headers=None):
    h = dict(headers or {})
    if env is not None:
        h["X-SIGIL-Envelope"] = env
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body_obj, *, env=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if env is not None:
        h["X-SIGIL-Envelope"] = env
    data = json.dumps(body_obj).encode() if body_obj is not None else b""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# ---- the bind guard (the exposure keystone) -------------------------------------------------------
def test_constructor_refuses_non_bind_ok_address():
    for bad in ("0.0.0.0", "::", "8.8.8.8", "1.2.3.4"):
        try:
            build_server(addr=bad, port=0, spine_path=_spine(), trusted_pubkey=OP, clock=CLOCK)
            assert False, f"binding {bad} (public/unspecified) must be refused"
        except ValueError:
            pass
    # a loopback / private (WireGuard) address is accepted
    srv = build_server(addr="127.0.0.1", port=0, spine_path=_spine(), trusted_pubkey=OP, clock=CLOCK)
    assert srv.server_address[0] == "127.0.0.1", "loopback binds fine"
    srv.server_close()


# ---- the device-approval phone path (/api/action) -------------------------------------------------
def test_authorized_device_action_clears_a_queued_a2():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)                     # queue an A2 with a secret subject
    srv, port = _serve(p)
    try:
        tgt = BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending()[0]["seq"]
        dev = _authorize(p)                                  # owner authorizes the device (desktop)
        code, body = _post(port, "/api/action", _approval_body(dev, tgt))
        assert code == 200 and json.loads(body)["ok"] is True, "an authorized device approval is accepted"
        assert not BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending(), "the A2 left the queue"
    finally:
        srv.shutdown()


def test_unauthorized_device_action_is_refused():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)
    srv, port = _serve(p)
    try:
        tgt = BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending()[0]["seq"]
        foreign = generate_keypair()                         # never authorized by the owner
        code, _ = _post(port, "/api/action", _approval_body(foreign, tgt))
        assert 400 <= code < 500, "a foreign/unauthorized device approval is refused (4xx)"
        assert BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending(), "the item is still queued"
    finally:
        srv.shutdown()


def test_no_owner_private_key_on_the_phone_path():
    # The phone approves using ONLY its device key; the server holds ONLY the owner PUBLIC key.
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A3)
    srv, port = _serve(p)
    try:
        tgt = BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending()[0]["seq"]
        dev = _authorize(p)
        code, _ = _post(port, "/api/action", _approval_body(dev, tgt))    # device key alone
        assert code == 200 and not BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending(), \
            "an owner-authorized device clears the queue with its key alone"
        assert srv.trusted_pubkey == OP, "the bridge trust anchor is the owner PUBLIC key"
        assert not hasattr(srv, "owner_key") and not hasattr(srv, "owner_keypair"), \
            "no owner PRIVATE key is ever held by the bridge"
    finally:
        srv.shutdown()


# ---- reads require a valid device envelope --------------------------------------------------------
def test_reads_require_a_valid_device_envelope():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)
    srv, port = _serve(p)
    try:
        assert _get(port, "/api/pending")[0] == 401, "no envelope → 401"
        foreign = generate_keypair()
        assert _get(port, "/api/pending", env=_env(foreign, "read:pending", {}, 1))[0] == 401, \
            "an unauthorized device's signed read → 401"
        dev = _authorize(p)
        code, body = _get(port, "/api/pending", env=_env(dev, "read:pending", {}, 1))
        assert code == 200, "an authorized device read → 200"
        assert "TOP SECRET" not in body and "subject" not in body, \
            "/api/pending carries only {seq,tier,kind} — no subject/secret over the tunnel"
        pend = json.loads(body)["pending"]
        assert pend and pend[0]["tier"] == "A2" and set(pend[0]) == {"seq", "tier", "kind"}
    finally:
        srv.shutdown()


def test_envelope_action_is_bound_to_the_endpoint():
    # a `read:pending` envelope must NOT be replayable against the more-sensitive `read:recall`.
    p = _spine()
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        code, _ = _get(port, "/api/recall?subject=x", env=_env(dev, "read:pending", {}, 1))
        assert code == 403, "an envelope scoped to one read cannot reach a different (more-sensitive) read"
        # the matching action is accepted
        code, _ = _get(port, "/api/recall?subject=x", env=_env(dev, "read:recall", {}, 1))
        assert code == 200, "the correctly-scoped read:recall envelope is accepted"
    finally:
        srv.shutdown()


def test_stale_timestamp_is_refused():
    p = _spine()
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        stale = _env(dev, "read:pending", {}, 1, ts=NOW - 10_000)     # far outside the ±120s window
        assert _get(port, "/api/pending", env=stale)[0] == 401, "a stale-timestamp request is refused"
        fresh = _env(dev, "read:pending", {}, 1, ts=NOW - 30)         # inside the window
        assert _get(port, "/api/pending", env=fresh)[0] == 200, "a fresh request is accepted"
    finally:
        srv.shutdown()


def test_record_endpoint_reverifies_provenance():
    p = _spine()
    SpineStore(p).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        code, body = _get(port, "/api/record/0", env=_env(dev, "read:record", {}, 1))
        d = json.loads(body)
        assert code == 200 and d["integrity_ok"] is True and d["entry_hash"], "an atom re-verifies live"
        code, body = _get(port, "/api/record/9999", env=_env(dev, "read:record", {}, 2))
        assert code == 404 and "not fabricated" in body, "an absent record is honest, not fabricated"
    finally:
        srv.shutdown()


# ---- the SSE stream carries only minimal frames ---------------------------------------------------
def test_sse_streams_minimal_frames_only():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)                     # queue an A2 with a secret subject
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        # without an envelope → 401 (not a stream)
        assert _stream_status(port, env=None) == 401, "SSE without a device envelope → 401"
        env = _env(dev, "read:stream", {}, 1)
        url = f"http://127.0.0.1:{port}/api/stream?since=-1&env={env}"
        with urllib.request.urlopen(url, timeout=5) as r:
            assert r.status == 200 and "event-stream" in r.headers.get("Content-Type", "")
            frame = None
            for _ in range(30):
                line = r.readline().decode()
                if line.startswith("data:"):
                    frame = line
                    break
        assert frame is not None, "a queued A2 produces a push frame"
        assert '"tier": "A2"' in frame, "the frame reports the tier"
        assert "subject" not in frame and "TOP SECRET" not in frame, \
            "the SSE frame carries only {seq,tier,kind} — never the subject/secret"
    finally:
        srv.shutdown()


def _stream_status(port, env):
    url = f"http://127.0.0.1:{port}/api/stream" + (f"?env={env}" if env else "")
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# ---- panic (effectful, fail-safe) -----------------------------------------------------------------
def test_panic_engages_the_kill_switch():
    p = _spine()
    srv, port = _serve(p)
    try:
        assert not KillSwitch(SpineStore(p), trusted_pubkey=OP).is_engaged(), "mesh starts live"
        dev = _authorize(p)
        code, body = _post(port, "/api/panic", None, env=_env(dev, "panic", {}, 1))
        assert code == 200 and json.loads(body)["ok"] is True, "an authorized panic is accepted"
        assert KillSwitch(SpineStore(p), trusted_pubkey=OP).is_engaged(), "panic engaged the kill-switch"
    finally:
        srv.shutdown()


# ---- relay (effectful) is strictly replay-resistant -----------------------------------------------
def test_replayed_relay_envelope_is_refused():
    # stub the KERNEL so relay doesn't spawn a real subprocess; we only care about the replay gate.
    import sigil.voice.dispatch as D
    _real = D.KernelDispatch
    D.KernelDispatch = lambda: type("_K", (), {"send": staticmethod(lambda text: f"kernel:{text}")})()
    p = _spine()
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        env1 = _env(dev, "relay", {"text": "status"}, nonce=1)
        assert _post(port, "/api/relay", None, env=env1)[0] == 200, "a fresh relay is accepted"
        # replay the EXACT same envelope (nonce=1, already receipted) → refused by the nonce gate
        assert _post(port, "/api/relay", None, env=env1)[0] == 409, "a replayed relay envelope is refused"
        # a strictly-fresher nonce is accepted again
        env2 = _env(dev, "relay", {"text": "status"}, nonce=2)
        assert _post(port, "/api/relay", None, env=env2)[0] == 200, "a fresher nonce is accepted"
    finally:
        D.KernelDispatch = _real
        srv.shutdown()


# ---- the anti-DNS-rebinding gate on the action plane ----------------------------------------------
def test_action_plane_refuses_rebinding_host_and_cross_origin():
    p = _spine()
    _Emitter(SpineStore(p)).run(Tier.A2)
    srv, port = _serve(p)
    try:
        tgt = BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending()[0]["seq"]
        dev = _authorize(p)
        body = _approval_body(dev, tgt)
        # (a) a rebinding Host → refused even WITH a valid device approval body
        assert _post(port, "/api/action", body, headers={"Host": "evil.example"})[0] == 403, \
            "a DNS-rebinding Host is refused"
        # (b) a cross-origin Origin → refused
        assert _post(port, "/api/action", body,
                     headers={"Origin": "http://evil.example", "Host": f"127.0.0.1:{port}"})[0] == 403, \
            "a cross-origin request is refused"
        # (c) a prefix-Origin must NOT pass exact-match
        assert _post(port, "/api/action", body,
                     headers={"Origin": f"http://127.0.0.1:{port}.evil.com", "Host": f"127.0.0.1:{port}"})[0] == 403, \
            "an Origin that merely shares the prefix is refused (exact match)"
        # (d) the same body over the allowed Host succeeds and clears the queue
        assert _post(port, "/api/action", body)[0] == 200, "the legitimate same-tunnel action succeeds"
        assert not BridgeDaemon(SpineStore(p), trusted_pubkey=OP).pending()
    finally:
        srv.shutdown()


def test_panic_plane_refuses_rebinding_host():
    p = _spine()
    srv, port = _serve(p)
    try:
        dev = _authorize(p)
        code, _ = _post(port, "/api/panic", None, env=_env(dev, "panic", {}, 1),
                        headers={"Host": "evil.example"})
        assert code == 403, "a rebinding Host is refused on the panic plane too"
        assert not KillSwitch(SpineStore(p), trusted_pubkey=OP).is_engaged(), "the refused panic had no effect"
    finally:
        srv.shutdown()


# ---- body cap -------------------------------------------------------------------------------------
def test_oversized_action_body_rejected():
    p = _spine()
    srv, port = _serve(p)
    try:
        big = {"signal": "governor.approval", "pad": "x" * 70000}
        code, _ = _post(port, "/api/action", big)
        assert code == 413, "an oversized body is rejected (no Content-Length hang / alloc)"
    finally:
        srv.shutdown()


# ---- the webapp is a later slice: serve gracefully ------------------------------------------------
def test_webapp_served_and_static_is_traversal_guarded():
    # the PWA landed in Wave 3, so / serves the installed index and /static/* serves its assets;
    # path traversal out of the webapp dir stays refused.
    p = _spine()
    srv, port = _serve(p)
    try:
        assert _get(port, "/")[0] == 200, "the installed PWA index is served at /"
        assert _get(port, "/static/app.js")[0] == 200, "webapp static assets are served"
        assert _get(port, "/static/../server.py")[0] == 404, "static serving is traversal-guarded (no path escape)"
        assert _get(port, "/static/../../etc/passwd")[0] == 404, "no traversal to arbitrary files"
    finally:
        srv.shutdown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-9 W1-B (WireGuard-bound bridge transport) guarantees hold")
