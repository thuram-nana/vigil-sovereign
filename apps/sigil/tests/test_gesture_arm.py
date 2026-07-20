"""SIGIL Phase 9 W2-K — device-signed REMOTE ARM of a gesture session (the deliberate, reviewed
trust-widening). Proves the full threat table: only an owner-authorized device can arm; forged /
replayed / stale / after-revoke arms are refused; the TTL is clamped shorter than a local arm; a device
arm never displaces a live session; the owner's kill-switch/disarm always wins; and every downstream
bound (A1-inject / A2-queue) is UNCHANGED for a device-armed session.
Run: ~/.sigil/venv/bin/python tests/test_gesture_arm.py"""
import tempfile
import time

from sigil.agents.base import Tier
from sigil.bridge.daemon import BridgeDaemon
from sigil.gesture.components import RecordingInputBackend
from sigil.gesture.session import (MAX_DEVICE_TTL, SESSION_ARMED, SessionGate, arm_request_message,
                                    pending_device_arms, sign_arm_request)
from sigil.gesture.types import GestureIntent
from sigil.mesh import authorize_device, revoke_device
from sigil.reuse import generate_keypair, verify_one
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
DEV = generate_keypair()          # a phone the owner will authorize
ATTACKER = generate_keypair()     # a device the owner NEVER authorized


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    """hid.pointer.* → A1 (inject in-session); hid.type/combo/launch → A2 (queue). No kernel subprocess."""
    def classify(self, tool):
        return Tier.A1 if tool.startswith("hid.pointer") else Tier.A2


def _gate(store, backend=None):
    return SessionGate(store, backend or RecordingInputBackend(), classifier=FakeCls(), trusted_pubkey=OP)


def _authorize(store, kp=DEV, device_id="phone1"):
    authorize_device(store, device_id, kp.public_key_b64, OWNER)


def _req(kp=DEV, *, device_id="phone1", nonce=1, ts=None, ttl=120.0):
    return sign_arm_request(kp, device_id=device_id, nonce=nonce, ts=ts if ts is not None else time.time(), ttl_seconds=ttl)


def _record_arm(store, req):
    """Append an arm-request record DIRECTLY (as `submit_arm_request` does, but bypassing its record-time
    freshness gate) — to simulate a request that was recorded fresh and has since AGED past freshness by
    the time the gesture daemon consumes it."""
    core = {k: req.get(k) for k in ("device_id", "nonce", "ts", "ttl_seconds")}
    return store.append(kind="event", source="mesh", actor="DEVICE",
                        payload={"signal": "gesture.arm_request", **core, "pubkey": req["pubkey"],
                                 "sig": req["sig"], "tier": "A0", "decision": "auto"})


# ---- happy path + TTL clamp ----------------------------------------------------------------------
def test_authorized_device_arms_and_ttl_is_clamped():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    sess = g.arm_by_device(_req(nonce=1, ts=now, ttl=120.0), now=now)
    assert sess is not None and sess.live, "an authorized, fresh, signed request arms a session"
    assert abs(sess.expires_at - (now + 120.0)) < 1e-6, "ttl within MAX is honored"
    # a request over the cap clamps to MAX_DEVICE_TTL (a trust-narrowing inside the widening)
    s2 = _store(); _authorize(s2); g2 = _gate(s2)
    sess2 = g2.arm_by_device(_req(nonce=1, ts=now, ttl=99999.0), now=now)
    assert abs(sess2.expires_at - (now + MAX_DEVICE_TTL)) < 1e-6, f"ttl clamped to {MAX_DEVICE_TTL}"


# ---- the threat table (each refusal records a refusal + returns None + arms nothing) --------------
def test_forged_device_cannot_arm():
    s = _store(); _authorize(s)                    # DEV authorized, ATTACKER is not
    g = _gate(s)
    now = time.time()
    assert g.arm_by_device(_req(kp=ATTACKER, ts=now), now=now) is None, "an unauthorized device cannot arm"
    assert g.session is None
    assert any(r.payload.get("signal") == "gesture.arm_request" and r.payload.get("decision") == "refused"
               for r in s.iter_records()), "the refusal is recorded"


def test_tampered_signature_refused():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    req = _req(ts=now)
    req["ttl_seconds"] = 999.0                      # mutate a SIGNED field after signing → sig no longer matches
    assert g.arm_by_device(req, now=now) is None and g.session is None, "a tampered arm request is refused"


def test_replayed_arm_nonce_refused():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    req = _req(nonce=7, ts=now)
    assert g.arm_by_device(req, now=now) is not None, "first arm with nonce 7 succeeds"
    g.disarm()
    assert g.arm_by_device(req, now=now) is None, "re-submitting the SAME (device,nonce) is refused (replay)"


def test_stale_arm_refused():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    assert g.arm_by_device(_req(ts=now - 100.0), now=now) is None, "a stale (old-ts) arm request is refused"


def test_arm_after_revoke_refused():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    assert g.arm_by_device(_req(nonce=1, ts=now), now=now) is not None, "authorized device arms"
    g.disarm()
    revoke_device(s, "phone1", DEV.public_key_b64, OWNER)
    assert g.arm_by_device(_req(nonce=2, ts=now), now=now) is None, "a REVOKED device can no longer arm"


def test_killswitch_blocks_arm():
    s = _store(); _authorize(s); g = _gate(s)
    BridgeDaemon(s, trusted_pubkey=OP).panic_engage(by="test")     # owner/phone panic
    now = time.time()
    assert g.arm_by_device(_req(ts=now), now=now) is None, "no arm while the kill-switch is engaged"


def test_single_session_not_displaced_by_device_arm():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    assert g.arm_by_device(_req(nonce=1, ts=now), now=now) is not None, "first arm succeeds"
    assert g.arm_by_device(_req(nonce=2, ts=now), now=now) is None, "a device arm never displaces a live session"


# ---- owner always wins + downstream bounds unchanged ---------------------------------------------
def test_owner_disarm_beats_a_device_armed_session():
    s = _store(); _authorize(s); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm_by_device(_req(ts=time.time()), now=time.time())
    g.disarm()
    v = g.handle(GestureIntent("move", dx=0.5, dy=0.5))
    assert not v["injected"] and b.calls == [], "after owner disarm, a device-armed session injects nothing"


def test_killswitch_neuters_a_device_armed_session_mid_flight():
    s = _store(); _authorize(s); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm_by_device(_req(ts=time.time()), now=time.time())
    BridgeDaemon(s, trusted_pubkey=OP).panic_engage(by="test")     # owner panic AFTER arming
    v = g.handle(GestureIntent("move", dx=0.5, dy=0.5))
    assert not v["injected"] and "kill-switch" in v["reason"], "an owner panic neuters injection mid-session"
    assert b.calls == [] and g.session is None, "the session is disarmed on the kill-switch"


def test_device_armed_session_still_bounds_to_a1_and_queues_type():
    s = _store(); _authorize(s); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm_by_device(_req(ts=time.time()), now=time.time())
    mv = g.handle(GestureIntent("move", dx=0.5, dy=0.5))
    assert mv["injected"] and mv["tier"] == "A1", "a pointer move auto-injects (A1) in a device-armed session"
    ty = g.handle(GestureIntent("type", arg="secret"))
    assert not ty["injected"] and ty.get("queued") is not None, "type NEVER auto-injects — it QUEUES (A2), even device-armed"


# ---- the arm record is self-verifying + the daemon transport gate ---------------------------------
def test_arm_record_is_self_verifying_against_the_device_ledger():
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    g.arm_by_device(_req(nonce=42, ts=now, ttl=120.0), now=now)
    rec = next(r for r in s.iter_records()
               if r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device")
    p = rec.payload
    core = {"signal": "gesture.arm_request", "device_id": p["device_id"], "nonce": p["nonce"],
            "ts": p["ts"], "ttl_seconds": p["ttl_seconds"]}
    assert verify_one(p["device_pubkey"], arm_request_message(core), p["sig"]), \
        "the armed record's authorization re-verifies against the device signature (tamper-evident)"


def test_daemon_submit_arm_request_gates_on_authorization():
    s = _store(); _authorize(s)
    d = BridgeDaemon(s, trusted_pubkey=OP)
    now = time.time()
    seq = d.submit_arm_request(_req(ts=now))
    assert isinstance(seq, int), "an authorized, signed arm request is recorded"
    try:
        d.submit_arm_request(_req(kp=ATTACKER, ts=now))
        assert False, "an unauthorized device's arm request must be refused"
    except ValueError:
        pass
    bad = _req(ts=now); bad["sig"] = "AAAA"          # forged/garbage signature
    try:
        d.submit_arm_request(bad)
        assert False, "a bad signature must be refused"
    except ValueError:
        pass


# ---- review fixes: NaN safety-bound bypass, clamp-self-verify, end-to-end consumption --------------
def test_nan_ts_and_ttl_are_refused():                            # red-pen BLOCK-1
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    assert g.arm_by_device(sign_arm_request(DEV, device_id="phone1", nonce=1, ts=float("nan"), ttl_seconds=120.0), now=now) is None, \
        "a signed NaN ts is refused (freshness is fail-closed for non-finite input)"
    assert g.arm_by_device(sign_arm_request(DEV, device_id="phone1", nonce=2, ts=now, ttl_seconds=float("nan")), now=now) is None, \
        "a signed NaN ttl is refused (no never-expiring session)"
    assert g.arm_by_device(sign_arm_request(DEV, device_id="phone1", nonce=3, ts=now, ttl_seconds=float("inf")), now=now) is None, \
        "a signed +Inf ttl is refused"
    assert g.session is None, "no non-finite request ever arms"


def test_arm_record_self_verifies_even_when_ttl_is_clamped():     # red-pen BLOCK-2
    s = _store(); _authorize(s); g = _gate(s)
    now = time.time()
    g.arm_by_device(_req(nonce=5, ts=now, ttl=99999.0), now=now)  # requested 99999 → clamped to MAX
    rec = next(r for r in s.iter_records()
               if r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device")
    p = rec.payload
    assert p["effective_ttl"] == MAX_DEVICE_TTL and p["ttl_seconds"] == 99999.0, \
        "the record keeps the ORIGINAL signed ttl AND the clamped effective ttl"
    core = {"signal": "gesture.arm_request", "device_id": p["device_id"], "nonce": p["nonce"],
            "ts": p["ts"], "ttl_seconds": p["ttl_seconds"]}
    assert verify_one(p["device_pubkey"], arm_request_message(core), p["sig"]), \
        "the armed record re-verifies against the device signature EVEN when the enforced TTL was clamped"


def test_recorded_arm_request_is_consumed_exactly_once():         # HIGH-3 consumption path
    s = _store(); _authorize(s)
    BridgeDaemon(s, trusted_pubkey=OP).submit_arm_request(_req(nonce=9, ts=time.time()))
    reqs = pending_device_arms(s, OP)
    assert len(reqs) == 1 and reqs[0]["pubkey"] == DEV.public_key_b64, "a recorded request is a pending candidate"
    g = _gate(s)
    assert g.arm_by_device(reqs[0], now=time.time()) is not None, "the daemon consumes it → armed"
    assert pending_device_arms(s, OP) == [], "once armed it is no longer pending (never double-consumed)"


def test_older_valid_arm_is_not_starved_by_a_newer_stale_one():   # re-check FINDING-4
    from sigil.gesture.components import ScriptedLandmarker
    from sigil.gesture.features import RuleClassifier
    from sigil.gesture.run import run_gesture
    from sigil.perception.camera_stream import ScriptedFrameSource
    s = _store(); _authorize(s)
    d = BridgeDaemon(s, trusted_pubkey=OP)
    now = time.time()
    d.submit_arm_request(_req(nonce=1, ts=now))              # R1: valid + fresh, recorded FIRST (older seq)
    _record_arm(s, _req(nonce=2, ts=now - 10_000))           # R2: aged/stale, recorded SECOND (newer seq)
    b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), trusted_pubkey=OP)
    run_gesture(store=s, source=ScriptedFrameSource([None] * 3), landmarker=ScriptedLandmarker([[]] * 3),
                classifier=RuleClassifier(), backend=b, gate=g, auto_arm=False, device_arm=True,
                trusted_pubkey=OP, max_frames=3)
    armed = [r.payload.get("nonce") for r in s.iter_records()
             if r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device"]
    assert 1 in armed, "the older VALID request arms — a newer STALE request does not shadow/starve it"


def test_run_gesture_device_arm_activates_from_a_recorded_request():   # HIGH-3 end-to-end
    from sigil.gesture.components import ScriptedLandmarker
    from sigil.gesture.features import RuleClassifier
    from sigil.gesture.run import run_gesture
    from sigil.perception.camera_stream import ScriptedFrameSource
    s = _store(); _authorize(s)
    BridgeDaemon(s, trusted_pubkey=OP).submit_arm_request(_req(nonce=1, ts=time.time()))
    b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), trusted_pubkey=OP)
    run_gesture(store=s, source=ScriptedFrameSource([None, None, None]),
                landmarker=ScriptedLandmarker([[], [], []]), classifier=RuleClassifier(),
                backend=b, gate=g, auto_arm=False, device_arm=True, trusted_pubkey=OP, max_frames=3)
    assert any(r.payload.get("signal") == SESSION_ARMED and r.payload.get("armed_by") == "device"
               for r in s.iter_records()), \
        "run_gesture(device_arm=True) consumed the recorded request and ARMED end-to-end (feature is not inert)"


def test_run_gesture_device_arm_does_not_respam_a_stale_request():   # fix-introduced-defect guard
    from sigil.gesture.components import ScriptedLandmarker
    from sigil.gesture.features import RuleClassifier
    from sigil.gesture.run import run_gesture
    from sigil.perception.camera_stream import ScriptedFrameSource
    s = _store(); _authorize(s)
    _record_arm(s, _req(nonce=1, ts=time.time() - 10_000))   # a recorded request that has AGED past freshness
    b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), trusted_pubkey=OP)
    run_gesture(store=s, source=ScriptedFrameSource([None] * 6), landmarker=ScriptedLandmarker([[]] * 6),
                classifier=RuleClassifier(), backend=b, gate=g, auto_arm=False, device_arm=True,
                trusted_pubkey=OP, max_frames=6)
    refusals = sum(1 for r in s.iter_records()
                   if r.payload.get("signal") == "gesture.arm_request" and r.payload.get("decision") == "refused")
    assert refusals <= 1, f"a stale recorded request is attempted at most ONCE (no per-frame refusal spam), got {refusals}"
    assert not any(r.payload.get("armed_by") == "device" for r in s.iter_records()), "the stale request never armed"


def test_killswitch_rescan_triggers_on_spine_growth():           # tightening #1 (panic latency)
    s = _store(); _authorize(s); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm_by_device(_req(ts=time.time()), now=time.time())
    now = time.time()
    assert g._killswitch_engaged(now) is False, "not engaged initially (fresh scan)"
    BridgeDaemon(s, trusted_pubkey=OP).panic_engage(by="test")   # a panic APPENDS → the spine file grows
    assert g._killswitch_engaged(now + 1.0) is True, \
        "spine growth (a panic append) invalidates the cache → the halt is detected on the next frame, not after a fixed TTL"


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
    print(f"{passed}/{len(fns)} Phase-9 W2-K (device-signed remote arm) guarantees hold")
