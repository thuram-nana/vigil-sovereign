"""SIGIL Phase 8 WS-F — SIGIL-HAND gesture control: debounced fail-safe FSM, invariant landmark
features, and THE KEYSTONE — injection only inside an owner-armed session, A2 actions queued (a
gesture can never type a password or launch an app). Run: ~/.sigil/venv/bin/python tests/test_gesture.py"""
import math
import tempfile
from pathlib import Path

from sigil.agents.base import Tier
from sigil.gesture import GesturePipeline, Session, SessionGate
from sigil.gesture.components import RecordingInputBackend, ScriptedGestures, ScriptedLandmarker
from sigil.gesture.features import RuleClassifier, invariant_features
from sigil.gesture.run import run_gesture
from sigil.gesture.types import GestureIntent, GestureReading, Hand
from sigil.perception.camera_stream import ScriptedFrameSource
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    """hid.pointer.* → A1 (inject); everything else → A2 (queue). Deterministic stand-in for the oracle."""
    def classify(self, tool):
        return Tier.A1 if tool.startswith("hid.pointer") else Tier.A2


# ---- F0 FSM: debounce + fail-safe ----------------------------------------------------------------
def test_fsm_requires_confirm_frames_and_is_failsafe_on_ambiguity():
    p = GesturePipeline(confirm_frames=3, margin_min=0.15, conf_min=0.6)
    hi = GestureReading("pinch", 0.9, margin=0.5)
    assert p.on_frame(hi) is None and p.on_frame(hi) is None, "one/two frames fire nothing (hysteresis)"
    fired = p.on_frame(hi)
    assert fired and fired.kind == "click", "3 consecutive confident pinches fire a click"
    # low margin → treated as neutral → nothing fires, streak resets
    p2 = GesturePipeline(confirm_frames=2, margin_min=0.2)
    p2.on_frame(GestureReading("pinch", 0.9, margin=0.5))
    assert p2.on_frame(GestureReading("pinch", 0.9, margin=0.05)) is None, "an ambiguous (low-margin) frame does nothing"


def test_fsm_hand_lost_disarms_and_point_moves():
    p = GesturePipeline(hand_lost_frames=2)
    assert p.on_frame(None) is None
    hl = p.on_frame(None)
    assert hl and hl.kind == "hand_lost", "sustained no-hand emits a disarm signal"
    p2 = GesturePipeline(deadzone=0.001)
    mv = p2.on_frame(GestureReading("point", 0.9, dx=0.5, dy=0.2, margin=0.4))
    assert mv and mv.kind == "move" and mv.dx == 0.5, "a point pose drives pointer movement"
    assert p2.on_frame(GestureReading("point", 0.9, dx=0.0, dy=0.0, margin=0.4)) is None, "sub-deadzone → no move"


# ---- F4 feature invariance -----------------------------------------------------------------------
def test_features_are_translation_scale_rotation_invariant():
    base = Hand(tuple((math.cos(i) * 0.1 + 0.5, math.sin(i) * 0.1 + 0.5, 0.0) for i in range(21)))
    f0 = invariant_features(base)
    translated = Hand(tuple((x + 0.3, y - 0.2, z) for x, y, z in base.landmarks))
    scaled = Hand(tuple((x * 2.0, y * 2.0, z) for x, y, z in base.landmarks))
    th, c, s = 0.7, math.cos(0.7), math.sin(0.7)
    rotated = Hand(tuple((x * c - y * s, x * s + y * c, z) for x, y, z in base.landmarks))
    for h, name in ((translated, "translate"), (scaled, "scale"), (rotated, "rotate")):
        f = invariant_features(h)
        assert max(abs(a - b) for a, b in zip(f0, f)) < 1e-6, f"features must be invariant to {name}"


def test_rule_classifier_reads_poses():
    fist = Hand(tuple((0.5, 0.5, 0) for _ in range(21)))            # all tips near wrist → fist
    assert RuleClassifier().classify([fist]).label in ("fist", "pinch")
    assert RuleClassifier().classify([]).label == "neutral", "no hand → neutral"


# ---- F6 THE KEYSTONE: armed session + tier gate --------------------------------------------------
def test_injection_only_inside_an_armed_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls())
    r = g.handle(GestureIntent("move", dx=3, dy=2))
    assert r["injected"] is False and "no armed session" in r["reason"] and not b.calls, "no session → NO injection"
    g.arm(owner_key=OWNER)
    r = g.handle(GestureIntent("move", dx=3, dy=2))
    assert r["injected"] is True and ("move", 3, 2) in b.calls, "A1 pointer move injects within the session"
    g.disarm()
    assert g.handle(GestureIntent("click"))["injected"] is False, "disarm stops injection"


def test_a2_gesture_actions_queue_never_inject():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls())
    g.arm(owner_key=OWNER)
    r = g.handle(GestureIntent("type", arg="my-password"))
    assert r["injected"] is False and "queued" in r, "a keystroke gesture QUEUES, never auto-injects"
    assert not any(c[0] == "type" for c in b.calls), "a gesture can NEVER type a password on its own"
    r2 = g.handle(GestureIntent("launch", arg="terminal"))
    assert r2["injected"] is False and "queued" in r2, "an app-launch gesture QUEUES for approval"
    # the queued record binds to the exact action + carries no injected effect
    queued = [x for x in s.iter_records() if x.payload.get("signal") == "gesture.action"]
    assert queued and queued[0].payload.get("action_token") and queued[0].payload["status"] == "awaiting-approval"


def test_hand_lost_intent_disarms_the_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls())
    g.arm(owner_key=OWNER)
    g.handle(GestureIntent("hand_lost"))
    assert g.session is None, "a hand-lost intent auto-disarms the session"
    assert g.handle(GestureIntent("move", dx=1, dy=1))["injected"] is False, "and injection then stops"


# ---- F2/F7 stream + end-to-end -------------------------------------------------------------------
def test_run_gesture_end_to_end_with_doubles():
    s = _store(); b = RecordingInputBackend()
    readings = [GestureReading("pinch", 0.9, margin=0.5)] * 3 + [GestureReading("point", 0.9, dx=0.4, dy=0.1, margin=0.4)]
    n = run_gesture(store=s, owner_key=OWNER, source=ScriptedFrameSource([None] * 4),
                    landmarker=ScriptedLandmarker([[]] * 4), classifier=ScriptedGestures(readings), backend=b,
                    gate=SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER),
                    pipeline=GesturePipeline(confirm_frames=3, deadzone=0.001))
    assert n == 4
    assert any(c[0] == "click" for c in b.calls), "3 pinch frames fired a click end-to-end"
    assert any(c[0] == "move" for c in b.calls), "the point pose moved the cursor"
    # the session was disarmed in the finally
    assert any(r.payload.get("signal") == "gesture.session_disarmed" for r in s.iter_records())


# ---- F5 capability flags -------------------------------------------------------------------------
def test_capability_advertises_hid_flags():
    from sigil.mesh import advertise_capability, capability_map
    s = _store()
    advertise_capability(s, {"host_id": "h", "os": "linux", "has_screen": True, "has_camera": True,
                             "has_gpu_vlm": False, "always_on": True,
                             "has_hid_inject": True, "has_camera_stream": True}, OWNER)
    m = capability_map(s, OP)
    assert m["h"]["has_hid_inject"] is True and m["h"]["has_camera_stream"] is True


# ---- F1 WARDEN input tables (real oracle) --------------------------------------------------------
def test_warden_input_tiers_and_danger_wins():
    from sigil.agents.kernel_classify import KernelClassifier
    k = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")
    if not k.exists():
        print("    (skip — kernel not built)")
        return
    kc = KernelClassifier(kernel_bin=str(k))
    assert kc.classify("hid.pointer.move") == Tier.A1 and kc.classify("hid.pointer.click") == Tier.A1
    assert kc.classify("hid.type") == Tier.A2 and kc.classify("hid.app.launch") == Tier.A2
    assert kc.classify("hid.pointer.delete") == Tier.A3, "danger token beats an input name"
    assert kc.classify("file.move") == Tier.A3 and kc.classify("data.type") == Tier.A3, "token-named tools unaffected"


# ---- red-pen negative controls (BLOCK-1/2/3/4) ---------------------------------------------------
def test_discrete_a1_injection_is_logged_but_moves_are_telemetry():   # BLOCK-1
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls()); g.arm(owner_key=OWNER)
    g.handle(GestureIntent("click"))
    logged = [r for r in s.iter_records() if r.payload.get("signal") == "gesture.action"
              and r.payload.get("tool") == "hid.pointer.click"]
    assert logged, "a discrete A1 click that actually injects is AUDITED on the spine"
    g.handle(GestureIntent("move", dx=1, dy=1))
    assert not [r for r in s.iter_records() if r.payload.get("tool") == "hid.pointer.move"], \
        "per-frame moves are telemetry (not per-frame spine records — no DoS)"


def test_session_ttl_bounds_injection():                              # BLOCK-2
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls())
    g.arm(owner_key=OWNER, ttl_seconds=0.0)                           # already expired
    r = g.handle(GestureIntent("click"))
    assert r["injected"] is False and "expired" in r["reason"], "an expired session refuses injection"
    assert g.session is None and not b.calls, "and auto-disarms — a session is bounded, never indefinite"


def test_arm_requires_the_owner_key():                                # BLOCK-3
    import sigil.governor.identity as ident
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls())
    orig = ident.owner_keypair
    ident.owner_keypair = lambda: None
    try:
        raised = False
        try:
            g.arm(owner_key=None)
        except RuntimeError:
            raised = True
        assert raised, "arming with NO owner key must raise (a session can't be armed without the owner identity)"
    finally:
        ident.owner_keypair = orig
    assert g.arm(owner_key=OWNER).live, "with the owner key it arms fine"


def test_session_gate_composes_with_the_real_oracle():                # BLOCK-4
    from sigil.agents.kernel_classify import KernelClassifier
    k = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")
    if not k.exists():
        print("    (skip — kernel not built)")
        return
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=KernelClassifier(kernel_bin=str(k)))   # the REAL WARDEN oracle
    g.arm(owner_key=OWNER)
    assert g.handle(GestureIntent("move", dx=1, dy=1))["injected"] is True, "real oracle: hid.pointer.move → A1 → inject"
    r = g.handle(GestureIntent("type", arg="my-secret-password"))
    assert r["injected"] is False and "queued" in r, "real oracle: hid.type → A2 → QUEUE (never inject)"
    assert not any(c[0] == "type" for c in b.calls), "the real composition never types on a gesture"


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
    print(f"{passed}/{len(fns)} Phase-8 WS-F (SIGIL-HAND gesture) guarantees hold")
