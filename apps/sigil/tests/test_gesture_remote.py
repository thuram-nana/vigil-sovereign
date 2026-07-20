"""SIGIL Phase 9 W2-I — phone-as-gesture-trackpad landmark stream. The phone runs its OWN on-device
landmark detection and streams tiny List[Hand] batches to the PC; the PC feeds them through the EXISTING
gesture pipeline, into a LOCAL owner-armed session ONLY. These tests prove: the remote path NEVER bypasses
Layer-1 (an unarmed session injects nothing); a `point` stream drives pointer `move` (A1) inside a local
owner-armed session; malformation decodes to an honest `[]`; and replayed/reordered/foreign-session batches
are dropped (no re-processing, no cross-session injection). A launch/type-class intent still QUEUES via the
same SessionGate (never auto-injects). Run: ~/.sigil/venv/bin/python tests/test_gesture_remote.py"""
import tempfile

from sigil.agents.base import Tier
from sigil.gesture.components import RecordingInputBackend
from sigil.gesture.features import RuleClassifier
from sigil.gesture.pipeline import GesturePipeline
from sigil.gesture.remote import (RemoteLandmarker, RemoteLandmarkSource, ScriptedRemoteSource,
                                  decode_hand_batch)
from sigil.gesture.run import run_gesture
from sigil.gesture.session import SessionGate
from sigil.gesture.types import GestureIntent, Hand
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    """hid.pointer.* → A1 (inject); everything else → A2 (queue). The oracle stand-in test_gesture.py uses."""
    def classify(self, tool):
        return Tier.A1 if tool.startswith("hid.pointer") else Tier.A2


# --- crafted landmark geometry the REAL RuleClassifier reads --------------------------------------
# A POINT pose: index extended (tip8 farther from wrist than pip6), all other fingers curled, thumb NOT
# near the index tip → RuleClassifier returns "point" (n==1, extended index, pinch False).
POINT_LM = [
    (0.50, 0.90, 0.0),                                       # 0  wrist
    (0.44, 0.82, 0.0), (0.40, 0.72, 0.0), (0.44, 0.76, 0.0), (0.48, 0.78, 0.0),   # 1-4  thumb (curled)
    (0.55, 0.60, 0.0), (0.55, 0.45, 0.0), (0.55, 0.35, 0.0), (0.55, 0.25, 0.0),   # 5-8  index (extended)
    (0.50, 0.60, 0.0), (0.50, 0.50, 0.0), (0.50, 0.58, 0.0), (0.50, 0.66, 0.0),   # 9-12 middle (curled)
    (0.45, 0.60, 0.0), (0.45, 0.50, 0.0), (0.45, 0.58, 0.0), (0.45, 0.66, 0.0),   # 13-16 ring (curled)
    (0.40, 0.60, 0.0), (0.40, 0.50, 0.0), (0.40, 0.58, 0.0), (0.40, 0.66, 0.0),   # 17-20 pinky (curled)
]
# A PINCH pose: all keypoints coincident → thumb-tip meets index-tip, no finger extended → "pinch".
PINCH_LM = [(0.5, 0.5, 0.0)] * 21


def _batch(session_id, seq, landmarks, *, ts=0.0, h="R", s=0.9):
    return {"t": "hand_batch", "session_id": session_id, "seq": seq, "ts": ts,
            "hands": [{"l": [list(p) for p in landmarks], "h": h, "s": s}]}


# =================================================================================================
# decode_hand_batch — strict validation, honest-empty on malformation
# =================================================================================================
def test_decode_hand_batch_valid_roundtrips_to_hands():
    hands = decode_hand_batch(_batch("S", 0, POINT_LM, h="L", s=0.8))
    assert len(hands) == 1 and isinstance(hands[0], Hand)
    assert len(hands[0].landmarks) == 21 and hands[0].landmarks[8] == (0.55, 0.25, 0.0)
    assert hands[0].handedness == "Left" and abs(hands[0].score - 0.8) < 1e-9
    # RuleClassifier reads the decoded geometry as a real "point" pose
    assert RuleClassifier().classify(hands).label == "point", "the crafted geometry classifies as point"


def test_decode_hand_batch_is_honest_empty_on_any_malformation():
    good = _batch("S", 0, POINT_LM)
    assert decode_hand_batch(good), "sanity: the well-formed batch decodes"
    bad_cases = {
        "not-a-dict": "nope",
        "wrong-type-tag": {**good, "t": "other"},
        "no-hands-key": {"t": "hand_batch", "session_id": "S", "seq": 0, "ts": 0.0},
        "too-many-hands": {**good, "hands": [good["hands"][0]] * 3},          # > 2 hands
        "20-landmarks": {**good, "hands": [{"l": [[0.5, 0.5, 0.0]] * 20, "h": "R", "s": 0.9}]},
        "22-landmarks": {**good, "hands": [{"l": [[0.5, 0.5, 0.0]] * 22, "h": "R", "s": 0.9}]},
        "landmark-not-triple": {**good, "hands": [{"l": [[0.5, 0.5]] + [[0.5, 0.5, 0.0]] * 20, "h": "R"}]},
        "non-numeric-coord": {**good, "hands": [{"l": [["x", 0.5, 0.0]] + [[0.5, 0.5, 0.0]] * 20, "h": "R"}]},
        "nan-coord": {**good, "hands": [{"l": [[float("nan"), 0.5, 0.0]] + [[0.5, 0.5, 0.0]] * 20, "h": "R"}]},
        "inf-coord": {**good, "hands": [{"l": [[float("inf"), 0.5, 0.0]] + [[0.5, 0.5, 0.0]] * 20, "h": "R"}]},
        "insane-coord": {**good, "hands": [{"l": [[999.0, 0.5, 0.0]] + [[0.5, 0.5, 0.0]] * 20, "h": "R"}]},
        "bad-handedness": {**good, "hands": [{"l": [list(p) for p in POINT_LM], "h": "Z", "s": 0.9}]},
        "score-out-of-range": {**good, "hands": [{"l": [list(p) for p in POINT_LM], "h": "R", "s": 5.0}]},
    }
    for name, obj in bad_cases.items():
        assert decode_hand_batch(obj) == [], f"malformed batch [{name}] must decode to honest []"


# =================================================================================================
# RemoteLandmarkSource — foreign-session / replay / reorder / freshness dropping
# =================================================================================================
def test_foreign_session_id_batches_are_dropped():
    sid = "S-live"
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch("S-attacker", 0, POINT_LM),   # foreign session → dropped
        _batch(sid, 0, POINT_LM),            # ours → accepted
        _batch("S-attacker", 1, POINT_LM),   # foreign session → dropped
    ]), session_id=sid)
    assert len(list(src.frames())) == 1, "only batches bound to the live session are yielded"


def test_replayed_and_reordered_seq_batches_are_dropped():
    sid = "S-live"
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch(sid, 0, POINT_LM),
        _batch(sid, 1, POINT_LM),
        _batch(sid, 1, POINT_LM),   # duplicate seq → dropped (replay)
        _batch(sid, 0, POINT_LM),   # older seq after a newer one → dropped (reorder/replay)
        _batch(sid, 2, POINT_LM),
    ]), session_id=sid)
    assert len(list(src.frames())) == 3, "seq 0,1,2 accepted; the duplicate/older seqs are dropped"


def test_stale_batch_outside_freshness_window_is_dropped():
    sid = "S-live"
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch(sid, 0, POINT_LM, ts=900.0),    # 100s old vs a 5s window → stale, dropped
        _batch(sid, 1, POINT_LM, ts=1000.0),   # fresh
    ]), session_id=sid, freshness_seconds=5.0, now=lambda: 1000.0)
    assert len(list(src.frames())) == 1, "a batch outside the freshness window is dropped"


# =================================================================================================
# RemoteLandmarker — on-box-honest, passes the Wave-1 egress gate
# =================================================================================================
def test_remote_landmarker_is_on_box_honest_and_passes_the_egress_gate():
    lm = RemoteLandmarker()
    assert lm.egresses is False and lm.source_kind == "remote_device_stream"
    hands = decode_hand_batch(_batch("S", 0, POINT_LM))
    assert lm.detect(hands) is hands, "detect returns the token's hands (the phone already inferred them)"
    assert lm.detect("not-a-list") == [], "honest-empty on a non-list token"
    # the loop's fail-closed egress gate refuses an EGRESSING model but PASSES this egresses=False one:
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)
    sid = g.arm(owner_key=OWNER).session_id
    src = RemoteLandmarkSource(ScriptedRemoteSource([_batch(sid, 0, POINT_LM)]), session_id=sid)
    n = run_gesture(store=s, owner_key=OWNER, source=src, landmarker=lm, classifier=RuleClassifier(),
                    backend=b, gate=g, pipeline=GesturePipeline(deadzone=0.0), auto_arm=False)
    assert n == 1, "the loop ran the RemoteLandmarker (not refused by the egress gate)"
    assert not any(r.payload.get("signal") == "gesture.refused" for r in s.iter_records()), \
        "a RemoteLandmarker (egresses=False) is NOT refused by the egress gate"


# =================================================================================================
# End-to-end: the KEYSTONE — remote stream cannot bypass the owner-armed session
# =================================================================================================
def test_remote_stream_into_an_UNARMED_session_injects_nothing():
    s = _store(); b = RecordingInputBackend()
    sid = "S-unarmed"
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)   # NOT armed
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch(sid, 0, POINT_LM), _batch(sid, 1, POINT_LM), _batch(sid, 2, POINT_LM),
    ]), session_id=sid)
    n = run_gesture(store=s, owner_key=OWNER, source=src, landmarker=RemoteLandmarker(),
                    classifier=RuleClassifier(), backend=b, gate=g,
                    pipeline=GesturePipeline(deadzone=0.0), auto_arm=False)
    assert n == 3, "the source delivered valid frames and the loop processed them"
    assert b.calls == [], "but with NO armed session the remote stream injects NOTHING (Layer-1 holds)"
    assert not any(r.payload.get("signal") == "gesture.session_armed" for r in s.iter_records()), \
        "auto_arm=False + an unarmed gate never arms a session"


def test_remote_point_stream_moves_in_a_LOCAL_owner_armed_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)
    sess = g.arm(owner_key=OWNER)                                  # owner arms LOCALLY at the PC
    sid = sess.session_id
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch(sid, 0, POINT_LM), _batch(sid, 1, POINT_LM), _batch(sid, 2, POINT_LM),
    ]), session_id=sid)
    n = run_gesture(store=s, owner_key=OWNER, source=src, landmarker=RemoteLandmarker(),
                    classifier=RuleClassifier(), backend=b, gate=g,
                    pipeline=GesturePipeline(deadzone=0.0), auto_arm=False)
    assert n == 3
    moves = [c for c in b.calls if c[0] == "move"]
    assert moves, "a point stream drives pointer MOVE (A1) injections inside the local owner-armed session"
    assert all(c[0] == "move" for c in b.calls), "a point stream only moves — no click/type/etc."
    # the session was disarmed in the finally (indicator cleared)
    assert any(r.payload.get("signal") == "gesture.session_disarmed" for r in s.iter_records())


def test_remote_pinch_stream_clicks_in_a_LOCAL_owner_armed_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)
    sess = g.arm(owner_key=OWNER)
    sid = sess.session_id
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch(sid, 0, PINCH_LM), _batch(sid, 1, PINCH_LM), _batch(sid, 2, PINCH_LM),
    ]), session_id=sid)
    run_gesture(store=s, owner_key=OWNER, source=src, landmarker=RemoteLandmarker(),
                classifier=RuleClassifier(), backend=b, gate=g,
                pipeline=GesturePipeline(confirm_frames=3, deadzone=0.0), auto_arm=False)
    assert any(c[0] == "click" for c in b.calls), "3 confirmed pinch batches fire a click (A1) end-to-end"


def test_malformed_remote_batch_injects_nothing_end_to_end():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)
    sess = g.arm(owner_key=OWNER)
    sid = sess.session_id
    # valid envelope (so the source reaches decode) but MALFORMED hands (20 landmarks) → decode [] → nothing
    malformed = {"t": "hand_batch", "session_id": sid, "seq": 0, "ts": 0.0,
                 "hands": [{"l": [[0.5, 0.5, 0.0]] * 20, "h": "R", "s": 0.9}]}
    src = RemoteLandmarkSource(ScriptedRemoteSource([malformed]), session_id=sid)
    n = run_gesture(store=s, owner_key=OWNER, source=src, landmarker=RemoteLandmarker(),
                    classifier=RuleClassifier(), backend=b, gate=g,
                    pipeline=GesturePipeline(deadzone=0.0), auto_arm=False)
    assert n == 1, "the envelope was valid so the loop ran once"
    assert b.calls == [], "a malformed batch decodes to [] → the pipeline emits nothing → no injection"


def test_foreign_session_batch_never_injects_in_an_armed_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), owner_key=OWNER)
    sess = g.arm(owner_key=OWNER)
    # the source is bound to the LIVE session, but every inbound batch carries an ATTACKER session id
    src = RemoteLandmarkSource(ScriptedRemoteSource([
        _batch("S-attacker", 0, POINT_LM), _batch("S-attacker", 1, POINT_LM),
    ]), session_id=sess.session_id)
    n = run_gesture(store=s, owner_key=OWNER, source=src, landmarker=RemoteLandmarker(),
                    classifier=RuleClassifier(), backend=b, gate=g,
                    pipeline=GesturePipeline(deadzone=0.0), auto_arm=False)
    assert n == 0, "foreign-session batches are dropped by the source → no frames reach the pipeline"
    assert b.calls == [], "an attacker who guesses the pose but not the session id injects NOTHING"


def test_launch_class_intent_QUEUES_via_the_session_gate_never_auto_injects():
    # RuleClassifier only emits move/click, so a launch/type-class intent is exercised through the SAME
    # SessionGate the remote loop uses (reuses test_gesture.py's A2 assertion): it QUEUES, never injects.
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls()); g.arm(owner_key=OWNER)
    r = g.handle(GestureIntent("launch", arg="terminal"))
    assert r["injected"] is False and "queued" in r, "a launch-class gesture QUEUES for approval"
    r2 = g.handle(GestureIntent("type", arg="my-password"))
    assert r2["injected"] is False and "queued" in r2, "a keystroke-class gesture QUEUES for approval"
    assert not any(c[0] in ("type", "combo") for c in b.calls), \
        "a remote gesture can NEVER type a password or launch an app on its own"
    queued = [x for x in s.iter_records() if x.payload.get("signal") == "gesture.action"
              and x.payload.get("status") == "awaiting-approval"]
    assert queued and queued[0].payload.get("action_token"), "the queued action binds to an approval token"


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
    print(f"{passed}/{len(fns)} Phase-9 W2-I (remote gesture landmark stream) guarantees hold")
