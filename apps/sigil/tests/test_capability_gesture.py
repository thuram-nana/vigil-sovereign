"""W0 — the `gesture` capability latch enforced at every gesture choke-point.

Proves that disabling gesture control refuses injection at the keystone (`handle`), refuses a local owner
arm (`arm`), refuses a device arm (`arm_by_device`), and refuses to even start the live loop
(`run_gesture`) — and that an owner-signed re-enable resumes injection. The checks are ADDITIVE (beside the
kill-switch), so the enabled path is unchanged (regression).

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_capability_gesture.py -q
"""
import tempfile
import time

import pytest

from sigil.agents.base import Tier
from sigil.gesture.components import RecordingInputBackend
from sigil.gesture.run import run_gesture
from sigil.gesture.session import SessionGate, sign_arm_request
from sigil.gesture.types import GestureIntent
from sigil.governor.capability import CapabilityGate
from sigil.mesh import authorize_device
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
DEV = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    def classify(self, tool):
        return Tier.A1 if tool.startswith("hid.pointer") else Tier.A2


def _gate(store, backend):
    return SessionGate(store, backend, classifier=FakeCls(), owner_key=OWNER, trusted_pubkey=OP)


def _disable(store):
    CapabilityGate(store, owner_key=OWNER, trusted_pubkey=OP).disable("gesture")


def _click():
    return GestureIntent(kind="click", dx=0.0, dy=0.0, arg=None)


def test_enabled_gesture_injects_normally():
    """Regression: with the capability enabled, an armed session injects an A1 click exactly as before."""
    s = _store(); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm(owner_key=OWNER)
    v = g.handle(_click())
    assert v["injected"] is True and ("click", "left") in b.calls


def test_disabled_gesture_neuters_handle_midsession():
    s = _store(); b = RecordingInputBackend(); g = _gate(s, b)
    g.arm(owner_key=OWNER)                       # armed while enabled
    _disable(s)                                  # owner disables gesture mid-session
    v = g.handle(_click())
    assert v["injected"] is False and "capability disabled" in v["reason"]
    assert b.calls == [], "nothing is injected once the capability is disabled"
    assert g.session is None, "the session is disarmed"


def test_disabled_gesture_refuses_local_arm():
    s = _store(); g = _gate(s, RecordingInputBackend())
    _disable(s)
    with pytest.raises(RuntimeError, match="capability disabled"):
        g.arm(owner_key=OWNER)
    assert g.session is None


def test_disabled_gesture_refuses_device_arm():
    s = _store(); g = _gate(s, RecordingInputBackend())
    authorize_device(s, "phone1", DEV.public_key_b64, OWNER)
    _disable(s)
    req = sign_arm_request(DEV, device_id="phone1", nonce=1, ts=time.time(), ttl_seconds=120.0)
    assert g.arm_by_device(req) is None, "a device arm is refused while gesture is disabled"
    refusals = [r for r in s.iter_records() if r.kind == "refusal"
                and r.payload.get("reason") == "gesture capability disabled"]
    assert refusals, "the refusal is recorded on the spine"


def test_disabled_gesture_refuses_loop_start():
    s = _store()
    _disable(s)
    assert run_gesture(store=s, trusted_pubkey=OP) == 0, "the loop refuses to start (0 frames, never armed)"
    refusals = [r for r in s.iter_records() if r.kind == "refusal"
                and r.payload.get("signal") == "gesture.refused"
                and "disabled" in (r.payload.get("reason") or "")]
    assert refusals, "the loop-start refusal is recorded"


def test_owner_signed_reenable_resumes_injection():
    s = _store(); b = RecordingInputBackend(); g = _gate(s, b)
    _disable(s)
    with pytest.raises(RuntimeError):
        g.arm(owner_key=OWNER)                   # refused while disabled
    CapabilityGate(s, owner_key=OWNER, trusted_pubkey=OP).enable("gesture")   # owner-signed re-enable
    g.arm(owner_key=OWNER)                        # now allowed
    v = g.handle(_click())
    assert v["injected"] is True and ("click", "left") in b.calls
