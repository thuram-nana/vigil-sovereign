"""
S3 — gesture NAV-MODE (`gesture.navmode` + `SessionGate.handle`).

Doctrine under test:
  * nav-mode is OPT-IN (default OFF, latest-wins toggle);
  * while ON, a live owner-armed session's DISCRETE gestures NAVIGATE (an A1 `sigil.nav` SIGNAL) and inject
    NOTHING — the input backend is never called; swipe→next/prev, pinch→home;
  * nav-mode is byte-identical OFF (a swipe still scrolls, a pinch still clicks);
  * it changes ONLY the discrete nav-candidates — `move` still injects, `type`/`launch` still QUEUE (A2);
  * every per-frame gate still applies: no armed session / kill-switch → the nav gesture is refused and
    emits NOTHING.
"""

from __future__ import annotations

import tempfile
import time

from sigil.agents.base import Tier
from sigil.bridge.daemon import BridgeDaemon
from sigil.governor.capability import CapabilityGate
from sigil.gesture.components import RecordingInputBackend
from sigil.gesture.navmode import nav_mode_on, set_nav_mode
from sigil.gesture.session import SessionGate
from sigil.gesture.types import GestureIntent
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class FakeCls:
    def classify(self, tool):
        return Tier.A1 if tool.startswith("hid.pointer") else Tier.A2


def _armed(store, backend):
    g = SessionGate(store, backend, classifier=FakeCls(), trusted_pubkey=OP)
    g.arm(owner_key=OWNER)
    return g


def _nav_records(store):
    out = []
    for r in store.iter_records(since_seq=-1):
        pay = getattr(store.decrypted_or_raw(r), "payload", None) or {}
        if isinstance(pay, dict) and pay.get("signal") == "sigil.nav":
            out.append(pay)
    return out


# ---- default off + latest-wins toggle ---------------------------------------

def test_nav_mode_defaults_off_and_toggles_latest_wins():
    s = _store()
    assert nav_mode_on(s) is False                     # opt-in: off with no record
    set_nav_mode(s, True); assert nav_mode_on(s) is True
    set_nav_mode(s, False); assert nav_mode_on(s) is False


# ---- nav-mode OFF: byte-identical scroll/click ------------------------------

def test_off_a_swipe_still_scrolls_and_injects():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    v = g.handle(GestureIntent("scroll_right", dx=0.2))
    assert v["injected"] and v["tool"] == "hid.pointer.scroll"   # normal A1 scroll
    assert b.calls and _nav_records(s) == []                     # injected, no nav emitted


# ---- nav-mode ON: navigate + inject NOTHING ---------------------------------

def test_on_swipe_right_navigates_next_and_injects_nothing():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    v = g.handle(GestureIntent("scroll_right", dx=0.2))
    assert v["injected"] is False and v["nav"] == "next" and v["tool"] is None
    assert b.calls == []                                        # the OS was NOT touched
    navs = _nav_records(s)
    assert navs and navs[-1]["signal"] == "sigil.nav" and navs[-1]["nav"] == "next" and navs[-1]["tier"] == "A1"


def test_on_swipe_left_navigates_prev():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    v = g.handle(GestureIntent("scroll_left"))
    assert v["nav"] == "prev" and b.calls == []


def test_on_pinch_navigates_home_by_screen_id():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    v = g.handle(GestureIntent("click"))
    assert v["injected"] is False and b.calls == []
    assert _nav_records(s)[-1]["screen_id"] == "home"


def test_on_move_still_injects_and_type_still_queues():
    # nav-mode only remaps the discrete nav-candidates; pointer move + the A2 type gate are unchanged.
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    mv = g.handle(GestureIntent("move", dx=0.4, dy=0.4))
    assert mv["injected"] and mv["tier"] == "A1"                # move still injects
    ty = g.handle(GestureIntent("type", arg="secret"))
    assert ty["injected"] is False and ty.get("queued") is not None   # type STILL queues (A2), never nav


# ---- every per-frame gate still applies in nav-mode -------------------------

def test_nav_gesture_refused_without_an_armed_session():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), trusted_pubkey=OP)   # NOT armed
    set_nav_mode(s, True)
    v = g.handle(GestureIntent("scroll_right"))
    assert v["injected"] is False and "no armed session" in v["reason"]
    assert _nav_records(s) == [] and b.calls == []              # no nav emitted, nothing injected


def test_killswitch_refuses_a_nav_gesture():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    BridgeDaemon(s, trusted_pubkey=OP).panic_engage(by="test")
    v = g.handle(GestureIntent("scroll_right"))
    assert v["injected"] is False and "kill-switch" in v["reason"]
    assert _nav_records(s) == [] and b.calls == []


def test_disabled_gesture_capability_refuses_a_nav_gesture():
    s = _store(); b = RecordingInputBackend(); g = _armed(s, b)
    set_nav_mode(s, True)
    CapabilityGate(s, owner_key=OWNER, trusted_pubkey=OP).disable("gesture")   # owner turns gesture off
    v = g.handle(GestureIntent("scroll_right"))
    assert v["injected"] is False and "capability disabled" in v["reason"]
    assert _nav_records(s) == [] and b.calls == []


def test_expired_session_refuses_a_nav_gesture():
    s = _store(); b = RecordingInputBackend()
    g = SessionGate(s, b, classifier=FakeCls(), trusted_pubkey=OP)
    g.arm(owner_key=OWNER, ttl_seconds=0.01)
    set_nav_mode(s, True)
    time.sleep(0.05)                                                # let the bounded session expire
    v = g.handle(GestureIntent("scroll_right"))
    assert v["injected"] is False and "expired" in v["reason"]
    assert _nav_records(s) == [] and b.calls == []
