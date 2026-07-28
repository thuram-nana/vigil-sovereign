"""
S2 — voice → UI navigation (`voice.nav`): the NavResolver + the gated RoutingDispatch.

Doctrine under test:
  * a nav is emitted ONLY on an unambiguous screen match AND with the `voice` latch ON AND the kill-switch
    OFF — otherwise the utterance falls through to the KERNEL cognition path (a nav can never bypass the
    latch / kill-switch, and never hijacks a real question);
  * the emitted `sigil.nav` record is an A1 SIGNAL that injects nothing, and its payload is fully PLAINTEXT
    (no CONTENT_FIELDS → no vault dependency), so the cockpit HUD can read the screen_id;
  * the resolver is strict + fail-safe: 0/ambiguous matches → no nav; a missing manifest → no nav.
"""

from __future__ import annotations

import tempfile

import pytest

from sigil.spine.store import SpineStore
from sigil.voice.nav import NavResolver, RoutingDispatch, Screen


class _FakeDelegate:
    def __init__(self):
        self.calls: list = []

    def send(self, text: str) -> str:
        self.calls.append(text)
        return "COGNITION:" + (text or "")


class _RaisingStore:
    def append(self, **kw):
        raise RuntimeError("spine down")


_SCREENS = [
    Screen("settings", "Settings", ("settings", "config", "preferences")),
    Screen("findings", "Findings", ("findings", "results", "bugs")),
    Screen("apikeys", "API Keys", ("api keys", "keys", "credentials")),
]


def _rd(delegate=None, store=None, *, enabled=True, killed=False, screens=_SCREENS):
    rd = RoutingDispatch(delegate or _FakeDelegate(), store=store,
                         resolver=NavResolver(screens=list(screens)))
    rd._voice_enabled = lambda: enabled
    rd._killswitch_engaged = lambda: killed
    return rd


# ---- resolver: strict + fail-safe -------------------------------------------

@pytest.mark.parametrize("utterance,expected", [
    ("open settings", "settings"),
    ("go to findings", "findings"),
    ("show me the api keys", "apikeys"),
    ("settings", "settings"),
    ("navigate to the findings screen", "findings"),
    ("what is sql injection", None),          # a real question, not a nav
    ("open the moon", None),                  # unknown screen
    ("", None),
])
def test_resolver_matches_only_unambiguous_commands(utterance, expected):
    r = NavResolver(screens=list(_SCREENS))
    s = r.resolve(utterance)
    assert (s.id if s else None) == expected


def test_resolver_ambiguous_match_yields_no_nav():
    # two screens sharing the same synonym → ambiguous → None (never guesses)
    dup = [Screen("a", "A", ("dashboard",)), Screen("b", "B", ("dashboard",))]
    assert NavResolver(screens=dup).resolve("dashboard") is None


def test_resolver_missing_manifest_is_fail_safe(tmp_path):
    r = NavResolver(manifest_path=tmp_path / "does-not-exist.json")
    assert r.screen_ids == set() and r.resolve("open settings") is None


def test_resolver_loads_the_real_committed_manifest():
    r = NavResolver()   # default path → the committed system-map.json
    assert {"settings", "findings", "apikeys", "sessions"} <= r.screen_ids


# ---- RoutingDispatch: gated emit vs delegate --------------------------------

def test_nav_hit_emits_sigil_nav_and_confirms():
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d = _FakeDelegate()
    rd = _rd(d, store, enabled=True, killed=False)
    out = rd.send("open settings")
    assert out == "Opening Settings." and d.calls == []       # navigated, did NOT delegate
    # the emitted record is a plaintext A1 sigil.nav SIGNAL readable without a vault
    seq = _last_seq(store)
    assert seq is not None
    rec = store.get(seq)
    assert rec is not None
    pay = rec.payload
    assert pay["signal"] == "sigil.nav" and pay["screen_id"] == "settings" and pay["tier"] == "A1"


def test_latch_off_delegates_and_emits_no_nav():
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d = _FakeDelegate()
    rd = _rd(d, store, enabled=False, killed=False)
    assert rd.send("open settings") == "COGNITION:open settings"   # delegated to cognition
    assert d.calls == ["open settings"]
    assert _last_seq(store) is None                                # nothing appended (no nav)


def test_killswitch_delegates_and_emits_no_nav():
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    d = _FakeDelegate()
    rd = _rd(d, store, enabled=True, killed=True)
    assert rd.send("open settings") == "COGNITION:open settings"
    assert _last_seq(store) is None


def test_non_nav_utterance_delegates():
    d = _FakeDelegate()
    rd = _rd(d, _RaisingStore(), enabled=True, killed=False)   # store never touched (no nav)
    assert rd.send("what is xss") == "COGNITION:what is xss"


def test_emit_failure_falls_through_to_cognition():
    d = _FakeDelegate()
    rd = _rd(d, _RaisingStore(), enabled=True, killed=False)
    # a spine error on emit must NOT crash the voice loop — it delegates instead
    assert rd.send("open settings") == "COGNITION:open settings"


# ---- gates are fail-closed --------------------------------------------------

def test_gates_fail_closed_on_a_broken_store():
    rd = RoutingDispatch(_FakeDelegate(), store=object(), resolver=NavResolver(screens=list(_SCREENS)))
    assert rd._voice_enabled() is False        # cannot read the latch ⇒ disabled
    assert rd._killswitch_engaged() is True     # cannot read the kill-switch ⇒ engaged (no nav)


# -- helper: the last appended seq (or None) ----------------------------------

def _last_seq(store: SpineStore):
    seqs = [r.seq for r in store.iter_records(since_seq=-1)]
    return max(seqs) if seqs else None
