"""W0 — the governed per-capability latch (`sigil/governor/capability.py`) + its hard-prune fold.

Proves the kill-switch asymmetry keyed PER CAPABILITY: default ENABLED; ANY disable takes effect (even
unsigned/attacker — the SAFE direction); only an OWNER-SIGNED enable re-enables (fail-closed); a read
error resolves to DISABLED; per-capability + cross-signal domain separation; and the snapshot fold is
byte-identical to a genesis scan (identity / split / pubkey-dependence), like the kill-switch fold.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_capability_latch.py -q
"""
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.capability import SIGNAL, CapabilityGate
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _cg(store, *, owner_key=OWNER):
    return CapabilityGate(store, owner_key=owner_key, trusted_pubkey=OWNER_PUB)


def _raw(store, capability, state, *, key=None):
    """Append a governor.capability record signed by `key` (None = unsigned) — bypasses CapabilityGate so we
    can forge attacker/unsigned records."""
    core = {"signal": SIGNAL, "capability": capability, "state": state}
    payload = {**signed_payload(core, key), "tier": "A0", "decision": "auto"}
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def test_default_is_enabled_for_both_independently():
    s = _store()
    cg = _cg(s)
    assert cg.is_enabled("gesture") and cg.is_enabled("voice")
    cg.disable("gesture")
    assert not cg.is_enabled("gesture") and cg.is_enabled("voice"), "capabilities are independent keys"


def test_any_disable_is_honored_even_unsigned_or_attacker():
    s = _store()
    _raw(s, "gesture", "disabled", key=None)          # unsigned disable
    assert not _cg(s).is_enabled("gesture"), "an unsigned disable still takes effect (fail-safe)"
    s2 = _store()
    _raw(s2, "voice", "disabled", key=ATTACKER)       # attacker-signed disable
    assert not _cg(s2).is_enabled("voice"), "an attacker disable still takes effect (fail-safe)"


def test_enable_requires_an_owner_signature():
    s = _store()
    _cg(s).disable("gesture")
    _raw(s, "gesture", "enabled", key=None)           # unsigned enable — must NOT re-enable
    assert not _cg(s).is_enabled("gesture")
    _raw(s, "gesture", "enabled", key=ATTACKER)       # attacker enable — must NOT re-enable
    assert not _cg(s).is_enabled("gesture"), "a forged enable can never revive a disabled capability"
    _cg(s).enable("gesture")                          # owner-signed enable DOES re-enable
    assert _cg(s).is_enabled("gesture")


def test_domain_separation_capability_and_signal():
    s = _store()
    cg = _cg(s)
    cg.disable("gesture")
    cg.disable("voice")
    cg.enable("voice")                                # owner enable of VOICE
    assert cg.is_enabled("voice") and not cg.is_enabled("gesture"), \
        "an owner-signed enable(voice) must not re-enable gesture (capability is in the signed core)"
    # a kill-switch release (different signal + core) must not re-enable any capability
    from sigil.governor.killswitch import KillSwitch
    KillSwitch(s, owner_key=OWNER, trusted_pubkey=OWNER_PUB).release(reason="unrelated")
    assert not cg.is_enabled("gesture"), "a kill-switch release cannot re-enable a capability (domain-separated)"


def test_fail_closed_on_read_error(monkeypatch):
    # a COLD read (fresh store path ⇒ cold cache) whose scan raises must resolve to DISABLED.
    s = _store()
    cg = _cg(s)
    monkeypatch.setattr(type(s), "iter_records", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cg.is_enabled("gesture") is False, "a scan error resolves to DISABLED (fail-closed)"
    # a change_token error also fails closed (raises before any scan)
    s2 = _store()
    cg2 = _cg(s2)
    monkeypatch.setattr(type(s2), "change_token", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cg2.is_enabled("voice") is False


def test_toggle_round_trip_is_immediate():
    s = _store()
    cg = _cg(s)
    cg.disable("voice")
    assert not cg.is_enabled("voice")
    cg.enable("voice")
    assert cg.is_enabled("voice"), "the change-token cache invalidates on append — a re-enable is immediate"


def test_unknown_capability_is_rejected():
    s = _store()
    with pytest.raises(ValueError, match="unknown capability"):
        _cg(s).disable("keyboard")
    with pytest.raises(ValueError):
        _cg(s).is_enabled("camera")


# ---------------------------------------------------------------------------------------------------
# Hard-prune fold split-equivalence (mirrors test_snapshot_fold_killswitch.py).
# ---------------------------------------------------------------------------------------------------
def _seed_store():
    """A store whose FINAL verdict for `gesture` is decided in the PREFIX and not re-decided in the live
    window at the load-bearing split — so dropping the seed would flip the answer (no green-wash)."""
    s = _store()
    cg = _cg(s)
    s.append(kind="message", source="t", actor="u", payload={"text": "seed"})   # seq0 noise
    cg.enable("gesture")                              # seq1 owner enable -> enabled
    cg.disable("gesture")                             # seq2 disable -> disabled  <-- LAST real change
    s.append(kind="message", source="t", actor="u", payload={"text": "d"})      # seq3 noise
    _raw(s, "gesture", "enabled", key=ATTACKER)       # seq4 forged enable -> IGNORED
    return s


def _synthetic(store, K, *, trusted_pubkey=OWNER_PUB):
    prefix = [r for r in store.iter_records() if r.seq < K]
    return build(prefix, trusted_pubkey=trusted_pubkey, base_seq=K, snapshot_seq=K - 1)


def test_fold_identity_known_correct():
    s = _seed_store()
    assert _cg(s)._scan_enabled("gesture") is False, "the seq2 disable stands; a forged enable can't revive it"
    _cg(s).enable("gesture")                          # owner enable un-disables
    assert _cg(s)._scan_enabled("gesture") is True
    assert _cg(s).is_enabled("gesture") is True       # cache wrapper agrees


def test_fold_split_prefix_seed_is_load_bearing(monkeypatch):
    s = _seed_store()
    full = _cg(s)._scan_enabled("gesture")
    assert full is False, "the seq2 disable is the last real change -> disabled"
    K = 3                                             # prefix [0..2] fixes disabled; live [3..4] = noise + forged
    synthetic = _synthetic(s, K)
    assert dict(synthetic.capability_latch).get("gesture") is False, "the folded prefix latch is a NON-TRIVIAL False"
    live = [r for r in s.iter_records(since_seq=K - 1)]
    assert all(not (r.payload.get("signal") == SIGNAL and r.payload.get("state") == "disabled") for r in live), \
        "live window has no disable -> without the seed the fold would (wrongly) yield enabled"
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: synthetic))
    split = _cg(s)._scan_enabled("gesture")
    assert split == full is False, "fold(prefix) ∘ fold(live) must equal the full genesis scan"


def test_fold_foreign_pubkey_snapshot_is_bypassed(monkeypatch):
    s = _store()
    _cg(s).disable("gesture")                         # genesis truth: disabled
    assert _cg(s)._scan_enabled("gesture") is False
    other = generate_keypair().public_key_b64
    poisoned = SnapshotState(base_seq=99, capability_latch=[["gesture", True]], trusted_pubkey=other)
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store: poisoned))
    assert _cg(s)._scan_enabled("gesture") is False, \
        "a snapshot under a foreign anchor is bypassed; its (enabled) latch cannot re-enable the capability"
