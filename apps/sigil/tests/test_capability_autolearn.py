"""K2 — the `autolearn` capability latch (activate/deactivate the Knowledge-Engine propose loop).

`autolearn` reuses the identical owner-signed, spine-backed CapabilityGate as gesture/voice: default
ENABLED, disable is the fail-safe (unsigned) direction, re-enable requires a valid OWNER signature. It is
deliberately NOT part of the "both" panic set, so registering it does not silently change the existing
gesture+voice control.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_capability_autolearn.py -q
"""

import tempfile

from sigil.governor import CAPABILITIES
from sigil.governor.capability import CapabilityGate
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import actions

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _gate(s, key=OWNER, pub=OP):
    return CapabilityGate(s, owner_key=key, trusted_pubkey=pub)


def test_autolearn_registered():
    assert "autolearn" in CAPABILITIES


def test_autolearn_default_enabled_disable_then_owner_signed_enable():
    s = _store()
    g = _gate(s)
    assert g.is_enabled("autolearn") is True            # default enabled (no record)
    g.disable("autolearn", reason="deactivate")
    assert g.is_enabled("autolearn") is False           # any disable takes effect (fail-safe)
    g.enable("autolearn", reason="activate")
    assert g.is_enabled("autolearn") is True            # owner-signed enable re-activates


def test_forged_enable_cannot_reactivate_autolearn():
    s = _store()
    _gate(s).disable("autolearn", reason="off")
    # an ENABLE signed by a non-owner key must NOT revive it (verify against the owner pubkey, fail-closed).
    CapabilityGate(s, owner_key=ATTACKER, trusted_pubkey=OP).enable("autolearn", reason="forged")
    assert _gate(s).is_enabled("autolearn") is False     # still disabled — the forged enable was ignored


def test_do_action_allowlist_and_both_excludes_autolearn(monkeypatch):
    import sigil.governor.identity as idmod
    monkeypatch.setattr(idmod, "ensure_owner_keypair", lambda: OWNER)   # no keyring/vault in the test

    assert {"enable_autolearn", "disable_autolearn"} <= actions.ACTIONS
    assert {"enable_autolearn", "disable_autolearn"} <= actions._CAP_ACTIONS

    s = _store()
    r = actions.do_action("enable_autolearn", {"reason": "on"}, store=s)
    assert r["capabilities"] == ["autolearn"]            # the explicit toggle targets only autolearn
    # "both" is the historical gesture+voice pair — registering autolearn must NOT sweep it in.
    rb = actions.do_action("disable_both", {"reason": "panic"}, store=s)
    assert rb["capabilities"] == ["gesture", "voice"] and "autolearn" not in rb["capabilities"]
