"""W0 — the `voice` capability latch enforced at the voice dispatch choke-point (`KernelDispatch.send`).

The latch gates ONLY the live voice channel (`voice_channel=True`); the shared cockpit `/api/ask` box and
the phone relay build a default `KernelDispatch()` and must keep working when voice is disabled.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_capability_voice.py -q
"""
import tempfile

from sigil.governor.capability import CapabilityGate
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.voice.dispatch import _VOICE_DISABLED_MSG, KernelDispatch

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _disable_voice(s):
    CapabilityGate(s, owner_key=OWNER, trusted_pubkey=OP).disable("voice")


def test_voice_channel_dispatch_refused_when_disabled():
    s = _store(); _disable_voice(s)
    # the voice-channel gate fires before any kernel/pin logic, so no kernel binary is needed.
    assert KernelDispatch(voice_channel=True, store=s).send("hello") == _VOICE_DISABLED_MSG


def test_default_channel_dispatch_is_not_gated_by_the_voice_latch():
    """The /api/ask box + phone relay use a default KernelDispatch() — disabling voice must NOT break them."""
    s = _store(); _disable_voice(s)
    assert KernelDispatch(store=s).send("hello") != _VOICE_DISABLED_MSG


def test_voice_channel_dispatch_proceeds_when_enabled():
    s = _store()   # voice enabled by default (no record)
    assert KernelDispatch(voice_channel=True, store=s).send("hello") != _VOICE_DISABLED_MSG
