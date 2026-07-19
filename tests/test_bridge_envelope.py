"""SIGIL Phase 9 W1-A — the device-signed, replay-resistant request envelope (the bridge auth
keystone; NO wire bearer secret). Authentication IS an Ed25519 signature over the canonical envelope
core by an owner-AUTHORIZED device key; replay is a spine-anchored per-device monotonic-nonce highwater.
Run: ~/.sigil/venv/bin/python tests/test_bridge_envelope.py"""
import tempfile

from sigil.bridge import (ACTIONS, RECEIPT_SIGNAL, build_core, consume,
                          device_nonce_highwater, envelope_message, record_receipt,
                          sign_envelope, verify_envelope)
from sigil.mesh import authorize_device, authorized_devices, revoke_device
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _authorized_device(s):
    """Authorize a fresh device against OWNER; return (device_key, authorized_set)."""
    device = generate_keypair()
    authorize_device(s, "phone-1", device.public_key_b64, OWNER)
    return device, authorized_devices(s, OP)


# ---- parity contract: the exact signed bytes a future JS client MUST reproduce -------------------
def test_envelope_message_fixed_vector_parity():
    # canonical_json = sorted keys, compact separators, UTF-8. For this fixed core the bytes are EXACTLY:
    #   {"action":"read:snapshot","args":{},"device":"DEVKEYB64","nonce":1,"ts":1700000000,"v":1}
    core = build_core("DEVKEYB64", "read:snapshot", {}, 1, 1700000000)
    expected = b'{"action":"read:snapshot","args":{},"device":"DEVKEYB64","nonce":1,"ts":1700000000,"v":1}'
    assert envelope_message(core) == expected, "the parity contract byte string must not drift"
    assert isinstance(envelope_message(core), bytes), "envelope_message returns bytes"


# ---- a well-formed signed envelope from an authorized device verifies ----------------------------
def test_well_formed_authorized_envelope_verifies():
    s = _store()
    device, authorized = _authorized_device(s)
    core = build_core(device.public_key_b64, "read:snapshot", {}, 1, 1700000000)
    payload = sign_envelope(device, core)
    ok, out = verify_envelope(payload, authorized)
    assert ok is True and out == core, "an authorized, correctly-signed envelope verifies and returns the core"


# ---- a foreign / unauthorized key is refused (fail-closed) ---------------------------------------
def test_foreign_unauthorized_key_refused():
    s = _store()
    _authorized_device(s)                                       # some OTHER device is authorized
    authorized = authorized_devices(s, OP)
    foreign = generate_keypair()                               # this one is NOT authorized
    core = build_core(foreign.public_key_b64, "read:snapshot", {}, 1, 1700000000)
    payload = sign_envelope(foreign, core)
    ok, reason = verify_envelope(payload, authorized)
    assert ok is False and "authorized" in reason, "a foreign key (validly self-signed) is not trusted"


def test_missing_signature_or_device_refused():
    s = _store()
    device, authorized = _authorized_device(s)
    core = build_core(device.public_key_b64, "read:snapshot", {}, 1, 1700000000)
    assert verify_envelope(core, authorized)[0] is False, "no signature -> refused"
    signed = sign_envelope(device, core)
    no_dev = {k: v for k, v in signed.items() if k != "device"}
    assert verify_envelope(no_dev, authorized)[0] is False, "no device -> refused"


# ---- replay resistance: monotonic nonce highwater on effectful requests --------------------------
def test_consume_effectful_nonce_replay_resistance():
    s = _store()
    device, authorized = _authorized_device(s)

    def env(action, nonce):
        return sign_envelope(device, build_core(device.public_key_b64, action, {}, nonce, 1700000000 + nonce))

    # nonce=1 succeeds
    core1 = consume(s, env("relay", 1), authorized, effectful=True)
    assert core1["nonce"] == 1 and device_nonce_highwater(s, device.public_key_b64) == 1

    # a SECOND nonce=1 (a replay) is refused
    try:
        consume(s, env("relay", 1), authorized, effectful=True)
        assert False, "a replayed effectful nonce must be refused"
    except ValueError as e:
        assert "replay" in str(e), "the refusal is a nonce-freshness replay error"

    # nonce=2 (fresh) succeeds
    core2 = consume(s, env("relay", 2), authorized, effectful=True)
    assert core2["nonce"] == 2 and device_nonce_highwater(s, device.public_key_b64) == 2


def test_reads_skip_freshness_but_still_receipt():
    s = _store()
    device, authorized = _authorized_device(s)
    read = sign_envelope(device, build_core(device.public_key_b64, "read:pending", {}, 7, 1700000007))
    consume(s, read, authorized, effectful=False)              # a read at nonce 7 advances the watermark
    assert device_nonce_highwater(s, device.public_key_b64) == 7, "a read receipts (advances the highwater)"
    # a read does not enforce freshness: a lower/equal read nonce is still allowed (no side effect)
    read_again = sign_envelope(device, build_core(device.public_key_b64, "read:pending", {}, 3, 1700000003))
    assert consume(s, read_again, authorized, effectful=False)["nonce"] == 3, "reads skip the freshness gate"


# ---- tamper: mutate the action AFTER signing -> signature no longer matches -----------------------
def test_tampered_action_breaks_signature():
    s = _store()
    device, authorized = _authorized_device(s)
    core = build_core(device.public_key_b64, "read:snapshot", {}, 1, 1700000000)
    payload = sign_envelope(device, core)
    payload["action"] = "relay"                               # attacker escalates read -> effectful, sig unchanged
    ok, reason = verify_envelope(payload, authorized)
    assert ok is False and "signature" in reason, "a tampered action invalidates the signature"


# ---- an action outside the allow-list is refused even when validly signed ------------------------
def test_unknown_action_refused():
    s = _store()
    device, authorized = _authorized_device(s)
    core = build_core(device.public_key_b64, "read:everything", {}, 1, 1700000000)
    payload = sign_envelope(device, core)
    ok, reason = verify_envelope(payload, authorized)
    assert ok is False and "unknown action" in reason, "an action outside ACTIONS is refused"
    assert "read:everything" not in ACTIONS


# ---- a revoked device is dropped from authorized -> verify + consume refused ----------------------
def test_revoked_device_refused():
    s = _store()
    device = generate_keypair()
    authorize_device(s, "phone-2", device.public_key_b64, OWNER)
    assert device.public_key_b64 in authorized_devices(s, OP)
    revoke_device(s, "phone-2", device.public_key_b64, OWNER)
    authorized = authorized_devices(s, OP)
    assert device.public_key_b64 not in authorized, "a revoked device is no longer authorized"
    payload = sign_envelope(device, build_core(device.public_key_b64, "panic", {}, 1, 1700000000))
    assert verify_envelope(payload, authorized)[0] is False, "a revoked device's envelope does not verify"
    try:
        consume(s, payload, authorized, effectful=True)
        assert False, "a revoked device's request must be refused"
    except ValueError:
        pass


# ---- record_receipt writes the minimal, subject-free routing fields ------------------------------
def test_receipt_carries_no_args_and_is_auto_tier():
    s = _store()
    device, _ = _authorized_device(s)
    core = build_core(device.public_key_b64, "relay", {"subject": "TOP SECRET wire $1M"}, 5, 1700000005)
    seq = record_receipt(s, core)
    rec = s.get(seq)
    assert rec.payload["signal"] == RECEIPT_SIGNAL and rec.payload["tier"] == "A0"
    assert rec.payload["decision"] == "auto" and rec.payload["nonce"] == 5
    assert "args" not in rec.payload and "subject" not in str(rec.payload), "the receipt leaks no args/subject"


# ---- purity: envelope.py reads no wallclock and no RNG -------------------------------------------
def test_module_is_pure_no_clock_no_random():
    import inspect

    import sigil.bridge.envelope as E
    src = inspect.getsource(E)
    for forbidden in ("import random", "import time", "datetime", "now_iso", "time.time", "Date"):
        assert forbidden not in src, f"envelope.py must be pure: found {forbidden!r}"


def _authed():
    s = _store()
    dev = generate_keypair()
    authorize_device(s, "dev", dev.public_key_b64, OWNER)
    return s, dev, authorized_devices(s, OP)


def test_malformed_signature_is_a_clean_refusal_not_a_crash():    # red-pen BLOCK-3
    s, dev, auth = _authed()
    bad = {**build_core(dev.public_key_b64, "read:pending", {}, 1, 1700000000), "sig": "AAAA"}
    ok, _reason = verify_envelope(bad, auth)                       # verify_one would RAISE on a wrong-length sig
    assert ok is False, "a malformed-length signature returns (False, reason), never an unhandled exception"


def test_non_finite_nonce_is_a_clean_refusal_not_a_crash():       # re-check BLOCK (int(inf) → OverflowError)
    s, dev, auth = _authed()
    for bad_nonce in (float("inf"), float("-inf"), float("nan")):
        env = sign_envelope(dev, build_core(dev.public_key_b64, "panic", {}, bad_nonce, 1700000000))
        try:
            consume(s, env, auth, effectful=True)
            assert False, f"a non-finite nonce ({bad_nonce}) must be refused"
        except ValueError:
            pass          # clean ValueError — NOT an uncaught OverflowError crashing the handler


def test_nonce_zero_is_a_valid_first_value():                     # sweep LOW-7
    s, dev, auth = _authed()
    consume(s, sign_envelope(dev, build_core(dev.public_key_b64, "panic", {}, 0, 1700000000)), auth, effectful=True)
    try:
        consume(s, sign_envelope(dev, build_core(dev.public_key_b64, "panic", {}, 0, 1700000000)), auth, effectful=True)
        assert False, "a replay of nonce 0 must be refused"
    except ValueError:
        pass


def test_concurrent_replay_of_one_effectful_envelope_accepted_once():   # red-pen BLOCK-4 / sweep MED-4
    import threading
    s, dev, auth = _authed()
    env = sign_envelope(dev, build_core(dev.public_key_b64, "relay", {"text": "x"}, 5, 1700000000))
    results, barrier = [], threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            consume(s, env, auth, effectful=True)
            results.append("ok")
        except ValueError:
            results.append("refused")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1, f"the atomic nonce gate accepts exactly ONE concurrent replay, got {results.count('ok')}"


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
    print(f"{passed}/{len(fns)} Phase-9 W1-A (device-signed request envelope) guarantees hold")
