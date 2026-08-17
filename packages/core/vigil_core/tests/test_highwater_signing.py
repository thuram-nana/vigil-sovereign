"""C-S2 — GOVERNANCE-signed offense high-water floor (parity with the signed sovereign floor).

Covers the two risk/negative-control tests the slice must be green on:

  * risk #7 (no-op fidelity): with NO signer, the persisted floor is BYTE-IDENTICAL to the pre-signing
    write, and ``load_highwater`` stays a PURE PARSE (it neither checks nor returns the signature).
  * risk #10 (signed-floor tamper / strip-to-unsigned): a signed floor whose ``entry_count`` is edited fails
    ``verify_highwater_signature`` (fail-closed); a floor STRIPPED to unsigned is warn+accepted (back-compat —
    the strip case is closed only by the out-of-band witnessed checkpoint, a separate slice); an untrusted or
    malformed signature fails closed.

Run: pytest packages/core/vigil_core/tests/test_highwater_signing.py -q
"""
import json
import os
import stat
from types import SimpleNamespace

import pytest

import vigil_core.highwater as hw_mod
from vigil_core import (
    advance_highwater,
    generate_keypair,
    load_highwater,
    read_highwater_dict,
    verify_highwater_signature,
)
from vigil_core.highwater import HighWaterError, _floor_dict


def _head(entry_count: int, last_seq: int) -> SimpleNamespace:
    return SimpleNamespace(entry_count=entry_count, last_seq=last_seq)


@pytest.fixture(autouse=True)
def _reset_warn_once():
    # The unsigned-floor warning is process-once; reset it so each test observes deterministic warn behaviour.
    hw_mod._warned_unsigned_highwater = False
    yield
    hw_mod._warned_unsigned_highwater = False


# --------------------------------------------------------------------------- risk #7: no-op fidelity


def test_unsigned_advance_is_byte_identical_to_pre_signing(tmp_path):
    """No signer → the on-disk bytes are EXACTLY the legacy ``json.dumps(_floor_dict(head), sort_keys=True)``.
    This guards against a hardening that changed the happy path."""
    p = tmp_path / "hw.json"
    written = advance_highwater(p, _head(3, 2))                      # no signer
    assert written == {"schema_version": 1, "entry_count": 3, "last_seq": 2}
    assert "sig" not in written and "pubkey" not in written
    expected = json.dumps(_floor_dict(_head(3, 2)), sort_keys=True)  # the pre-C.2 serialisation
    assert p.read_text(encoding="utf-8") == expected


def test_load_highwater_stays_pure_parse_on_a_signed_floor(tmp_path):
    """``load_highwater`` returns the normalised monotonic view and NEVER checks or leaks the signature — the
    sig check lives in ``verify_highwater_signature`` at the trust-anchor holder (mirrors floor.load_floor)."""
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(4, 3), signer=kp)
    # normalised view: sig/pubkey/schema_version dropped, byte-identical shape to an unsigned load
    assert load_highwater(p) == {"entry_count": 4, "last_seq": 3}
    # a tampered signature does NOT make load_highwater raise (it is not the signature checker)
    raw = json.loads(p.read_text(encoding="utf-8"))
    raw["sig"] = "AA" + raw["sig"][2:]
    p.write_text(json.dumps(raw), encoding="utf-8")
    assert load_highwater(p) == {"entry_count": 4, "last_seq": 3}


def test_signed_advance_is_still_upward_only_and_0600(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(2, 1), signer=kp)
    advance_highwater(p, _head(5, 4), signer=kp)                     # upward: fine
    assert load_highwater(p) == {"entry_count": 5, "last_seq": 4}
    with pytest.raises(hw_mod.HighWaterDowngrade):
        advance_highwater(p, _head(3, 2), signer=kp)                 # downgrade refused, even signed
    assert load_highwater(p) == {"entry_count": 5, "last_seq": 4}
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


# --------------------------------------------------------------------------- risk #10: tamper / strip / trust


def test_signed_floor_verifies_under_the_governance_key(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    written = advance_highwater(p, _head(7, 6), signer=kp)
    assert written["pubkey"] == kp.public_key_b64 and isinstance(written["sig"], str)
    raw = read_highwater_dict(p)
    ok, why = verify_highwater_signature(raw, [kp.public_key_b64])
    assert ok, why


def test_edited_entry_count_fails_closed(tmp_path):
    """A signed floor whose monotonic core is edited under a retained signature MUST fail verification."""
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(7, 6), signer=kp)
    raw = read_highwater_dict(p)
    raw["entry_count"] = 999                                          # tamper the core, keep the old sig
    ok, why = verify_highwater_signature(raw, [kp.public_key_b64])
    assert not ok and "does not verify" in why


def test_edited_last_seq_fails_closed(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(7, 6), signer=kp)
    raw = read_highwater_dict(p)
    raw["last_seq"] = 0
    ok, _ = verify_highwater_signature(raw, [kp.public_key_b64])
    assert not ok


def test_strip_to_unsigned_is_warn_accept_backcompat(tmp_path, caplog):
    """Stripping the signature back to a legacy unsigned floor is ACCEPTED with a one-time warning (the
    honest back-compat limit) — the strip case is closed only by the retained out-of-band witness, not here."""
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(7, 6), signer=kp)
    raw = read_highwater_dict(p)
    raw.pop("sig"), raw.pop("pubkey")                                 # strip to unsigned
    with caplog.at_level("WARNING"):
        ok, why = verify_highwater_signature(raw, [kp.public_key_b64])
    assert ok and "unsigned" in why
    assert any("UNSIGNED" in r.message for r in caplog.records)       # warned once


def test_unsigned_with_no_trusted_key_is_silent_accept(tmp_path, caplog):
    """No trust anchor at all → silent accept (byte-identical to the pre-signing spine; never bricks a cold
    verifier that never provisioned a key)."""
    p = tmp_path / "hw.json"
    advance_highwater(p, _head(2, 1))                                 # unsigned
    raw = read_highwater_dict(p)
    with caplog.at_level("WARNING"):
        ok, _ = verify_highwater_signature(raw, [])
    assert ok
    assert not any("UNSIGNED" in r.message for r in caplog.records)   # no warn without a key present


def test_signature_from_untrusted_key_fails_closed(tmp_path):
    """A validly-signed floor whose pubkey is NOT in the trusted governance set is refused (an attacker who
    re-signs a rolled-back floor under their OWN key must not be accepted)."""
    p = tmp_path / "hw.json"
    attacker = generate_keypair()
    advance_highwater(p, _head(7, 6), signer=attacker)
    raw = read_highwater_dict(p)
    owner_governance = generate_keypair()
    ok, why = verify_highwater_signature(raw, [owner_governance.public_key_b64])
    assert not ok and "not from a trusted governance key" in why


def test_malformed_signature_material_fails_closed(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    advance_highwater(p, _head(7, 6), signer=kp)
    raw = read_highwater_dict(p)
    raw["sig"] = "!!!not base64!!!"
    ok, why = verify_highwater_signature(raw, [kp.public_key_b64])
    assert not ok and ("malformed" in why or "does not verify" in why)


def test_evidence_shaped_core_signs_and_verifies_with_the_same_helpers(tmp_path):
    """The helpers are generic over the core dict, so the evidence twin's ``{last_seq}`` floor signs/verifies
    through the SAME implementation (dedup). A different core shape → different signing bytes (no cross-replay)."""
    from vigil_core.highwater import _sign_highwater

    kp = generate_keypair()
    ev = _sign_highwater({"last_seq": 9}, kp)
    assert ev["last_seq"] == 9 and ev["pubkey"] == kp.public_key_b64
    ok, _ = verify_highwater_signature(ev, [kp.public_key_b64])
    assert ok
    # a signature over {last_seq:9} must NOT verify when transplanted onto the richer core (domain-separated
    # by content: canonical_json differs, so the bytes differ)
    forged = {"schema_version": 1, "entry_count": 9, "last_seq": 9, "sig": ev["sig"], "pubkey": ev["pubkey"]}
    ok2, _ = verify_highwater_signature(forged, [kp.public_key_b64])
    assert not ok2


# --------------------------------------------------------------------------- read_highwater_dict guards


def test_read_highwater_dict_symlink_and_absent_guards(tmp_path):
    assert read_highwater_dict(tmp_path / "missing.json") is None    # absent
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"schema_version": 1, "entry_count": 1, "last_seq": 0}))
    link = tmp_path / "hw.json"
    os.symlink(str(real), str(link))
    with pytest.raises(HighWaterError):                              # symlink refused, not followed
        read_highwater_dict(link)
    dangling = tmp_path / "d.json"
    os.symlink(str(tmp_path / "nope.json"), str(dangling))
    with pytest.raises(HighWaterError):                             # dangling refused (is_symlink before exists)
        read_highwater_dict(dangling)
