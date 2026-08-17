"""C-S3 — the offense evidence anti-rollback high-water gains a GOVERNANCE signature (parity with the signed
sovereign floor), WITHOUT changing evidence-verify exit codes / SOUND-bundle gating.

Two levels:
  * unit — ``_save_highwater`` / ``_load_highwater`` keep the symlink-precedes-exists guard, the unsigned
    write is BYTE-IDENTICAL, a signed write verifies under the governance anchor, and a tampered/untrusted
    signature fails CLOSED (raises ``_HighwaterCorrupt``).
  * end-to-end — a real SOUND bundle verified via the CLI ``verify`` subcommand: with ``--highwater-signer-file``
    the advanced high-water is signed + re-verifies + a re-verify is still exit 0 (gating unchanged); a
    tampered signed high-water then fails the verify CLOSED (exit 2); and the no-signer path stays exit 0 with
    an unsigned ``{last_seq}`` file.

Run: pytest engine/crucible/framework/v2/evidence/tests/test_highwater_signed.py -q
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.evidence.cli import _HighwaterCorrupt, _load_highwater, _save_highwater, main
from vigil_core.highwater import _HW_DOMAIN, _HW_EVIDENCE_DOMAIN, verify_highwater_signature

from .test_evidence import _DIVERGENT, _finding, _trust_root


# --------------------------------------------------------------------------- unit: save/load parity


def test_unsigned_save_is_byte_identical_and_loads(tmp_path):
    p = tmp_path / "hw.json"
    _save_highwater(p, 7)                                            # no signer
    assert p.read_text(encoding="utf-8") == json.dumps({"last_seq": 7})
    assert _load_highwater(p) == 7
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_symlink_guard_survives_on_load_and_save(tmp_path):
    # load: a symlink (incl. dangling) is refused, never read as first-run
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"last_seq": 5}))
    link = tmp_path / "hw.json"
    os.symlink(str(real), str(link))
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(link)
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(link, trusted_pubkeys=["x"])                # the added anchor arg keeps the guard
    dangling = tmp_path / "d.json"
    os.symlink(str(tmp_path / "nope.json"), str(dangling))
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(dangling)
    # save: refuses a symlink target and never follows it
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL")
    slink = tmp_path / "s.json"
    os.symlink(str(victim), str(slink))
    kp = generate_keypair()
    with pytest.raises(ValueError, match="symlink"):
        _save_highwater(slink, 9, signer=kp)                        # even with a signer, the guard holds first
    assert victim.read_text() == "ORIGINAL"


def test_signed_save_verifies_and_load_is_still_int(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    _save_highwater(p, 11, signer=kp)
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert raw["last_seq"] == 11 and raw["pubkey"] == kp.public_key_b64 and isinstance(raw["sig"], str)
    ok, why = verify_highwater_signature(raw, [kp.public_key_b64], domain=_HW_EVIDENCE_DOMAIN)
    assert ok, why
    # cross-variant separation: this evidence floor must NOT verify under the attestation-log default domain
    assert verify_highwater_signature(raw, [kp.public_key_b64], domain=_HW_DOMAIN)[0] is False
    # load without an anchor → pure int (back-compat interface preserved for verify_bundle)
    assert _load_highwater(p) == 11
    # load WITH the governance anchor → still 11 (valid sig verifies, no raise)
    assert _load_highwater(p, trusted_pubkeys=[kp.public_key_b64]) == 11


def test_load_rejects_a_floor_signed_under_the_attestation_log_domain(tmp_path):
    """HIGH-1 fix — the exploit path. A floor signed under the ATTESTATION-LOG default domain (which shares the
    ``last_seq`` field the evidence side reads) must be REJECTED by the evidence ``_load_highwater``, not
    accepted as an evidence floor. Before the per-variant domain, this cross-context floor verified here."""
    from vigil_core.highwater import _sign_highwater
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    # a WRONG-variant floor: correctly signed, but under the DEFAULT (attestation-log) domain
    wrong = _sign_highwater({"schema_version": 1, "entry_count": 9, "last_seq": 9}, kp)   # default _HW_DOMAIN
    p.write_text(json.dumps(wrong), encoding="utf-8")
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(p, trusted_pubkeys=[kp.public_key_b64])


def test_tampered_signed_highwater_fails_closed(tmp_path):
    p = tmp_path / "hw.json"
    kp = generate_keypair()
    _save_highwater(p, 11, signer=kp)
    raw = json.loads(p.read_text(encoding="utf-8"))
    raw["last_seq"] = 99                                            # edit the core, keep the old sig
    p.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(p, trusted_pubkeys=[kp.public_key_b64])
    # with NO anchor, load is byte-identical to before (no sig check) → returns the (tampered) int
    assert _load_highwater(p) == 99


def test_untrusted_signer_fails_closed(tmp_path):
    p = tmp_path / "hw.json"
    attacker = generate_keypair()
    _save_highwater(p, 11, signer=attacker)
    governance = generate_keypair()
    with pytest.raises(_HighwaterCorrupt):
        _load_highwater(p, trusted_pubkeys=[governance.public_key_b64])


def test_unsigned_with_anchor_is_warn_accept(tmp_path):
    """An existing UNSIGNED high-water loaded WITH a governance anchor is accepted (warn-once) — exit codes
    unchanged for pre-C.2 files; only a PRESENT-but-bad signature fails closed."""
    p = tmp_path / "hw.json"
    _save_highwater(p, 7)                                           # unsigned
    kp = generate_keypair()
    assert _load_highwater(p, trusted_pubkeys=[kp.public_key_b64]) == 7


# --------------------------------------------------------------------------- end-to-end: CLI verify gating


def _make_sound_bundle(tmp_path):
    """certify a real SOUND single-finding bundle via the CLI; return (report, bundle, trust_root) paths."""
    tr, signers = _trust_root(threshold=2, n=3)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"active_findings": [_finding(_DIVERGENT)]}), encoding="utf-8")
    bundle = tmp_path / "bundle"
    argv = ["certify", "--report", str(report), "--slug", "acme", "--out", str(bundle)]
    for kid, priv in signers[:2]:                                  # 2-of-3
        argv += ["--signer", f"{kid}:{priv}"]
    assert main(argv) == 0
    trust_root = tmp_path / "trust-root.json"
    trust_root.write_text(tr.model_dump_json(), encoding="utf-8")
    return report, bundle, trust_root


def test_e2e_verify_writes_a_verifiable_signed_highwater_and_gating_unchanged(tmp_path):
    report, bundle, trust_root = _make_sound_bundle(tmp_path)
    hw = tmp_path / "hw.json"
    hw_kp = generate_keypair()
    signer_file = tmp_path / "gov.json"
    signer_file.write_text(json.dumps(
        {"public_key_b64": hw_kp.public_key_b64, "private_key_b64": hw_kp.private_key_b64}), encoding="utf-8")

    base = ["verify", "--report", str(report), "--bundle", str(bundle), "--trust-root", str(trust_root),
            "--highwater", str(hw)]
    # SOUND bundle → exit 0, and the advanced high-water is GOVERNANCE-SIGNED
    assert main(base + ["--highwater-signer-file", str(signer_file)]) == 0
    raw = json.loads(hw.read_text(encoding="utf-8"))
    assert "sig" in raw and raw["pubkey"] == hw_kp.public_key_b64
    ok, why = verify_highwater_signature(raw, [hw_kp.public_key_b64], domain=_HW_EVIDENCE_DOMAIN)
    assert ok, why
    # re-verify over the SIGNED high-water → still exit 0 (a signed floor loads + verifies + gating unchanged)
    assert main(base + ["--highwater-signer-file", str(signer_file)]) == 0


def test_e2e_tampered_signed_highwater_makes_verify_fail_closed(tmp_path):
    report, bundle, trust_root = _make_sound_bundle(tmp_path)
    hw = tmp_path / "hw.json"
    hw_kp = generate_keypair()
    signer_file = tmp_path / "gov.json"
    signer_file.write_text(json.dumps(
        {"public_key_b64": hw_kp.public_key_b64, "private_key_b64": hw_kp.private_key_b64}), encoding="utf-8")
    base = ["verify", "--report", str(report), "--bundle", str(bundle), "--trust-root", str(trust_root),
            "--highwater", str(hw)]
    assert main(base + ["--highwater-signer-file", str(signer_file)]) == 0

    # tamper the SIGNED high-water core (keep the retained signature) → verify must REFUSE (exit 2)
    raw = json.loads(hw.read_text(encoding="utf-8"))
    raw["last_seq"] = raw["last_seq"] + 1000
    hw.write_text(json.dumps(raw), encoding="utf-8")
    assert main(base + ["--highwater-signer-file", str(signer_file)]) == 2


def test_e2e_no_signer_writes_unsigned_and_stays_sound(tmp_path):
    """The no-signer path is byte-identical: a SOUND bundle still verifies (exit 0) and the high-water is a
    plain unsigned ``{last_seq}`` — proving the dedup did not change SOUND-bundle gating."""
    report, bundle, trust_root = _make_sound_bundle(tmp_path)
    hw = tmp_path / "hw.json"
    assert main(["verify", "--report", str(report), "--bundle", str(bundle), "--trust-root", str(trust_root),
                 "--highwater", str(hw)]) == 0
    raw = json.loads(hw.read_text(encoding="utf-8"))
    assert set(raw.keys()) == {"last_seq"}                          # unsigned, byte-identical shape
    assert main(["verify", "--report", str(report), "--bundle", str(bundle), "--trust-root", str(trust_root),
                 "--highwater", str(hw)]) == 0                      # idempotent re-verify still SOUND
