"""W7-6 (#464) + PR #630 rework: the orchestrator ``MANIFEST.json`` is GOVERNANCE-SIGNED, the DEFAULT
``vigil restore`` is AUTHENTICATED against a host-local TOFU trust anchor (not merely integrity-checked), and
restore refuses an unsigned / tampered / wrong-key / re-minted / rolled-back manifest.

The two-plane ``vigil backup`` orchestrator writes a plaintext ``MANIFEST.json`` — the index of what a backup
contains (which encrypted file is which plane, and each part's sha256, the values restore uses to LOCATE and
integrity-check each part before invoking any leg). Unsigned, anyone who can reach the backup at rest could
edit it. Signed but UNPINNED, an attacker who reached the backup could RE-SIGN a tampered index under a key
THEY generated and an unpinned verify would accept it (the honest residual the red-pen reproduced as ATTACK 1).
This suite proves:

  * signing is over DOMAIN-SEPARATED bytes (LOW-4) — a same-key signature over other bytes does not verify;
  * ``vigil backup`` records the trusted governance key + a monotonic ``backup_seq`` to a HOST-LOCAL trust
    anchor, and the DEFAULT restore PINS against it — so ATTACK 1 (the attacker re-mint) is REFUSED once an
    anchor exists (this CLI test FAILS on the pre-rework code, where the default accepted the re-mint);
  * with NO anchor, the production posture refuses fail-closed while non-production is integrity-only (which
    honestly ACCEPTS the re-mint — the residual the anchor closes);
  * a rollback to a genuine OLDER signed backup is refused (monotonic ``backup_seq``), with an explicit
    ``--allow-rollback`` override;
  * an explicit ``--expect-governance-pubkey`` always overrides the anchor.

FATAL-2: the orchestrator signs with the OFFENSE governance key only; the sovereign owner key never enters this
process. Determinism: the signature is Ed25519 over fixed domain-tagged bytes — no wallclock/rng enters it; the
freshness marker is a PERSISTED counter, not the wallclock.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

import vigil_integration.backup as backup
import vigil_integration.cli as cli
from vigil_core import generate_keypair, sign
from vigil_integration.backup import (
    OffenseBackupError,
    check_backup_freshness,
    load_trust_anchor,
    record_backup_trust_anchor,
    resolve_manifest_pin,
    sign_orchestrator_manifest,
    verify_orchestrator_manifest,
)

# A realistic orchestrator manifest body (the exact shape `_cmd_backup` writes), as fixed bytes so the crypto
# is tested independently of the wallclock `created_utc` the CLI stamps into a live one.
_MANIFEST = {
    "schema": 2,
    "created_utc": "2026-08-22T00:00:00Z",
    "host": "vigil-test-host",
    "planes": {"offense": {"file": "offense.vglbk", "sha256": "a" * 64, "bytes": 1234}},
    "backup_seq": 1,
    "retention_hint": {"keep_days": 30, "keep_last": 10},
    "note": "TWO SEPARATE encrypted files, one per plane.",
}


def _manifest_bytes() -> bytes:
    return json.dumps(_MANIFEST, indent=2, sort_keys=True).encode("utf-8")


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Every test gets its OWN throwaway trust anchor (never ~/.vigil) and a non-production posture by default.
    Tests that need production set VIGIL_POSTURE themselves; tests that need 'no anchor' delete the file."""
    monkeypatch.setenv("VIGIL_BACKUP_TRUST_ANCHOR", str(tmp_path / "trust-anchor.json"))
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    yield


def _anchor_path() -> Path:
    return Path(os.environ["VIGIL_BACKUP_TRUST_ANCHOR"])


# --------------------------------------------------------------------------------------------------
# Unit level — the sign/verify primitives directly.
# --------------------------------------------------------------------------------------------------
def test_sign_then_verify_roundtrips(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    assert sig_doc["algo"] == "ed25519"
    assert sig_doc["schema"] == backup._ORCH_MANIFEST_SIG_SCHEMA == 2
    signer = verify_orchestrator_manifest(mb, sig_doc)
    assert signer == sig_doc["pubkey"]
    assert verify_orchestrator_manifest(mb, sig_doc, expect_pubkey=sig_doc["pubkey"]) == sig_doc["pubkey"]


def test_signing_is_deterministic_no_wallclock_or_rng(tmp_path):
    """The HARD RULE: signing introduces no wallclock/rng. Ed25519 over the SAME domain-tagged bytes with the
    SAME persisted key yields byte-identical output on repeat, so the signature is re-verifiable."""
    mb = _manifest_bytes()
    first = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    second = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    assert first == second, "signing is not deterministic — wallclock/rng leaked into the signed envelope"


def test_verify_refuses_tampered_manifest_bytes(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    tampered = mb.replace(b"offense.vglbk", b"attacker.vglbk")
    assert tampered != mb
    with pytest.raises(OffenseBackupError, match="does not verify"):
        verify_orchestrator_manifest(tampered, sig_doc)


def test_verify_refuses_unsigned_manifest(tmp_path):
    mb = _manifest_bytes()
    for bad in (None, {}, {"algo": "ed25519"}, {"pubkey": "x", "sig": ""}):
        with pytest.raises(OffenseBackupError):
            verify_orchestrator_manifest(mb, bad)


def test_verify_refuses_wrong_key_pin(tmp_path):
    mb = _manifest_bytes()
    sig_doc = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    other = generate_keypair().public_key_b64
    assert other != sig_doc["pubkey"]
    with pytest.raises(OffenseBackupError, match="not signed by the expected governance key"):
        verify_orchestrator_manifest(mb, sig_doc, expect_pubkey=other)


def test_verify_refuses_a_non_domain_tagged_signature(tmp_path):
    """LOW-4: a signature over the RAW manifest bytes (no domain tag) — e.g. a same-key .sig.json minted by a
    DIFFERENT emitter over some other artifact — does NOT verify as an orchestrator manifest signature. The
    same key over DOMAIN-tagged bytes does verify. This is what prevents a cross-emitter replay."""
    mb = _manifest_bytes()
    kp = generate_keypair()
    env = {"schema": 2, "algo": "ed25519", "signs": "x", "manifest_sha256": backup.sha256_hex(mb),
           "pubkey": kp.public_key_b64, "sig": sign(kp.private_key_b64, mb)}   # RAW bytes — no domain tag
    with pytest.raises(OffenseBackupError, match="does not verify"):
        verify_orchestrator_manifest(mb, env)
    env["sig"] = sign(kp.private_key_b64, backup._orch_manifest_signing_bytes(mb))   # domain-tagged
    assert verify_orchestrator_manifest(mb, env) == kp.public_key_b64


def test_pin_blocks_a_remint_that_integrity_only_would_accept(tmp_path):
    """The honest residual, pinned down (unit level). An attacker who cannot decrypt the parts but can reach
    the index re-signs a tampered manifest — WITH the domain tag, under a key THEY generated. WITHOUT the pin
    that self-signed envelope verifies (integrity-only); WITH the pin naming the true key it is refused. The
    DEFAULT restore path (see the CLI tests) uses the trust anchor as that pin."""
    mb = _manifest_bytes()
    real = sign_orchestrator_manifest(mb, base_dir=str(tmp_path / "base"))
    attacker = generate_keypair()
    forged_bytes = mb.replace(b'"keep_last": 10', b'"keep_last": 1')
    forged_env = {
        "schema": 2, "algo": "ed25519", "signs": "MANIFEST.json (raw bytes under the vigil-orch-manifest-v1 domain tag)",
        "manifest_sha256": backup.sha256_hex(forged_bytes),
        "pubkey": attacker.public_key_b64,
        "sig": sign(attacker.private_key_b64, backup._orch_manifest_signing_bytes(forged_bytes)),
    }
    assert verify_orchestrator_manifest(forged_bytes, forged_env) == attacker.public_key_b64
    with pytest.raises(OffenseBackupError, match="not signed by the expected governance key"):
        verify_orchestrator_manifest(forged_bytes, forged_env, expect_pubkey=real["pubkey"])


# --------------------------------------------------------------------------------------------------
# Unit level — trust anchor + restore-time resolution helpers.
# --------------------------------------------------------------------------------------------------
def test_record_anchor_establishes_advances_and_refuses_rotation(tmp_path):
    p = _anchor_path()
    assert load_trust_anchor(p) is None                      # absent on a fresh host
    _, action = record_backup_trust_anchor(governance_pubkey="KEY-A", backup_seq=1, manifest_sha256="s1", path=p)
    assert action == "established"
    anc = load_trust_anchor(p)
    assert anc["governance_pubkey"] == "KEY-A" and anc["backup_seq"] == 1
    _, action = record_backup_trust_anchor(governance_pubkey="KEY-A", backup_seq=2, manifest_sha256="s2", path=p)
    assert action == "advanced" and load_trust_anchor(p)["backup_seq"] == 2
    # a DIFFERENT key is refused without reset (rotation must be deliberate)...
    with pytest.raises(OffenseBackupError, match="DIFFERENT governance key"):
        record_backup_trust_anchor(governance_pubkey="KEY-B", backup_seq=3, manifest_sha256="s3", path=p)
    # ...and adopted with reset, continuing the monotonic counter.
    _, action = record_backup_trust_anchor(governance_pubkey="KEY-B", backup_seq=3, manifest_sha256="s3",
                                           path=p, reset=True)
    assert action == "rotated"
    assert load_trust_anchor(p)["governance_pubkey"] == "KEY-B"
    assert load_trust_anchor(p)["backup_seq"] == 3


def test_load_trust_anchor_fails_closed_on_corruption(tmp_path):
    p = _anchor_path()
    p.write_text("{not json")
    with pytest.raises(OffenseBackupError, match="corrupt"):
        load_trust_anchor(p)
    p.write_text('{"schema": 1}')                            # no governance_pubkey
    with pytest.raises(OffenseBackupError, match="malformed"):
        load_trust_anchor(p)


def test_resolve_manifest_pin_modes():
    # explicit pin always wins.
    assert resolve_manifest_pin({"governance_pubkey": "A"}, "EXPLICIT", True) == ("EXPLICIT", "explicit", None)
    # anchor present, no explicit → pin the recorded key.
    assert resolve_manifest_pin({"governance_pubkey": "A"}, None, True) == ("A", "anchor", None)
    # no anchor + production → fail closed.
    with pytest.raises(OffenseBackupError, match="production"):
        resolve_manifest_pin(None, None, True)
    # no anchor + non-production → integrity-only with a warning.
    pub, mode, warn = resolve_manifest_pin(None, None, False)
    assert pub is None and mode == "integrity-only" and warn and "INTEGRITY-ONLY" in warn


def test_check_backup_freshness():
    anc = {"governance_pubkey": "A", "backup_seq": 2}
    assert check_backup_freshness(anc, 2, False) is None            # latest is fine
    assert check_backup_freshness(anc, 3, False) is None            # newer is fine
    assert check_backup_freshness(None, 1, False) is None           # no anchor → unverifiable, not refused here
    with pytest.raises(OffenseBackupError, match="rollback detected"):
        check_backup_freshness(anc, 1, False)                       # older → refused
    with pytest.raises(OffenseBackupError, match="rollback detected"):
        check_backup_freshness(anc, None, False)                    # missing seq → fail-closed
    warn = check_backup_freshness(anc, 1, True)                     # override
    assert warn and "ROLLBACK OVERRIDE" in warn


# --------------------------------------------------------------------------------------------------
# CLI level — the whole `vigil backup` → `vigil restore` path. Several of these FAIL on the pre-rework code.
# --------------------------------------------------------------------------------------------------
def _backup_ns(tmp_path, **kw):
    d = dict(sovereign_only=False, offense_only=True, out=str(tmp_path / "out"),
             base_dir=str(tmp_path / "base"), crucible_root="", passphrase_env="VIGIL_BACKUP_PASSPHRASE",
             push="", prune=False, keep_days=None, keep_last=None, reset_trust_anchor=False)
    d.update(kw)
    return argparse.Namespace(**d)


def _restore_ns(tmp_path, src, **kw):
    d = dict(sovereign_only=False, offense_only=True, src=str(src),
             base_dir=str(tmp_path / "restored-base"), crucible_root="", sigil_home="",
             expect_governance_pubkey="", force=False, passphrase_env="VIGIL_BACKUP_PASSPHRASE",
             allow_rollback=False)
    d.update(kw)
    return argparse.Namespace(**d)


def _drive_backup(tmp_path, monkeypatch, **ns_over):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", "pw-for-the-test-123")
    monkeypatch.setattr(cli, "_resolve_crucible_root", lambda: None)

    def fake_create(dest, pw, *, base_dir, crucible_root=None):
        Path(dest).write_bytes(b"fake-offense-ciphertext-bytes")
        return {"files": 1, "secrets": 0, "scope": "x", "bytes": 29}
    monkeypatch.setattr(backup, "create_offense_backup", fake_create)
    ns = _backup_ns(tmp_path, **ns_over)
    rc = cli._cmd_backup(ns)
    subdirs = sorted(p for p in Path(ns.out).iterdir() if p.is_dir()) if Path(ns.out).is_dir() else []
    return rc, (subdirs[0] if subdirs else None)


def _make_backup(tmp_path, monkeypatch, **ns_over) -> Path:
    rc, subdir = _drive_backup(tmp_path, monkeypatch, **ns_over)
    assert rc == 0 and subdir is not None
    return subdir


def _stub_restore(monkeypatch) -> dict:
    calls: dict = {"offense": 0}

    def fake_restore(off, base_dir, pw, *, crucible_root=None, expect_pubkey=None, force=False):
        calls["offense"] += 1
        calls["last_expect"] = expect_pubkey
        return {"new_base": base_dir, "files": 1, "secrets": 0, "bundles_verified": 0}
    monkeypatch.setattr(backup, "restore_offense_backup", fake_restore)
    return calls


def _attacker_remint(subdir: Path) -> None:
    """The exact ATTACK 1 the red-pen reproduced: a non-key-holder edits the index and RE-SIGNS it under a key
    THEY generated (domain-tagged, so the signature itself is well-formed), rewriting the self-describing
    sidecar."""
    mb = (subdir / "MANIFEST.json").read_bytes()
    manifest = json.loads(mb)
    manifest["retention_hint"]["keep_last"] = 1
    forged = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    attacker = generate_keypair()
    env = {"schema": 2, "algo": "ed25519",
           "signs": "MANIFEST.json (raw bytes under the vigil-orch-manifest-v1 domain tag)",
           "manifest_sha256": backup.sha256_hex(forged), "pubkey": attacker.public_key_b64,
           "sig": sign(attacker.private_key_b64, backup._orch_manifest_signing_bytes(forged))}
    (subdir / "MANIFEST.json").write_bytes(forged)
    (subdir / "MANIFEST.sig.json").write_text(json.dumps(env, indent=2, sort_keys=True))


def test_backup_writes_a_verifying_signature_and_establishes_the_anchor(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    manifest_bytes = (subdir / "MANIFEST.json").read_bytes()
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    assert verify_orchestrator_manifest(manifest_bytes, sig_doc) == sig_doc["pubkey"]
    # the host trust anchor was established with the signing key + seq 1.
    anc = load_trust_anchor(_anchor_path())
    assert anc["governance_pubkey"] == sig_doc["pubkey"] and anc["backup_seq"] == 1
    # and the manifest carries the monotonic freshness marker.
    assert json.loads(manifest_bytes)["backup_seq"] == 1


def test_default_restore_authenticates_against_the_anchor(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 0
    assert calls["offense"] == 1
    # the inner offense manifest is pinned with the SAME anchor key by default.
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    assert calls["last_expect"] == sig_doc["pubkey"]


def test_default_restore_refuses_attacker_remint_once_anchor_exists(tmp_path, monkeypatch):
    """ATTACK 1, DEFAULT restore. FAILS ON PRE-REWORK: the old default (no anchor pin) accepted this re-mint
    and ran the leg. Here the anchor pins the real key, so the re-mint is refused before the leg runs."""
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    _attacker_remint(subdir)
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0, "the attacker re-mint must be refused by the default (anchor-pinned) restore"


def test_integrity_only_without_anchor_nonproduction_accepts_remint(tmp_path, monkeypatch):
    """The honest residual the anchor closes: with NO anchor and NON-production posture, restore is
    integrity-only (a loud warning) and ACCEPTS the attacker re-mint. This documents exactly what the default
    anchored path buys — and why production refuses it."""
    subdir = _make_backup(tmp_path, monkeypatch)
    _anchor_path().unlink()                                  # no anchor on this host
    calls = _stub_restore(monkeypatch)
    _attacker_remint(subdir)
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 0
    assert calls["offense"] == 1


def test_production_with_no_anchor_fails_closed(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    _anchor_path().unlink()                                  # no anchor on this host
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    calls = _stub_restore(monkeypatch)
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0, "production must refuse an unauthenticated (no-anchor, no-pin) restore"
    # an explicit out-of-band pin authenticates it even in production with no anchor.
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir, expect_governance_pubkey=sig_doc["pubkey"])) == 0
    assert calls["offense"] == 1


def test_default_restore_refuses_rollback_to_an_older_backup(tmp_path, monkeypatch):
    first = _make_backup(tmp_path, monkeypatch, out=str(tmp_path / "out1"))     # backup_seq 1
    second = _make_backup(tmp_path, monkeypatch, out=str(tmp_path / "out2"))    # backup_seq 2 → anchor seq 2
    assert json.loads((first / "MANIFEST.json").read_bytes())["backup_seq"] == 1
    assert json.loads((second / "MANIFEST.json").read_bytes())["backup_seq"] == 2
    calls = _stub_restore(monkeypatch)
    # restoring the OLDER (seq 1) backup is refused as a rollback — the sig/pin do NOT catch this.
    assert cli._cmd_restore(_restore_ns(tmp_path, first)) == 2
    assert calls["offense"] == 0
    # the LATEST restores.
    assert cli._cmd_restore(_restore_ns(tmp_path, second)) == 0
    assert calls["offense"] == 1
    # --allow-rollback deliberately restores the older one.
    assert cli._cmd_restore(_restore_ns(tmp_path, first, allow_rollback=True)) == 0
    assert calls["offense"] == 2


def test_restore_refuses_a_tampered_manifest(tmp_path, monkeypatch):
    """Substitution attack: replace the offense part AND rewrite its sha256 so the OLD per-part sha256 check
    would pass — only the manifest SIGNATURE catches it. Refused before the leg is invoked."""
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    (subdir / "offense.vglbk").write_bytes(b"attacker-substituted-ciphertext")
    manifest = json.loads((subdir / "MANIFEST.json").read_bytes())
    manifest["planes"]["offense"]["sha256"] = cli._sha256_file(subdir / "offense.vglbk")
    (subdir / "MANIFEST.json").write_bytes(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0


def test_restore_refuses_an_unsigned_manifest(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    (subdir / "MANIFEST.sig.json").unlink()
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir)) == 2
    assert calls["offense"] == 0


def test_explicit_pin_mismatch_refused_and_correct_pin_accepted(tmp_path, monkeypatch):
    subdir = _make_backup(tmp_path, monkeypatch)
    calls = _stub_restore(monkeypatch)
    sig_doc = json.loads((subdir / "MANIFEST.sig.json").read_bytes())
    wrong = generate_keypair().public_key_b64
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir, expect_governance_pubkey=wrong)) == 2
    assert calls["offense"] == 0
    assert cli._cmd_restore(_restore_ns(tmp_path, subdir, expect_governance_pubkey=sig_doc["pubkey"])) == 0
    assert calls["offense"] == 1


def test_backup_refuses_key_rotation_without_reset(tmp_path, monkeypatch):
    _make_backup(tmp_path, monkeypatch)                         # anchor under base
    # a DIFFERENT base_dir mints a DIFFERENT governance key while the anchor env is the same → refused.
    rc, _ = _drive_backup(tmp_path, monkeypatch, base_dir=str(tmp_path / "base2"), out=str(tmp_path / "out2"))
    assert rc == 1
    # with --reset-trust-anchor the rotation is adopted (a deliberate, logged step).
    rc, sub = _drive_backup(tmp_path, monkeypatch, base_dir=str(tmp_path / "base2"),
                            out=str(tmp_path / "out3"), reset_trust_anchor=True)
    assert rc == 0 and sub is not None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
