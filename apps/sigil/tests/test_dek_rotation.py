"""Tests for spine DEK rotation — re-encrypt content under a fresh DEK, verify + rollback (audit W9-2).

The pure engine (reencrypt_payload / reencrypt_records) is exercised directly, then the wired
rotate_spine_dek is driven end-to-end over an UN-ANCHORED single-file spine with a fake TPM. Proves the
acceptance controls: after rotation every sealed field reads under the NEW DEK to its exact original AND the
OLD DEK no longer opens a re-keyed field; the rebuilt chain verifies; a segmented/anchored spine is refused
fail-closed. This file FAILS on a tree without the change — rotate_spine_dek / reencrypt_records do not exist.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sigil import config
from sigil.spine import envelope as env
from sigil.spine.dek_rotation import (
    DekRotationError, reencrypt_payload, reencrypt_records, rotate_spine_dek,
)
from vigil_core.canonical import digest_payload
from vigil_core.chain import build_chain
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault


def make_fake_tpm():
    def run(argv, stdin):
        cmd = argv[0]

        def flag(name):
            return argv[argv.index(name) + 1]

        if cmd == "tpm2_createprimary":
            Path(flag("-c")).write_bytes(b"primary"); return TpmResult(0, b"")
        if cmd == "tpm2_create":
            Path(flag("-u")).write_bytes(b"pub"); Path(flag("-r")).write_bytes(b"SEALED\x00" + (stdin or b""))
            return TpmResult(0, b"")
        if cmd == "tpm2_load":
            priv = Path(flag("-r")).read_bytes()
            if not priv.startswith(b"SEALED\x00"):
                return TpmResult(1, b"")
            Path(flag("-c")).write_bytes(priv[len(b"SEALED\x00"):]); return TpmResult(0, b"")
        if cmd == "tpm2_unseal":
            return TpmResult(0, Path(flag("-c")).read_bytes())
        return TpmResult(1, b"")
    return run


def _record(dek, seq, text):
    payload = env.seal_payload(dek, {"text": text, "usage": {"tokens": seq}}, scope="sigil", seq=seq)
    return {"seq": seq, "scope": "sigil", "kind": "note", "source": "t", "actor": "t",
            "payload": payload, "parent_id": None, "supersedes_id": None, "ts": "2026-01-01T00:00:00Z",
            "schema_version": 2}


def _chain(records):
    digests = []
    for r in records:
        content = {"scope": r["scope"], "kind": r["kind"], "source": r["source"], "actor": r["actor"],
                   "payload": r["payload"], "parent_id": r["parent_id"], "supersedes_id": r["supersedes_id"]}
        digests.append(digest_payload(content))
    for r, e in zip(records, build_chain(digests)):
        r["cert_digest"], r["prev_hash"], r["entry_hash"] = e.cert_digest, e.prev_hash, e.entry_hash
    return records


# --- pure engine -----------------------------------------------------------------------------------


def test_reencrypt_records_new_reads_old_fails_chain_verifies():
    old, new = os.urandom(32), os.urandom(32)
    before = _chain([_record(old, 0, "alpha-secret"), _record(old, 1, "bravo-secret")])
    old_digests = [r["cert_digest"] for r in before]

    after = reencrypt_records(old, new, before)

    from sigil.spine.store import SpineStore  # reuse the store's keyless verify over the re-keyed records
    for r in after:
        # POSITIVE: opens under the NEW DEK to the exact original plaintext.
        plain = env.open_payload(new, r["payload"], scope=r["scope"], seq=r["seq"])
        assert plain["text"] in ("alpha-secret", "bravo-secret")
        # NEGATIVE control: the OLD DEK can no longer open the re-keyed field.
        with pytest.raises(env.SpinePayloadLocked):
            env.open_payload(old, r["payload"], scope=r["scope"], seq=r["seq"])
    # ciphertext (and therefore cert_digest) changed, and the rebuilt chain verifies internally.
    assert [r["cert_digest"] for r in after] != old_digests
    entries = [SpineStore._entry_from_line(json.dumps(r)) for r in after]
    from vigil_core.chain import verify_chain
    assert verify_chain(entries)[0] is True


def test_reencrypt_payload_passes_through_a_plaintext_record():
    old, new = os.urandom(32), os.urandom(32)
    payload = {"decision": "allow", "usage": {"tokens": 3}}   # no content field => nothing sealed
    assert reencrypt_payload(old, new, payload, scope="sigil", seq=0) == payload


def test_reencrypt_records_refuses_non_genesis_chain():
    old, new = os.urandom(32), os.urandom(32)
    recs = _chain([_record(old, 0, "x")])
    recs[0]["seq"] = 5   # a non-genesis start (as a segment would present) is refused fail-closed
    with pytest.raises(DekRotationError):
        reencrypt_records(old, new, recs)


# --- wired rotate_spine_dek ------------------------------------------------------------------------


@pytest.fixture
def wired(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SPINE_DEK_PATH", tmp_path / "spine.dek")
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine.jsonl")
    monkeypatch.setattr(config, "HEAD_PATH", tmp_path / "head.json")     # absent => un-anchored
    monkeypatch.setattr(config, "FLOOR_PATH", tmp_path / "floor.json")   # absent => un-anchored
    v = Vault(tmp_path / "vault", make_fake_tpm()); v.provision()
    monkeypatch.setattr("sigil.platform.vault.owner_vault", lambda: v)
    return tmp_path, v


def test_rotate_spine_dek_end_to_end(wired):
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)   # mints + seals the DEK file
    before = _chain([_record(old_dek, 0, "top-secret-0"), _record(old_dek, 1, "top-secret-1")])
    config.SPINE_PATH.write_text("\n".join(json.dumps(r) for r in before) + "\n", encoding="utf-8")

    res = rotate_spine_dek(config.SPINE_PATH, v)
    assert res["rotated"] == 2

    new_dek = env.load_or_create_dek(v, create=False)
    assert new_dek != old_dek
    after = [json.loads(line) for line in config.SPINE_PATH.read_text().splitlines() if line.strip()]
    for r in after:
        assert env.open_payload(new_dek, r["payload"], scope=r["scope"], seq=r["seq"])["text"].startswith("top-secret-")
        with pytest.raises(env.SpinePayloadLocked):
            env.open_payload(old_dek, r["payload"], scope=r["scope"], seq=r["seq"])
    assert not config.SPINE_PATH.with_name(config.SPINE_PATH.name + ".rot").exists()


def test_rotate_spine_dek_refuses_anchored_spine(wired):
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)
    before = _chain([_record(old_dek, 0, "secret")])
    config.SPINE_PATH.write_text(json.dumps(before[0]) + "\n", encoding="utf-8")
    config.HEAD_PATH.write_text("{}", encoding="utf-8")   # a signed head => anchored
    spine_bytes = config.SPINE_PATH.read_bytes()
    with pytest.raises(DekRotationError):
        rotate_spine_dek(config.SPINE_PATH, v)
    assert config.SPINE_PATH.read_bytes() == spine_bytes   # nothing was swapped (fail-closed)


def test_rotate_spine_dek_refuses_unprovisioned_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine.jsonl")
    monkeypatch.setattr(config, "HEAD_PATH", tmp_path / "head.json")
    monkeypatch.setattr(config, "FLOOR_PATH", tmp_path / "floor.json")
    monkeypatch.setattr(config, "SPINE_DEK_PATH", tmp_path / "spine.dek")
    config.SPINE_PATH.write_text("", encoding="utf-8")
    v = Vault(tmp_path / "vault", make_fake_tpm())   # NOT provisioned
    with pytest.raises(DekRotationError):
        rotate_spine_dek(config.SPINE_PATH, v)


# --- red-pen W9-2 HIGH regression: DEK rotation crash anchor + reconciler --------------------------


def test_rotate_spine_dek_uses_and_retires_a_crash_anchor(wired):
    """A clean rotation must leave NO `.prev` anchor behind (it is dropped only after the spine is confirmed
    swapped)."""
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)
    before = _chain([_record(old_dek, 0, "anchor-0")])
    config.SPINE_PATH.write_text(json.dumps(before[0]) + "\n", encoding="utf-8")
    rotate_spine_dek(config.SPINE_PATH, v)
    assert not config.SPINE_DEK_PATH.with_name(config.SPINE_DEK_PATH.name + ".prev").exists()


def test_dek_anchor_survives_a_power_loss_and_reconcile_recovers(wired, monkeypatch):
    """Red-pen HIGH: power loss BETWEEN the DEK write and the spine swap must be recoverable. Without the
    `.prev` crash anchor the old DEK is gone and the spine (still old-ciphertext) is unrecoverable. We
    simulate the crash with a BaseException (uncaught → no rollback) on the spine swap, then prove the anchor
    lets reconcile_spine_dek finish the rotation. Reverting the anchor snapshot makes recovery impossible."""
    import sigil.spine.dek_rotation as dr
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)
    before = _chain([_record(old_dek, 0, "cs-0"), _record(old_dek, 1, "cs-1")])
    config.SPINE_PATH.write_text("\n".join(json.dumps(r) for r in before) + "\n", encoding="utf-8")

    real_awt = dr.atomic_write_text

    def power_loss(*a, **k):  # simulate power loss on the SPINE swap (BaseException => uncaught, no rollback)
        raise KeyboardInterrupt("simulated power loss during spine swap")

    monkeypatch.setattr(dr, "atomic_write_text", power_loss)
    dek_prev = config.SPINE_DEK_PATH.with_name(config.SPINE_DEK_PATH.name + ".prev")
    with pytest.raises(KeyboardInterrupt):
        dr.rotate_spine_dek(config.SPINE_PATH, v)

    # crash state: the anchor is present, the DEK is already the NEW one, the spine is still old-ciphertext.
    assert dek_prev.exists()
    cur = env.load_or_create_dek(v, create=False)
    assert cur != old_dek
    recs = [json.loads(x) for x in config.SPINE_PATH.read_text().splitlines() if x.strip()]
    with pytest.raises(env.SpinePayloadLocked):
        env.open_payload(cur, recs[0]["payload"], scope="sigil", seq=0)   # new DEK can't read the old spine

    monkeypatch.setattr(dr, "atomic_write_text", real_awt)
    assert dr.dek_rotation_incomplete() is True
    res = dr.reconcile_spine_dek(config.SPINE_PATH, v)
    assert res["status"] == "completed"
    assert dr.dek_rotation_incomplete() is False
    after = [json.loads(x) for x in config.SPINE_PATH.read_text().splitlines() if x.strip()]
    for r in after:
        assert env.open_payload(cur, r["payload"], scope=r["scope"], seq=r["seq"])["text"].startswith("cs-")
    assert not dek_prev.exists()


def test_reconcile_dek_rolls_back_when_the_new_dek_never_landed(wired):
    """Crash BEFORE the new DEK was written (anchor == current DEK) → nothing was committed → reconcile rolls
    back cleanly (drops the anchor + any staged `.rot`), leaving the spine readable under the old DEK."""
    import shutil

    from sigil.spine.dek_rotation import reconcile_spine_dek
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)
    before = _chain([_record(old_dek, 0, "s0")])
    config.SPINE_PATH.write_text(json.dumps(before[0]) + "\n", encoding="utf-8")
    dek_path = config.SPINE_DEK_PATH
    dek_prev = dek_path.with_name(dek_path.name + ".prev")
    shutil.copyfile(dek_path, dek_prev)                       # anchor == current DEK (new never landed)
    staged = config.SPINE_PATH.with_name(config.SPINE_PATH.name + ".rot")
    staged.write_text("garbage", encoding="utf-8")

    res = reconcile_spine_dek(config.SPINE_PATH, v)
    assert res["status"] == "rolled-back"
    assert not dek_prev.exists() and not staged.exists()
    r = json.loads(config.SPINE_PATH.read_text().splitlines()[0])
    assert env.open_payload(old_dek, r["payload"], scope="sigil", seq=0)["text"] == "s0"


def test_reconcile_dek_completes_when_spine_already_swapped(wired):
    """Crash AFTER the spine swap but before the anchor was dropped → the spine already opens under the new
    (current) DEK → reconcile just retires the stale anchor (idempotent, no re-encryption)."""
    import base64
    import shutil

    from sigil.spine.dek_rotation import reconcile_spine_dek, reencrypt_records
    tmp, v = wired
    old_dek = env.load_or_create_dek(v, create=True)
    before = _chain([_record(old_dek, 0, "done-0"), _record(old_dek, 1, "done-1")])
    config.SPINE_PATH.write_text("\n".join(json.dumps(r) for r in before) + "\n", encoding="utf-8")
    dek_path = config.SPINE_DEK_PATH
    dek_prev = dek_path.with_name(dek_path.name + ".prev")

    # hand-build the "spine already swapped" state: anchor = OLD dek, current dek = NEW, spine = new-ciphertext.
    shutil.copyfile(dek_path, dek_prev)                       # anchor holds the OLD sealed DEK
    new_dek = os.urandom(32)
    after = reencrypt_records(old_dek, new_dek, before)
    v.write_text_secret(dek_path, base64.b64encode(new_dek).decode("ascii"), context=env._DEK_CONTEXT)
    config.SPINE_PATH.write_text("\n".join(json.dumps(r) for r in after) + "\n", encoding="utf-8")

    res = reconcile_spine_dek(config.SPINE_PATH, v)
    assert res["status"] == "completed"
    assert not dek_prev.exists()
    cur = env.load_or_create_dek(v, create=False)
    for r in [json.loads(x) for x in config.SPINE_PATH.read_text().splitlines() if x.strip()]:
        assert env.open_payload(cur, r["payload"], scope=r["scope"], seq=r["seq"])["text"].startswith("done-")
