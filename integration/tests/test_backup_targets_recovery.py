"""W7-2 (offense leg) — the ``targets/`` engagement tree is backed up + functionally restored, and the
W16-8 crypto-shred EVIDENCE KEYSTORE is NEVER packaged next to the ciphertext it seals.

The offense backup used to capture only ``.blackboard/store.sqlite`` + ``.console/runs`` under crucible_root,
omitting the ENTIRE ``targets/`` tree — every charter and every byte of per-action HTTP evidence. A restore
lost all client engagement evidence. This suite proves:

  * ``targets/<slug>/`` (charter + evidence bytes) is packaged and restored, and a restored charter LOADS with
    its real content (functional, not merely present) — ``test_targets_tree_backed_up_and_functionally_restored``;
  * NEGATIVE control (per item): dropping the targets unit FROM THE BACKUP (re-signed with the governance key
    so the drop is otherwise valid) makes the charter irrecoverable — ``test_dropping_targets_breaks_recovery``;
  * the W16-8 rule: the per-engagement DEK keystore is NEVER in the backup — even when
    ``CRUCIBLE_EVIDENCE_KEYS_DIR`` relocates it UNDER a captured tree — ``test_evidence_keystore_is_never_packaged``;
  * a forced leak (an iterator that yields a keystore file) is REFUSED at create time (belt-and-braces
    defence-in-depth) — ``test_create_refuses_a_leaked_evidence_key``.

Needs framework (the restore's evidence re-verify import) → run in the OFFENSE leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_targets_recovery.py -q
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("framework.v2.evidence.cli")   # this suite only runs where `framework` is importable

from vigil_core import canonical_json, sign
from vigil_core.sealing import seal
from vigil_integration import backup as ob
from vigil_integration.backup import (
    OffenseBackupError,
    _BODY_CONTEXT,
    _CRUCIBLE_PREFIX,
    _MAGIC,
    _SALT_LEN,
    _derive_key,
    _read_header,
    create_offense_backup,
    restore_offense_backup,
)
from vigil_integration.live.governance_identity import DEFAULT_GOVERNANCE_KEY_FILE

from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore  # noqa: E402

_CHARTER = f"# Engagement charter for {SLUG}\n\n## 2. In-scope systems\n- 127.0.0.1 (owner-authorized)\n"
_CRED_EVIDENCE = b"GET /admin HTTP/1.1\r\nAuthorization: Bearer SECRET-TARGET-TOKEN\r\n\r\n"
_DEK = b"\x11" * 32   # a fake per-engagement crypto-shred DEK


def _seed_targets(croot):
    """A ``targets/<slug>/`` engagement tree: a charter, a note, and a per-action HTTP evidence capture that
    holds a real Authorization header (exactly the credential-bearing sink W16-8 governs)."""
    t = croot / "targets" / SLUG
    (t / "notes").mkdir(parents=True)
    (t / "charter.md").write_text(_CHARTER)
    (t / "notes" / "engagement-log.md").write_text("recon complete\n")
    ev = t / "evidence" / "a-0001"
    ev.mkdir(parents=True)
    (ev / "response.bin").write_bytes(_CRED_EVIDENCE)


def _seed_keystore(keys_dir):
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / f"{SLUG}.dek").write_bytes(_DEK)


def _decrypt_body(dest):
    salt, sealed = _read_header(dest)
    from vigil_core.sealing import unseal
    return json.loads(unseal(_derive_key(PW, salt), sealed, context=_BODY_CONTEXT))


def test_targets_tree_backed_up_and_functionally_restored(tmp_path):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)

    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    body = _decrypt_body(dest)
    rels = set(body["files"])
    assert f"{_CRUCIBLE_PREFIX}targets/{SLUG}/charter.md" in rels, rels
    assert f"{_CRUCIBLE_PREFIX}targets/{SLUG}/evidence/a-0001/response.bin" in rels, rels

    # restore into FRESH dirs and prove the charter is functionally usable + the evidence bytes survive.
    new_base = tmp_path / "rbase"
    new_croot = tmp_path / "rcrucible"
    out = restore_offense_backup(dest, new_base, PW, crucible_root=new_croot)
    assert out["verified"] is True
    charter = (new_croot / "targets" / SLUG / "charter.md").read_text()
    assert "In-scope systems" in charter and SLUG in charter        # FUNCTIONAL: the charter loads + parses
    assert (new_croot / "targets" / SLUG / "evidence" / "a-0001" / "response.bin").read_bytes() == _CRED_EVIDENCE


def test_dropping_targets_breaks_recovery(tmp_path):
    """PER-ITEM negative control: a backup with the targets unit removed (still validly signed) restores the
    spine fine but cannot recover the charter — proving targets coverage has teeth."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)

    body = _decrypt_body(dest)
    # drop every targets/* file, then RE-SIGN the manifest with the governance key carried in the body (a valid
    # backup that simply omitted the targets unit — not a tamper).
    gov_priv = json.loads(body["secrets"][DEFAULT_GOVERNANCE_KEY_FILE])["private_key_b64"]
    drop = [r for r in body["files"] if r.startswith(f"{_CRUCIBLE_PREFIX}targets/")]
    assert drop, "fixture must contain targets files to drop"
    for r in drop:
        body["files"].pop(r)
        body["manifest"]["file_sha256"].pop(r)
    body["manifest_sig"] = sign(gov_priv, canonical_json(body["manifest"]))
    salt = __import__("os").urandom(_SALT_LEN)
    dest.write_bytes(_MAGIC + salt + seal(_derive_key(PW, salt), canonical_json(body), context=_BODY_CONTEXT))

    new_base = tmp_path / "rbase"
    new_croot = tmp_path / "rcrucible"
    out = restore_offense_backup(dest, new_base, PW, crucible_root=new_croot)
    assert out["verified"] is True                                  # the spine still restores + re-verifies
    assert not (new_croot / "targets" / SLUG / "charter.md").exists()   # but the charter is gone


def test_evidence_keystore_is_never_packaged(tmp_path):
    """W16-8: the crypto-shred DEK keystore is excluded from the backup — even when relocated UNDER a captured
    tree by CRUCIBLE_EVIDENCE_KEYS_DIR — so an erasure-by-key-destruction cannot be undone from the backup."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    # relocate the keystore to sit INSIDE the captured targets tree — the hostile case the skip must survive.
    keys_dir = croot / "targets" / SLUG / ".evidence-keys"
    _seed_keystore(keys_dir)

    dest = tmp_path / "off.vglbk"
    monkey = pytest.MonkeyPatch()
    monkey.setenv("CRUCIBLE_EVIDENCE_KEYS_DIR", str(keys_dir))
    try:
        create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    finally:
        monkey.undo()

    body = _decrypt_body(dest)
    # no packaged rel is under the keystore, and the raw DEK bytes appear nowhere in the packaged blobs.
    assert not any(".evidence-keys" in r for r in body["files"]), [r for r in body["files"] if ".evidence-keys" in r]
    import base64
    for b64 in body["files"].values():
        assert _DEK not in base64.b64decode(b64)
    # the charter (a sibling of the keystore) IS still captured — only the keystore is excluded.
    assert f"{_CRUCIBLE_PREFIX}targets/{SLUG}/charter.md" in body["files"]

    # and a restore does NOT resurrect the DEK into the fresh crucible root.
    monkey2 = pytest.MonkeyPatch()
    monkey2.setenv("CRUCIBLE_EVIDENCE_KEYS_DIR", str(tmp_path / "rcrucible" / "targets" / SLUG / ".evidence-keys"))
    try:
        restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=tmp_path / "rcrucible")
    finally:
        monkey2.undo()
    assert not (tmp_path / "rcrucible" / "targets" / SLUG / ".evidence-keys" / f"{SLUG}.dek").exists()


def test_create_refuses_a_leaked_evidence_key(tmp_path):
    """Belt-and-braces: if a future iterator change ever yielded a keystore file, create() REFUSES rather than
    co-locate a DEK with its ciphertext."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    keys_dir = ob._evidence_keys_dir(croot)
    _seed_keystore(keys_dir)
    leaked_abs = keys_dir / f"{SLUG}.dek"
    leaked_rel = _CRUCIBLE_PREFIX + leaked_abs.relative_to(croot).as_posix()

    real = ob._iter_crucible_files

    def _leaky(c):
        yield from real(c)
        yield leaked_abs, leaked_rel        # force the DEK into the source list

    ob._iter_crucible_files = _leaky
    try:
        with pytest.raises(OffenseBackupError, match="crypto-shred"):
            create_offense_backup(tmp_path / "leak.vglbk", PW, base_dir=base, crucible_root=croot)
    finally:
        ob._iter_crucible_files = real
