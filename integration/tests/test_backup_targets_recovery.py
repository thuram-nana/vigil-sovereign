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
    defence-in-depth) — ``test_create_refuses_a_leaked_evidence_key``;
  * (#460) the entitlement TRUST ROOT (``framework/v2/.entitlement``) and the DestructionAuthority
    (``framework/v2/.authority``) are backed up + functionally restored, a restore MISSING them is DETECTED
    (dropping them is a fail-OPEN posture regression), and an off-tree ``CRUCIBLE_ENTITLEMENT_DIR`` override is
    a documented exclusion — ``test_trust_state_*`` / ``test_dropping_trust_state_breaks_recovery`` /
    ``test_entitlement_override_is_excluded_but_authority_still_captured``;
  * (#460) the W16-8 co-location skip + create-time leak assertion now also cover the BASE tree —
    ``test_base_evidence_keystore_relocated_under_base_is_never_packaged`` /
    ``test_create_refuses_a_leaked_evidence_key_from_the_base_tree``.

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


# W7-2 (#460): the entitlement TRUST ROOT + the DestructionAuthority — trust state a functional recovery needs.
_TRUST_ROOT = {"threshold": 2, "authorizers": [{"key_id": "owner", "public_key_b64": "AAAA"},
                                               {"key_id": "second", "public_key_b64": "BBBB"}]}
_ENTITLEMENT = {"scope": ["127.0.0.1"], "signatures": [{"key_id": "owner", "signature_b64": "sig"}]}
_AUTHORITY = {"engagement_slug": SLUG, "scope": ["127.0.0.1"], "max_actions": 10000}


def _seed_trust_state(croot):
    """``framework/v2/.entitlement`` (trust root + signed entitlement + revocation list) and
    ``framework/v2/.authority`` (the per-slug signed authority + a ``{slug}.halt`` kill-switch) at their
    DEFAULT in-tree locations — the trust state whose loss on restore is a fail-OPEN posture regression."""
    ent = croot / "framework" / "v2" / ".entitlement"
    ent.mkdir(parents=True)
    (ent / "trust-root.json").write_text(json.dumps(_TRUST_ROOT))
    (ent / "entitlement.json").write_text(json.dumps(_ENTITLEMENT))
    (ent / "revocation.json").write_text(json.dumps({"revoked": []}))
    auth = croot / "framework" / "v2" / ".authority"
    auth.mkdir(parents=True)
    (auth / f"{SLUG}.authority.json").write_text(json.dumps(_AUTHORITY))
    (auth / f"{SLUG}.halt").write_text("halted by operator\n")
    return ent, auth


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


# ---------------------------------------------------------------------------------------------------
# W7-2 (#460): the entitlement TRUST ROOT + the DestructionAuthority are backed up + functionally restored,
# and a restore MISSING them is detected (the BLOCK: dropping them is a fail-OPEN posture regression).
# ---------------------------------------------------------------------------------------------------
def test_trust_state_backed_up_and_functionally_restored(tmp_path):
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    _seed_trust_state(croot)

    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    body = _decrypt_body(dest)
    rels = set(body["files"])
    # the entitlement trust root + the destruction authority + the kill-switch are all in the signed file table.
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.entitlement/trust-root.json" in rels, rels
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.entitlement/entitlement.json" in rels, rels
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.entitlement/revocation.json" in rels, rels
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.authority/{SLUG}.authority.json" in rels, rels
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.authority/{SLUG}.halt" in rels, rels

    # restore into FRESH dirs and prove the trust root + authority come back and PARSE (functional, not present).
    new_base = tmp_path / "rbase"
    new_croot = tmp_path / "rcrucible"
    out = restore_offense_backup(dest, new_base, PW, crucible_root=new_croot)
    assert out["verified"] is True
    tr = json.loads((new_croot / "framework" / "v2" / ".entitlement" / "trust-root.json").read_text())
    assert tr["threshold"] == 2 and len(tr["authorizers"]) == 2          # FUNCTIONAL: the trust root loads
    auth = json.loads((new_croot / "framework" / "v2" / ".authority" / f"{SLUG}.authority.json").read_text())
    assert auth["engagement_slug"] == SLUG                               # FUNCTIONAL: the authority loads
    assert (new_croot / "framework" / "v2" / ".authority" / f"{SLUG}.halt").exists()   # kill-switch survives


def test_dropping_trust_state_breaks_recovery(tmp_path):
    """The RED-PEN's exact attack: a backup whose ``.entitlement``/``.authority`` files are dropped (still
    validly signed) restores the spine fine, but the trust root + destruction authority are GONE — a restore
    missing them is DETECTED (the recovered install would come up fail-OPEN, which this test refuses to accept).
    Reverting the #460 capture makes this test fail (the files were never in the backup to begin with)."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    _seed_trust_state(croot)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)

    body = _decrypt_body(dest)
    # sanity: the FULL backup DID carry the trust state (so the drop below is a real removal, not a no-op —
    # this is the assertion that goes red if #460's capture is reverted).
    trust_rels = [r for r in body["files"]
                  if r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.entitlement/")
                  or r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.authority/")]
    assert trust_rels, "the backup must carry the entitlement/authority trust state before we can drop it"

    # drop every entitlement/authority file, then RE-SIGN the manifest with the governance key carried in the
    # body (a valid backup that simply omitted the trust state — not a tamper).
    gov_priv = json.loads(body["secrets"][DEFAULT_GOVERNANCE_KEY_FILE])["private_key_b64"]
    for r in trust_rels:
        body["files"].pop(r)
        body["manifest"]["file_sha256"].pop(r)
    body["manifest_sig"] = sign(gov_priv, canonical_json(body["manifest"]))
    salt = __import__("os").urandom(_SALT_LEN)
    dest.write_bytes(_MAGIC + salt + seal(_derive_key(PW, salt), canonical_json(body), context=_BODY_CONTEXT))

    new_base = tmp_path / "rbase"
    new_croot = tmp_path / "rcrucible"
    out = restore_offense_backup(dest, new_base, PW, crucible_root=new_croot)
    assert out["verified"] is True                                       # the spine still restores + re-verifies
    # DETECTED: the trust root + destruction authority are absent — recovery is NOT functional / is fail-OPEN.
    assert not (new_croot / "framework" / "v2" / ".entitlement" / "trust-root.json").exists()
    assert not (new_croot / "framework" / "v2" / ".authority" / f"{SLUG}.authority.json").exists()


def test_entitlement_override_is_excluded_but_authority_still_captured(tmp_path):
    """An off-tree CRUCIBLE_ENTITLEMENT_DIR is a DOCUMENTED exclusion (the operator keeps the trust root on a
    separate secure mount, re-provisioned on restore) — so it is NOT packaged; the in-tree authority still is."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    croot.mkdir()
    _seed_targets(croot)
    _seed_trust_state(croot)
    off_mount = tmp_path / "secure-mount" / "entitlement"
    off_mount.mkdir(parents=True)
    (off_mount / "trust-root.json").write_text(json.dumps(_TRUST_ROOT))

    dest = tmp_path / "off.vglbk"
    monkey = pytest.MonkeyPatch()
    monkey.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(off_mount))
    try:
        create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    finally:
        monkey.undo()
    body = _decrypt_body(dest)
    rels = set(body["files"])
    # the relocated entitlement material is NOT in the backup (documented exclusion) ...
    assert not any("secure-mount" in r for r in rels)
    assert not any(r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.entitlement/") for r in rels), rels
    # ... but the DestructionAuthority (no override; always in-tree) still IS captured.
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.authority/{SLUG}.authority.json" in rels, rels


# ---------------------------------------------------------------------------------------------------
# W16-8 (MEDIUM): the co-location skip + create-time leak assertion now cover the BASE sources too.
# ---------------------------------------------------------------------------------------------------
def test_base_evidence_keystore_relocated_under_base_is_never_packaged(tmp_path):
    """If CRUCIBLE_EVIDENCE_KEYS_DIR relocates the crypto-shred keystore UNDER base_dir, _iter_base_files skips
    it — the DEK never travels next to the ciphertext even from the base tree."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    keys_dir = base / "nested" / ".evidence-keys"
    _seed_keystore(keys_dir)

    dest = tmp_path / "off.vglbk"
    monkey = pytest.MonkeyPatch()
    monkey.setenv("CRUCIBLE_EVIDENCE_KEYS_DIR", str(keys_dir))
    try:
        create_offense_backup(dest, PW, base_dir=base)      # base-only backup, no crucible_root
    finally:
        monkey.undo()
    body = _decrypt_body(dest)
    assert not any(".evidence-keys" in r for r in body["files"]), [r for r in body["files"] if ".evidence-keys" in r]
    import base64
    for b64 in body["files"].values():
        assert _DEK not in base64.b64decode(b64)


def test_create_refuses_a_leaked_evidence_key_from_the_base_tree(tmp_path):
    """Belt-and-braces: the create-time leak assertion now covers the BASE sources — an iterator that yields a
    keystore file from base_dir is REFUSED, not silently packaged next to the ciphertext it seals."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    keys_dir = base / "nested" / ".evidence-keys"
    _seed_keystore(keys_dir)
    leaked_abs = keys_dir / f"{SLUG}.dek"
    leaked_rel = leaked_abs.relative_to(base).as_posix()

    real = ob._iter_base_files

    def _leaky(b, *, evidence_keys_dir=None):
        yield from real(b, evidence_keys_dir=None)          # bypass the skip so the DEK reaches the source list
        yield leaked_abs, leaked_rel

    ob._iter_base_files = _leaky
    monkey = pytest.MonkeyPatch()
    monkey.setenv("CRUCIBLE_EVIDENCE_KEYS_DIR", str(keys_dir))
    try:
        with pytest.raises(OffenseBackupError, match="crypto-shred"):
            create_offense_backup(tmp_path / "leak.vglbk", PW, base_dir=base)
    finally:
        ob._iter_base_files = real
        monkey.undo()
