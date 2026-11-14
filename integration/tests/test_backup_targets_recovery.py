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
    """``framework/v2/.entitlement`` (trust root + signed entitlement + revocation list),
    ``framework/v2/.authority`` (the per-slug signed authority + a ``{slug}.halt`` kill-switch), and
    ``framework/v2/.authority-root`` (Phase 0.1: the governance authority TrustRoot that VERIFIES the signed
    authorities) at their DEFAULT in-tree locations — the trust state whose loss on restore is a
    fail-OPEN/fail-CLOSED posture regression."""
    ent = croot / "framework" / "v2" / ".entitlement"
    ent.mkdir(parents=True)
    (ent / "trust-root.json").write_text(json.dumps(_TRUST_ROOT))
    (ent / "entitlement.json").write_text(json.dumps(_ENTITLEMENT))
    (ent / "revocation.json").write_text(json.dumps({"revoked": []}))
    auth = croot / "framework" / "v2" / ".authority"
    auth.mkdir(parents=True)
    (auth / f"{SLUG}.authority.json").write_text(json.dumps(_AUTHORITY))
    (auth / f"{SLUG}.halt").write_text("halted by operator\n")
    auth_root = croot / "framework" / "v2" / ".authority-root"
    auth_root.mkdir(parents=True)
    (auth_root / "trust-root.json").write_text(json.dumps(_TRUST_ROOT))
    return ent, auth, auth_root


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


def test_create_refuses_a_leaked_evidence_key(tmp_path, monkeypatch):
    """Belt-and-braces: if a future iterator change ever yielded a keystore file, create() REFUSES rather than
    co-locate a DEK with its ciphertext."""
    # This test's premise is a DEK co-located UNDER the crucible root, so opt out of the autouse
    # _isolate_evidence_keys_dir fixture (which points CRUCIBLE_EVIDENCE_KEYS_DIR off-tree) — the documented
    # per-test override — so _evidence_keys_dir(croot) resolves to <croot>/.evidence-keys and the DEK is
    # relative_to(croot). Mirrors test_trust_state_backed_up_and_functionally_restored's delenv of the sibling
    # isolation vars.
    monkeypatch.delenv("CRUCIBLE_EVIDENCE_KEYS_DIR", raising=False)
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
def test_trust_state_backed_up_and_functionally_restored(tmp_path, monkeypatch):
    # This asserts the DEFAULT in-tree capture of the trust-state units, so opt out of the autouse per-test
    # dir-isolation fixtures (_isolate_entitlement_dir / _isolate_authority_root_dir) — with those env vars set,
    # _iter_crucible_files treats the roots as "held off-tree" and excludes them (the documented override path,
    # covered by test_entitlement_override_is_excluded_but_authority_still_captured).
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_DIR", raising=False)
    monkeypatch.delenv("VIGIL_AUTHORITY_ROOT_DIR", raising=False)
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
    # Phase 0.1: the governance authority trust root that VERIFIES the signed authorities is captured too.
    assert f"{_CRUCIBLE_PREFIX}framework/v2/.authority-root/trust-root.json" in rels, rels

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
    ar = json.loads((new_croot / "framework" / "v2" / ".authority-root" / "trust-root.json").read_text())
    assert ar["threshold"] == 2 and len(ar["authorizers"]) == 2   # FUNCTIONAL: the authority-root loads (Phase 0.1)


def test_dropping_trust_state_breaks_recovery(tmp_path, monkeypatch):
    """The RED-PEN's exact attack: a backup whose ``.entitlement``/``.authority`` files are dropped (still
    validly signed) restores the spine fine, but the trust root + destruction authority are GONE — a restore
    missing them is DETECTED (the recovered install would come up fail-OPEN, which this test refuses to accept).
    Reverting the #460 capture makes this test fail (the files were never in the backup to begin with)."""
    # Assert DEFAULT in-tree capture: opt out of the autouse per-test dir-isolation (see the sibling test).
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_DIR", raising=False)
    monkeypatch.delenv("VIGIL_AUTHORITY_ROOT_DIR", raising=False)
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
                  or r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.authority/")
                  or r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.authority-root/")]
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
    # ... and the authority TRUST ROOT is likewise EXCLUDED here — this test runs with VIGIL_AUTHORITY_ROOT_DIR
    # set (autouse isolation), so like the entitlement root it is held off-tree and not packaged (Phase 0.1).
    assert not any(r.startswith(f"{_CRUCIBLE_PREFIX}framework/v2/.authority-root/") for r in rels), rels


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


# --- E4d: the committed ``targets/_template`` scaffold is repo content, not part of the targets unit -----------

_REPO = __import__("pathlib").Path(__file__).resolve().parents[2]
_COMMITTED_TEMPLATE = _REPO / "engine" / "crucible" / "targets" / "_template"


def _tree_bytes(root):
    """Every file under ``root`` with its exact bytes (a byte-level monitor of a dir)."""
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _fresh_checkout(path, *, newer: bool = True):
    """A crucible root exactly as a fresh checkout has it: the repo's committed ``targets/_template`` and no
    engagement state. ``newer`` makes it one commit ahead of the backed-up box (a changed file + a new file)."""
    import shutil
    assert (_COMMITTED_TEMPLATE / "charter.md").is_file()
    shutil.copytree(_COMMITTED_TEMPLATE, path / "targets" / "_template")
    if newer:
        (path / "targets" / "_template" / "README.md").write_text("# template, one commit newer\n")
        (path / "targets" / "_template" / "added-in-a-newer-commit.md").write_text("new scaffold file\n")
    return path


def _backup_of_a_box_with_the_template(tmp_path):
    """An offense backup of a box whose crucible root holds the committed scaffold AND one engagement."""
    import shutil
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    shutil.copytree(_COMMITTED_TEMPLATE, croot / "targets" / "_template")
    _seed_targets(croot)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    return dest


def test_a_default_restore_onto_a_fresh_checkout_works_and_never_touches_the_template(tmp_path):
    """The audit repro: a fresh checkout ALWAYS carries ``targets/_template``, so a default restore refused with
    ``['targets']`` every time. It must restore the engagement without ``--force`` and leave the checkout's
    committed scaffold byte-identical (here one commit NEWER than the backup's)."""
    dest = _backup_of_a_box_with_the_template(tmp_path)
    fresh = _fresh_checkout(tmp_path / "checkout")
    before = _tree_bytes(fresh / "targets" / "_template")
    out = restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh)
    assert out["verified"] is True
    assert (fresh / "targets" / SLUG / "charter.md").read_text() == _CHARTER
    assert (fresh / "targets" / SLUG / "evidence" / "a-0001" / "response.bin").read_bytes() == _CRED_EVIDENCE
    assert _tree_bytes(fresh / "targets" / "_template") == before


def test_a_forced_restore_replaces_engagements_but_never_rewrites_the_template(tmp_path):
    """``--force`` over live engagements: the gate still refuses without it; with it every engagement is the
    backup's (one the backup lacks is dropped — the DR-snapshot semantic) and the committed scaffold is untouched."""
    dest = _backup_of_a_box_with_the_template(tmp_path)
    fresh = _fresh_checkout(tmp_path / "checkout")
    (fresh / "targets" / SLUG).mkdir()
    (fresh / "targets" / SLUG / "charter.md").write_text("a live charter the backup predates\n")
    (fresh / "targets" / "later-engagement").mkdir()
    (fresh / "targets" / "later-engagement" / "charter.md").write_text("made after the backup\n")
    before = _tree_bytes(fresh / "targets" / "_template")
    with pytest.raises(OffenseBackupError, match=r"refusing to overwrite live CRUCIBLE proof state \['targets'\]"):
        restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh)
    restore_offense_backup(dest, tmp_path / "rbase2", PW, crucible_root=fresh, force=True)
    assert (fresh / "targets" / SLUG / "charter.md").read_text() == _CHARTER
    assert not (fresh / "targets" / "later-engagement").exists()
    assert _tree_bytes(fresh / "targets" / "_template") == before
    assert sorted(p.name for p in (fresh / "targets").iterdir()) == ["_template", SLUG]   # no aside left behind


def test_the_template_is_never_captured_but_every_other_targets_entry_is(tmp_path):
    """The unit boundary on the CAPTURE side: no ``targets/_template`` file is packaged, while engagements, the
    archived-engagement dir ``targets/.archive`` and an operator's own ``_``-named dir are (none is repo content)."""
    import shutil
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    shutil.copytree(_COMMITTED_TEMPLATE, croot / "targets" / "_template")
    _seed_targets(croot)
    for extra in (".archive/old-engagement", "_practice"):
        (croot / "targets" / extra).mkdir(parents=True)
        (croot / "targets" / extra / "charter.md").write_text(f"{extra}\n")
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    rels = set(_decrypt_body(dest)["files"])
    assert not [r for r in rels if r.startswith(f"{_CRUCIBLE_PREFIX}targets/_template/")]
    for kept in (f"{SLUG}/charter.md", ".archive/old-engagement/charter.md", "_practice/charter.md"):
        assert f"{_CRUCIBLE_PREFIX}targets/{kept}" in rels, rels
    # and they all come back on a default restore onto a fresh checkout
    fresh = _fresh_checkout(tmp_path / "checkout", newer=False)
    restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh)
    assert (fresh / "targets" / ".archive" / "old-engagement" / "charter.md").read_text() == ".archive/old-engagement\n"
    assert (fresh / "targets" / "_practice" / "charter.md").read_text() == "_practice\n"


def test_an_older_backup_carrying_the_template_never_rewrites_it(tmp_path):
    """A backup made before this fix packaged ``targets/_template``. Restoring it (default AND ``--force``) onto a
    newer checkout must never swap that stale copy over the committed scaffold."""
    import base64

    from vigil_core import sha256_hex
    dest = _backup_of_a_box_with_the_template(tmp_path)
    body = _decrypt_body(dest)
    gov_priv = json.loads(body["secrets"][DEFAULT_GOVERNANCE_KEY_FILE])["private_key_b64"]
    for p in sorted(_COMMITTED_TEMPLATE.rglob("*")):
        if p.is_file():                                     # exactly what the pre-fix capture packaged
            rel = f"{_CRUCIBLE_PREFIX}targets/_template/{p.relative_to(_COMMITTED_TEMPLATE).as_posix()}"
            body["files"][rel] = base64.b64encode(p.read_bytes()).decode()
            body["manifest"]["file_sha256"][rel] = sha256_hex(p.read_bytes())
    body["manifest_sig"] = sign(gov_priv, canonical_json(body["manifest"]))
    salt = __import__("os").urandom(_SALT_LEN)
    dest.write_bytes(_MAGIC + salt + seal(_derive_key(PW, salt), canonical_json(body), context=_BODY_CONTEXT))
    for force in (False, True):
        fresh = _fresh_checkout(tmp_path / f"checkout-{force}")
        before = _tree_bytes(fresh / "targets" / "_template")
        restore_offense_backup(dest, tmp_path / f"rbase-{force}", PW, crucible_root=fresh, force=force)
        assert (fresh / "targets" / SLUG / "charter.md").read_text() == _CHARTER
        assert _tree_bytes(fresh / "targets" / "_template") == before, f"force={force}"


def test_the_force_gate_still_sees_engagements_behind_a_symlinked_targets_dir(tmp_path):
    """The gate follows a symlinked ``targets/`` (as it always has): a live engagement there still refuses a
    default restore — leaving the scaffold out of the unit must not turn the gate off for that layout."""
    dest = _backup_of_a_box_with_the_template(tmp_path)
    elsewhere = tmp_path / "engagements-disk"
    (elsewhere / SLUG).mkdir(parents=True)
    (elsewhere / SLUG / "charter.md").write_text("live charter\n")
    croot = tmp_path / "checkout"
    croot.mkdir()
    (croot / "targets").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(OffenseBackupError, match=r"\['targets'\]"):
        restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=croot)
    assert (elsewhere / SLUG / "charter.md").read_text() == "live charter\n"


# --- the targets unit is swapped WHOLE, whatever ``targets`` is at the destination --------------------------------

_TRUST_UNITS = (".entitlement", ".authority", ".authority-root")


def _backup_with_trust_state(tmp_path, monkeypatch):
    """A backup of a box with the scaffold, one engagement AND the three trust-state units (captured in-tree)."""
    import shutil
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_DIR", raising=False)
    monkeypatch.delenv("VIGIL_AUTHORITY_ROOT_DIR", raising=False)
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    shutil.copytree(_COMMITTED_TEMPLATE, croot / "targets" / "_template")
    _seed_targets(croot)
    _seed_trust_state(croot)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    return dest, croot


def _assert_fully_restored(src_croot, croot):
    """Every unit came back: the engagement, the committed scaffold, and all three trust-state units."""
    t = croot / "targets"
    assert (t / SLUG / "charter.md").read_text() == _CHARTER
    assert _tree_bytes(t / "_template") == _tree_bytes(_COMMITTED_TEMPLATE)
    for unit in _TRUST_UNITS:
        got = croot / "framework" / "v2" / unit
        assert _tree_bytes(got) == _tree_bytes(src_croot / "framework" / "v2" / unit), unit


def _simulate_other_filesystem(monkeypatch, other_root):
    """rename(2) across a mount: ``os.replace`` between a dirent whose DIRECTORY lies under ``other_root`` and one
    whose directory does not raises EXDEV (renaming a symlink that POINTS there is a same-filesystem rename)."""
    import errno
    import os
    from pathlib import Path
    real, other = os.replace, Path(other_root).resolve()

    def on_other(p):
        d = Path(os.path.abspath(p)).parent.resolve()
        return d == other or other in d.parents

    def replace(src, dst, *a, **k):
        if on_other(src) != on_other(dst):
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), str(src), None, str(dst))
        return real(src, dst, *a, **k)
    monkeypatch.setattr(os, "replace", replace)


@pytest.fixture(params=["simulated", "real"])
def other_filesystem(request, tmp_path, monkeypatch):
    """A directory on ANOTHER filesystem: a real tmpfs (``/dev/shm``) when it is a different device, else skipped;
    and always a simulated one (EXDEV injected exactly where rename(2) would return it)."""
    import os
    import shutil
    import tempfile
    from pathlib import Path
    if request.param == "simulated":
        d = tmp_path / "other-fs"
        d.mkdir()
        _simulate_other_filesystem(monkeypatch, d)
        yield d
        return
    shm = Path("/dev/shm")
    if not shm.is_dir() or not os.access(shm, os.W_OK):
        pytest.skip("no writable /dev/shm")
    d = Path(tempfile.mkdtemp(prefix="vigil-targets-", dir=str(shm)))
    try:
        if os.stat(d).st_dev == os.stat(tmp_path).st_dev:
            pytest.skip("/dev/shm is on the same filesystem as the test tmp dir")
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize("force", [False, True])
def test_a_restore_onto_targets_linked_to_another_filesystem_completes(tmp_path, monkeypatch, other_filesystem,
                                                                        force):
    """``targets/`` is a symlink onto another filesystem (an evidence volume). A per-entry swap THROUGH the link
    raised EXDEV after the base dir, the db and the runs had been swapped, leaving the trust units unrestored (and
    under ``--force`` deleted engagements on the volume, outside crucible_root). The unit is swapped whole: the
    restore completes, and nothing on the volume is written or deleted."""
    import shutil
    dest, src_croot = _backup_with_trust_state(tmp_path, monkeypatch)
    vol = other_filesystem / "targets"
    shutil.copytree(_COMMITTED_TEMPLATE, vol / "_template")
    if force:                                            # live engagements on the volume: --force is required
        (vol / SLUG).mkdir()
        (vol / SLUG / "charter.md").write_text("a live charter the backup predates\n")
        (vol / "later-engagement").mkdir()
        (vol / "later-engagement" / "charter.md").write_text("made after the backup\n")
    on_volume = _tree_bytes(vol)
    croot = tmp_path / "checkout"
    croot.mkdir()
    (croot / "targets").symlink_to(vol, target_is_directory=True)
    out = restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=croot, force=force)
    assert out["verified"] is True
    _assert_fully_restored(src_croot, croot)
    assert _tree_bytes(vol) == on_volume                 # never written or deleted THROUGH the link
    assert sorted(p.name for p in croot.iterdir()) == ["framework", "targets"]    # no aside / staging debris


@pytest.mark.parametrize("shape", ["dangling_symlink", "regular_file"])
def test_a_non_directory_targets_is_replaced_whole_never_half_restored(tmp_path, monkeypatch, shape):
    """A dangling ``targets`` link or a regular file passes the force-gate (no engagement in it). The per-entry
    swap then failed after the base, db and runs swaps; the whole-unit swap restores every unit."""
    dest, src_croot = _backup_with_trust_state(tmp_path, monkeypatch)
    croot = tmp_path / "checkout"
    croot.mkdir()
    if shape == "dangling_symlink":
        (croot / "targets").symlink_to(tmp_path / "gone", target_is_directory=True)
    else:
        (croot / "targets").write_text("not a directory\n")
    out = restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=croot)
    assert out["verified"] is True
    assert (croot / "targets" / SLUG / "charter.md").read_text() == _CHARTER
    for unit in _TRUST_UNITS:
        assert _tree_bytes(croot / "framework" / "v2" / unit) == _tree_bytes(src_croot / "framework" / "v2" / unit)
    assert not (tmp_path / "gone").exists()


def test_a_scaffold_that_cannot_be_carried_refuses_before_anything_is_swapped(tmp_path, monkeypatch):
    """Carrying the destination's scaffold into the staged unit happens BEFORE the base swap, so a copy failure is a
    clean OffenseBackupError with every destination still the complete old state."""
    dest, _src = _backup_with_trust_state(tmp_path, monkeypatch)
    fresh = _fresh_checkout(tmp_path / "checkout")
    before = _tree_bytes(fresh)

    def broken(*a, **k):
        raise OSError("read error on the scaffold")
    monkeypatch.setattr(ob.shutil, "copytree", broken)
    with pytest.raises(OffenseBackupError, match="nothing was swapped"):
        restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh)
    assert not (tmp_path / "rbase").exists() and _tree_bytes(fresh) == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]


def test_a_forced_restore_of_a_backup_with_no_engagement_still_drops_later_ones(tmp_path):
    """The scaffold is never packaged, so a box whose ``targets/`` held only the scaffold packs NO targets file.
    The signed manifest still records the unit as captured, so ``--force`` keeps the DR-snapshot semantic (an
    engagement the backup lacks is dropped) instead of depending on whether the backup happened to hold one; the
    default restore still refuses over it; the committed scaffold stays byte-identical."""
    import shutil
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    shutil.copytree(_COMMITTED_TEMPLATE, croot / "targets" / "_template")        # no engagement, no other state
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    body = _decrypt_body(dest)
    assert not [r for r in body["files"] if r.startswith(_CRUCIBLE_PREFIX)]
    assert body["manifest"][ob._TARGETS_UNIT_MANIFEST_FLAG] is True
    fresh = _fresh_checkout(tmp_path / "checkout")
    (fresh / "targets" / "planted").mkdir()
    (fresh / "targets" / "planted" / "charter.md").write_text("made after the backup\n")
    before = _tree_bytes(fresh / "targets" / "_template")
    with pytest.raises(OffenseBackupError, match=r"\['targets'\]"):
        restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh)
    restore_offense_backup(dest, tmp_path / "rbase2", PW, crucible_root=fresh, force=True)
    assert sorted(p.name for p in (fresh / "targets").iterdir()) == ["_template"]
    assert _tree_bytes(fresh / "targets" / "_template") == before


def test_a_backup_that_never_captured_targets_leaves_them_untouched(tmp_path):
    """Control for the flag: capture never follows a symlinked ``targets/``, so that backup did NOT cover the unit
    — a ``--force`` restore of it must not drop the destination's engagements."""
    base = tmp_path / "base"
    _seed_offense_home(base)
    croot = tmp_path / "crucible"
    runs = croot / "framework" / "v2" / ".console" / "runs" / "r1"
    runs.mkdir(parents=True)
    (runs / "report.json").write_text("{}\n")                                    # other crucible state
    elsewhere = tmp_path / "engagements-disk"
    (elsewhere / SLUG).mkdir(parents=True)
    (elsewhere / SLUG / "charter.md").write_text(_CHARTER)
    (croot / "targets").symlink_to(elsewhere, target_is_directory=True)
    dest = tmp_path / "off.vglbk"
    create_offense_backup(dest, PW, base_dir=base, crucible_root=croot)
    body = _decrypt_body(dest)
    assert ob._TARGETS_UNIT_MANIFEST_FLAG not in body["manifest"]
    assert not [r for r in body["files"] if r.startswith(f"{_CRUCIBLE_PREFIX}targets/")]
    fresh = _fresh_checkout(tmp_path / "checkout")
    (fresh / "targets" / "planted").mkdir()
    (fresh / "targets" / "planted" / "charter.md").write_text("live engagement\n")
    restore_offense_backup(dest, tmp_path / "rbase", PW, crucible_root=fresh, force=True)
    assert (fresh / "targets" / "planted" / "charter.md").read_text() == "live engagement\n"
    assert (fresh / "framework" / "v2" / ".console" / "runs" / "r1" / "report.json").is_file()


def test_the_scaffold_set_is_exactly_the_committed_targets_content():
    """Pin ``_CRUCIBLE_TARGETS_SCAFFOLD`` to the repo: every tracked path under ``engine/crucible/targets/`` lies
    in a scaffold entry, and every scaffold entry is tracked. A new committed entry there must be added to the set
    (or a fresh checkout's restore refuses again)."""
    import shutil
    import subprocess
    if shutil.which("git") is None:
        pytest.skip("git is not available")
    r = subprocess.run(["git", "-C", str(_REPO), "ls-files", "engine/crucible/targets"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        pytest.skip("not a git checkout")
    top = {line.split("/")[3] for line in r.stdout.splitlines() if line.count("/") >= 3}
    assert top == set(ob._CRUCIBLE_TARGETS_SCAFFOLD), top
