"""W7-2 — back up EVERYTHING recovery needs, and prove a restored install is FUNCTIONAL (not merely present).

The G3(a) backup used to omit ``witness.trust.json`` (the roster the HA failover guard depends on),
``secrets.sealed`` (the sealed KV secret store), ``sigil.env`` (persisted config / legacy secret tier),
``budgets.json`` (governor caps), and the ``qdrant/`` + ``graph/`` memory stores. A restore produced an
install that was *present* but not *functional* and lost operator config. This suite proves the new coverage:

  * every named omission is packaged into the backup (``test_every_named_omission_is_covered`` — FAILS on a
    pre-W7-2 tree, so the change is observed, not assumed);
  * a restore into a FRESH home brings the install up and EXERCISES a real operation per item — the spine head
    re-verifies, the governor loads its caps, the witness roster loads + verifies, the KV secret decrypts, the
    sigil.env / qdrant / graph bytes are back (``test_restore_is_functional``);
  * a PER-ITEM negative control: deliberately dropping ONE covered item FROM THE BACKUP (re-signed with the
    owner key so the drop is otherwise valid) makes exactly that item's functional check fail
    (``test_dropping_a_covered_item_breaks_its_functional_check``) — the coverage gate is not a no-op;
  * the coverage CONTRACT is structural: a populated home leaves NO top-level entry unclassified, and an
    unknown new artifact IS flagged (``test_coverage_contract_*``), so a future omission is a forced decision.

Runs in the REQUIRED ``sigil-governor`` CI job (the whole ``apps/sigil/tests/`` dir; pure-Python, no Rust
kernel / heavy deps). Sovereign-only — never imports ``framework``/offense (FATAL-2 clean).
"""
from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from vigil_core.sealing import seal, unseal

from sigil import backup
from sigil.backup import BackupError, create_backup, restore_backup
from sigil.governor.core import _load_caps
from sigil.reuse import canonical_json, generate_keypair, sign
from sigil.reuse.chain import sign_head
from sigil.spine.store import SpineStore
from sigil.spine.witness import load_roster, set_roster
from vigil_core.kek import TpmResult
from vigil_core.vault import Vault

PW = "correct horse battery staple W7-2"
SCOPE = "sigil"
_KV = {"SIGIL_ANTHROPIC_API_KEY": "sk-ant-RECOVER-ME", "vault/acme/password": "hunter2"}


def make_fake_tpm():
    """A deterministic in-process stand-in for the tpm2 CLI (no real TPM in CI). Each Vault seals under its
    OWN generated KEK held in its OWN vault dir — two vaults => two KEKs, exactly like two machines."""
    from pathlib import Path

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


def _make_full_source(tmp_path, *, provision=True):
    """A source SIGIL_HOME with EVERY W7-2-covered artifact: a signed 2-record spine, owner key, DEK, the
    sealed KV store, the config files (witness roster + budgets + sigil.env), and the qdrant/graph state.
    Returns (src, vault, owner, witness_kp)."""
    owner = generate_keypair()
    witness_kp = generate_keypair()          # an INDEPENDENT witness (a paired device) => a real quorum roster
    src = tmp_path / "src"
    store = SpineStore(str(src / "spine" / "spine.jsonl"))
    store.append(kind="message", source="c", actor="u", payload={"text": "memory one"})
    store.append(kind="decision", source="c", actor="u", payload={"text": "memory two"})
    head = sign_head(store.entries(), engagement_slug=SCOPE, signers=[("owner", owner.private_key_b64)])
    (src / "spine" / "head.json").write_text(head.model_dump_json())
    keys = src / "spine" / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "owner.pub").write_text(owner.public_key_b64)

    v = Vault(src / "vault", make_fake_tpm())
    if provision:
        v.provision()
    v.write_text_secret(keys / "owner.priv", owner.private_key_b64, context=backup._OWNER_PRIV_CONTEXT)
    v.write_text_secret(keys / "spine.dek", base64.b64encode(b"D" * 32).decode(), context=backup._DEK_CONTEXT)
    # the sealed KV secret store (operator API keys) — sealed through the SOURCE vault, like the real store.
    v.write_text_secret(src / "secrets.sealed", json.dumps(_KV), context=backup._SECRETS_KV_CONTEXT)

    # config: an owner-signed witness roster naming an INDEPENDENT witness, the governor caps, the env file.
    set_roster([{"key_id": "owner", "public_key_b64": owner.public_key_b64},
                {"key_id": "phone", "public_key_b64": witness_kp.public_key_b64}],
               threshold=2, path=src / "witness.trust.json", owner_key=owner, scope=SCOPE)
    (src / "budgets.json").write_text(json.dumps({"daily_actions": 42, "daily_cost_usd": 3.5}))
    (src / "sigil.env").write_text("SIGIL_QDRANT_URL=http://127.0.0.1:6333\n")
    (src / "floor.json").write_text(json.dumps({"seq": 2}))
    (src / "security.manifest.json").write_text(json.dumps({"v": 1}))
    # a minimal WARDEN permission-kernel dir (kernel key rides sealed, re-created 0600 on restore)
    (src / "warden").mkdir()
    (src / "warden" / "tools.json").write_text("{}")
    (src / "warden" / "warden.key").write_text("WARDEN-KERNEL-KEY")

    # memory state: opaque bytes under qdrant/ and graph/ (no real Qdrant/Kùzu needed to prove the capture).
    (src / "qdrant" / "collection").mkdir(parents=True)
    (src / "qdrant" / "collection" / "storage.bin").write_bytes(b"QDRANT-VECTORS-\x00\x01\x02")
    (src / "graph" / "current").mkdir(parents=True)
    (src / "graph" / "current" / "kuzu.db").write_bytes(b"KUZU-GRAPH-MIRROR")
    return src, v, owner, witness_kp


# ---------------------------------------------------------------------------------------------------
# COVERAGE: every named omission is actually packaged (this FAILS on a pre-W7-2 tree).
# ---------------------------------------------------------------------------------------------------
def _decrypt_body(dest):
    salt, sealed = backup._read_header(dest)
    return json.loads(unseal(backup._derive_key(PW, salt), sealed, context=backup._BODY_CONTEXT))


def test_every_named_omission_is_covered(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    res = create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    assert res["secrets_kv"] is True
    body = _decrypt_body(dest)
    rels = set(body["files"])
    # the config files + memory subtrees are in the signed file table
    assert "witness.trust.json" in rels
    assert "budgets.json" in rels
    assert "sigil.env" in rels
    assert any(r.startswith("qdrant/") for r in rels), rels
    assert any(r.startswith("graph/") for r in rels), rels
    # the KV secret store is RE-WRAPPED (portable), and — the W16-8 co-location rule — its ciphertext is
    # NEVER packaged as a raw file entry: only the plaintext, re-sealed on restore under the NEW vault.
    assert body["manifest"]["has_secrets_kv"] is True
    assert isinstance(body.get("secrets_kv_b64"), str) and body["secrets_kv_b64"]
    assert "secrets.sealed" not in rels
    # and the whole CAPTURED contract is satisfied for this fully-populated home.
    covered = rels | ({"secrets.sealed"} if body["manifest"]["has_secrets_kv"] else set())
    covered_units = {r.split("/", 1)[0] for r in covered}
    assert backup.CAPTURED_TOP_LEVEL <= covered_units, backup.CAPTURED_TOP_LEVEL - covered_units


def test_secrets_sealed_ciphertext_is_never_packaged_as_a_raw_file(tmp_path):
    """W16-8 defence-in-depth: create() refuses if the sealed KV ciphertext would ride as a raw file entry
    (the DEK/ciphertext co-location rule) — proven by forcing _spine_files to include it."""
    src, v, owner, _w = _make_full_source(tmp_path)
    real = backup._spine_files

    def _leaky(home):
        out = real(home)
        f = home / backup._SECRETS_KV_FILE
        if f.is_file():
            out.append((f, backup._SECRETS_KV_FILE))
        return out

    backup._spine_files = _leaky
    try:
        with pytest.raises(BackupError, match="re-wrapped from plaintext"):
            create_backup(tmp_path / "leak.sglbk", PW, home=src, vault=v, owner_key=owner)
    finally:
        backup._spine_files = real


# ---------------------------------------------------------------------------------------------------
# FUNCTIONAL restore: a restored install is USABLE, per item (not merely present).
# ---------------------------------------------------------------------------------------------------
def _restore(tmp_path, dest, *, provision=True, name="restored"):
    new = tmp_path / name
    rv = Vault(new / "vault", make_fake_tpm())
    if provision:
        rv.provision()
    out = restore_backup(dest, new, PW, vault=rv)
    return new, rv, out


def _assert_functional(new, rv, owner):
    """Every item's REAL operation works on the restored home. Raises AssertionError otherwise."""
    # 1. spine: the restore already re-verified the chain; confirm the records + head are back and load.
    recs = [r.payload["text"] for r in SpineStore(str(new / "spine" / "spine.jsonl")).iter_records()]
    assert recs == ["memory one", "memory two"], recs
    assert json.loads((new / "spine" / "head.json").read_text())["engagement_slug"] == SCOPE
    # 2. owner key + DEK recovered through the NEW vault
    assert rv.read_text_secret(new / "spine" / "keys" / "owner.priv",
                               context=backup._OWNER_PRIV_CONTEXT) == owner.private_key_b64
    # 3. KV secret store: decrypts through the NEW vault to the exact secrets
    kv = rv.read_text_secret(new / "secrets.sealed", context=backup._SECRETS_KV_CONTEXT)
    assert kv is not None and json.loads(kv) == _KV
    # 4. witness roster: loads + verifies against the owner key, and carries the independent witness
    roster = load_roster(new / "witness.trust.json", owner_pub=owner.public_key_b64, scope=SCOPE)
    assert roster is not None and roster["threshold"] == 2 and len(roster["authorizers"]) == 2
    # 5. governor caps: the REAL loader reads the restored budgets.json (SIGIL_HOME pointed at the new home)
    import sigil.config as _cfg
    _saved = _cfg.SIGIL_HOME
    _cfg.SIGIL_HOME = new
    try:
        caps = _load_caps()
    finally:
        _cfg.SIGIL_HOME = _saved
    assert caps.daily_actions == 42 and caps.daily_cost_usd == 3.5
    # 6. config + memory bytes are back verbatim
    assert (new / "sigil.env").read_text() == "SIGIL_QDRANT_URL=http://127.0.0.1:6333\n"
    assert (new / "qdrant" / "collection" / "storage.bin").read_bytes() == b"QDRANT-VECTORS-\x00\x01\x02"
    assert (new / "graph" / "current" / "kuzu.db").read_bytes() == b"KUZU-GRAPH-MIRROR"


def test_restore_is_functional(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    new, rv, out = _restore(tmp_path, dest)
    assert out["verified"] is True and out["secrets_kv"] is True
    _assert_functional(new, rv, owner)


def test_sigil_env_restored_0600(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    new, _rv, _out = _restore(tmp_path, dest)
    mode = stat.S_IMODE((new / "sigil.env").stat().st_mode)
    assert mode == 0o600, oct(mode)      # holds a potential signing secret → never world-readable


# ---------------------------------------------------------------------------------------------------
# PER-ITEM NEGATIVE CONTROL: drop one covered item FROM THE BACKUP → its functional check fails.
# ---------------------------------------------------------------------------------------------------
def _rewrite_backup(dest, owner, *, drop_files=(), drop_secret=None):
    """Produce a still-valid backup with one covered item removed — re-signed with the owner key we hold (so
    the drop is not a tamper; every OTHER integrity check still passes). Models 'the backup omitted item X'."""
    body = _decrypt_body(dest)
    manifest = body["manifest"]
    for rel in drop_files:
        body["files"].pop(rel, None)
        manifest["file_sha256"].pop(rel, None)
    if drop_secret is not None:
        body.pop(drop_secret, None)
        manifest[{"secrets_kv_b64": "has_secrets_kv"}[drop_secret]] = False
    # re-sign the (mutated) manifest with the owner key — the sig lives in the body, never in the manifest.
    body["manifest"] = manifest
    body["manifest_sig"] = sign(owner.private_key_b64, canonical_json(manifest))
    salt = os.urandom(backup._SALT_LEN)
    sealed = seal(backup._derive_key(PW, salt), canonical_json(body), context=backup._BODY_CONTEXT)
    dest.write_bytes(backup._MAGIC + salt + sealed)


# (item label, files-to-drop, secret-to-drop, functional-check that must now RAISE/return-empty)
_DROP_CASES = [
    ("witness.trust.json", ("witness.trust.json",), None,
     lambda new, rv, owner: load_roster(new / "witness.trust.json", owner_pub=owner.public_key_b64, scope=SCOPE)),
    ("budgets.json", ("budgets.json",), None, None),
    ("sigil.env", ("sigil.env",), None, None),
    ("secrets.sealed", (), "secrets_kv_b64", None),
    ("qdrant", ("qdrant/collection/storage.bin",), None, None),
    ("graph", ("graph/current/kuzu.db",), None, None),
]


@pytest.mark.parametrize("label,drop_files,drop_secret,_probe", _DROP_CASES,
                         ids=[c[0] for c in _DROP_CASES])
def test_dropping_a_covered_item_breaks_its_functional_check(tmp_path, label, drop_files, drop_secret, _probe):
    src, v, owner, _w = _make_full_source(tmp_path)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)

    # sanity: the FULL backup restores functionally (the positive control, same run).
    good, gv, _ = _restore(tmp_path, dest, name="restored-good")
    _assert_functional(good, gv, owner)

    # drop exactly this item, restore again — the restore itself still SUCCEEDS (the spine is intact) …
    _rewrite_backup(dest, owner, drop_files=drop_files, drop_secret=drop_secret)
    bad, bv, out = _restore(tmp_path, dest, name="restored-bad")
    assert out["verified"] is True                       # a functional restore must still verify the spine
    # … but THIS item's real operation now fails, proving the coverage of THIS item has teeth.
    if label == "witness.trust.json":
        assert load_roster(bad / "witness.trust.json", owner_pub=owner.public_key_b64, scope=SCOPE) is None
    elif label == "budgets.json":
        import sigil.config as _cfg
        _saved = _cfg.SIGIL_HOME; _cfg.SIGIL_HOME = bad
        try:
            assert _load_caps().daily_actions is None    # missing budgets.json → uncapped default
        finally:
            _cfg.SIGIL_HOME = _saved
    elif label == "sigil.env":
        assert not (bad / "sigil.env").exists()
    elif label == "secrets.sealed":
        assert not (bad / "secrets.sealed").exists()
        assert bv.read_text_secret(bad / "secrets.sealed", context=backup._SECRETS_KV_CONTEXT) is None
    elif label == "qdrant":
        assert not (bad / "qdrant" / "collection" / "storage.bin").exists()
    elif label == "graph":
        assert not (bad / "graph" / "current" / "kuzu.db").exists()


# ---------------------------------------------------------------------------------------------------
# STRUCTURAL COVERAGE CONTRACT: nothing unclassified; an unknown artifact IS flagged.
# ---------------------------------------------------------------------------------------------------
def _source_top_level_home_names():
    """INDEPENDENT source of truth for the coverage gate: the set of TOP-LEVEL ``SIGIL_HOME`` entry names the
    PRODUCTION sigil package actually writes, harvested by STATIC SCAN of the source — NOT from the classifier's
    own sets (that would be tautological). Matches ``<home-accessor> / "<name>"`` where the accessor is one of
    the established home handles (``SIGIL_HOME`` / a bare ``home`` / ``_home()``), capturing the FIRST path
    segment (the top-level child). A component that starts writing a NEW top-level artifact adds a literal here,
    so if it is not also classified, :func:`test_coverage_contract_leaves_nothing_unclassified` goes RED — the
    silently-dropped-artifact guard the tautological version never provided."""
    import pathlib
    import re

    pkg = pathlib.Path(backup.__file__).parent
    pat = re.compile(r'(?:SIGIL_HOME|_home\(\)|\bhome)\s*/\s*"([^"/]+)"')
    names: set[str] = set()
    for py in pkg.rglob("*.py"):
        for m in pat.finditer(py.read_text(encoding="utf-8", errors="ignore")):
            names.add(m.group(1))
    return names


def test_coverage_contract_is_grounded_in_the_real_source(tmp_path):
    """The structural gate is NOT tautological: it enumerates an INDEPENDENT source of truth (a static scan of
    the production package for top-level ``SIGIL_HOME`` writes) and asserts EVERY such name classifies as
    captured-or-excluded. Reverting a name out of CAPTURED_TOP_LEVEL/EXCLUSION_REASONS (or a component adding a
    new top-level artifact) makes it 'unclassified' → this test goes red."""
    scanned = _source_top_level_home_names()
    # sanity: the scan actually found the real home artifacts (guards against a broken regex silently passing).
    assert {"spine", "vault", "warden", "witness.trust.json", "qdrant", "graph"} <= scanned, scanned
    unclassified = sorted(n for n in scanned if backup.classify_top_level(n) == "unclassified")
    assert not unclassified, (
        f"production code writes these top-level SIGIL_HOME artifacts that are neither CAPTURED nor a documented "
        f"exclusion — decide capture-vs-exclude in sigil.backup (a silent drop from disaster recovery): {unclassified}")


def test_coverage_contract_leaves_nothing_unclassified(tmp_path):
    """RUNTIME half: a home POPULATED BY REAL COMPONENTS (SpineStore, Vault, set_roster, the sealed KV store,
    the config writers) leaves NO top-level entry unclassified — so a component whose real output is dropped
    from the classifier turns this red, not a self-referential enumeration of the classifier's own sets."""
    src, _v, _owner, _w = _make_full_source(tmp_path)   # a real home built by the real writers
    populated = {e.name for e in src.iterdir()}
    # the real writers produced a non-trivial home (not an empty dir that would pass vacuously) ...
    assert {"spine", "vault", "secrets.sealed", "witness.trust.json"} <= populated, populated
    unclassified = sorted(n for n in populated if backup.classify_top_level(n) == "unclassified")
    assert not unclassified, f"unclassified SIGIL_HOME entries a real component wrote (decide capture vs exclude): {unclassified}"
    # every excluded name carries a documented reason (the 'documented exclusion' acceptance criterion).
    for name in backup.EXCLUDED_TOP_LEVEL:
        assert backup._EXCLUSION_REASONS[name]


def test_coverage_contract_flags_an_unknown_artifact(tmp_path):
    """NEGATIVE control for the structural gate: a brand-new top-level artifact is 'unclassified' (the gate
    is live, not a no-op that waves everything through), while lockfiles/tmp are always excluded."""
    assert backup.classify_top_level("some-new-state.db") == "unclassified"
    assert backup.classify_top_level("spine") == "captured"
    assert backup.classify_top_level("vault") == "excluded"
    assert backup.classify_top_level("spine.lock") == "excluded"
