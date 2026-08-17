"""A-S2 — the OFFENSE-plane off-box backup + verified restore (vigil_integration.backup).

Proves the disaster-recovery property for the offense plane, end to end:
  * a real engagement's durable state (a signed {slug}.spine + the three identity keys) plus a self-contained
    CRUCIBLE evidence bundle are backed up, a wiped copy is restored into FRESH dirs, and the restore
    RE-VERIFIES — the spine chain re-checks under the restored spine key, no segment FAILS, and the restored
    evidence bundle re-verifies SOUND (exit 0), the "restore actually preserves the proof" gate;
  * the restored identity keys land 0600 (not the process umask);
  * NEGATIVE controls (must be green): a 1-byte tamper of the archive → restore refuses BEFORE any write;
    a path-escape (`../../etc/x`) in the file table → refused; a wrong passphrase → refused; corrupting a
    restored evidence byte flips the bundle to NOT SOUND (the re-verify has real teeth).

Needs framework (mint + evidence verify) → run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_roundtrip.py -q
"""
from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")   # this suite only runs where `framework` is importable

from vigil_core import canonical_json, generate_keypair, sha256_hex, sign
from vigil_core.sealing import seal
from vigil_core.vault import Vault
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.attestation.identity import load_or_create_operator_keypair
from vigil_integration.backup import (
    OffenseBackupError,
    _BODY_CONTEXT,
    _MAGIC,
    _SALT_LEN,
    _derive_key,
    create_offense_backup,
    restore_offense_backup,
)
from vigil_integration.live.governance_identity import (
    DEFAULT_GOVERNANCE_KEY_FILE,
    load_or_create_governance_keypair,
)
from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
from vigil_integration.live.spine_verify import FAILED, verify_offense_home
from vigil_integration.live.spine_vigilcore import VigilCoreSpine
from vigil_integration.proof.bundle import export_bundle
from vigil_integration.proof.run import build_report_mint, read_reverifiable
from vigil_integration.proof.sink import CAPTURE_KEY

PW = "correct horse battery staple offense"
SLUG = "loopback"
RUN_ID = "20260101-000000-000"

# the error-signature oracle fires on a distinctive datastore error → a response-side FACT that reproduces.
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _seed_offense_home(base: Path) -> None:
    """A base_dir with the three persisted identity keys and a signed {slug}.spine, signed by the SAME
    offense-spine key that is persisted (so the post-restore integrity re-verify recovers a matching pubkey)."""
    vault = Vault(base / "vault")                       # unprovisioned → plaintext 0600 keys (no TPM in CI)
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=vault)
    load_or_create_governance_keypair(path=str(base / DEFAULT_GOVERNANCE_KEY_FILE), vault=vault)
    load_or_create_operator_keypair(path=str(base / "operator.key"), vault=vault)
    spine = VigilCoreSpine(spine_kp, str(base / f"{SLUG}.spine"))
    for i in range(3):
        st = AgentState(engagement_slug=SLUG, phase=Phase.EXPLOITATION, iteration=i, objective="own the box")
        st.record_fact(Finding(ref=f"f-{i}", bug_class="sqli", title="auth bypass", severity="critical"),
                       evidence_ref=f"cert:evi-{i}")
        spine.write_state(st, seq=i, engagement=SLUG)


def _seed_evidence_bundle(crucible_root: Path) -> Path:
    """Mint a reproducing FACT into a run dir under crucible_root/.console/runs, then export a self-contained
    verifiable bundle UNDER that run dir (so the backup's .console/runs capture grabs it). Returns the bundle.
    Mirrors test_proof_bundle: export_bundle defaults its signing authority to the run dir."""
    mint_signer = generate_keypair()
    run_dir = crucible_root / ".console" / "runs" / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    mint = build_report_mint(run_dir=run_dir, signers=[("root0", mint_signer.private_key_b64)],
                             engagement_slug=SLUG)
    res = mint({
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR}},
    })
    assert res is not None and res.is_fact
    assert read_reverifiable(run_dir)["active_findings"], "mint must persist a re-verifiable finding"
    bundle = run_dir / "bundle"
    out = export_bundle(run_dir=run_dir, out_dir=bundle, engagement_slug=SLUG)
    assert out["ok"] and out["certificates"] == 1, out
    return bundle


def _evidence_verify(bundle: Path) -> int:
    """Run the deterministic CRUCIBLE evidence verify over a self-contained bundle; return the exit code."""
    from framework.v2.evidence.cli import main as evidence_main
    return evidence_main(["verify", "--report", str(bundle / "reverifiable.json"), "--bundle", str(bundle),
                          "--trust-root", str(bundle / "trust-root.json"),
                          "--evidence-root", str(bundle / "evidence")])


def test_offense_backup_restore_roundtrip_reverifies(tmp_path):
    base = tmp_path / "src-base"
    croot = tmp_path / "src-crucible"
    _seed_offense_home(base)
    _seed_evidence_bundle(croot)

    dest = tmp_path / "offense.vglbk"
    summary = create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))
    assert summary["files"] >= 2 and summary["secrets"] == 3      # spine + bundle files; 3 identity keys

    # restore into FRESH dirs (simulating new hardware where the originals are gone)
    new_base = tmp_path / "restored-base"
    new_croot = tmp_path / "restored-crucible"
    res = restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot))
    assert res["verified"] is True
    # the restore's OWN post-write evidence re-verify must have re-verified the bundle SOUND (exit 0 internally).
    assert res["bundles_verified"] >= 1, "the restore must re-verify the restored evidence bundle"

    # the restored spine round-tripped and re-verifies with no FAILED segment.
    assert (new_base / f"{SLUG}.spine").is_file()
    assert not any(v.status == FAILED for v in verify_offense_home(str(new_base)))

    # restored identity keys are 0600 (owner-only), not the process umask.
    for name in ("operator.key", DEFAULT_SPINE_KEY_FILE, DEFAULT_GOVERNANCE_KEY_FILE):
        mode = stat.S_IMODE(os.stat(new_base / name).st_mode)
        assert mode == 0o600, f"{name} restored {oct(mode)}, expected 0o600"

    # independent positive control: the restored self-contained bundle verifies SOUND via the CLI (exit 0).
    restored_bundle = new_croot / ".console" / "runs" / RUN_ID / "bundle"
    assert restored_bundle.is_dir()
    assert _evidence_verify(restored_bundle) == 0, "the restored evidence bundle must re-verify SOUND"


def test_corrupt_restored_evidence_byte_flips_bundle_not_sound(tmp_path):
    """Teeth check: after a clean restore, flip one byte of a restored raw evidence artifact → the bundle
    verify now exits non-zero (the certificate's artifact sha256 no longer matches). Proves the re-verify is
    real, not a rubber stamp."""
    base, croot = tmp_path / "b", tmp_path / "c"
    _seed_offense_home(base)
    _seed_evidence_bundle(croot)
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))
    new_base, new_croot = tmp_path / "nb", tmp_path / "nc"
    restore_offense_backup(dest, str(new_base), PW, crucible_root=str(new_croot))

    bundle = new_croot / ".console" / "runs" / RUN_ID / "bundle"
    assert _evidence_verify(bundle) == 0                          # sound before tamper
    victim = next(p for p in (bundle / "evidence").rglob("*") if p.is_file())
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0x01
    victim.write_bytes(bytes(data))
    assert _evidence_verify(bundle) != 0, "a corrupted restored evidence byte MUST fail verification"


def test_one_byte_archive_tamper_refuses_before_any_write(tmp_path):
    base = tmp_path / "b"
    _seed_offense_home(base)
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base))
    raw = bytearray(dest.read_bytes())
    raw[-1] ^= 0xFF                                               # flip a ciphertext byte → AEAD fails
    dest.write_bytes(raw)
    new_base = tmp_path / "nb"
    with pytest.raises(OffenseBackupError):
        restore_offense_backup(dest, str(new_base), PW)
    assert not (new_base / f"{SLUG}.spine").exists()             # nothing written on a failed restore


def test_wrong_passphrase_refuses(tmp_path):
    base = tmp_path / "b"
    _seed_offense_home(base)
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base))
    with pytest.raises(OffenseBackupError, match="wrong passphrase"):
        restore_offense_backup(dest, str(tmp_path / "nb"), "WRONG passphrase")


def test_no_spine_refuses_to_back_up(tmp_path):
    base = tmp_path / "empty"
    base.mkdir()
    with pytest.raises(OffenseBackupError, match="nothing to back up"):
        create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))


def _craft_backup(dest: Path, *, files: dict, secrets_body=None, secrets_names=None):
    """Craft a well-formed, correctly GOVERNANCE-signed offense backup with an arbitrary file table (the
    passphrase-holder controls the manifest key) — to prove the restore-time guards hold even for a body a
    forger with the passphrase could produce."""
    kp = generate_keypair()
    hashes = {rel: sha256_hex(base64.b64decode(b64)) for rel, b64 in files.items()}
    manifest = {"schema": 1, "scope": kp.public_key_b64, "file_sha256": hashes,
                "secrets": sorted((secrets_names if secrets_names is not None else (secrets_body or {}).keys()))}
    body = {"manifest": manifest, "manifest_sig": sign(kp.private_key_b64, canonical_json(manifest)),
            "manifest_pubkey": kp.public_key_b64, "files": files, "secrets": (secrets_body or {})}
    salt = b"\x05" * _SALT_LEN
    sealed = seal(_derive_key(PW, salt), canonical_json(body), context=_BODY_CONTEXT)
    dest.write_bytes(_MAGIC + salt + sealed)


def test_path_escape_in_the_file_table_is_refused(tmp_path):
    """A correctly-signed backup whose file table contains a traversal rel is refused BEFORE any write —
    unconditionally (the same class-fix guard the sovereign leg uses, copied verbatim)."""
    evil = base64.b64encode(b"pwned").decode("ascii")
    dest = tmp_path / "evil.vglbk"
    _craft_backup(dest, files={"../../etc/x": evil})
    new_base = tmp_path / "nb"
    with pytest.raises(OffenseBackupError, match="unsafe backup path"):
        restore_offense_backup(dest, str(new_base), PW)
    assert not (tmp_path / "etc" / "x").exists()     # nothing escaped
    assert not new_base.exists()                     # and the guard fires BEFORE new_base is created


def test_crucible_prefixed_path_escape_is_refused(tmp_path):
    """The crucible-routed leg applies the SAME path guard — a `crucible/../../etc/x` rel cannot escape the
    crucible_root either."""
    evil = base64.b64encode(b"pwned").decode("ascii")
    dest = tmp_path / "evil2.vglbk"
    _craft_backup(dest, files={"crucible/../../etc/x": evil})
    with pytest.raises(OffenseBackupError, match="unsafe backup path"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW, crucible_root=str(tmp_path / "nc"))


def test_crucible_files_without_crucible_root_refuse(tmp_path):
    """Fail-closed: a backup carrying crucible-prefixed files but no crucible_root to route them into refuses
    (a partial restore that silently drops the proof state is not acceptable)."""
    good = base64.b64encode(b"data").decode("ascii")
    dest = tmp_path / "cru.vglbk"
    _craft_backup(dest, files={"crucible/.blackboard/store.sqlite": good})
    with pytest.raises(OffenseBackupError, match="no crucible_root"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)      # crucible_root omitted


def test_tampered_manifest_signature_refuses(tmp_path):
    """A body whose manifest was edited after signing fails the governance-signature check (fail-closed)."""
    good = base64.b64encode(b"data").decode("ascii")
    dest = tmp_path / "sig.vglbk"
    _craft_backup(dest, files={f"{SLUG}.spine": good})
    # decrypt, mutate the signed manifest's scope, re-seal WITHOUT re-signing → signature must no longer verify.
    from vigil_core.sealing import unseal
    raw = dest.read_bytes()
    salt, sealed = raw[len(_MAGIC):len(_MAGIC) + _SALT_LEN], raw[len(_MAGIC) + _SALT_LEN:]
    body = json.loads(unseal(_derive_key(PW, salt), sealed, context=_BODY_CONTEXT))
    body["manifest"]["scope"] = "attacker-rewrote-this"
    resealed = seal(_derive_key(PW, salt), canonical_json(body), context=_BODY_CONTEXT)
    dest.write_bytes(_MAGIC + salt + resealed)
    with pytest.raises(OffenseBackupError, match="signature does not verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


# --- BLOCK-1: `verified: True` is NEVER returned for a spine re-verify that did not RUN --------------------

def test_create_refuses_a_spine_without_its_verifying_key(tmp_path):
    """Fail closed at the SOURCE: a base_dir that has a *.spine but no offense-spine key cannot be backed up —
    the restored spine could never be integrity-re-verified, so a `verified: True` restore would be unearned."""
    base = tmp_path / "b"
    _seed_offense_home(base)
    os.remove(base / DEFAULT_SPINE_KEY_FILE)                      # lose/rotate the spine key
    with pytest.raises(OffenseBackupError, match="offense-spine key .* is missing|could never be re-verified"):
        create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))


def test_restore_refuses_a_spine_with_no_reverify_key_handcrafted(tmp_path):
    """The exact hole the red-pen found: a (passphrase-forgeable) body carrying a spine file but NO spine-key
    secret must NOT restore to `verified: True` — restore has no pubkey to re-verify the spine under, so the
    integrity check does not run and the restore MUST fail closed rather than rubber-stamp success."""
    dest = tmp_path / "noverify.vglbk"
    junk = base64.b64encode(b"THIS IS NOT A VALID SIGNED SPINE - attacker-controlled junk").decode("ascii")
    _craft_backup(dest, files={f"{SLUG}.spine": junk}, secrets_body={}, secrets_names=[])
    with pytest.raises(OffenseBackupError, match="no usable offense-spine public key|cannot re-verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


def test_restore_refuses_a_subdir_spine_with_no_reverify_key(tmp_path):
    """BLOCK-1a: `create` packages spines RECURSIVELY (rglob), so a spine can land in a SUBDIR. The post-write
    re-verify must enumerate spines the same way — a non-recursive glob would miss `sub/evil.spine` and wave it
    through to `verified: True`. Craft one at a subdir with no spine key → restore must fail closed."""
    dest = tmp_path / "subdir.vglbk"
    junk = base64.b64encode(b"THIS IS NOT A VALID SIGNED SPINE - attacker junk in a subdir").decode("ascii")
    _craft_backup(dest, files={"sub/evil.spine": junk}, secrets_body={}, secrets_names=[])
    with pytest.raises(OffenseBackupError, match="no usable offense-spine public key|cannot re-verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


def test_restore_refuses_a_crucible_routed_spine_with_no_reverify_key(tmp_path):
    """BLOCK-1a (crucible leg): a spine routed under the `crucible/` prefix lands in crucible_root, which the
    old non-recursive `new_base`-only glob never looked at. It must be re-verified (or refused) too."""
    dest = tmp_path / "cruspine.vglbk"
    junk = base64.b64encode(b"attacker junk spine under the crucible run tree").decode("ascii")
    _craft_backup(dest, files={"crucible/.console/runs/eng/evil.spine": junk}, secrets_body={}, secrets_names=[])
    with pytest.raises(OffenseBackupError, match="no usable offense-spine public key|cannot re-verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW, crucible_root=str(tmp_path / "nc"))


def test_restore_refuses_a_records_free_spine_even_with_a_key(tmp_path):
    """BLOCK-1b: a spine whose body has NO complete (newline-terminated) records verifies VACUOUSLY — the
    binder's empty-chain verify is trivially true even under a NON-matching key. Restore must refuse a
    content-free spine rather than stamp it `verified` (it attests nothing, yet passed under a wrong key)."""
    kp = generate_keypair()
    sk_json = json.dumps({"public_key_b64": kp.public_key_b64, "private_key_b64": kp.private_key_b64})
    dest = tmp_path / "recfree.vglbk"
    junk = base64.b64encode(b"not a valid spine").decode("ascii")     # no trailing newline -> 0 attested records
    _craft_backup(dest, files={f"{SLUG}.spine": junk},
                  secrets_body={DEFAULT_SPINE_KEY_FILE: sk_json}, secrets_names=[DEFAULT_SPINE_KEY_FILE])
    with pytest.raises(OffenseBackupError, match="attests NO records|did NOT re-verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


def test_restore_refuses_a_corrupt_spine_when_the_key_is_present(tmp_path):
    """Contrast control (the teeth exist when the key IS present): corrupt a spine byte in the SOURCE before
    backing up (so the packaged hash matches the corrupted bytes → passes the pre-write hash check), then
    restore → the post-write signature re-verify under the packaged key FAILS → refuse."""
    base = tmp_path / "b"
    _seed_offense_home(base)
    spine = base / f"{SLUG}.spine"
    data = bytearray(spine.read_bytes())
    data[len(data) // 2] ^= 0x01                                  # mid-record flip (not a torn tail)
    spine.write_bytes(bytes(data))
    dest = tmp_path / "o.vglbk"
    create_offense_backup(dest, PW, base_dir=str(base))
    with pytest.raises(OffenseBackupError, match="did NOT re-verify"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


# --- BLOCK-1c: the ATTESTED-record guard (a single trailing byte must not flip refusal to `verified`) ------

def _spine_key_secret() -> str:
    """A JSON offense-spine keypair as the re-wrapped ``offense-spine.key`` secret carries it — enough for
    restore to DERIVE a spine pubkey, so the post-write re-verify reaches the ATTESTED-record guard rather than
    the earlier no-key refusal."""
    kp = generate_keypair()
    return json.dumps({"public_key_b64": kp.public_key_b64, "private_key_b64": kp.private_key_b64})


@pytest.mark.parametrize("rel, routed", [
    (f"{SLUG}.spine", False),                             # base_dir root
    ("sub/evil.spine", False),                            # a subdir (create packages spines via rglob)
    ("crucible/.console/runs/eng/evil.spine", True),      # routed under crucible_root
])
def test_single_trailing_byte_does_not_flip_a_garbage_spine_to_verified(tmp_path, rel, routed):
    """BLOCK-1c (the re-red-pen bypass): ``b"not a valid spine\\n"`` — a NON-JSON line WITH a trailing newline —
    has ``_count_records`` == 1 (one non-empty newline chunk), but the binder's ``_read_lines`` yields ZERO
    objects, so ``verify()`` chain-verifies an EMPTY entry list and is vacuously True under ANY key. The OLD
    ``_count_records < 1`` guard was satisfied → an unearned ``verified: True``. The single trailing byte is the
    whole exploit: ``b"not a valid spine"`` (no newline) is already refused, ``+\\n`` flipped it to verified.
    The fixed ATTESTED-record guard (JSON-object lines only) refuses it — at root, in a subdir, and under the
    crucible tree (the three locations ``create`` packages spines from). A spine KEY secret is present so the
    re-verify reaches the count guard, not the no-key refusal."""
    junk = base64.b64encode(b"not a valid spine\n").decode("ascii")   # trailing newline = the single-byte bypass
    dest = tmp_path / "onebyte.vglbk"
    _craft_backup(dest, files={rel: junk},
                  secrets_body={DEFAULT_SPINE_KEY_FILE: _spine_key_secret()},
                  secrets_names=[DEFAULT_SPINE_KEY_FILE])
    kwargs = {"crucible_root": str(tmp_path / "nc")} if routed else {}
    with pytest.raises(OffenseBackupError, match="attests NO records"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW, **kwargs)


@pytest.mark.parametrize("body", [b"[1,2,3]\n", b'"x"\n', b"123\n", b"true\n"])
def test_json_scalar_or_array_spine_line_attests_nothing_and_is_refused(tmp_path, body):
    """A line that is VALID JSON but NOT an object (a scalar or an array) is skipped by the binder's
    ``_read_lines`` (only dicts become ``SpineLine`` candidates), so ``verify()`` chain-verifies an EMPTY entry
    list = vacuously True. ``_count_records`` counts it (1), but 0 records were ATTESTED → the fixed guard
    refuses it (the same class as the single-byte bypass, via a well-formed JSON non-object)."""
    junk = base64.b64encode(body).decode("ascii")
    dest = tmp_path / "scalar.vglbk"
    _craft_backup(dest, files={f"{SLUG}.spine": junk},
                  secrets_body={DEFAULT_SPINE_KEY_FILE: _spine_key_secret()},
                  secrets_names=[DEFAULT_SPINE_KEY_FILE])
    with pytest.raises(OffenseBackupError, match="attests NO records"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


def test_spine_free_handcrafted_body_is_not_reported_verified(tmp_path):
    """The folded-in advisory: a crafted body with NO ``*.spine`` and NO self-contained evidence bundle
    re-verifies NOTHING, so it must NOT be reported ``verified: True``. A real offense backup ALWAYS carries a
    ``{slug}.spine`` (``create`` refuses a spine-free base at the source) — this only bites a hand-crafted
    (passphrase-forgeable) body, and the honest fix fails it closed rather than stamp an empty restore."""
    good = base64.b64encode(b"budget-data").decode("ascii")
    dest = tmp_path / "spinefree.vglbk"
    _craft_backup(dest, files={"token-budgets.json": good})           # no spine, no crucible, no secrets
    with pytest.raises(OffenseBackupError, match="re-verified NOTHING"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW)


# --- BLOCK-2: out-of-band governance-pubkey pin upgrades authenticity past passphrase-possession ----------

def test_expect_governance_pubkey_pin_rejects_a_wrong_key_and_accepts_the_right_one(tmp_path):
    """With `expect_pubkey`, restore refuses a manifest not signed by the pinned governance key (a forged
    backup any passphrase-holder could mint), and accepts the genuine one. Proves the pin is real authenticity,
    not decoration."""
    base, croot = tmp_path / "b", tmp_path / "c"
    _seed_offense_home(base)
    _seed_evidence_bundle(croot)
    dest = tmp_path / "o.vglbk"
    summary = create_offense_backup(dest, PW, base_dir=str(base), crucible_root=str(croot))
    real_gov_pub = summary["scope"]                              # the genuine offense-governance pubkey

    # a DIFFERENT key is refused before anything is trusted
    with pytest.raises(OffenseBackupError, match="authenticity pin failed"):
        restore_offense_backup(dest, str(tmp_path / "nb1"), PW, crucible_root=str(tmp_path / "nc1"),
                               expect_pubkey=generate_keypair().public_key_b64)
    # the genuine pubkey pins cleanly and the restore still fully re-verifies
    res = restore_offense_backup(dest, str(tmp_path / "nb2"), PW, crucible_root=str(tmp_path / "nc2"),
                                 expect_pubkey=real_gov_pub)
    assert res["verified"] is True and res["bundles_verified"] >= 1


def test_a_forged_manifest_that_passes_the_passphrase_is_still_caught_by_the_pin(tmp_path):
    """The threat the pin closes: a passphrase-holder who does NOT hold the governance private key crafts a
    fully self-consistent, correctly self-signed backup (passes decrypt + sig + hash). Without a pin it would
    restore; WITH the correct pin it is refused because the forger's pubkey ≠ the pinned governance pubkey."""
    victim_gov = generate_keypair().public_key_b64               # the real key the recipient pins, out of band
    dest = tmp_path / "forged.vglbk"
    good = base64.b64encode(b"data").decode("ascii")
    _craft_backup(dest, files={"token-budgets.json": good})       # _craft_backup self-signs with a FRESH key
    with pytest.raises(OffenseBackupError, match="authenticity pin failed"):
        restore_offense_backup(dest, str(tmp_path / "nb"), PW, expect_pubkey=victim_gov)
