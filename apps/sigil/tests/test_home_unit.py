"""A home's spine verified as ONE unit (``sigil.spine.home_unit``) — every member of a hard-pruned set, read by the
real readers in a child process scoped to that home.

A hard-pruned spine is readable only together with its owner-signed head, the floor, the owner public key(s), the
live segments and the archive of the pruned prefix. Each test copies a REAL pruned home (built in a child process,
``tests/_real_home.py``), takes one member away or swaps in one from elsewhere, and checks the unit is refused
naming that member — and that the complete set verifies (also a floor one head behind, and a prune's crash window).

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_home_unit.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sigil.spine import home_unit as hu
from sigil.spine.home_unit import HomeUnit, unit_shape, verify_unit_isolated

from tests._real_home import env, read_home, run_in_home, signed_home  # type: ignore

CRASH_PRUNE = """
import os
from sigil import config
import sigil.spine.store as st
from sigil.spine import prune
def hook(name):
    if name == "prune_after_head":
        os._exit(77)
st._crash_hook = hook
prune.commit_prune(st.SpineStore(config.SPINE_PATH), 10, confirm=True)
"""

# a re-anchor whose floor advance did not land: the floor still records the PARENT of the standing head
FLOOR_LAG = """
from sigil import config
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
saved = config.FLOOR_PATH.read_bytes()
s.append(kind="event", source="t", actor="u", payload={"i": "after"})
cp.checkpoint(s)
config.FLOOR_PATH.write_bytes(saved)
"""

ROTATE = """
import time
from sigil import config
from sigil.governor import key_history as kh
from sigil.spine import checkpoint as cp
from sigil.spine.store import SpineStore
s = SpineStore(config.SPINE_PATH)
standing = cp.standing_pruned_head(s)
kh.rotate(s, issued_at=time.time())
cp.checkpoint(s, carry=standing)
"""

LIVE_CHECK = """
import json, sys
from sigil.spine.home_unit import check_live_unit
print(json.dumps(check_live_unit(require_archive=True, deep=sys.argv[1] == "deep")))
"""


def _public_only(home: Path) -> Path:
    (home / "spine" / "keys" / "owner.priv").unlink()
    return home


@pytest.fixture(scope="module")
def homes(tmp_path_factory):
    """Real homes, built once: a pruned world home; a crash-window home; a rotated pruned home with the retired
    public key kept; a second, foreign pruned home."""
    root = tmp_path_factory.mktemp("homes")
    out = {}
    out["pruned"] = signed_home(root, pruned=True, world=True, name="pruned")
    crash = signed_home(root, pruned=False, world=True, name="crash")
    assert run_in_home(crash, CRASH_PRUNE, check=False).returncode == 77
    out["crash"] = crash
    rot = signed_home(root, pruned=True, world=True, name="rot")
    out["retired_pub"] = (rot / "spine" / "keys" / "owner.pub").read_text()
    run_in_home(rot, ROTATE)
    out["rot"] = rot
    out["foreign"] = signed_home(root, pruned=True, world=True, name="foreign")
    return out


def _copy(homes, tmp_path, name="pruned", *, public_only=True) -> Path:
    dst = tmp_path / f"unit-{name}"
    shutil.copytree(homes[name], dst)
    return _public_only(dst) if public_only else dst


def _verify(home: Path, tmp_path: Path, **kw) -> dict:
    return verify_unit_isolated(HomeUnit.for_home(home), work_dir=tmp_path / "work", **kw)


def _failed(res: dict) -> "tuple[str, str]":
    for c in res["checks"]:
        if not c["ok"]:
            return c["name"], c["why"]
    return "", res.get("refused", "")


# ---- the complete set verifies ------------------------------------------------------------------------------
def test_a_real_pruned_home_with_public_keys_only_verifies_as_one_unit(homes, tmp_path):
    home = _copy(homes, tmp_path)
    res = _verify(home, tmp_path)
    assert res["ok"] is True and res["pruned"] is True, res
    assert res["shape"]["base_seq"] == 10 and res["shape"]["snapshot_seq"] == 23
    assert res["shape"]["archive_segments"] == 2
    assert [c["name"] for c in res["checks"]] == ["members", "chain", "signed_head", "succession_tip",
                                                  "snapshot_seed", "registry_read", "archive"]
    assert "kill switch engaged" in res["checks"][5]["why"]


def test_a_floor_one_head_behind_still_verifies(homes, tmp_path):
    home = _copy(homes, tmp_path, public_only=False)
    run_in_home(home, FLOOR_LAG)
    _public_only(home)
    sh = unit_shape(HomeUnit.for_home(home))
    assert sh.floor_head_sig_hash != sh.head_sig_hash and not sh.refusals
    assert _verify(home, tmp_path)["ok"] is True


def test_a_prune_crash_window_home_is_pruned_and_verifies(homes, tmp_path):
    """The head is signed (the prune's commit) while the pruned prefix is still on disk: the live window starts at
    seq 0 — legal, and still a pruned unit."""
    home = _copy(homes, tmp_path, "crash")
    sh = unit_shape(HomeUnit.for_home(home))
    assert sh.pruned is True and sh.live_start == 0 and sh.head_base_seq == 10 and not sh.refusals
    res = _verify(home, tmp_path)
    assert res["ok"] is True and res["pruned"] is True, res


def test_an_unpruned_home_is_not_a_pruned_unit(tmp_path):
    home = _public_only(signed_home(tmp_path, pruned=False))
    res = _verify(home, tmp_path)
    assert res["ok"] is True and res["pruned"] is False


# ---- a partial or mismatched set is refused naming the member -------------------------------------------------
def _flip_byte(p: Path) -> None:
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    p.write_bytes(bytes(raw))


def _drop_archive_row(home: Path) -> None:
    am = home / "spine" / "archive" / "archive.manifest.json"
    d = json.loads(am.read_text())
    d["segments"] = d["segments"][1:]
    am.write_text(json.dumps(d))


def _front_segment(home: Path) -> Path:
    m = json.loads((home / "spine" / "spine.manifest.json").read_text())
    first = sorted(m["segments"], key=lambda s: s["first_seq"])[0]
    return home / "spine" / first["file"]


def _scope(home: Path) -> None:
    f = home / "floor.json"
    d = json.loads(f.read_text())
    d["scope"] = "another-scope"
    f.write_text(json.dumps(d))


def _drop_middle_segment(home: Path) -> None:
    f = home / "spine" / "spine.manifest.json"
    m = json.loads(f.read_text())
    segs = sorted(m["segments"], key=lambda s: s["first_seq"])
    m["segments"] = [segs[0]] + segs[2:]
    f.write_text(json.dumps(m))


def _rebase_head(home: Path, base: int) -> None:
    f = home / "spine" / "head.json"
    d = json.loads(f.read_text())
    d["base_seq"] = base
    f.write_text(json.dumps(d))


def _tamper_live_payload(home: Path) -> None:
    """Rewrite one live record's payload, keeping its chain fields (cert_digest / entry_hash) as they were."""
    seg = _front_segment(home)
    lines = seg.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"] = {"i": "rewritten"}
    lines[1] = json.dumps(rec)
    seg.write_text("\n".join(lines) + "\n")


NEGATIVE = {
    # name: (mutation(home, homes), the failing check, a phrase naming the member)
    "head deleted": (lambda h, H: (h / "spine" / "head.json").unlink(), "members", "head.json) is missing"),
    "head garbage": (lambda h, H: (h / "spine" / "head.json").write_text("{not json"), "members", "unparseable"),
    "head from before the prune": (None, "members", "declares no prune"),
    "head committing another prune boundary": (lambda h, H: _rebase_head(h, 15), "members",
                                               "commits a prune at seq 15 but the live window starts at seq 10"),
    "floor deleted": (lambda h, H: (h / "floor.json").unlink(), "members", "floor.json (the durable"),
    "floor from another home": (lambda h, H: shutil.copyfile(H["foreign"] / "floor.json", h / "floor.json"),
                                "members", "a floor from another home"),
    "floor scope mismatch": (lambda h, H: _scope(h), "members", "floor.json cannot be used"),
    "archive dir deleted": (lambda h, H: shutil.rmtree(h / "spine" / "archive"), "members", "no archive manifest"),
    "archived segment byte flipped": (lambda h, H: _flip_byte(sorted((h / "spine" / "archive" / "segments").iterdir())[0]),
                                      "archive", "sha256 mismatch"),
    "archive manifest row removed": (lambda h, H: _drop_archive_row(h), "archive", "archive"),
    "segment manifest deleted": (lambda h, H: (h / "spine" / "spine.manifest.json").unlink(), "members",
                                 "manifest spine.manifest.json is missing"),
    "segment manifest garbage": (lambda h, H: (h / "spine" / "spine.manifest.json").write_text("{x"), "members",
                                 "is unreadable"),
    "segment manifest not one run": (lambda h, H: _drop_middle_segment(h), "members", "not one contiguous"),
    "front live segment removed": (lambda h, H: _front_segment(h).unlink(), "members", "manifest lists are missing"),
    "live record payload rewritten": (lambda h, H: _tamper_live_payload(h), "chain", "binding break"),
    "owner.pub replaced by another key": (lambda h, H: shutil.copyfile(H["foreign"] / "spine" / "keys" / "owner.pub",
                                                                       h / "spine" / "keys" / "owner.pub"),
                                          "chain", "signed head"),
}


@pytest.mark.parametrize("case", sorted(NEGATIVE))
def test_a_partial_or_mismatched_set_is_refused_naming_the_member(homes, tmp_path, case):
    mutate, check, phrase = NEGATIVE[case]
    if case == "head from before the prune":
        home = _copy(homes, tmp_path)
        pre = signed_home(tmp_path, pruned=False, world=True, name="pre")
        shutil.copyfile(pre / "spine" / "head.json", home / "spine" / "head.json")
    else:
        home = _copy(homes, tmp_path)
        mutate(home, homes)
    res = _verify(home, tmp_path)
    assert res["ok"] is False, res
    name, why = _failed(res)
    assert name == check and phrase in why, (name, why)


def test_a_missing_floor_is_refused_although_the_production_readers_accept_it(homes, tmp_path):
    """Why the floor is an explicit member: with floor.json gone, every production reader of the home still
    answers (verify_checkpoint, the archive, the seeded registries) — only the unit check refuses."""
    home = _copy(homes, tmp_path, public_only=False)
    (home / "floor.json").unlink()
    seen = read_home(home)
    assert seen["verify_checkpoint"][0] is True and seen["verify_archive"][0] is True
    assert seen["killswitch_engaged"] is True and seen["wallet_acme"] == 100
    _public_only(home)
    res = _verify(home, tmp_path)
    assert res["ok"] is False and _failed(res)[0] == "members" and "floor.json" in _failed(res)[1]


def test_a_crash_window_home_with_a_replaced_owner_key_fails_the_signed_head(homes, tmp_path):
    """In a prune's crash window the live window still starts at genesis, so the chain check needs no head: the
    signed-head check is what refuses a foreign owner key there."""
    home = _copy(homes, tmp_path, "crash")
    shutil.copyfile(homes["foreign"] / "spine" / "keys" / "owner.pub", home / "spine" / "keys" / "owner.pub")
    res = _verify(home, tmp_path)
    assert res["ok"] is False and _failed(res)[0] == "signed_head", res


def test_a_rotated_home_verifies_and_its_retired_key_is_not_the_tip(homes, tmp_path):
    home = _copy(homes, tmp_path, "rot")
    assert _verify(home, tmp_path)["ok"] is True
    (home / "spine" / "keys" / "owner.pub").write_text(homes["retired_pub"])
    res = _verify(home, tmp_path / "again")
    assert res["ok"] is False and _failed(res)[0] == "succession_tip", res
    assert "not the validated owner-key succession tip" in _failed(res)[1]


def test_a_rotated_home_without_its_genesis_pin_fails_the_snapshot_seed(homes, tmp_path):
    home = _copy(homes, tmp_path, "rot")
    (home / "spine" / "keys" / "owner.genesis.pub").unlink()
    res = _verify(home, tmp_path)
    assert res["ok"] is False and _failed(res)[0] == "snapshot_seed", res


# ---- the isolated child is scoped to its unit ------------------------------------------------------------------
def _child(home: Path, work: Path, *, nonce_ok=True, sigil_home=None, tmpdir=None, archive=None):
    work.mkdir(parents=True, exist_ok=True)
    (work / "tmp").mkdir(exist_ok=True)
    (work / hu._NONCE_FILE).write_text("a" * 32)
    archive = archive or (home / "spine" / "archive")
    e, py = env(sigil_home or home, TMPDIR=tmpdir or (work / "tmp"), SIGIL_SPINE_ARCHIVE_DIR=archive,
                **{hu._NONCE_ENV: "a" * 32 if nonce_ok else "b" * 32})
    r = subprocess.run([py, "-m", "sigil.spine.home_unit", hu._CHILD_FLAG, str(home), "--work-dir", str(work),
                        "--archive-dir", str(home / "spine" / "archive"), "--require-archive"],
                       env=e, capture_output=True, text=True, check=True)
    assert not (work / hu._NONCE_FILE).exists()                        # one-shot: consumed either way
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("scope", ["ok", "wrong_nonce", "wrong_home", "tmp_outside", "wrong_archive", "private_key",
                                   "data_key"])
def test_the_child_refuses_unless_scoped_to_its_unit(homes, tmp_path, scope):
    home = _copy(homes, tmp_path, public_only=(scope != "private_key"))
    if scope == "data_key":                                   # the spine DEK is key material too
        (home / "spine" / "keys" / "spine.dek").write_text("a data key")
    other = tmp_path / "other-home"
    other.mkdir()
    res = _child(home, tmp_path / "w", nonce_ok=scope != "wrong_nonce",
                 sigil_home=other if scope == "wrong_home" else None,
                 tmpdir=tmp_path / "elsewhere" if scope == "tmp_outside" else None,
                 archive=tmp_path / "sentinel-archive" if scope == "wrong_archive" else None)
    if scope == "ok":
        assert res["ok"] is True, res
        return
    assert res["ok"] is False and res["checks"] == [] and "not scoped to its unit" in res["refused"], res
    phrase = {"wrong_nonce": "nonce", "wrong_home": "SIGIL_HOME", "tmp_outside": "TMPDIR",
              "wrong_archive": "SIGIL_SPINE_ARCHIVE_DIR", "private_key": "owner.priv", "data_key": "spine.dek"}[scope]
    assert phrase in res["refused"]


def test_the_archive_dir_is_never_taken_from_the_environment(homes, tmp_path, monkeypatch):
    """A restore / drill host's SIGIL_SPINE_ARCHIVE_DIR names the LIVE archive: the unit's archive is explicit."""
    monkeypatch.setenv("SIGIL_SPINE_ARCHIVE_DIR", str(tmp_path / "sentinel"))
    unit = HomeUnit.for_home(tmp_path / "h")
    assert unit.archive_dir == tmp_path / "h" / "spine" / "archive"
    home = _copy(homes, tmp_path)
    assert _verify(home, tmp_path)["ok"] is True
    assert not (tmp_path / "sentinel").exists()


def test_the_work_dir_must_not_overlap_the_unit(homes, tmp_path):
    home = _copy(homes, tmp_path)
    res = verify_unit_isolated(HomeUnit.for_home(home), work_dir=home / "w")
    assert res["ok"] is False and "overlaps" in res["refused"]


def _digest_excl_transient(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.name.endswith((".idx", ".lock")):
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_the_verifier_writes_only_read_sidecars_into_the_unit_and_nothing_into_this_home(homes, tmp_path):
    import sigil.config as cfg
    home = _copy(homes, tmp_path)
    before = _digest_excl_transient(home)
    own_before = _digest_excl_transient(cfg.SIGIL_HOME) if cfg.SIGIL_HOME.exists() else {}
    assert _verify(home, tmp_path)["ok"] is True
    assert _digest_excl_transient(home) == before
    assert (_digest_excl_transient(cfg.SIGIL_HOME) if cfg.SIGIL_HOME.exists() else {}) == own_before


# ---- the in-process check of this process's own home ----------------------------------------------------------
def test_check_live_unit_cheap_and_deep(homes, tmp_path):
    home = _copy(homes, tmp_path, public_only=False)
    cheap = json.loads(run_in_home(home, LIVE_CHECK, "cheap", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert cheap["ok"] is True and cheap["checks"][-1]["name"] == "archive", cheap
    # a flipped archived byte: only the deep check re-derives the archive
    _flip_byte(sorted((home / "spine" / "archive" / "segments").iterdir())[0])
    cheap = json.loads(run_in_home(home, LIVE_CHECK, "cheap", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    deep = json.loads(run_in_home(home, LIVE_CHECK, "deep", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert cheap["ok"] is True and deep["ok"] is False and _failed(deep)[0] == "archive"


@pytest.mark.parametrize("field", ["base_seq", "cumulative_merkle_root"])
def test_check_live_unit_cheap_archive_tail_compares_with_the_signed_head(homes, tmp_path, field):
    home = _copy(homes, tmp_path, public_only=False)
    am = home / "spine" / "archive" / "archive.manifest.json"
    d = json.loads(am.read_text())
    d["snapshots"][-1][field] = 9 if field == "base_seq" else "0" * 64
    am.write_text(json.dumps(d))
    cheap = json.loads(run_in_home(home, LIVE_CHECK, "cheap", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert cheap["ok"] is False and _failed(cheap)[0] == "archive", cheap


def test_check_live_unit_cheap_archive_tail_requires_every_listed_segment(homes, tmp_path):
    home = _copy(homes, tmp_path, public_only=False)
    sorted((home / "spine" / "archive" / "segments").iterdir())[-1].unlink()
    cheap = json.loads(run_in_home(home, LIVE_CHECK, "cheap", SIGIL_SPINE_ARCHIVE_DIR=None).stdout.splitlines()[-1])
    assert cheap["ok"] is False and "missing" in _failed(cheap)[1], cheap


# ---- `sigil spine verify-unit` ----------------------------------------------------------------------------------
_CLI = "import sys\nfrom sigil.cli import main\nmain(sys.argv[1:])\n"


def test_cli_verify_unit_exit_codes(homes, tmp_path):
    good = _copy(homes, tmp_path)
    r = run_in_home(good, _CLI, "spine", "verify-unit", check=False, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert r.returncode == 0 and "OK: the spine unit" in r.stdout, r.stderr
    caller = tmp_path / "caller-home"
    caller.mkdir()
    r = run_in_home(caller, _CLI, "spine", "verify-unit", "--home", str(good), check=False)
    assert r.returncode == 0 and "OK: the spine unit" in r.stdout, r.stderr
    (good / "floor.json").unlink()
    r = run_in_home(caller, _CLI, "spine", "verify-unit", "--home", str(good), check=False)
    assert r.returncode == 2 and "REFUSED" in r.stderr and "floor.json" in r.stderr


def test_cli_verify_unit_on_an_unpruned_home_and_on_a_home_holding_the_private_key(tmp_path):
    home = signed_home(tmp_path, pruned=False)
    r = run_in_home(home, _CLI, "spine", "verify-unit", check=False, SIGIL_SPINE_ARCHIVE_DIR=None)
    assert r.returncode == 0 and "not pruned" in r.stdout, r.stderr
    caller = tmp_path / "caller-home"
    caller.mkdir()
    r = run_in_home(caller, _CLI, "spine", "verify-unit", "--home", str(home), check=False)
    assert r.returncode == 2 and f"SIGIL_HOME={home}" in r.stderr
    r = run_in_home(caller, _CLI, "spine", "status", "--deep", check=False)
    assert r.returncode == 2 and "does not take --deep" in r.stderr
