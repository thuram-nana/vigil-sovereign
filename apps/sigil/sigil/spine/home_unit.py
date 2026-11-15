"""A SIGIL_HOME's spine verified as ONE unit — the path-aware check a restore, a backup and an operator share.

A hard-pruned spine is readable only together with the members that carry its pruned prefix: the owner-signed head
(the prune boundary), the durable anti-rollback floor, the owner public key(s), the segment manifest and segments of
the live window, and the cold archive of the pruned records. A copy that lacks one of them, or holds one from
another home or another generation, must be refused as a whole — never read as a shorter spine.

Every reader of those members resolves its paths from the PROCESS's ``SIGIL_HOME`` at import time. So:

  * :func:`unit_shape` is the PURE pre-check (no process globals, no keys): it reads the members at the paths a
    :class:`HomeUnit` derives for any home and names the member of a partial or mismatched set;
  * :func:`verify_unit_isolated` verifies ANOTHER home in a child process whose ``SIGIL_HOME`` is that home (and
    whose archive dir is the unit's, given explicitly) — the real readers then read that home's own head, floor,
    keys and archive. The unit must hold PUBLIC keys only: the child refuses a unit with a private key or a DEK;
  * :func:`check_live_unit` runs the same checks in-process for this process's own home.

``sigil spine verify-unit`` is the operator's entry point. Read-only apart from the read-index sidecars and
lockfiles any reader leaves beside the segments. Sovereign plane; imports no offense code.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from .isolated_child import consume_nonce, last_json_line, run_isolated, tempdir_outside
from .manifest import SpineLayout

_CHILD_FLAG = "--verify-isolated"        # internal: verify a unit in a child scoped to it
_NONCE_FILE = ".unit-verify-nonce"       # <work_dir>/…: the parent's one-shot proof that it launched the child
_NONCE_ENV = "SIGIL_UNIT_VERIFY_NONCE"
_CHILD_TIMEOUT_S = 6 * 3600


@dataclass(frozen=True)
class HomeUnit:
    """The members of one home's spine unit, derived from the home exactly as ``config`` derives them for the
    process's own home (``spine/spine.jsonl``, ``spine/head.json``, ``spine/keys``, ``floor.json`` at the home root)
    and as ``SpineLayout`` derives the segment layout. The archive dir is EXPLICIT: never read from the
    environment (on a restore or drill host, ``SIGIL_SPINE_ARCHIVE_DIR`` names the LIVE home's archive)."""
    home: Path
    archive_dir: Path

    @classmethod
    def for_home(cls, home: "Path | str", archive_dir: "Path | str | None" = None) -> "HomeUnit":
        home = Path(home)
        return cls(home=home, archive_dir=Path(archive_dir) if archive_dir is not None else home / "spine" / "archive")

    @property
    def spine_dir(self) -> Path:
        return self.home / "spine"

    @property
    def data_path(self) -> Path:
        return self.spine_dir / "spine.jsonl"

    @property
    def layout(self) -> SpineLayout:
        return SpineLayout.for_path(self.data_path)

    @property
    def head_path(self) -> Path:
        return self.spine_dir / "head.json"

    @property
    def keys_dir(self) -> Path:
        return self.spine_dir / "keys"

    @property
    def owner_pub(self) -> Path:
        return self.keys_dir / "owner.pub"

    @property
    def floor_path(self) -> Path:
        return self.home / "floor.json"

    @property
    def archive_manifest(self) -> Path:
        return self.archive_dir / "archive.manifest.json"

    def members(self) -> "dict[str, Path]":
        lay = self.layout
        return {"head": self.head_path, "manifest": lay.manifest_path, "segments": lay.segments_dir,
                "owner.pub": self.owner_pub, "owner.genesis.pub": self.keys_dir / "owner.genesis.pub",
                "floor": self.floor_path, "archive": self.archive_manifest}

    def secret_files(self) -> "list[str]":
        """Private key material in the unit's keys dir (an owner private key, a staged one, a DEK, or a temp copy
        of one), by name — never read."""
        try:
            names = [p.name for p in self.keys_dir.iterdir()]
        except OSError:
            return []
        return sorted(n for n in names if ".priv" in n or n.endswith(".dek") or ".dek." in n)


@dataclass(frozen=True)
class UnitShape:
    """What the members of a unit declare, read without keys or process globals. ``pruned`` is True when the live
    window starts above seq 0 OR the head commits a prune (a prune's crash window: the head is signed while the
    pruned prefix is still on disk, so the live window still starts at 0 — that is legal). ``refusals`` names each
    missing or mismatched member; an empty tuple means the set is complete and consistent as far as shape goes
    (the signatures and the archive are verified by the readers)."""
    pruned: bool
    live_start: int
    head_present: bool
    head_base_seq: int = 0
    snapshot_seq: int = -1
    last_seq: int = -1
    entry_count: int = 0
    head_sig_hash: str = ""
    cumulative_merkle_root: str = ""
    floor_present: bool = False
    floor_head_sig_hash: str = ""
    archive_present: bool = False
    refusals: "tuple[str, ...]" = field(default_factory=tuple)

    def as_dict(self) -> "dict[str, Any]":
        d = asdict(self)
        d["refusals"] = list(self.refusals)
        return d


def unit_shape(unit: HomeUnit, *, require_archive: bool = True) -> UnitShape:
    """The shape of ``unit`` and every reason it is not a complete, consistent pruned set (see :class:`UnitShape`).
    Pure: reads the unit's own files only, never a process-global path or a key."""
    from ..reuse import SignedChainHead
    from .floor import head_sig_hash, load_floor
    from .manifest import read_manifest
    from .store import _segment_run_break

    refusals: "list[str]" = []
    lay = unit.layout
    live_start = 0
    manifest = None
    try:
        manifest = read_manifest(lay)
    except Exception as e:  # noqa: BLE001 — a present-but-unreadable manifest is a refusal, never "no manifest"
        refusals.append(f"the segment manifest {lay.manifest_path.name} is unreadable ({type(e).__name__}: {e})")
    if manifest is not None:
        brk = _segment_run_break(manifest)
        if brk is not None:
            refusals.append(f"the segment manifest is not one contiguous segment run ({brk})")
        segs = manifest.ordered()
        live_start = segs[0].first_seq if segs else 0
        missing = [s.file for s in segs if not lay.seg_path(s).is_file()]
        if missing:
            refusals.append(f"segment file(s) the manifest lists are missing: {', '.join(missing[:3])}")
    elif not refusals and lay.segments_dir.is_dir() and any(lay.segments_dir.iterdir()):
        refusals.append(f"the segment manifest {lay.manifest_path.name} is missing while segment files are present")

    head = None
    head_state = "missing"
    if unit.head_path.exists():
        try:
            head = SignedChainHead.model_validate_json(unit.head_path.read_text(encoding="utf-8"))
            head_state = "present"
        except Exception as e:  # noqa: BLE001 — a garbage / future-schema head is no head for this check
            head_state = f"unparseable ({type(e).__name__})"
    pruned = live_start > 0 or (head is not None and head.snapshot_seq >= 0)

    if live_start > 0 and head is None:
        refusals.append(f"the live window starts at seq {live_start} (a hard-pruned spine) but its signed head "
                        f"(spine/head.json) is {head_state}")
    elif live_start > 0 and head is not None and head.snapshot_seq < 0:
        refusals.append(f"the live window starts at seq {live_start} (a hard-pruned spine) but spine/head.json "
                        f"declares no prune (a head from before the prune)")
    if head is not None and head.snapshot_seq >= 0 and live_start not in (0, head.base_seq):
        refusals.append(f"spine/head.json commits a prune at seq {head.base_seq} but the live window starts at seq "
                        f"{live_start} (a head from another generation)")

    floor_present = unit.floor_path.exists()
    floor_hsh = ""
    if pruned:
        if not floor_present:
            refusals.append("floor.json (the durable anti-rollback floor) is missing — a hard-pruned spine is "
                            "restored only together with its floor")
        else:
            try:
                fl = load_floor(unit.floor_path)
            except Exception as e:  # noqa: BLE001 — corrupt / wrong scope / too new: never certifies anything
                fl = None
                refusals.append(f"floor.json cannot be used ({type(e).__name__}: {e})")
            if fl is not None:
                floor_hsh = fl.head_sig_hash
                if head is not None and fl.head_sig_hash not in (head_sig_hash(head), head.prev_head_hash):
                    refusals.append("floor.json records neither this spine/head.json nor its parent head (a floor "
                                    "from another home or another generation)")
        if require_archive and not unit.archive_manifest.is_file():
            refusals.append(f"no archive manifest at {unit.archive_manifest} — the pruned prefix of a hard-pruned "
                            f"spine lives only in its archive")
    return UnitShape(
        pruned=pruned, live_start=live_start, head_present=head is not None,
        head_base_seq=head.base_seq if head is not None else 0,
        snapshot_seq=head.snapshot_seq if head is not None else -1,
        last_seq=head.last_seq if head is not None else -1,
        entry_count=head.entry_count if head is not None else 0,
        head_sig_hash=head_sig_hash(head) if head is not None else "",
        cumulative_merkle_root=head.cumulative_merkle_root if head is not None else "",
        floor_present=floor_present, floor_head_sig_hash=floor_hsh,
        archive_present=unit.archive_manifest.is_file(), refusals=tuple(refusals))


# ---- the checks the real readers run (in the child for another home, in-process for this one) -------------------
def _archive_tail_check(unit: HomeUnit) -> "tuple[bool, str]":
    """O(1) archive check for a routine read: the archive manifest is present, its last snapshot row is the prune the
    signed head commits (base_seq and cumulative Merkle root), and every segment file it lists exists. The full
    re-derivation is ``prune.verify_with_archive`` (``deep``)."""
    from ..reuse import SignedChainHead
    try:
        am = json.loads(unit.archive_manifest.read_text(encoding="utf-8"))
        head = SignedChainHead.model_validate_json(unit.head_path.read_text(encoding="utf-8"))
        rows = sorted(am["snapshots"], key=lambda s: int(s["base_seq"]))
        segs = am["segments"]
        files = [unit.archive_dir / str(r["file"]) for r in segs]
    except Exception as e:  # noqa: BLE001 — an unreadable manifest/head is a failed check, never a pass
        return False, f"the archive manifest at {unit.archive_manifest} cannot be read ({type(e).__name__}: {e})"
    if not rows or int(rows[-1]["base_seq"]) != head.base_seq:
        return False, (f"the archive's last snapshot row is not the prune the signed head commits (head base_seq "
                       f"{head.base_seq})")
    if rows[-1].get("cumulative_merkle_root") != head.cumulative_merkle_root:
        return False, "the archive's cumulative Merkle root is not the one the signed head commits"
    missing = [str(p.name) for p in files if not p.is_file()]
    if missing:
        return False, f"archived segment file(s) missing: {', '.join(missing[:3])}"
    return True, f"archive tail matches the signed head ({len(segs)} segment(s))"


def _run_checks(unit: HomeUnit, *, require_archive: bool, deep: bool, store=None) -> "dict[str, Any]":
    """The unit checks over the CURRENT process's home (``unit`` must be it; ``store`` a handle on its spine, or
    None for a fresh one): shape, then each real reader. Stops at the first failure (later readers depend on the
    earlier ones). Returns ``{ok, pruned, checks, shape}``."""
    from .. import config
    from ..governor import identity
    from ..governor.killswitch import KillSwitch
    from .checkpoint import owner_succession, verify_checkpoint
    from .prune import verify_with_archive
    from .snapshot import SnapshotState, seed_applies
    from .store import SpineStore

    checks: "list[dict[str, Any]]" = []
    out: "dict[str, Any]" = {"ok": False, "pruned": False, "checks": checks, "shape": {}}

    def add(name: str, ok: bool, why: str) -> bool:
        checks.append({"name": name, "ok": bool(ok), "why": str(why)})
        return bool(ok)

    shape = unit_shape(unit, require_archive=require_archive)
    out["pruned"] = shape.pruned
    if not add("members", not shape.refusals, "; ".join(shape.refusals) or "complete set"):
        return out
    if not shape.pruned:
        add("pruned", True, "not pruned — the spine starts at genesis (`sigil verify` checks it)")
        out["ok"] = True
        return out

    def step(name: str, fn) -> "tuple[bool, Any]":
        """Run one reader; a raise fails the check named ``name`` (never escapes)."""
        try:
            return True, fn()
        except Exception as e:  # noqa: BLE001 — a reader that raises fails the unit, naming why
            add(name, False, f"{type(e).__name__}: {e}")
            return False, None

    ran, store = step("chain", lambda: store if store is not None else SpineStore(config.SPINE_PATH))
    if not ran:
        return out
    ran, res = step("chain", store.verify)
    if not ran or not add("chain", res[0], res[1]):
        return out
    ran, res = step("signed_head", lambda: verify_checkpoint(store))
    if not ran or not add("signed_head", res[0], res[1]):
        return out
    pub = identity.owner_pubkey()
    ran, succ = step("succession_tip", lambda: owner_succession(store))
    if not ran:
        return out
    tip = succ.current if succ is not None else None
    if not add("succession_tip", bool(tip) and tip == pub,
               "owner.pub is the validated owner-key succession tip" if tip and tip == pub else
               "the unit's owner key is not the validated owner-key succession tip (a unit whose key is not the "
               "tip can never re-anchor its pruned head)"):
        return out
    ran, snap = step("snapshot_seed", lambda: SnapshotState.load(store))
    if not ran:
        return out
    ran, applies = step("snapshot_seed", lambda: seed_applies(snap, pub, store))
    if not ran or not add("snapshot_seed", bool(applies),
                          f"seed at seq {snap.snapshot_seq} applies (live window from seq {snap.base_seq})" if applies
                          else "the snapshot seed does not apply under this unit's owner key"):
        return out
    ran, engaged = step("registry_read", lambda: KillSwitch(store).is_engaged())
    if not ran:
        return out
    add("registry_read", True, f"seeded registry read ok (kill switch {'engaged' if engaged else 'released'})")
    archive_segments = 0
    if require_archive:
        ran, res = step("archive", (lambda: verify_with_archive(store, adir=unit.archive_dir)) if deep
                        else (lambda: _archive_tail_check(unit)))
        if not ran or not add("archive", res[0], res[1]):
            return out
        try:
            archive_segments = len(json.loads(unit.archive_manifest.read_text(encoding="utf-8"))["segments"])
        except Exception:  # noqa: BLE001 — counted for the report only
            archive_segments = 0
    out["shape"] = {"base_seq": snap.base_seq, "snapshot_seq": snap.snapshot_seq, "last_seq": shape.last_seq,
                    "entry_count": shape.entry_count, "archive_segments": archive_segments,
                    "succession_tip": tip, "head_sig_hash": shape.head_sig_hash,
                    "floor_head_sig_hash": shape.floor_head_sig_hash,
                    "cumulative_merkle_root": shape.cumulative_merkle_root}
    out["ok"] = True
    return out


def check_live_unit(store=None, *, require_archive: bool = True, deep: bool = False,
                    archive_dir: "Path | str | None" = None) -> "dict[str, Any]":
    """The unit checks for THIS process's own home, in-process (its globals are path-correct for it). The archive
    dir is the one the services use (``SIGIL_SPINE_ARCHIVE_DIR`` or the default) unless given. ``deep`` re-derives
    the whole archive (``prune.verify_with_archive``); otherwise an O(1) tail check against the signed head."""
    from .. import config
    from .prune import archive_dir as _effective_archive_dir
    unit = HomeUnit.for_home(config.SIGIL_HOME, archive_dir if archive_dir is not None else _effective_archive_dir())
    return _run_checks(unit, require_archive=require_archive, deep=deep, store=store)


def verify_unit_isolated(unit: HomeUnit, *, work_dir: "Path | str", require_archive: bool = True,
                         timeout: float = _CHILD_TIMEOUT_S) -> "dict[str, Any]":
    """Verify ANOTHER home's spine unit with the real readers in a child process whose ``SIGIL_HOME`` is
    ``unit.home`` and whose archive dir is ``unit.archive_dir`` (set explicitly — an inherited value never wins), with
    the fold cache off and ``TMPDIR`` inside ``work_dir``. The archive is re-derived in full. The unit must hold
    public keys only (the child refuses otherwise). Never raises for a failed check: returns ``{ok, pruned, checks,
    shape}`` (``refused`` names a scoping refusal)."""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    home_r, work_r = unit.home.resolve(), work_dir.resolve()
    if work_r == home_r or home_r in work_r.parents or work_r in home_r.parents:
        return {"ok": False, "pruned": None, "checks": [], "shape": {},
                "refused": f"the work dir {work_dir} overlaps the unit's home {unit.home}"}
    argv = [_CHILD_FLAG, str(unit.home), "--work-dir", str(work_dir), "--archive-dir", str(unit.archive_dir)]
    if require_archive:
        argv.append("--require-archive")
    try:
        proc = run_isolated("sigil.spine.home_unit", argv, home=unit.home, work_dir=work_dir, nonce_file=_NONCE_FILE,
                            nonce_env=_NONCE_ENV, timeout=timeout,
                            extra_env={"SIGIL_SPINE_ARCHIVE_DIR": str(unit.archive_dir),
                                       "VIGIL_FOLD_CACHE_ENABLED": "0"})
    except Exception as e:  # noqa: BLE001 — a child that could not run (or timed out) verified nothing
        return {"ok": False, "pruned": None, "checks": [], "shape": {},
                "refused": f"the isolated verifier did not complete ({type(e).__name__}: {e})"}
    res = last_json_line(proc.stdout)
    if res is None or "ok" not in res:
        tail = (proc.stderr or proc.stdout or "").strip()[-600:]
        return {"ok": False, "pruned": None, "checks": [], "shape": {},
                "refused": f"the isolated verifier failed (rc={proc.returncode}): {tail}"}
    return res


def failure_reason(res: "dict[str, Any]") -> str:
    """One line naming why a unit check did not pass (the scoping refusal, or the first failed check)."""
    if res.get("refused"):
        return str(res["refused"])
    for c in res.get("checks") or []:
        if not c.get("ok"):
            return f"{c.get('name')}: {c.get('why')}"
    return "the unit did not verify"


def _child_main(home: str, work_dir: str, archive_dir: str, require_archive: bool) -> int:
    """The isolated child. Refuses unless the parent's one-shot nonce matches, this process's SIGIL_HOME IS the
    unit's home, its temp dir is inside the work dir, the archive dir it would read is the one the parent named,
    and the unit holds no private key material. Prints one JSON verdict line."""
    from .. import config
    h, w = Path(home).resolve(), Path(work_dir).resolve()
    nonce_ok = consume_nonce(w, _NONCE_FILE, _NONCE_ENV)
    tmp = tempdir_outside(w)
    env_archive = os.environ.get("SIGIL_SPINE_ARCHIVE_DIR", "")
    unit = HomeUnit(home=h, archive_dir=Path(archive_dir))
    secrets_present = unit.secret_files()
    why = ("no matching one-shot nonce from the parent verifier" if not nonce_ok
           else f"SIGIL_HOME={config.SIGIL_HOME} is not the unit's home {h}" if config.SIGIL_HOME.resolve() != h
           else f"TMPDIR={tmp} is outside the work dir" if tmp is not None
           else "SIGIL_SPINE_ARCHIVE_DIR is not the unit's archive dir"
           if not env_archive or Path(env_archive).resolve() != Path(archive_dir).resolve()
           else f"the unit holds {len(secrets_present)} private key file(s) — it is verified with public keys only"
           if secrets_present
           else "")
    if why:
        res: "dict[str, Any]" = {"ok": False, "pruned": None, "checks": [], "shape": {},
                                 "refused": f"refusing: the isolated unit verifier is not scoped to its unit ({why})"}
    else:
        res = _run_checks(unit, require_archive=require_archive, deep=True)
    print(json.dumps(res, sort_keys=True, default=str))
    return 0


def main(argv: "Optional[list[str]]" = None) -> int:
    """Internal entry point of the isolated child (``python -m sigil.spine.home_unit --verify-isolated …``)."""
    import argparse
    ap = argparse.ArgumentParser(description="SIGIL spine unit verifier (internal child entry point)")
    ap.add_argument(_CHILD_FLAG, dest="home", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--archive-dir", required=True)
    ap.add_argument("--require-archive", action="store_true")
    a = ap.parse_args(argv)
    return _child_main(a.home, a.work_dir, a.archive_dir, a.require_archive)


def verify_other_home(home: "Path | str", *, archive_dir: "Path | str | None" = None,
                      require_archive: bool = True) -> "dict[str, Any]":
    """``verify_unit_isolated`` in a throwaway work dir (for the CLI)."""
    unit = HomeUnit.for_home(home, archive_dir)
    with tempfile.TemporaryDirectory(prefix="sigil-unit-verify-") as tmp:
        return verify_unit_isolated(unit, work_dir=Path(tmp), require_archive=require_archive)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
