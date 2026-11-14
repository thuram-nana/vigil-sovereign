"""Seam migration — find launch-seam records kept in a former seam directory, and keep the migration journal.

Every plane resolves ONE seam directory (``vigil_core.seam_base``; the shipped units set
``VIGIL_BASE_DIR=%h/.sigil/credit-lease``). A host whose processes used another directory before — most often the
cockpit's working-directory default ``$SIGIL_HOME/.vigil-live`` — still holds launch-seam records there (published
leases, settlement / pause / paused-past-expiry markers, single-use floors, owner-signed publications). They are
carried into the seam by ``sigil seam migrate``; this module is what that command, ``vigil doctor`` and the
migration guard (``VIGIL_SEAM_MIGRATION_GUARD``) share:

* :data:`SEAM_CLASSES` — every seam artifact class, by path, with how it is carried over (its merge rule);
  everything else in a former seam directory is left in place and never read (:data:`LEFT_IN_PLACE`: the owner's
  passkey store, the cockpit bootstrap token, ``hostcmd/`` and the offense engine's own state).
* :func:`inventory` — a bounded, symlink-refusing walk of ONLY the class paths of a tree, with a content digest.
* :func:`legacy_candidates` — the former seam directories of this host: ``$SIGIL_HOME/.vigil-live``, the
  ``.vigil-live`` of each configured writer unit's working directory, a unit's still-set retired
  ``VIGIL_SETTLE_BASE_DIR`` and ``VIGIL_SEAM_LEGACY_DIRS``; minus the seam itself, every configured unit's current
  seam and the base of a running ``vigil up``.
* the journal ``<seam>/.seam-migration/journal.json`` (0600 in a 0700 directory, written atomically, locked by
  ``journal.json.lock``) that records, per source tree, the digest the migration committed.
* :func:`unmigrated_legacy` — each candidate that holds seam-class content not committed by a migration at its
  current digest (``no_journal`` / ``incomplete`` / ``changed_since`` / ``unsafe`` / ``too_large``).

A source tree is never modified or deleted by any of this: it stays the rollback and re-migration source.

FATAL-2: stdlib + ``vigil_core`` + the import-clean ``vigil_integration`` seam modules only, so the sovereign CLI
and ``vigil doctor`` (offense venv) both import it.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional

__all__ = [
    "SEAM_CLASSES", "LEFT_IN_PLACE", "SeamClass", "active_classes", "inventory", "legacy_candidates",
    "running_up_base", "journal_path", "journal_lock", "read_journal", "write_journal", "new_journal",
    "unmigrated_legacy", "LEGACY_DIRS_ENV", "JOURNAL_KIND",
]

#: Extra former seam directories to check (colon-separated ABSOLUTE paths). Detection only: it can add candidates,
#: never remove one. Default empty.
LEGACY_DIRS_ENV = "VIGIL_SEAM_LEGACY_DIRS"
JOURNAL_DIRNAME = ".seam-migration"
JOURNAL_NAME = "journal.json"
JOURNAL_KIND = "vigil-seam-migration-v1"
JOURNAL_SCHEMA_VERSION = 1
#: Inventory bounds: past either, a tree is ``too_large`` (it then counts as not migrated).
MAX_FILES = 100_000
MAX_BYTES = 256 * 1024 * 1024
#: The ``vigil up`` pointer (``${XDG_STATE_HOME:-~/.local/state}/vigil/vigil-up.json``) names the seam a running
#: ``vigil up`` uses; while its pid is alive that directory is a live seam, never a former one.
UP_POINTER_SCHEMA = "vigil-up-pointer-v1"
_LOCK_WAIT_S = 5.0


@dataclass(frozen=True)
class SeamClass:
    """One seam artifact class. ``path`` is the directory under the seam (or the file, when ``pattern`` is empty);
    ``pattern`` globs its leaves (``"<dir glob>/<file>"`` for a per-slug nested file at the seam root). ``rule`` is
    how ``sigil seam migrate`` carries it; ``override_env`` names the variable that, when set, keeps this class
    OUTSIDE the seam (it is then neither inventoried nor carried)."""
    name: str
    path: str
    rule: str
    pattern: str = "*"
    override_env: str = ""


#: Merge rules: ``union_nonces`` (nonce-set markers: the set union), ``union_files`` (one file per spent token:
#: the file union), ``floor_max`` (monotonic floors: the higher wins, never lowered), ``pause_delta`` (pauses: each
#: legacy (slug, nonce) carried ONCE, journaled), ``lease`` (lease bundles: create-if-absent, same nonce only),
#: ``rederive`` (owner-sealed publications: rebuilt from the spine, never copied), ``model_grant`` (copied only for
#: a live, unsettled lease), ``copy_if_absent`` (owner-signed files: copied when absent, a differing copy is a
#: conflict) and ``key`` (the offense-governance key: the same, for one file).
SEAM_CLASSES: "tuple[SeamClass, ...]" = (
    SeamClass("settlements", "credit-lease-settlements", "union_nonces", "*.json"),
    SeamClass("paused_past_expiry", "credit-lease-paused-past-expiry", "union_nonces", "*.json"),
    SeamClass("approval_nonces", "approval-nonces", "union_files", "*", "VIGIL_APPROVAL_NONCE_DIR"),
    SeamClass("engage_attempts", ".engage-attempts", "union_files", "*.json"),
    SeamClass("lease_floors", ".credit-lease-highwater", "floor_max", "*.json"),
    SeamClass("eval_grant_floors", ".eval-grant-highwater", "floor_max", "*.json"),
    SeamClass("eval_attestation_floors", ".eval-offense-highwater", "floor_max", "*.json"),
    SeamClass("pauses", "credit-lease-pauses", "pause_delta", "*.json"),
    SeamClass("leases", "credit-launch-leases", "lease", "*.json"),
    SeamClass("eval_grants", "eval-capability-grants", "rederive", "*.json"),
    SeamClass("eval_attestations", "eval-offense-attestations", "rederive", "*.json"),
    SeamClass("target_authorizations", "target-authorizations", "copy_if_absent", "*.json"),
    SeamClass("approval_authority", "approval-authority.json", "copy_if_absent", ""),
    SeamClass("approvals_pending", "approvals/pending", "copy_if_absent", "*.json"),
    SeamClass("approvals_signed", "approvals/signed", "copy_if_absent", "*.json"),
    SeamClass("model_grants", "model-grants", "model_grant", "*.json"),
    SeamClass("eval_grant_overrides", "eval-capability-grant-overrides", "copy_if_absent", "*"),
    SeamClass("launch_delegations", "", "copy_if_absent", "cust_*/offense-governance.deleg.json"),
    SeamClass("aegis_monitoring_authority", "aegis/monitoring_authority", "copy_if_absent", "*",
              "VIGIL_MONITORING_PUBLISH_DIR"),
    SeamClass("aegis_report_secrets", "aegis/report_secrets", "copy_if_absent", "*", "VIGIL_MONITORING_SECRETS_DIR"),
    SeamClass("governance_key", "offense-governance.key", "key", ""),
)

#: What a former seam directory may also hold that is NOT seam state: never inventoried, read, copied or touched.
LEFT_IN_PLACE: "tuple[str, ...]" = (
    "webauthn-credentials.json", "cockpit-bootstrap-token", "hostcmd", "ui", "jobs", "vault", "operator.key",
    "offense-spine.key", "install-manifest.json", "restricted-mode", "proofs", "runs", "vigil-live-reports",
    JOURNAL_DIRNAME,
)


def active_classes(env: "Optional[Mapping[str, str]]" = None) -> "tuple[SeamClass, ...]":
    """The classes that live in the seam in this environment (a class whose ``override_env`` is set lives elsewhere)."""
    e = os.environ if env is None else env
    return tuple(c for c in SEAM_CLASSES if not (c.override_env and (e.get(c.override_env) or "").strip()))


def _skipped(name: str) -> bool:
    """Transients both backup legs skip: lock files and atomic-write temporaries."""
    return name.endswith(".lock") or ".tmp-" in name or name.endswith(".tmp")


class _Unsafe(Exception):
    pass


def _lstat(p: Path) -> "Optional[os.stat_result]":
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def _dir_or_none(tree: Path, rel: str) -> Optional[Path]:
    """``tree/rel`` when every component is a real directory; None when one is absent; unsafe on a symlink or a
    non-directory on the way."""
    cur = tree
    for part in [p for p in rel.split("/") if p]:
        cur = cur / part
        st = _lstat(cur)
        if st is None:
            return None
        if not stat.S_ISDIR(st.st_mode):
            raise _Unsafe(str(cur))
    return cur


def _leaf(p: Path) -> "Optional[os.stat_result]":
    st = _lstat(p)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise _Unsafe(str(p))
    return st


def class_files(tree: Any, cls: SeamClass) -> "list[tuple[str, Path]]":
    """``[(relpath, path)]`` of the leaves of ``cls`` under ``tree`` (sorted), never following a symlink. Raises
    :class:`_Unsafe` on a symlink or non-regular entry inside a class path."""
    root = Path(tree)
    out: "list[tuple[str, Path]]" = []
    if not cls.pattern:                                         # one file at a fixed path
        parent, _, name = cls.path.rpartition("/")
        d = _dir_or_none(root, parent) if parent else root
        if d is not None and _leaf(d / name) is not None:
            out.append((cls.path, d / name))
        return out
    if "/" in cls.pattern:                                      # <dir glob>/<file> at the seam root
        dglob, _, name = cls.pattern.partition("/")
        try:
            entries = sorted(os.scandir(root), key=lambda e: e.name)
        except FileNotFoundError:
            return out
        for e in entries:
            if not fnmatch.fnmatchcase(e.name, dglob):
                continue
            st = _lstat(Path(e.path))
            if st is None:
                continue
            if not stat.S_ISDIR(st.st_mode):
                raise _Unsafe(e.path)
            if _leaf(Path(e.path) / name) is not None:
                out.append((f"{e.name}/{name}", Path(e.path) / name))
        return out
    d = _dir_or_none(root, cls.path)
    if d is None:
        return out
    for e in sorted(os.scandir(d), key=lambda e: e.name):
        if _skipped(e.name):
            continue
        if _leaf(Path(e.path)) is None:
            continue
        if fnmatch.fnmatchcase(e.name, cls.pattern):
            out.append((f"{cls.path}/{e.name}", Path(e.path)))
    return out


def _sha256_file(p: Path) -> "tuple[int, str]":
    fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    h = hashlib.sha256()
    size = 0
    try:
        while True:
            b = os.read(fd, 1 << 16)
            if not b:
                break
            size += len(b)
            h.update(b)
    finally:
        os.close(fd)
    return size, h.hexdigest()


def inventory(tree: Any, *, env: "Optional[Mapping[str, str]]" = None) -> dict:
    """The seam-class content of ``tree``: ``{"path", "status", "files", "bytes", "digest", "classes", "entries"}``.

    ``status`` is ``ok``, ``unsafe`` (a symlink or non-regular entry inside a class path — nothing is followed) or
    ``too_large`` (past :data:`MAX_FILES` / :data:`MAX_BYTES`). ``digest`` is sha256 over the sorted
    ``(relpath, size, sha256(bytes))`` of every class leaf (lock files and temporaries excluded), so ANY change to a
    class file changes it. ``entries`` maps each relpath to ``(size, sha256)``. Only class paths are walked; nothing
    in :data:`LEFT_IN_PLACE` is ever opened. Never raises for a missing tree (it is empty)."""
    out: dict = {"path": str(tree), "status": "ok", "files": 0, "bytes": 0, "digest": "", "classes": {},
                 "entries": {}}
    entries: "dict[str, tuple[int, str]]" = {}
    total = 0
    try:
        for cls in active_classes(env):
            files = class_files(tree, cls)
            if files:
                out["classes"][cls.name] = len(files)
            for rel, p in files:
                if len(entries) >= MAX_FILES:
                    out["status"] = "too_large"
                    break
                size, digest = _sha256_file(p)
                total += size
                if total > MAX_BYTES:
                    out["status"] = "too_large"
                    break
                entries[rel] = (size, digest)
            if out["status"] != "ok":
                break
    except _Unsafe as e:
        out["status"] = "unsafe"
        out["unsafe"] = os.path.relpath(str(e), str(tree)) if str(e).startswith(str(tree)) else str(e)
    except OSError as e:                     # an unreadable class path: it cannot be shown migrated
        out["status"] = "unsafe"
        out["unsafe"] = f"{type(e).__name__}"
    h = hashlib.sha256()
    for rel in sorted(entries):
        size, d = entries[rel]
        h.update(f"{rel}\0{size}\0{d}\n".encode("utf-8"))
    out.update(files=len(entries), bytes=total, digest="sha256:" + h.hexdigest(), entries=entries)
    return out


# ── candidates ─────────────────────────────────────────────────────────────────────────────────────────────────

def _pid_alive(pid: Any) -> bool:
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    try:
        os.kill(p, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def up_pointer_path(env: "Optional[Mapping[str, str]]" = None, home: "Optional[Path]" = None) -> Path:
    e = os.environ if env is None else env
    state = (e.get("XDG_STATE_HOME") or "").strip()
    root = Path(state) if state else (Path(home) if home is not None else Path.home()) / ".local" / "state"
    return root / "vigil" / "vigil-up.json"


def running_up_base(env: "Optional[Mapping[str, str]]" = None, home: "Optional[Path]" = None) -> Optional[str]:
    """The seam of a RUNNING ``vigil up`` (its pointer file, while its pid is alive), else None. Never raises."""
    try:
        obj = json.loads(up_pointer_path(env, home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("schema") != UP_POINTER_SCHEMA or not isinstance(obj.get("base"), str):
        return None
    return obj["base"] if obj["base"] and _pid_alive(obj.get("pid")) else None


def legacy_candidates(seam: Any, *, units: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
                      sigil_home: Any = None, env: "Optional[Mapping[str, str]]" = None,
                      home: "Optional[Path]" = None) -> "list[str]":
    """The former seam directories of this host (real paths, existing directories, in a stable order): the union of
    ``$SIGIL_HOME/.vigil-live``; ``<WorkingDirectory>/.vigil-live`` of each configured WRITER unit
    (``seam_base_units.WRITER_SEAM_UNITS``); a unit's still-set retired ``VIGIL_SETTLE_BASE_DIR`` naming another tree;
    and each absolute path in ``VIGIL_SEAM_LEGACY_DIRS``. Removed: ``seam`` itself, every configured unit's CURRENT
    seam (units that disagree are reported by ``vigil doctor`` separately) and a running ``vigil up``'s base.
    ``units`` is ``seam_base_units.unit_details()`` (default: computed here)."""
    from .seam_base_units import WRITER_SEAM_UNITS, unit_details
    e = os.environ if env is None else env
    if units is None:
        units = unit_details(home=home)
    if sigil_home is None:
        sigil_home = (e.get("SIGIL_HOME") or "").strip() or str((Path(home) if home is not None else Path.home())
                                                                  / ".sigil")
    raw: "list[str]" = [os.path.join(os.path.expanduser(str(sigil_home)), ".vigil-live")]
    for u in WRITER_SEAM_UNITS:
        got = units.get(u)
        if not got:
            continue
        if got.get("workdir"):
            raw.append(os.path.join(str(got["workdir"]), ".vigil-live"))
        legacy = got.get("legacy")
        if legacy and os.path.realpath(str(legacy)) != os.path.realpath(str(got.get("seam") or "")):
            raw.append(str(legacy))
    for part in (e.get(LEGACY_DIRS_ENV) or "").split(":"):
        part = os.path.expanduser(part.strip())
        if part and os.path.isabs(part):
            raw.append(part)
    excluded = {os.path.realpath(str(seam))}
    excluded |= {os.path.realpath(str(u["seam"])) for u in units.values() if u.get("seam")}
    up = running_up_base(e, home)
    if up:
        excluded.add(os.path.realpath(up))
    out: "list[str]" = []
    for r in raw:
        real = os.path.realpath(r)
        if real in excluded or real in out or not os.path.isdir(real):
            continue
        out.append(real)
    return out


# ── the journal ────────────────────────────────────────────────────────────────────────────────────────────────

def journal_path(seam: Any) -> Path:
    return Path(seam) / JOURNAL_DIRNAME / JOURNAL_NAME


@contextmanager
def journal_lock(seam: Any, *, wait_s: float = _LOCK_WAIT_S) -> Iterator[None]:
    """Exclusive cross-process lock on the journal (``journal.json.lock`` — a ``*.lock`` both backup legs skip). A
    lock that cannot be taken raises (``LockBusy`` / ``OSError``); nothing is held then."""
    from .live.seam_lock import locked_file
    p = journal_path(seam)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with locked_file(p.parent / (p.name + ".lock"), wait_s=wait_s):
        yield


def new_journal(seam: Any) -> dict:
    return {"schema_version": JOURNAL_SCHEMA_VERSION, "kind": JOURNAL_KIND, "seam": os.path.realpath(str(seam)),
            "sources": {}}


def read_journal(seam: Any) -> Optional[dict]:
    """The journal of ``seam``; None when there is none. Raises ``ValueError`` for one that exists but cannot be
    read as a journal (never treated as absent by a writer)."""
    p = journal_path(seam)
    st = _lstat(p)
    if st is None:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("the seam migration journal is not a regular file")
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"the seam migration journal cannot be read: {type(e).__name__}") from e
    if (not isinstance(obj, dict) or obj.get("kind") != JOURNAL_KIND or not isinstance(obj.get("sources"), dict)
            or obj.get("schema_version") != JOURNAL_SCHEMA_VERSION):
        raise ValueError("the seam migration journal is not a vigil-seam-migration-v1 journal")
    return obj


def write_journal(seam: Any, obj: dict) -> None:
    """Replace the journal atomically (0600, fsync'd, then ``os.replace``; the directory is 0700)."""
    p = journal_path(seam)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tmp = p.parent / (p.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(p))
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
    try:
        dfd = os.open(str(p.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def held_launches(seam: Any) -> "set[tuple[str, str]]":
    """``{(slug, nonce)}`` the journal of ``seam`` lists as held for the owner (``legacy_hold``). Never raises: an
    unreadable journal holds nothing here (``vigil doctor`` and the guard report the journal itself)."""
    try:
        j = read_journal(seam)
    except ValueError:
        return set()
    out: "set[tuple[str, str]]" = set()
    for src in (j or {}).get("sources", {}).values():
        for h in (src.get("held") or []) if isinstance(src, dict) else []:
            if isinstance(h, dict) and h.get("slug") and h.get("nonce"):
                out.add((str(h["slug"]), str(h["nonce"])))
    return out


def unmigrated_legacy(seam: Any, candidates: "list[str]", *,
                      env: "Optional[Mapping[str, str]]" = None) -> "list[dict]":
    """``[{"path", "reason", "files"}]`` for each candidate holding seam-class content that is not committed into
    ``seam`` at its CURRENT digest: ``no_journal`` (no migration recorded for it), ``incomplete`` (a migration that
    did not commit), ``changed_since`` (its content changed after the migration committed), ``unsafe`` (a symlink or
    non-regular entry in a class path) or ``too_large``. A candidate with no class files is not listed."""
    try:
        journal = read_journal(seam) or {}
    except ValueError:
        journal = {}
    sources = journal.get("sources") if isinstance(journal.get("sources"), dict) else {}
    out: "list[dict]" = []
    for c in candidates:
        inv = inventory(c, env=env)
        if inv["status"] in ("unsafe", "too_large"):
            out.append({"path": c, "reason": inv["status"], "files": inv["files"]})
            continue
        if not inv["files"]:
            continue
        src = sources.get(os.path.realpath(c))
        if not isinstance(src, dict):
            reason = "no_journal"
        elif src.get("state") != "complete":
            reason = "incomplete"
        elif (src.get("inventory") or {}).get("digest") != inv["digest"]:
            reason = "changed_since"
        else:
            continue
        out.append({"path": c, "reason": reason, "files": inv["files"]})
    return out
