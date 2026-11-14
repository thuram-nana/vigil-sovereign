"""`sigil seam migrate` — carry the launch-seam records of a former seam directory into the seam.

Every plane resolves ONE seam directory (``vigil_core.seam_base``; the shipped units set
``VIGIL_BASE_DIR=%h/.sigil/credit-lease``). A host whose cockpit used another directory before (its working-directory
default ``$SIGIL_HOME/.vigil-live``) keeps launch-seam records there: published leases, settlement, pause and
paused-past-expiry markers, single-use floors, owner-signed authorizations and publications. This command carries each
of them into the seam with the rule its class needs (``vigil_integration.seam_migration.SEAM_CLASSES``), so every
guarantee those records carry holds on the seam exactly as it did on the former directory: a settled launch stays
settled, a started launch stays started, a consumed lease stays consumed, a revoked grant stays revoked.

REPORT-ONLY BY DEFAULT: without ``--apply`` it plans and prints, and writes nothing (no journal, no spool move, no
spine record). The PLAN reads the source's seam-class content (``seam_migration.inventory``), verifies every legacy
lease under the owner key, reads the spine ONCE for their settlement evidence and classifies each lease ``settled``
(a marker in either tree, or spine evidence), ``live`` (unsettled, window open) or ``expired_unsettled``. It lists
every CONFLICT, which the operator resolves (nothing is decided automatically): the seam holding a different lease
for an unsettled legacy slug, the same nonce with different bytes, a differing offense-governance key or owner-signed
file, a marker or floor that cannot be read, an unsafe (symlinked / non-regular) entry.

The former directory is NEVER modified or deleted: it stays the rollback and re-migration source, and it keeps the
owner state that shares it (the passkey store, the cockpit bootstrap token, ``hostcmd/``), which is never read.

SOVEREIGN PLANE ONLY (FATAL-2): ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from .reuse import assert_no_offense

assert_no_offense()  # SOVEREIGN plane: the seam migration must never pull the offense engine (FATAL-2)

#: The spine ``event`` signal of the one audit record a committed migration appends.
AUDIT_SIGNAL = "seam.migrated"
_SETTLE_KIND = "vigil-credit-lease-settlement-v1"
_PAUSE_KIND = "vigil-credit-lease-pause-v1"
_PAST_EXPIRY_KIND = "vigil-credit-lease-paused-past-expiry-v1"
_MAX_MARKER_BYTES = 1 << 20


class MigrateRefused(Exception):
    """The migration cannot run here (exit 2): nothing was read past the refusal, nothing was written."""


# ── reading the trees ─────────────────────────────────────────────────────────────────────────────────────────

def _read_bounded(p: Path, limit: int = _MAX_MARKER_BYTES) -> bytes:
    fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError("file too large")
    return data


def _marker_nonces(p: Path, kind: str) -> "Optional[list[str]]":
    """The nonce set of a marker file: [] when absent, None when it exists but cannot be read cleanly."""
    try:
        obj = json.loads(_read_bounded(p).decode("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return None
    if not isinstance(obj, dict) or obj.get("kind") != kind or not isinstance(obj.get("nonces"), list):
        return None
    return [str(n) for n in obj["nonces"]]


def _bytes_or_none(p: Path) -> Optional[bytes]:
    try:
        return _read_bounded(p, 1 << 24)
    except FileNotFoundError:
        return None


def _floor(p: Path) -> "Optional[tuple[int, int]]":
    """``(entry_count, last_seq)`` of a high-water floor, None when absent. Raises ``HighWaterError`` when present
    but unreadable or tampered."""
    from vigil_core.highwater import load_highwater
    hw = load_highwater(p)
    return None if hw is None else (int(hw["entry_count"]), int(hw["last_seq"]))


def _owner_root(owner_pub: str) -> Any:
    from vigil_core import AuthorizerKey, TrustRoot
    return TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                             public_key_b64=owner_pub)])


# ── PLAN ──────────────────────────────────────────────────────────────────────────────────────────────────────

def _empty_plan(src: str, inv: dict) -> dict:
    return {"from": src, "status": "planned", "digest": inv["digest"], "files": inv["files"],
            "classes": {}, "leases": [], "conflicts": [], "left_in_place": [], "requeue": [], "held": [],
            "_ops": [], "_carried": []}


def _conflict(plan: dict, cls: str, rel: str, why: str) -> None:
    plan["conflicts"].append({"class": cls, "path": rel, "why": why})


def plan_source(store: Any, owner_pub: str, seam: Any, src: Any, *, now: float, journal: "Optional[dict]" = None,
                env: "Optional[Mapping[str, str]]" = None, spool: Any = None) -> dict:
    """What migrating ``src`` into ``seam`` would do — read-only. Returns the per-source report (``status``:
    ``empty`` / ``migrated`` (committed at this digest) / ``planned`` / ``conflict`` / ``unsafe`` / ``too_large``)
    plus the internal ``_ops`` list APPLY executes."""
    from vigil_core import verify_credit_launch_lease
    from vigil_integration.live.credit_lease_broker import _read_lease_file, is_lease_settled
    from vigil_integration.seam_migration import active_classes, class_files, inventory

    from .governor.launch_settlement import scan_settlements

    src_s, seam_p = os.path.realpath(str(src)), Path(seam)
    inv = inventory(src_s, env=env)
    plan = _empty_plan(src_s, inv)
    plan["_inventory"] = inv
    if inv["status"] != "ok":
        plan["status"] = inv["status"]
        _conflict(plan, "tree", str(inv.get("unsafe") or ""), inv["status"])
        return plan
    if not inv["files"]:
        plan["status"] = "empty"
        return plan
    srcj = ((journal or {}).get("sources") or {}).get(src_s)
    if isinstance(srcj, dict) and srcj.get("state") == "complete" and \
            (srcj.get("inventory") or {}).get("digest") == inv["digest"]:
        plan["status"] = "migrated"
        return plan
    migrated_pauses = set((srcj or {}).get("migrated_pauses") or []) if isinstance(srcj, dict) else set()
    root = _owner_root(owner_pub)
    counts: "dict[str, dict]" = {}
    leases: "list[dict]" = []
    lease_files: "dict[str, tuple[Path, bytes]]" = {}
    deferred: "list[tuple]" = []          # (cls, rel, path) for the classes decided after the lease classification
    for cls in active_classes(env):
        try:
            files = class_files(src_s, cls)
        except Exception:  # noqa: BLE001 — changed under us since the inventory (a symlink appeared): unsafe
            _conflict(plan, cls.name, cls.path or cls.pattern, "unsafe")
            continue
        if not files:
            continue
        c = counts.setdefault(cls.name, {"files": len(files)})
        for rel, path in files:
            dst = seam_p / rel
            if cls.rule == "union_nonces":
                kind = _SETTLE_KIND if cls.name == "settlements" else _PAST_EXPIRY_KIND
                have, want = _marker_nonces(dst, kind), _marker_nonces(path, kind)
                if want is None or have is None:
                    _conflict(plan, cls.name, rel, "a marker cannot be read cleanly")
                    continue
                add = sorted(set(want) - set(have))
                c["nonces_added"] = c.get("nonces_added", 0) + len(add)
                slug = path.name[:-len(".json")]
                plan["_ops"] += [(cls.name, "marker", slug, n) for n in add]
            elif cls.rule == "pause_delta":
                want = _marker_nonces(path, _PAUSE_KIND)
                if want is None:
                    _conflict(plan, cls.name, rel, "a pause marker cannot be read cleanly")
                    continue
                slug = path.name[:-len(".json")]
                add = [n for n in sorted(set(want)) if f"{slug}:{n}" not in migrated_pauses]
                c["nonces_added"] = c.get("nonces_added", 0) + len(add)
                plan["_ops"] += [(cls.name, "pause", slug, n) for n in add]
            elif cls.rule == "floor_max":
                from vigil_core.highwater import HighWaterError
                try:
                    lf, df = _floor(path), _floor(dst)
                except HighWaterError:
                    _conflict(plan, cls.name, rel, "a single-use floor cannot be read cleanly")
                    continue
                plan.setdefault("_floors", []).append(rel)
                if lf is not None and (df is None or lf[0] > df[0] or lf[1] > df[1]):
                    c["raised"] = c.get("raised", 0) + 1
                    plan["_ops"].append((cls.name, "floor", rel, None))
                else:
                    c["kept"] = c.get("kept", 0) + 1
            elif cls.rule == "lease":
                b = _read_lease_file(path)
                if b is None:
                    plan["left_in_place"].append({"class": cls.name, "path": rel, "why": "unreadable lease bundle"})
                    continue
                d = b.signed_lease.document
                if d.engagement_slug != b.slug or not verify_credit_launch_lease(b.signed_lease, root)[0]:
                    plan["left_in_place"].append({"class": cls.name, "path": rel,
                                                  "why": "a lease bundle that does not verify under the owner key"})
                    continue
                leases.append({"slug": b.slug, "org_id": str(d.org_id), "nonce": str(d.nonce),
                               "not_after": float(d.not_after.timestamp()), "rel": rel})
                lease_files[b.slug] = (path, _read_bounded(path, 1 << 24))
            elif cls.rule == "rederive":
                slug = path.name[:-len(".json")]
                c["slugs"] = c.get("slugs", 0) + 1
                plan["_ops"].append((cls.name, "rederive", slug, None))
            else:                                       # copy_if_absent / key / union_files / model_grant
                deferred.append((cls, rel, path))
    # one spine pass for every legacy lease's settlement evidence (verified under the owner key)
    evs = scan_settlements(store, owner_pub, keys=[(x["org_id"], x["slug"], x["nonce"]) for x in leases]) \
        if leases else {}
    for x in leases:
        ev = evs.get((x["org_id"], x["slug"], x["nonce"]))
        settled = bool(is_lease_settled(src_s, x["slug"], x["nonce"]) or is_lease_settled(str(seam_p), x["slug"],
                                                                                         x["nonce"])
                       or (ev is not None and ev.settled))
        x["state"] = "settled" if settled else ("live" if now < x["not_after"] else "expired_unsettled")
        if settled and not is_lease_settled(src_s, x["slug"], x["nonce"]) \
                and not is_lease_settled(str(seam_p), x["slug"], x["nonce"]):
            plan["_ops"].append(("settlements", "marker", x["slug"], x["nonce"]))   # spine-settled: mark it too
        path, data = lease_files[x["slug"]]
        dst = seam_p / x["rel"]
        have = _bytes_or_none(dst)
        if have is None:
            x["action"] = "copy"
            plan["_ops"].append(("leases", "copy", x["rel"], None))
            plan["_carried"].append(x["rel"])
        elif have == data:
            x["action"] = "identical"
            plan["_carried"].append(x["rel"])
        else:
            other = _read_lease_file(dst)
            other_nonce = str(other.signed_lease.document.nonce) if other is not None else None
            if other_nonce == x["nonce"]:
                x["action"] = "conflict"
                _conflict(plan, "leases", x["rel"], "the seam holds the same lease with different bytes")
            elif settled:
                x["action"] = "superseded_settled"      # the seam holds a later launch; this one is settled
            else:
                x["action"] = "conflict"
                _conflict(plan, "leases", x["rel"], "the seam holds a different lease for an unsettled legacy launch")
        plan["leases"].append({k: x[k] for k in ("slug", "nonce", "state", "action")})
    plan["_leases"] = leases
    live = {x["slug"]: x["nonce"] for x in leases if x["state"] == "live"}
    for cls, rel, path in deferred:
        c = counts[cls.name]
        if cls.rule == "model_grant":
            try:
                g = json.loads(_read_bounded(path).decode("utf-8"))
            except (OSError, ValueError):
                g = None
            slug = path.name[:-len(".json")]
            if not isinstance(g, dict) or live.get(slug) is None or str(g.get("nonce")) != live[slug]:
                c["skipped"] = c.get("skipped", 0) + 1  # only a live, unsettled launch's grant is carried
                continue
        have, data = _bytes_or_none(seam_p / rel), _read_bounded(path, 1 << 24)
        if have is None:
            c["copied"] = c.get("copied", 0) + 1
            plan["_ops"].append((cls.name, "copy", rel, None))
            plan["_carried"].append(rel)
        elif have == data or cls.rule == "union_files":
            c["identical"] = c.get("identical", 0) + 1  # a spent-token file: present is present
            if have == data:
                plan["_carried"].append(rel)
        else:
            _conflict(plan, cls.name, rel, "the seam holds a different copy of this owner-signed file"
                      if cls.rule != "key" else "the seam holds a different offense-governance key")
    plan["_rules"] = {c.name: c.rule for c in active_classes(env)}
    plan["classes"] = counts
    plan["requeue"], plan["held"] = _completion_plan(spool, [x for x in leases if x["state"] == "expired_unsettled"])
    plan["status"] = "conflict" if plan["conflicts"] else "planned"
    return plan


def _envelope_target(p: Path) -> "Optional[tuple[str, str]]":
    """``(slug, nonce)`` an archived completion envelope names (UNVERIFIED — the drain verifies it), else None."""
    from .inbound.completion_spool import _SEAM_SCHEMA as COMPLETION_SEAM_SCHEMA
    try:
        obj = json.loads(_read_bounded(p).decode("utf-8"))
    except (OSError, ValueError):
        return None
    doc = obj.get("document") if isinstance(obj, dict) else None
    if not isinstance(doc, dict) or obj.get("schema") != COMPLETION_SEAM_SCHEMA:
        return None
    slug, nonce = doc.get("engagement_slug"), doc.get("nonce")
    return (str(slug), str(nonce)) if slug and nonce else None


def _completion_plan(spool: Any, expired: "list[dict]") -> "tuple[list, list]":
    """For each expired, unsettled legacy launch: the archived completions in ``<spool>/processed`` that name it
    (to requeue), or — when no completion names it anywhere in the spool (or there is no spool) — a hold for the
    owner."""
    want = {(x["slug"], x["nonce"]) for x in expired}
    if not want:
        return [], []
    found: "dict[tuple[str, str], list[str]]" = {}
    pending: "set[tuple[str, str]]" = set()
    sp = Path(spool) if spool is not None else None
    for sub in ("processed", "incoming", "working", "rejected") if sp is not None else ():
        try:
            names = sorted(f.name for f in (sp / sub).glob("*.json"))
        except OSError:
            names = []
        for name in names:
            t = _envelope_target(sp / sub / name)
            if t in want:
                if sub == "processed":
                    found.setdefault(t, []).append(name)
                else:
                    pending.add(t)
    requeue = sorted(n for t, ns in found.items() if t not in pending for n in ns)
    held = [{"slug": s, "nonce": n, "why": "no archived completion"} for s, n in sorted(want)
            if (s, n) not in found and (s, n) not in pending]
    return requeue, held


# ── APPLY / VERIFY / COMMIT ───────────────────────────────────────────────────────────────────────────────────

class MigrateAborted(Exception):
    """APPLY stopped before COMMIT (the source's journal entry stays ``applying``; a re-run finishes it)."""


def _fault(label: str) -> None:
    """Called before every write the migration makes (``label`` names it). A no-op; the crash-safety test makes it
    raise at each write in turn."""
    return None


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(str(d), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _copy_if_absent(src: Path, dst: Path) -> str:
    """Create ``dst`` with ``src``'s bytes only if it does not exist (tmp + fsync + ``os.link``, so a reader never sees
    a partial file and an existing one is never replaced). Returns ``copied`` / ``identical`` / ``differs``."""
    import secrets
    data = _read_bounded(src, 1 << 24)
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    have = _bytes_or_none(dst)
    if have is not None:
        return "identical" if have == data else "differs"
    tmp = dst.parent / (dst.name + ".tmp-" + secrets.token_hex(8))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(str(tmp), str(dst))
        except FileExistsError:
            have = _bytes_or_none(dst)
            return "identical" if have == data else "differs"
    finally:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
    _fsync_dir(dst.parent)
    return "copied"


def _raise_floor(src: Path, dst: Path) -> None:
    """Raise the floor at ``dst`` to at least the one at ``src`` (each field the max of both; never lowered)."""
    from types import SimpleNamespace

    from vigil_core.highwater import advance_highwater, highwater_lock
    with highwater_lock(dst):
        lf, df = _floor(src), _floor(dst)
        if lf is None:
            return
        head = (max(lf[0], df[0]), max(lf[1], df[1])) if df is not None else lf
        if df is None or head != df:
            advance_highwater(dst, SimpleNamespace(entry_count=head[0], last_seq=head[1]), _locked=True)


def _sha(p: Path) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(_read_bounded(p, 1 << 24)).hexdigest()


def _apply(store: Any, owner_key: Any, seam_s: str, plan: dict, journal: dict, *,
           env: "Optional[Mapping[str, str]]" = None, spool: Any = None) -> dict:
    """APPLY then VERIFY then COMMIT one planned source (the caller holds the journal lock and the settle lock). Every
    step is idempotent and atomic; a crash or an error leaves the source ``applying`` and a re-run finishes it."""
    from vigil_integration.live.credit_lease_broker import is_lease_settled, read_credit_lease, record_lease_settlement
    from vigil_integration.live.credit_lease_pause import (
        paused_past_expiry, record_lease_pause, record_paused_past_expiry,
    )
    from vigil_integration.seam_migration import inventory, write_journal

    src, seam = Path(plan["from"]), Path(seam_s)
    srcj = journal["sources"].setdefault(plan["from"], {})
    srcj.update(state="applying", started_at=time.time(),
                inventory={"digest": plan["digest"], "files": plan["files"]})
    srcj.setdefault("migrated_pauses", [])
    srcj.setdefault("copied", {})
    _fault("journal:applying")
    seam.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_journal(seam_s, journal)
    ops, rules = plan["_ops"], plan["_rules"]
    # a. floors (never lowered)
    for cls, kind, rel, _ in ops:
        if kind == "floor":
            _fault(f"floor:{rel}")
            _raise_floor(src / rel, seam / rel)
    # b./c. settlement and paused-past-expiry markers (the nonce-set union)
    for cls, kind, slug, nonce in ops:
        if kind == "marker":
            _fault(f"marker:{cls}:{slug}:{nonce}")
            (record_lease_settlement if cls == "settlements" else record_paused_past_expiry)(seam_s, slug, nonce)
    # d. pauses: each legacy (slug, nonce) carried ONCE, then journaled — a pause lifted on the seam afterwards is
    # never re-applied by a re-run
    added = []
    for cls, kind, slug, nonce in ops:
        if kind == "pause":
            _fault(f"pause:{slug}:{nonce}")
            record_lease_pause(seam_s, slug, nonce)
            added.append(f"{slug}:{nonce}")
    if added:
        srcj["migrated_pauses"] = sorted(set(srcj["migrated_pauses"]) | set(added))
        _fault("journal:pauses")
        write_journal(seam_s, journal)
    # e./f. lease bundles, then the copy-if-absent classes (create-if-absent; never replace)
    for want_leases in (True, False):
        for cls, kind, rel, _ in ops:
            if kind != "copy" or (cls == "leases") != want_leases:
                continue
            _fault(f"copy:{rel}")
            got = _copy_if_absent(src / rel, seam / rel)
            if got == "differs" and rules.get(cls) != "union_files":
                raise MigrateAborted(f"{rel} appeared on the seam with different content during the migration")
    # g. owner-sealed eval publications: REBUILT from the spine (the truth), never copied — a grant the spine shows
    # revoked stays revoked whatever the former directory published
    for cls, kind, slug, _ in ops:
        if kind == "rederive":
            _fault(f"rederive:{cls}:{slug}")
            _publisher(cls, store, owner_key, seam_s)._publish(slug)
    # VERIFY
    for cls, kind, slug, _ in ops:
        if kind == "rederive" and not _publication_verifies(cls, seam_s, slug, owner_key.public_key_b64):
            raise MigrateAborted(f"verify: the {cls} publication of {slug} on the seam does not verify under the "
                                 f"owner key")
    for cls, kind, slug, nonce in ops:
        if kind == "marker" and not (is_lease_settled(seam_s, slug, nonce) if cls == "settlements"
                                     else paused_past_expiry(seam_s, slug, nonce)):
            raise MigrateAborted(f"verify: the {cls} record of {slug} is not on the seam")
    for x in plan.get("_leases", []):
        if x["state"] == "settled" and not is_lease_settled(seam_s, x["slug"], x["nonce"]):
            raise MigrateAborted(f"verify: the settled launch {x['slug']} is not marked settled on the seam")
        if x.get("action") in ("copy", "identical"):
            b = read_credit_lease(seam_s, x["slug"])
            if b is None or str(b.signed_lease.document.nonce) != x["nonce"]:
                raise MigrateAborted(f"verify: the lease of {x['slug']} is not on the seam")
    for rel in plan.get("_floors", []):
        lf, df = _floor(src / rel), _floor(seam / rel)
        if lf is not None and (df is None or df[0] < lf[0] or df[1] < lf[1]):
            raise MigrateAborted(f"verify: the floor {rel} on the seam is below the former directory's")
    if inventory(str(src), env=env)["digest"] != plan["digest"]:
        raise MigrateAborted("the former directory changed during the migration; stop every process that writes it "
                             "and run the migration again")
    for rel in plan["_carried"]:                       # every class file the seam now holds with the source's bytes
        if _bytes_or_none(seam / rel) != _bytes_or_none(src / rel):
            raise MigrateAborted(f"verify: {rel} is not on the seam with the former directory's content")
        srcj["copied"][rel] = _sha(seam / rel)
    # REQUEUE (after every lease is on the seam, so the drain always finds the lease it settles)
    requeued, held = _requeue(seam_s, plan, journal, srcj, spool)
    # COMMIT: one owner-signed audit record (no nonce, no amount), then the journal entry
    counts = {k: v.get("files", 0) for k, v in plan["classes"].items()}
    _fault("audit")
    _audit_once(store, owner_key, src=plan["from"], seam=seam_s, digest=plan["digest"], counts=counts,
                requeued=len(requeued), held=len(held))
    srcj.update(state="complete", completed_at=time.time(), classes=counts, held=held, requeued=requeued,
                left_in_place=[x["path"] for x in plan["left_in_place"]])
    _fault("journal:complete")
    write_journal(seam_s, journal)
    return {"status": "migrated", "requeue": requeued, "held": held}


def _requeue(seam_s: str, plan: dict, journal: dict, srcj: dict, spool: Any) -> "tuple[list[str], list[dict]]":
    """Hand each EXPIRED, UNSETTLED legacy launch's archived completion back to the settle drain: under the
    completion spool's exclusive lock (taken after the settle lock, the sweep's order), journal the move, then move
    ``<spool>/processed/<name>`` to ``incoming/<name>``. The drain verifies it under its delegation and settles the
    launch on the seam at the completion's outcome; settle idempotency per (slug, nonce) is the backstop. A settled
    launch's completion is never selected. An expired, unsettled launch with no completion anywhere in the spool is
    HELD for the owner (``legacy_hold`` in both reservation sweeps; no money moves). The settle drain's scan
    checkpoint is removed, so its next pass reads the whole spine (lease bundles reached the seam without a publish).
    Returns ``(requeued names, held)``."""
    from vigil_integration.live.seam_lock import LockBusy, locked_file
    from vigil_integration.seam_migration import write_journal
    expired = [x for x in plan.get("_leases", []) if x["state"] == "expired_unsettled"]
    if spool is None:
        return [], _completion_plan(None, expired)[1]
    sp = Path(spool)
    if not sp.is_dir():
        return [], _completion_plan(None, expired)[1]
    lock = locked_file(sp / ".spool.lock", wait_s=5.0)
    try:
        lock.__enter__()
    except (LockBusy, OSError) as e:
        raise MigrateAborted(f"the completion spool {sp} is locked or unusable ({type(e).__name__}); stop the settle "
                             f"drain and retry") from e
    try:
        names, held = _completion_plan(sp, expired)
        planned = sorted(set(srcj.get("requeue_planned") or []) | set(names))
        if planned != (srcj.get("requeue_planned") or []):
            srcj["requeue_planned"] = planned
            _fault("journal:requeue")
            write_journal(seam_s, journal)
        for name in names:
            _fault(f"requeue:{name}")
            (sp / "incoming").mkdir(exist_ok=True)
            os.replace(sp / "processed" / name, sp / "incoming" / name)
        requeued = [n for n in planned if (sp / "incoming" / n).is_file()]
        ck = sp / ".settle-scan.json"
        if ck.exists():
            _fault("checkpoint")
            ck.unlink()
    finally:
        lock.__exit__(None, None, None)
    return requeued, held


def _publisher(cls: str, store: Any, owner_key: Any, seam_s: str) -> Any:
    if cls == "eval_grants":
        from .governor.eval_capability_grant import EvalCapabilityGrant
        return EvalCapabilityGrant(store, owner_key=owner_key, trusted_pubkey=owner_key.public_key_b64, base_dir=seam_s)
    from .governor.eval_offense_attestation import EvalOffenseAttestation
    return EvalOffenseAttestation(store, owner_key=owner_key, trusted_pubkey=owner_key.public_key_b64, base_dir=seam_s)


def _publication_verifies(cls: str, seam_s: str, slug: str, owner_pub: str) -> bool:
    """The seam's publication of ``slug`` carries an owner seal that verifies over its record list, at or above the
    seam's publication floor (what the offense reader enforces)."""
    if cls == "eval_grants":
        from vigil_integration.live import eval_capability_grant as mod
    else:
        from vigil_integration.live import eval_attestation as mod  # type: ignore[no-redef]
    obj = mod._read_published(seam_s, slug)
    if obj is None or not isinstance(obj.get("records"), list):
        return False
    ok, seq, _ = mod._verify_seal(obj.get("seal"), slug, [r for r in obj["records"] if isinstance(r, dict)],
                                  frozenset({owner_pub}))
    path = mod._shared_floor_path(seam_s, slug)
    floor = _floor(path) if path is not None else None
    return bool(ok) and (floor is None or seq >= floor[1])


def _audit_once(store: Any, owner_key: Any, *, src: str, seam: str, digest: str, counts: dict, requeued: int,
                held: int) -> None:
    """Append the ``seam.migrated`` audit event unless this exact commit (source, seam, digest) already has one (a
    re-run after a crash between the record and the journal adds nothing)."""
    from .governor.authn import signed_payload
    for r in store.iter_records():
        p = r.payload if isinstance(r.payload, dict) else {}
        if (p.get("signal") == AUDIT_SIGNAL and p.get("from") == src and p.get("to") == seam
                and p.get("digest") == digest):
            return
    core = {"signal": AUDIT_SIGNAL, "v": 1, "from": src, "to": seam, "digest": digest, "counts": counts,
            "requeued": int(requeued), "held": int(held)}
    store.append(kind="event", source="governor", actor="OWNER", payload=signed_payload(core, owner_key))


def public_report(plan: dict) -> dict:
    """The printable part of a source report (no internal op list)."""
    return {k: v for k, v in plan.items() if not k.startswith("_")}


def run(store: Any, owner_key: Any, *, seam: Any, sources: "list[str]", spool: Any = None, apply: bool = False,
        now: Optional[float] = None, env: "Optional[Mapping[str, str]]" = None) -> "tuple[int, dict]":
    """Plan (and with ``apply`` carry) every source into ``seam``. Returns ``(exit_code, report)``: 0 when every
    source is migrated or has nothing to carry, 1 when a source has conflicts / is unsafe / too large."""
    from vigil_integration.seam_migration import read_journal
    if owner_key is None:
        raise MigrateRefused("no owner identity on this machine — the migration verifies every lease and records "
                             "itself under the owner key")
    now = time.time() if now is None else float(now)
    seam_s = os.path.realpath(str(seam))
    for s in sources:
        r = os.path.realpath(str(s))
        if r == seam_s or r.startswith(seam_s + os.sep) or seam_s.startswith(r + os.sep):
            raise MigrateRefused(f"the source {r} and the seam {seam_s} overlap; refusing")
    try:
        journal = read_journal(seam_s)
    except ValueError as e:
        raise MigrateRefused(f"{e}; restore it from a backup or move it aside after checking it") from e
    out = {"to": seam_s, "applied": bool(apply), "sources": []}
    if not apply:
        code = 0
        for s in sources:
            plan = plan_source(store, owner_key.public_key_b64, seam_s, s, now=now, journal=journal, env=env,
                               spool=spool)
            out["sources"].append(public_report(plan))
            if plan["status"] in ("conflict", "unsafe", "too_large"):
                code = 1
        return code, out
    return _run_apply(store, owner_key, seam_s, sources, spool=spool, now=now, env=env, out=out)


def _run_apply(store: Any, owner_key: Any, seam_s: str, sources: "list[str]", *, spool: Any, now: float,
               env: "Optional[Mapping[str, str]]", out: dict) -> "tuple[int, dict]":
    """``--apply``: under the journal lock then the settle lock (so no settle, cancel, sweep or publish interleaves),
    re-plan each source and carry it. A source with conflicts commits nothing."""
    from vigil_integration.live.seam_lock import LockBusy
    from vigil_integration.seam_migration import journal_lock, new_journal, read_journal

    from .governor.launch_settlement import settle_lock
    from .ops_sweeps import root_apply_refusal
    why = root_apply_refusal(
        [("seam directory", seam_s), ("spine directory", Path(store.path).parent),
         *[("former seam directory", s) for s in sources]],
        [("completion spool", spool)] if spool is not None else [])
    if why:
        raise MigrateRefused(f"running as root, but {why}; run it as the service user that owns those directories")
    code = 0
    try:
        jl = journal_lock(seam_s)
        jl.__enter__()
    except (LockBusy, OSError) as e:
        raise MigrateRefused(f"the seam migration journal is locked or unusable ({type(e).__name__}); is another "
                             f"migration running?") from e
    try:
        try:
            journal = read_journal(seam_s) or new_journal(seam_s)
        except ValueError as e:
            raise MigrateRefused(str(e)) from e
        try:
            sl = settle_lock(store)
            sl.__enter__()
        except (LockBusy, OSError, ValueError) as e:
            raise MigrateRefused(f"the settle lock is busy or unusable ({type(e).__name__}); stop the cockpit, the "
                                 f"customer server and the settle drain, then retry") from e
        try:
            for s in sources:
                plan = plan_source(store, owner_key.public_key_b64, seam_s, s, now=now, journal=journal, env=env,
                                   spool=spool)
                rep = public_report(plan)
                if plan["status"] == "planned":
                    try:
                        rep.update(_apply(store, owner_key, seam_s, plan, journal, env=env, spool=spool))
                    except MigrateAborted as e:
                        rep.update(status="aborted", error=str(e))
                    except OSError as e:                # an I/O failure mid-run: the source stays `applying`
                        rep.update(status="aborted", error=f"{type(e).__name__}: {e}; fix it and run again")
                if rep["status"] in ("conflict", "unsafe", "too_large", "aborted") or rep.get("held"):
                    code = 1
                out["sources"].append(rep)
        finally:
            sl.__exit__(None, None, None)
    finally:
        jl.__exit__(None, None, None)
    return code, out


def format_report(report: dict) -> str:
    lines = [f"seam: {report['to']}" + ("" if report.get("applied") else "  (report only; nothing written — "
                                                                          "--apply carries it)")]
    if not report["sources"]:
        lines.append("  no former seam directory holds launch-seam records")
    for s in report["sources"]:
        lines.append(f"  from {s['from']}: {s['status']} ({s['files']} file(s))")
        for name, c in sorted(s.get("classes", {}).items()):
            lines.append(f"    {name}: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
        for x in s.get("leases", []):
            lines.append(f"    lease {x['slug']}: {x['state']}, {x['action']}")
        if s.get("requeue"):
            lines.append(f"    archived completions to requeue: {len(s['requeue'])}")
        for h in s.get("held", []):
            lines.append(f"    HELD for the owner: {h['slug']} ({h['why']})")
        for x in s.get("left_in_place", []):
            lines.append(f"    left in place: {x['path']} ({x['why']})")
        for x in s.get("conflicts", []):
            lines.append(f"    CONFLICT {x['class']}: {x['path']} — {x['why']}")
        if s.get("error"):
            lines.append(f"    ABORTED: {s['error']}")
    return "\n".join(lines)
