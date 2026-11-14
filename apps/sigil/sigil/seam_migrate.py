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
            "_ops": []}


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
        elif have == data:
            x["action"] = "identical"
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
        elif have == data or cls.rule == "union_files":
            c["identical"] = c.get("identical", 0) + 1  # a spent-token file: present is present
        else:
            _conflict(plan, cls.name, rel, "the seam holds a different copy of this owner-signed file"
                      if cls.rule != "key" else "the seam holds a different offense-governance key")
    plan["classes"] = counts
    if spool is not None:
        plan["requeue"], plan["held"] = _completion_plan(spool, [x for x in leases if x["state"] ==
                                                                 "expired_unsettled"])
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
    (to requeue), or — when no completion names it anywhere in the spool — a hold for the owner."""
    sp = Path(spool)
    want = {(x["slug"], x["nonce"]) for x in expired}
    if not want:
        return [], []
    found: "dict[tuple[str, str], list[str]]" = {}
    pending: "set[tuple[str, str]]" = set()
    for sub in ("processed", "incoming", "working", "rejected"):
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
    out = {"to": seam_s, "applied": False, "sources": []}
    code = 0
    for s in sources:
        plan = plan_source(store, owner_key.public_key_b64, seam_s, s, now=now, journal=journal, env=env,
                           spool=spool)
        out["sources"].append(public_report(plan))
        if plan["status"] in ("conflict", "unsafe", "too_large"):
            code = 1
    return code, out


def format_report(report: dict) -> str:
    lines = [f"seam: {report['to']}" + ("" if report.get("applied") else "  (report only; nothing written)")]
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
    return "\n".join(lines)
