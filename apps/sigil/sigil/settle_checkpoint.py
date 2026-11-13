"""settle_checkpoint — the settle drain reads the spine's settlement evidence INCREMENTALLY (E3bc).

Every settle-drain pass (``ops_sweeps.finish_interrupted_settles``, while ``VIGIL_SETTLE_SPINE_RECORD`` is on) needs
the settlement evidence of every lease on the seam in its scope. Read from seq 0 each pass, that is a read of the
whole spine every ~60 s even when nothing needs finishing. So the drain keeps a small CHECKPOINT beside its completion
spool (``<spool>/.settle-scan.json``, written atomically, 0600, at most :data:`MAX_BYTES`) and each pass reads only the
records appended since:

  ``spine`` / ``owner`` / ``scope``  the spine's path, the owner key the evidence was verified under, the drain scope;
  ``live_from``                      the first seq the spine still holds (a prune moves it);
  ``anchor``                         ``[seq, entry_hash]`` of the last record the pass read (its ``through``);
  ``listed_from``                    the spine tip read BEFORE that pass listed the seam;
  ``listing_clean``                  every in-scope lease file on the seam was read and verified by that listing;
  ``full_at``                        the pass clock of the last FULL read (one is made at least every
                                     :data:`FULL_RESCAN_S`);
  ``leases`` / ``evidence``          every lease that listing found, and the non-empty evidence of each through the
                                     anchor (``launch_settlement.evidence_to_json``).

A pass CONTINUES from the checkpoint only when it reads back exactly as written and names this spine, owner key, scope
and live window, and its anchor record is still on the spine with the same ``entry_hash``. Anything else — no file,
an unreadable or oversized one, another spine, a reset or restored spine, a prune since — is a FULL scan.

WHY A CONTINUED PASS MISSES NOTHING. A lease the checkpoint carries has its evidence through the anchor, and the pass
reads every record after it. A lease the checkpoint does NOT carry was not on the seam when that earlier pass listed
it (its listing was clean). Its current bundle was therefore written after that listing began — after
``listed_from`` was read — by ``LaunchGate.publish_lease``, which, holding the settle lock from its check to its
write, refuses a lease the spine already shows settled (a decision record or a settle entry). Every settle record of
a lease (its decision and each settle entry) is appended by ``LaunchGate._settle_once`` under that same settle lock.
So every settlement record of such a lease was appended after its bundle was written, hence after ``listed_from`` was
read: its seq is greater than ``listed_from``, and a pass with such a lease reads from ``min(anchor, listed_from)``.
(Reading ``(listed_from, anchor]`` again for the carried leases changes nothing: the first verified decision wins and
the landed entries are a set.) A listing that was not clean gives no such guarantee, so a new lease after it is a
full scan. Only a publish writes a lease bundle, but the seam can also be restored from a backup out of step with the
spine; so a pass reads the whole spine again at least every :data:`FULL_RESCAN_S` (and whenever its clock is behind
the checkpoint's), and a bundle that reappeared on the seam any other way is found within that time.

The checkpoint never decides money: it only selects the leases the pass hands to ``settle_launch(finish_only=True)``,
which re-reads the spine under its locks and moves only the recorded decision, exactly once. A lost or stale
checkpoint costs one full read of the spine; it is operational state like the seam files beside it.

SOVEREIGN PLANE ONLY (FATAL-2): ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any, Iterable, Optional

from .reuse import assert_no_offense

assert_no_offense()

#: The checkpoint's file name in the completion spool directory.
CHECKPOINT_NAME = ".settle-scan.json"
_SCHEMA = "vigil-settle-scan-checkpoint-v1"
#: The largest checkpoint written or read; a larger one is not kept (each pass then reads the whole spine).
MAX_BYTES = 4 << 20
#: A pass reads the whole spine at least this often (seconds of the pass clock), whatever the checkpoint says.
FULL_RESCAN_S = 3600.0


def spine_tip(store) -> int:
    """The highest seq on the spine as ``store`` last saw it (-1: empty). Read BEFORE a pass lists the seam; a stale
    value is only ever lower than the real tip, which keeps the checkpoint conservative."""
    return int(store.next_seq) - 1


def _live_from(store) -> int:
    """The first seq the spine still holds: 0 for a legacy single-file spine (it is never pruned), else the lowest
    ``first_seq`` of its segments (a committed prune drops a prefix of them)."""
    info = store.segment_info()
    return min((int(s["first_seq"]) for s in info), default=0)


class _Checkpoint:
    __slots__ = ("through", "anchor_hash", "listed_from", "listing_clean", "full_at", "keys", "evidence")

    def __init__(self, through: int, anchor_hash: str, listed_from: int, listing_clean: bool, full_at: float,
                 keys: "set[tuple[str, str, str]]", evidence: "dict[tuple[str, str, str], Any]") -> None:
        self.through, self.anchor_hash = through, anchor_hash
        self.listed_from, self.listing_clean, self.full_at = listed_from, listing_clean, full_at
        self.keys, self.evidence = keys, evidence


def _read_bounded(path: Path) -> Optional[bytes]:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks: "list[bytes]" = []
        left = MAX_BYTES + 1
        while left > 0:
            b = os.read(fd, left)
            if not b:
                break
            chunks.append(b)
            left -= len(b)
    except OSError:
        return None
    finally:
        os.close(fd)
    data = b"".join(chunks)
    return data if len(data) <= MAX_BYTES else None


def _key(v: Any) -> "tuple[str, str, str]":
    if not (isinstance(v, list) and len(v) == 3 and all(isinstance(x, str) and x for x in v)):
        raise ValueError("bad lease key")
    return (v[0], v[1], v[2])


def _load(path: Path, store, pubkey: str, scope: str) -> Optional[_Checkpoint]:
    """The checkpoint at ``path`` when it is usable for ``store`` / ``pubkey`` / ``scope`` (see the module docstring),
    else None. A spine read error while checking the anchor propagates (the pass reports it)."""
    from .governor.launch_settlement import evidence_from_json
    raw = _read_bounded(path)
    if raw is None:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict) or obj.get("schema") != _SCHEMA:
            return None
        if obj.get("spine") != str(store.path) or obj.get("owner") != pubkey or obj.get("scope") != scope:
            return None
        anchor, listed_from, clean = obj["anchor"], obj["listed_from"], obj["listing_clean"]
        if not (isinstance(anchor, list) and len(anchor) == 2 and type(anchor[0]) is int and anchor[0] >= 0
                and isinstance(anchor[1], str) and anchor[1]):
            return None
        through = int(anchor[0])
        if type(listed_from) is not int or not -1 <= listed_from <= through or not isinstance(clean, bool):
            return None
        if type(obj.get("live_from")) is not int:
            return None
        full_at = obj["full_at"]
        if isinstance(full_at, bool) or not isinstance(full_at, (int, float)) or not math.isfinite(full_at):
            return None
        keys = {_key(k) for k in obj["leases"]}
        evidence: "dict[tuple[str, str, str], Any]" = {}
        for item in obj["evidence"]:
            if not (isinstance(item, list) and len(item) == 2):
                return None
            k = _key(item[0])
            if k not in keys or k in evidence:
                return None
            evidence[k] = evidence_from_json(item[1], through=through)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None
    # the spine it was read from: the same live window, and the anchor record still there with the same hash
    if obj["live_from"] != _live_from(store):
        return None
    rec = store.get(through)
    if rec is None or rec.seq != through or rec.entry_hash != anchor[1]:
        return None
    return _Checkpoint(through, anchor[1], listed_from, clean, float(full_at), keys, evidence)


def _save(path: Path, store, pubkey: str, scope: str, *, live_from: int, through: int, through_hash: str,
          listed_from: int, listing_clean: bool, full_at: float,
          evidence: "dict[tuple[str, str, str], Any]") -> None:
    """Replace the checkpoint atomically (best-effort: a write that fails, or would exceed :data:`MAX_BYTES`, leaves
    no checkpoint, so the next pass reads the whole spine)."""
    from .governor.launch_settlement import evidence_to_json
    from .spine.atomicio import atomic_write_text
    body = json.dumps({
        "schema": _SCHEMA, "spine": str(store.path), "owner": pubkey, "scope": scope, "live_from": int(live_from),
        "anchor": [int(through), str(through_hash)], "listed_from": int(min(listed_from, through)),
        "listing_clean": bool(listing_clean), "full_at": float(full_at), "leases": sorted([list(k) for k in evidence]),
        "evidence": sorted([[list(k), evidence_to_json(ev)] for k, ev in evidence.items() if ev.settled]),
    }, sort_keys=True, separators=(",", ":"))
    try:
        if len(body.encode("utf-8")) > MAX_BYTES:
            raise OSError("checkpoint too large")
        atomic_write_text(path, body, prefix=".settle-scan-")
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass


def scan(store, pubkey: str, *, keys: "Iterable[tuple[str, str, str]]", path: "Optional[Path]", scope: str,
         listed_from: int, listing_clean: bool, now: float) -> "dict[tuple[str, str, str], Any]":
    """The settlement evidence of every lease in ``keys`` — what ``launch_settlement.scan_settlements`` returns for
    the records the spine holds — reading only what was appended since the checkpoint at ``path`` when it is usable
    (the module docstring), else the whole spine; then the checkpoint is replaced (best-effort). ``listed_from`` is
    the spine tip this pass read before it listed ``keys`` (:func:`spine_tip`) and ``listing_clean`` whether that
    listing read and verified every in-scope lease file; ``now`` is the pass clock (a full read is due every
    :data:`FULL_RESCAN_S`). ``path=None`` reads the whole spine and keeps nothing. A spine read failure raises."""
    from .governor.launch_settlement import scan_settlements_since
    want = {(str(o), str(s), str(n)) for o, s, n in keys}
    cp = _load(path, store, pubkey, scope) if path is not None else None
    if cp is not None and not (want <= cp.keys or cp.listing_clean):
        cp = None                                          # a new lease after a listing that was not clean: full
    if cp is not None and not cp.full_at <= now < cp.full_at + FULL_RESCAN_S:
        cp = None                                          # a full read is due (or the clock went back): full
    since, start = None, -1
    if cp is not None:
        # A lease the checkpoint does not carry was published after its listing began: every settlement record of
        # it is after ``listed_from`` (module docstring), so the pass reads from there.
        start = cp.through if want <= cp.keys else min(cp.through, cp.listed_from)
        since = {k: cp.evidence[k] for k in want & cp.keys if k in cp.evidence}
    evs, through, through_hash = scan_settlements_since(store, pubkey, keys=want, since=since, since_seq=start)
    full_at = cp.full_at if cp is not None else float(now)
    if path is not None:
        if through_hash is None and cp is not None and through == cp.through:
            through_hash = cp.anchor_hash                  # nothing appended since the anchor: it still holds
        if through_hash is not None:
            _save(path, store, pubkey, scope, live_from=_live_from(store), through=through,
                  through_hash=through_hash, listed_from=listed_from, listing_clean=listing_clean,
                  full_at=full_at, evidence=evs)
    return evs
