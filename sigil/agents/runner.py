"""Orchestrate the agent mesh (SIGIL §4). v1 = ARCHIVIST → SENTINEL → STEWARD → ENVOY, each
gated by its autonomy ceiling and writing provenance-linked spine records. `morning` produces
the acceptance deliverable (the unprompted brief, with SENTINEL alerts folded in)."""
from __future__ import annotations

import logging
from typing import Optional

from ..spine.store import SpineStore
from .envoy import Envoy, FileInbox, InboxSource
from .sentinel import Sentinel, SpineActivityWatcher, SystemHealthWatcher
from .steward import Steward

_log = logging.getLogger(__name__)


def _sentinel_scan(store: SpineStore):
    head = store.next_seq - 1
    return Sentinel(store).run([
        SpineActivityWatcher(store, since_seq=max(-1, head - 500)),
        SystemHealthWatcher(),
    ])


def _load_bastion(store: SpineStore):
    """Build a BASTION from ~/.sigil/bastion-assets.json (+ optional bastion-cve-feed.json) if
    present; None otherwise. Keeps the default brief path unchanged when no infra is configured."""
    import json

    from ..config import SIGIL_HOME
    from .bastion import Asset, Bastion
    inv_f = SIGIL_HOME / "bastion-assets.json"
    if not inv_f.exists():
        return None
    try:
        raw = json.loads(inv_f.read_text(encoding="utf-8"))
        items = raw.get("assets", raw) if isinstance(raw, dict) else raw
    except (OSError, ValueError):
        return None
    # Build assets PER ITEM: a single malformed entry (typo'd key, wrong type) is skipped with a loud
    # stderr signal — never all-or-nothing, which would silently hide a real misconfiguration (RP-3).
    inv = []
    for a in items if isinstance(items, list) else []:
        try:
            inv.append(Asset(name=a["name"], kind=a["kind"], ref=a["ref"], meta=a.get("meta")))
        except (KeyError, TypeError) as e:
            _log.warning("BASTION skipping malformed asset entry %r: missing/invalid %s", a, e)
    if not inv:
        return None
    feed = []
    feed_f = SIGIL_HOME / "bastion-cve-feed.json"
    if feed_f.exists():
        try:
            feed = json.loads(feed_f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            feed = []
    return Bastion(store, inventory=inv, cve_feed=feed)


def morning(store: Optional[SpineStore] = None, *, date_label: str = "today", bastion=None) -> dict:
    """Run SENTINEL + BASTION (so their alerts/findings are fresh), then STEWARD's brief which folds
    them in. `bastion` may be injected (tests); otherwise it auto-loads from config if present."""
    store = store or SpineStore()
    sent = _sentinel_scan(store)
    b = bastion if bastion is not None else _load_bastion(store)
    bres = b.run() if b is not None else None
    stew = Steward(store)
    stew_res = stew.run(date_label=date_label)
    brief = stew.brief_text(date_label=date_label)   # composed AFTER SENTINEL/BASTION wrote records
    out = {"sentinel": sent, "steward": stew_res, "brief": brief}
    if bres is not None:
        out["bastion"] = bres
    return out


def triage(store: Optional[SpineStore] = None, *, inbox: Optional[InboxSource] = None,
           inbox_path: Optional[str] = None) -> dict:
    store = store or SpineStore()
    from ..config import SIGIL_HOME
    src = inbox or FileInbox(inbox_path or str(SIGIL_HOME / "inbox.json"))
    res = Envoy(store).run(src)
    return {"envoy": res}


def run_all(store: Optional[SpineStore] = None, *, inbox_path: Optional[str] = None,
            consolidate: bool = False) -> dict:
    store = store or SpineStore()
    out: dict = {}
    if consolidate:
        from .archivist import Archivist
        out["archivist"] = Archivist(store).run()
    out.update(morning(store))
    out.update(triage(store, inbox_path=inbox_path))
    return out
