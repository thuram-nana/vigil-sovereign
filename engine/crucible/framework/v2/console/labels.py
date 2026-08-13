"""console.labels — the ENGAGEMENT-LIBRARY label store: a human name for a past job.

The operator comes back to a job months later. ``20260812-143355-118`` and ``acme-prod`` are stable
machine identities and must stay that way; a human needs "Acme — Q3 external review" to find the work
again. This module is where that human name lives.

THE LOAD-BEARING PROPERTY — a label is PRESENTATION METADATA, NEVER SIGNED CONTENT:

  * It is stored ALONGSIDE the immutable identity, in ONE side-car file of its own
    (``<CRUCIBLE_ROOT>/framework/v2/.console/labels.json``), keyed by the identity.
  * NOTHING here writes into a run dir, a target dir, an evidence certificate, a reverifiable
    document, a dossier entry, or the append-only signed spine. There is no code path from this
    module to any of them — renaming touches exactly one file, and that file is in no manifest.
  * So a relabelled engagement/run still re-verifies: the same certificates, the same digests, the
    same offline PASS. The label can be changed as often as the operator likes; the proof is
    untouched. (Consistent with the dossier builder's own ``--label``, which is likewise
    presentation-only: it names the job in the readable documents and reaches no signed claim.)

Fail-closed on identity: an engagement slug must match the charter slug shape and a run id must pass
the console's ONE traversal guard (``actions._safe_run_id``) before it is ever used as a key — a
caller-supplied id can neither traverse nor create a junk key. The label text itself is stripped of
control characters and length-capped (it is rendered, logged and put in a filename-free JSON body;
it is never a path component).

Concurrency: the console runs on a ThreadingHTTPServer, so every mutation takes an in-process lock
and persists with a UNIQUE temp file + atomic ``os.replace`` (0600 under the console's own dir), so
concurrent renames never tear the store or collide on a temp name.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = 1
_MAX_LABEL = 200
_MAX_ENTRIES = 5000        # bound the side-car so a runaway caller cannot grow it without limit

# A charter engagement slug: the same conservative shape `paths`/`_slugify` produce. It is used as a
# JSON KEY only (never a path component here), but it is validated anyway — defense in depth, and it
# keeps a junk key out of the store.
_SAFE_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_LOCK = threading.RLock()


def store_path() -> Path:
    """The label side-car, next to the console's own run store (so it follows ``CRUCIBLE_ROOT``,
    exactly like the runs it names — never the process CWD)."""
    from . import actions
    return actions.console_dir() / "labels.json"


def safe_slug(raw: str) -> str:
    """Validate an engagement slug used as a label key. Raises ``ValueError`` (→ a clean refusal)."""
    s = str(raw or "").strip()
    if not _SAFE_SLUG.match(s):
        raise ValueError(f"unsafe engagement slug: {raw!r}")
    return s


def safe_run_id(raw: str) -> str:
    """Validate a run id used as a label key — reuses the console's ONE traversal guard."""
    from . import actions
    return actions._safe_run_id(raw)      # noqa: SLF001 — the console's single run-id guard


def clean_label(raw: str) -> str:
    """A display label: strip, drop control characters (JSON/log/line safety), cap the length.
    Empty is allowed and MEANS "no label" (the UI falls back to the machine identity)."""
    s = "".join(c for c in str(raw or "") if c == " " or (c.isprintable() and c not in "\r\n\t"))
    return s.strip()[:_MAX_LABEL]


# ---------------------------------------------------------------------------
# persistence (atomic, bounded, total)
# ---------------------------------------------------------------------------


def _blank() -> dict[str, Any]:
    return {"schema": _SCHEMA, "engagements": {}, "runs": {}}


def _load() -> dict[str, Any]:
    """Read the side-car. Total: an absent/corrupt/foreign-shaped file reads as EMPTY — a rename
    store is disposable presentation state, so a bad read must never break a listing."""
    try:
        doc = json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _blank()
    if not isinstance(doc, dict):
        return _blank()
    out = _blank()
    for section in ("engagements", "runs"):
        got = doc.get(section)
        if isinstance(got, dict):
            out[section] = {str(k): v for k, v in got.items() if isinstance(v, dict)}
    return out


def _save(doc: dict[str, Any]) -> None:
    """Atomically persist the side-car (0600, unique temp + replace). Called under ``_LOCK``."""
    p = store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".labels.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _set(section: str, key: str, label: str) -> dict[str, Any]:
    with _LOCK:
        doc = _load()
        sec = doc.setdefault(section, {})
        if not label:
            sec.pop(key, None)                       # clearing a label removes the entry entirely
        else:
            if key not in sec and len(sec) >= _MAX_ENTRIES:
                return {"error": f"label store is full (max {_MAX_ENTRIES} {section})"}
            sec[key] = {"label": label, "updated": time.time()}
        _save(doc)
        return {"ok": True, "label": label}


# ---------------------------------------------------------------------------
# public API — engagements
# ---------------------------------------------------------------------------


def engagement_labels() -> dict[str, str]:
    """``slug -> label`` for every labelled engagement (the mapping injected into
    ``Blackboard.list_engagements``). Total: ``{}`` on any read problem."""
    return {k: str(v.get("label", "") or "") for k, v in _load().get("engagements", {}).items()
            if str(v.get("label", "") or "")}


def engagement_label(slug: str) -> str:
    """One engagement's label, or ``""``. Total (an unsafe slug is simply unlabelled)."""
    try:
        key = safe_slug(slug)
    except ValueError:
        return ""
    return str((_load().get("engagements", {}).get(key) or {}).get("label", "") or "")


def set_engagement_label(slug: str, label: str) -> dict[str, Any]:
    """Rename an engagement for humans. Presentation only: it writes ONE key in the label side-car
    and touches no run dir, no certificate and no spine event. Fail-closed on an unsafe slug."""
    try:
        key = safe_slug(slug)
    except ValueError as e:
        return {"error": str(e)}
    return {**_set("engagements", key, clean_label(label)), "slug": key}


# ---------------------------------------------------------------------------
# public API — runs
# ---------------------------------------------------------------------------


def run_labels() -> dict[str, str]:
    """``run_id -> label`` for every labelled run."""
    return {k: str(v.get("label", "") or "") for k, v in _load().get("runs", {}).items()
            if str(v.get("label", "") or "")}


def run_label(run_id: str) -> str:
    """One run's label, or ``""``. Total (an unsafe id is simply unlabelled)."""
    try:
        key = safe_run_id(run_id)
    except ValueError:
        return ""
    return str((_load().get("runs", {}).get(key) or {}).get("label", "") or "")


def set_run_label(run_id: str, label: str) -> dict[str, Any]:
    """Rename ONE run for humans. Fail-closed: the run id must pass the traversal guard AND the run
    must actually exist on disk (a label for a run that was never launched is refused, so the store
    cannot be stuffed with junk keys). Presentation only — nothing signed is touched."""
    from . import actions
    try:
        key = safe_run_id(run_id)
    except ValueError as e:
        return {"error": str(e)}
    try:
        if not (actions.run_dir(key) / "meta.json").is_file():
            return {"error": f"no such run {key!r}"}
    except (OSError, ValueError) as e:
        return {"error": str(e)}
    return {**_set("runs", key, clean_label(label)), "run_id": key}
