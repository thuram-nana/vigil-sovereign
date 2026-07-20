"""The nightly ARCHIVIST brief (SIGIL §6.3.5 / §C8) — a human-readable sitrep built ONLY
from grounded, cited records. Appended to the spine as a `brief` record."""
from __future__ import annotations

from ..spine.store import SpineStore
from .grounding import CONSOLIDATE_SOURCE
from .queries import due_commitments, open_threads, pending_contradictions


def compose(store: SpineStore) -> tuple[str, dict]:
    threads = open_threads(store, limit=10)
    due = due_commitments(store, limit=10)
    contras = pending_contradictions(store, limit=10)
    lines = ["# ARCHIVIST brief",
             f"Open threads: {len(threads)} · Commitments with due dates: {len(due)} · "
             f"Pending contradictions: {len(contras)}", ""]
    if threads:
        lines.append("## Open threads (most stale first)")
        for t in threads:
            lines.append(f"- [{t['kind']} seq {t['seq']}] {t['text']}  (from seq {t['source_seqs']})")
    if due:
        lines.append("\n## Commitments with due dates")
        for c in due:
            lines.append(f"- due {c['due']} — {c['text']}  (owner {c.get('owner')}, seq {c['seq']})")
    if contras:
        lines.append("\n## Pending contradictions (review)")
        for x in contras:
            lines.append(f"- {x['subject']}: decisions at seqs {x['conflicting_seqs']}")
    text = "\n".join(lines)
    return text, {"open_threads": len(threads), "due_commitments": len(due),
                  "pending_contradictions": len(contras)}


def write_brief(store: SpineStore) -> int:
    text, counts = compose(store)
    return store.append(kind="brief", source=CONSOLIDATE_SOURCE, actor=CONSOLIDATE_SOURCE,
                        payload={"text": text, **counts})
