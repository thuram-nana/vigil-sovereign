"""
vigil_integration.jobs — the normalized ``SecurityJob`` spine (repo-connect + PR-bot wave, Slice 1).

ONE execution architecture behind SIX trigger adapters. Every trigger source (webhook / manual / api /
scheduled / ci / reconciliation) NORMALIZES to a single :class:`SecurityJob` event (``model``), which is
enqueued onto a durable, idempotent, deduplicated queue (``queue``) and only ever reaches the engine
through a worker that FIRST passes the hard tenant + asset-scope authorization gate (``authorize``). No
trigger invokes execution directly — the queue is the sole path, and an unauthorized job is refused and
never run (fail-closed). See docs/decisions and the plan for the full event-driven architecture.
"""
