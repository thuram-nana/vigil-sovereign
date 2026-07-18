"""verify_record (Phase 7, P0.2) — the single "prove-this-atom" helper reused by the live tail,
the UI `/api/record` endpoint, and the mobile daemon, so "serve-the-quote / prove-don't-guess" is
ONE implementation, not three. It performs the two per-atom checks the store's `verify()` does for
the whole log, on a single record:

  1. BINDING — the record's content still hashes to its stored `cert_digest` (catches a silent
     payload edit).
  2. DERIVATION — `entry_hash` is correctly derived from (seq, prev_hash, cert_digest) (catches an
     entry-field tamper).

Cross-record LINKAGE (prev_hash == the predecessor's entry_hash) needs the predecessor and is done
by `SpineTailer` as records stream. Reuses `reuse.digest_payload` and the canonical `_entry_hash`
from `reuse.chain` verbatim — never a re-implementation that could drift from the enforced path.

SCOPE (honest): these are UNKEYED sha-256 checks. They catch accidental corruption and a naive
stale-field tamper, but they do NOT prove AUTHENTICITY against a writer who can recompute the
digests (a tip tamper or a forward-cascaded fork stays internally consistent). Resistance to that
requires the owner-SIGNED head — `SpineTailer.check_anchor` (`checkpoint.classify_head`/`verify_head`),
which is what marks a record `anchored`. Treat a passing `verify_record` as well-formedness, not proof."""
from __future__ import annotations

from ..reuse import digest_payload
from ..reuse.chain import _entry_hash


def verify_record(record) -> tuple[bool, str]:
    """(ok, reason) for a single SpineRecord — binding + entry-hash derivation. Fail-closed."""
    content = {
        "scope": record.scope, "kind": record.kind, "source": record.source, "actor": record.actor,
        "payload": record.payload, "parent_id": record.parent_id, "supersedes_id": record.supersedes_id,
    }
    if digest_payload(content) != record.cert_digest:
        return False, f"binding break at seq {record.seq}: payload does not match cert_digest (record tampered)"
    if _entry_hash(record.seq, record.prev_hash, record.cert_digest) != record.entry_hash:
        return False, f"entry_hash mismatch at seq {record.seq}: derivation broken (entry tampered)"
    return True, f"seq {record.seq} binds and derives cleanly"
