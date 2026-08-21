"""The episodic spine record — one immutable event, source of truth (SIGIL §6.1)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# event kinds (superset of the CRUCIBLE blackboard EventKind, extended for SIGIL sources).
# W5-1: this set is now an ENFORCED constraint, not a comment. `SpineStore.append` refuses any kind
# outside it (fail-closed), and `verify()` re-checks it on read — a two-layer guard that mirrors the
# offense blackboard's Python `if kind not in ALL_EVENT_KINDS` + SQL `CHECK(kind IN (...))` on the
# sovereign JSONL spine (which has no SQL layer of its own). Every kind actually written by a real
# append path is a member; extend the set BEFORE adding a new append kind.
KINDS = frozenset({
    "message", "tool_call", "tool_result", "decision", "commitment",
    "commit", "document", "brief", "refusal", "email", "session",
    "entity", "contradiction",  # promoted by the ARCHIVIST consolidation pass (§6.3)
    "warden_checkpoint",        # WARDEN (Phase 1) cross-anchors its action-log head here (anti-rollback)
    "event", "finding", "interaction", "draft",  # the agent mesh (Phase 3, §4): SENTINEL/BASTION/ENVOY
    "report", "pr",             # Phase 4: SCHOLAR sourced research reports, ARTIFICER PR proposals
    "web_page", "operation",    # Phase 7/8: SCRIBE fetched-page provenance; OPERATOR plan/execute records
    "detection",                # P10 inbound: a Detection-Mirror FACT admitted by the finding receiver
    "snapshot",                 # cold-archive hard-prune: the owner-signed folded summary of a pruned prefix
})

# W5-1: per-record schema version. `SCHEMA_VERSION` is stamped on every NEW append; `KNOWN_SCHEMA_VERSIONS`
# is the set the writer accepts (an append with a version outside it fails closed). A record predating this
# field (no `schema_version` key on the line) reads as `LEGACY_SCHEMA_VERSION` — additive + migration-safe:
# `schema_version` is INFORMATIONAL (like `ts`/`seq`), carried on the record line but NOT part of the
# content digested into `cert_digest`, so stamping it on new records and defaulting it on old ones leaves
# every existing record's cert_digest — and the whole hash chain — byte-for-byte intact (no chain break).
# The security-critical field, `kind`, is already inside the digested content, so it stays tamper-bound.
LEGACY_SCHEMA_VERSION = 0
SCHEMA_VERSION = 1
KNOWN_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})


def now_iso() -> str:
    """Informational wallclock timestamp. NOT part of the content digest (replay-stable)."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SpineRecord:
    """One line of the spine. `cert_digest`/`prev_hash`/`entry_hash` are the chain fields;
    `scope`..`supersedes_id` is the digested content (`ts` is informational, excluded from the digest).
    `schema_version` (W5-1) is likewise informational and NOT digested — a legacy record that predates
    the field reads as `LEGACY_SCHEMA_VERSION`, so its cert_digest and the chain are unchanged."""
    seq: int
    scope: str
    kind: str
    source: str            # "claude-code" | "git" | "doc" | ...
    actor: str             # "user" | "assistant" | session id | commit author | ...
    payload: dict[str, Any]
    parent_id: int | None
    supersedes_id: int | None
    ts: str
    cert_digest: str
    prev_hash: str
    entry_hash: str
    schema_version: int = LEGACY_SCHEMA_VERSION   # 0 == pre-W5-1 record (no `schema_version` on the line)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SpineRecord":
        return cls(
            seq=d["seq"], scope=d["scope"], kind=d["kind"], source=d["source"],
            actor=d["actor"], payload=d.get("payload") or {},
            parent_id=d.get("parent_id"), supersedes_id=d.get("supersedes_id"),
            ts=d.get("ts", ""), cert_digest=d["cert_digest"],
            prev_hash=d["prev_hash"], entry_hash=d["entry_hash"],
            # Migration-safe read: an older line has no `schema_version` key -> LEGACY_SCHEMA_VERSION.
            schema_version=int(d.get("schema_version", LEGACY_SCHEMA_VERSION)),
        )

    def text(self) -> str:
        """Best-effort human/searchable text of the record (for embedding + display)."""
        p = self.payload or {}
        for key in ("text", "content", "message", "summary", "body", "title"):
            v = p.get(key)
            if isinstance(v, str) and v.strip():
                return v
        # tool records / structured payloads: compact JSON fallback
        import json
        return json.dumps(p, ensure_ascii=False)[:4000]
