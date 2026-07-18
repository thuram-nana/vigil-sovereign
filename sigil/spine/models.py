"""The episodic spine record — one immutable event, source of truth (SIGIL §6.1)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# event kinds (superset of the CRUCIBLE blackboard EventKind, extended for SIGIL sources)
KINDS = frozenset({
    "message", "tool_call", "tool_result", "decision", "commitment",
    "commit", "document", "brief", "refusal", "email", "session",
    "entity", "contradiction",  # promoted by the ARCHIVIST consolidation pass (§6.3)
    "warden_checkpoint",        # WARDEN (Phase 1) cross-anchors its action-log head here (anti-rollback)
    "event", "finding", "interaction", "draft",  # the agent mesh (Phase 3, §4): SENTINEL/BASTION/ENVOY
    "report", "pr",             # Phase 4: SCHOLAR sourced research reports, ARTIFICER PR proposals
    "web_page", "operation",    # Phase 7/8: SCRIBE fetched-page provenance; OPERATOR plan/execute records
})


def now_iso() -> str:
    """Informational wallclock timestamp. NOT part of the content digest (replay-stable)."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SpineRecord:
    """One line of the spine. `cert_digest`/`prev_hash`/`entry_hash` are the chain fields;
    everything above `ts` is the digested content (ts is informational, excluded from the digest)."""
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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SpineRecord":
        return cls(
            seq=d["seq"], scope=d["scope"], kind=d["kind"], source=d["source"],
            actor=d["actor"], payload=d.get("payload") or {},
            parent_id=d.get("parent_id"), supersedes_id=d.get("supersedes_id"),
            ts=d.get("ts", ""), cert_digest=d["cert_digest"],
            prev_hash=d["prev_hash"], entry_hash=d["entry_hash"],
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
