"""
chainast.model — the typed leaves of a reversible reasoning/tool-call AST (VIGIL-FUSION F7, §5 C6).

Reimplements the SHAPE of pentagi's ``pkg/cast`` Chain-AST (design-only; Go + license — NOT vendored):
a raw provider message chain becomes a typed tree ``ChainAST → ChainSection[] → {Header, BodyPair[]}``.
This module holds the *leaves* — the message record and the enums — plus the single canonical byte
codec that makes the whole projection RE-EXECUTABLE (anyone re-derives byte-identical bytes).

Sovereign distinctions baked into the types:

  * A ``BodyPair`` carries a veracity tag ``FACT / LEAD / SUMMARY`` (``Veracity``). A body-pair is a
    FACT only when its records are oracle-confirmed (a non-empty signed ``evidence_ref`` **and**
    ``signature_ref`` on a ``status="fact"`` record — mirroring the F2 ``Finding`` / F4 projector
    invariant). A SUMMARIZATION pair is ALWAYS ``SUMMARY`` and can NEVER be a FACT, even if its records
    lie about their status — a lossy, non-authoritative summary must never masquerade as a fact inside
    the agent's own context.
  * ``ChainRecord`` is a pure data leaf keyed on the spine ``seq`` (the deterministic temporal
    coordinate — no wallclock). Claude extended-thinking blocks + their cryptographic signatures are
    first-class fields so compaction can hard-preserve them verbatim (a provider API requirement).

Nothing here makes anything true or authorizes anything. Import-clean: pydantic + stdlib only.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

# --- constants (pentagi Chain-Summary vocabulary, reimplemented) --------------------------------

# A summarization body-pair is a synthetic tool call whose response carries the summary text, so a
# compacted turn stays a structurally-valid AI+tool block to the provider API (not a bare text blob).
SUMMARIZATION_TOOL_NAME = "execute_task_and_return_summary"
SUMMARIZATION_TOOL_QUESTION = "summarize the covered reasoning/tool-call history"
SUMMARIZED_CONTENT_PREFIX = "[VIGIL-SUMMARY] "  # marks a tool-response as summarized content
SUMMARIZATION_KIND = "Summarization"            # the spine record kind for an append-only summary
FALLBACK_RESPONSE_CONTENT = "the call was not handled, please try again"  # repair placeholder


class MessageRole(str, Enum):
    """The role of a message record — the LangChain/provider message kinds, reimplemented."""

    SYSTEM = "system"   # opens a chain (turn 0 only in a well-formed chain)
    HUMAN = "human"     # opens a turn
    AI = "ai"           # an assistant message (may carry thinking + tool calls)
    TOOL = "tool"       # a tool-response message answering an AI tool call by id


class BodyPairType(str, Enum):
    """What kind of AI+tool-response block a body-pair is (pentagi ``BodyPairType``)."""

    COMPLETION = "completion"              # an AI message with no tool calls / no responses
    REQUEST_RESPONSE = "request_response"  # an AI message with tool calls + their responses
    SUMMARIZATION = "summarization"        # a synthetic summary block (append-only compaction)


class Veracity(str, Enum):
    """The veracity tag on a body-pair. The whole anti-trust-laundering guarantee at the context layer
    rests on this split: a SUMMARY (lossy) or a LEAD (unconfirmed claim) can never be read as a FACT."""

    FACT = "fact"       # oracle-confirmed: a record carries a signed evidence_ref + signature_ref
    LEAD = "lead"       # an unconfirmed proposal
    SUMMARY = "summary"  # a lossy, non-authoritative compaction — NEVER a fact


class ToolCallSpec(BaseModel):
    """One tool call emitted inside an AI message. ``args`` is serialised with sorted keys in the
    canonical codec so the round-trip is byte-stable regardless of dict insertion order."""

    id: str = ""
    name: str = ""
    args: dict[str, Any] = Field(default_factory=dict)


class SummaryCitation(BaseModel):
    """What an append-only ``Summarization`` record CITES: the contiguous ``[start, end]`` spine range
    it covers, the number of records, and the RFC-6962 Merkle root over exactly those covered records
    (so anyone can re-derive the commitment from the signed originals — the originals are never
    deleted). Deterministic; no wallclock/RNG."""

    covered_start_seq: int = 0
    covered_end_seq: int = 0
    covered_count: int = 0
    merkle_root: str = ""


class ChainRecord(BaseModel):
    """One message record in a reasoning/tool-call chain — a pure data leaf over a signed spine entry.

    ``thinking`` / ``thinking_signature`` hold a Claude extended-thinking block and its cryptographic
    signature verbatim; compaction must never rewrite the most recent one (a hard API requirement).
    ``status`` / ``evidence_ref`` / ``signature_ref`` carry the veracity provenance re-derived (never
    trusted) by :func:`record_confirmed`. Extra/unknown fields on an untrusted dict are ignored — the
    projection stays total on malformed input."""

    seq: int = 0
    role: MessageRole
    content: str = ""
    thinking: str = ""              # Claude extended-thinking text (verbatim; signature-protected)
    thinking_signature: str = ""    # provider-mandatory cryptographic thinking signature (verbatim)
    tool_calls: list[ToolCallSpec] = Field(default_factory=list)   # AI message → its tool calls
    tool_call_id: str = ""          # TOOL message → the AI tool-call id it answers
    name: str = ""                  # tool name (for a TOOL response / a summarization call)
    status: str = "lead"            # "lead" | "fact" (a fact still needs signed evidence to confirm)
    evidence_ref: str = ""          # SCITT/OpenVEX cert id / signed oracle evidence (⇔ confirmed)
    signature_ref: str = ""         # signed-head / signature reference
    kind: str = ""                  # optional spine-kind hint; a summary record is SUMMARIZATION_KIND
    summary_citation: Optional[SummaryCitation] = None  # set on an append-only Summarization record


def record_confirmed(rec: ChainRecord) -> bool:
    """A record is oracle-CONFIRMED iff it is a ``status="fact"`` carrying BOTH a non-empty signed
    ``evidence_ref`` AND a ``signature_ref``. Mirrors the F2 ``Finding._fact_needs_evidence`` invariant
    and the F4 projector's ``_is_confirmed`` — a bare ``status="fact"`` with no signed evidence is NOT
    confirmed. Total: never raises on a malformed record."""
    try:
        return (getattr(rec, "status", "") == "fact"
                and bool((rec.evidence_ref or "").strip())
                and bool((rec.signature_ref or "").strip()))
    except Exception:  # noqa: BLE001 — a malformed record is simply "not confirmed"
        return False


# --- the single canonical byte codec (the re-executable projection) -----------------------------


def record_bytes(rec: Any) -> bytes:
    """The canonical bytes of one record: minified JSON with SORTED keys (deep — nested tool-call
    ``args`` included), so two records equal in value serialise to identical bytes regardless of field
    or dict-key insertion order. This is the leaf a re-executable byte-identical round-trip rests on.
    Total: a malformed/non-record input is coerced through :func:`_coerce_record`; anything that cannot
    be a record (or will not serialise) degrades to ``b""`` (no signal), never raises."""
    rec = _coerce_record(rec)
    if rec is None:
        return b""
    try:
        return json.dumps(rec.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    except Exception:  # noqa: BLE001 — a record that will not serialise is no-signal, not a crash
        return b""


def to_canonical_bytes(records: Any) -> bytes:
    """Canonical newline-delimited serialisation of a record list (each record is exactly one line —
    internal newlines are JSON-escaped, so the framing is unambiguous). Deterministic: the same records
    always yield the same bytes, so anyone re-derives the projection. Total: the input is coerced through
    :func:`normalize`, so garbage/``None``/a str degrades to ``b""`` (no signal), never raises."""
    return b"\n".join(record_bytes(r) for r in normalize(records))


def _coerce_record(item: Any) -> Optional[ChainRecord]:
    """Best-effort coercion of one untrusted element to a ``ChainRecord``. A ``ChainRecord`` passes
    through; a dict is validated; anything else (or a dict with an unknown/absent role) degrades to
    ``None`` (no signal), never raises — a crash is a denial-of-cognition."""
    if isinstance(item, ChainRecord):
        return item
    if isinstance(item, dict):
        try:
            return ChainRecord.model_validate(item)
        except Exception:  # noqa: BLE001 — an unparseable record is dropped (total on garbage)
            return None
    return None


def normalize(records: Any) -> list[ChainRecord]:
    """Coerce an untrusted iterable of records/dicts into a clean ``list[ChainRecord]``, dropping any
    element that cannot be a record. Total: a non-iterable or ``None`` yields ``[]``."""
    if isinstance(records, (str, bytes)) or records is None:
        return []
    try:
        items = list(records)
    except TypeError:
        return []
    out: list[ChainRecord] = []
    for item in items:
        rec = _coerce_record(item)
        if rec is not None:
            out.append(rec)
    return out


def from_canonical_bytes(data: Any) -> list[ChainRecord]:
    """Parse canonical newline-delimited bytes back into records. Total: a non-bytes input, a torn
    line, or a malformed record is skipped, never crashed on — so ``from_canonical_bytes`` degrades a
    lossy/attacker-tampered blob to the records it can recover rather than raising."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        return []
    out: list[ChainRecord] = []
    for raw in bytes(data).split(b"\n"):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            continue
        rec = _coerce_record(obj)
        if rec is not None:
            out.append(rec)
    return out
