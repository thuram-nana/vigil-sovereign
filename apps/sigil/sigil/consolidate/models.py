"""Consolidation domain types (SIGIL §6.3). Offense-free personal-memory analogue of the
CRUCIBLE recon vocabulary — a candidate fact an extractor proposes, and the gate's verdict.

A `CandidateFact` is a PROPOSAL, never a fact. It becomes a fact only if `gate.admit`
re-executes its citation successfully; otherwise it is recorded honestly as a refusal. The
model's `model_confidence` can only ever LOWER effective ranking — it never promotes."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CandidateFact:
    """A candidate durable fact proposed by an ExtractionProvider over spine records.

    `quote` MUST be a verbatim span copied from one of the `source_seqs` records — the gate
    re-fetches those records and refuses to ground anything whose quote it cannot find."""
    kind: str                       # "decision" | "commitment" | "entity" | "contradiction"
    subject: str                    # canonical subject/key (what this fact is ABOUT)
    statement: str                  # advisory summary in the owner's terms (NEVER the served fact)
    quote: str                      # verbatim span from a cited record (the ground)
    source_seqs: list[int]          # spine seqs the extractor cited
    model_confidence: float = 0.5   # DEMOTE-ONLY: may lower ranking, never promote
    owner: str | None = None        # commitments: who is on the hook
    due_iso: str | None = None      # commitments: due date (ISO), if any
    extractor: str = "unknown"      # provenance of the proposal (heuristic | agent | replay)
    quotes: tuple[str, ...] = ()    # contradictions: a verbatim quote from EACH conflicting record

    def key_fields(self) -> dict:
        # identity is the GROUNDED content (the verbatim quote/quotes), not the model's
        # paraphrase — so two reaffirmations quoting the same span dedupe. Commitments also key
        # on owner/due (canonicalized) so a CHANGED deadline is a new promotion, not a duplicate.
        content = " ".join((self.quote or "").split()).casefold()
        if self.quotes:
            content = " || ".join(sorted(" ".join(q.split()).casefold() for q in self.quotes))
        base = {"kind": self.kind, "subject": self.subject.strip().lower(), "content": content}
        if self.kind == "commitment":
            base["owner"] = (self.owner or "").strip().casefold()
            base["due_iso"] = (self.due_iso or "").strip()
        return base


@dataclass(frozen=True)
class GateVerdict:
    """The sole admission authority's decision — decided by RE-EXECUTION, not model text."""
    grounded: bool
    grounding: str                  # "ingest:seq=<n>" (grounded) | "llm:ungrounded" (demoted)
    verified_seqs: list[int] = field(default_factory=list)
    reason: str = ""
    text: str = ""                  # the BYTE-verbatim record span(s) — the served fact content
