"""Perception recall (Phase 7, WS-A V-iv) — "where did I last see X?" answered from GROUNDED
perception history. Scans perception `event` records for the most recent whose authoritative OCR
`captured_text` contains the subject (all its salient tokens), and serves the VERBATIM OCR span +
frame ref + timestamp — the owner's own on-screen text, never a paraphrase and never an advisory VLM
lead. A0 (observe). Reuses the `consolidate.gate` grounding tokenizer + verbatim-span extractor so
recall grounds exactly like the memory gate."""
from __future__ import annotations

from typing import Optional

from ..consolidate.gate import salient
from ..spine.store import SpineStore

PERCEPTION_SIGNAL = "perception"


def _grounded_line(subject_tokens: set[str], captured: str) -> Optional[str]:
    """The verbatim OCR LINE that contains ALL the subject's salient tokens (so the served sighting
    always actually shows the subject), or None if no single line holds them (red-pen BLOCK-4 — a
    whole-frame token match whose tokens are scattered across lines is NOT a grounded sighting)."""
    for line in captured.splitlines():
        if line.strip() and subject_tokens <= salient(line):
            return line.strip()
    return None


def recall(store: SpineStore, subject: str) -> Optional[dict]:
    """The most recent grounded sighting of `subject`, or None. Grounded = every salient token of the
    subject appears in that frame's captured OCR text (the authoritative ground truth)."""
    subj = salient(subject)
    if not subj:
        return None
    latest = None
    latest_line = None
    for r in store.iter_records():
        if r.kind != "event" or r.payload.get("signal") != PERCEPTION_SIGNAL:
            continue
        r = store.decrypted(r)                # G1 slice-4: captured_text is a sealed content field
        line = _grounded_line(subj, r.payload.get("captured_text") or "")
        if line is not None:                  # subject co-located on a real OCR line → a grounded sighting
            latest, latest_line = r, line     # seq-ascending iteration → last match is most recent
    if latest is None:
        return None
    return {
        "seq": latest.seq, "entry_hash": latest.entry_hash, "when": latest.ts,
        "frame_sha256": latest.payload.get("frame_sha256"),
        "quote": latest_line,                 # verbatim OCR line that actually contains the subject
    }
