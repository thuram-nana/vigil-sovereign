"""Perception veracity (Phase 7, WS-A V-iii) — grounded object CLAIMS vs advisory LEADS. A VLM's
object list ("a Firefox window, a laptop, a coffee mug") is a set of advisory LEADS. A lead is
promoted to a GROUNDED claim only if it is corroborated by an INDEPENDENT grounded signal — the
frame's authoritative OCR `captured_text`: a mention grounds iff it appears verbatim as a salient
token in the captured text. A grounded claim is phrased as corroboration ("corroborated by on-screen
text 'Firefox'") and carries the verbatim OCR span — never "there is physically a Firefox." This
mirrors CRUCIBLE's oracle/veracity discipline: the model advises, an independent ground-truth signal
confirms. Reuses the `consolidate.gate.salient` tokenizer so the corroboration rule is identical to
the memory gate's."""
from __future__ import annotations

import re

from ..consolidate.gate import salient


def _span(token: str, text: str) -> str:
    """The real (case-preserving) OCR substring that corroborates a lowercased token."""
    m = re.search(re.escape(token), text, re.IGNORECASE)
    return m.group(0) if m else token


def corroborate(reading: str, captured_text: str) -> tuple[list[dict], list[str]]:
    """(grounded, leads). `grounded` = VLM-mentioned salient tokens that appear verbatim in the OCR
    ground truth, each with its real OCR quote; `leads` = the rest of the VLM's salient tokens
    (advisory, uncorroborated). If there is no captured text, EVERYTHING is a lead (nothing to
    corroborate against) — an image-only frame can never yield a grounded object claim."""
    cap = salient(captured_text)
    read = salient(reading)
    if not cap:
        return [], sorted(read)
    grounded = [{"mention": t, "quote": _span(t, captured_text)} for t in sorted(read) if t in cap]
    leads = sorted(read - cap)
    return grounded, leads
