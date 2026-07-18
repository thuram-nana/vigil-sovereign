"""Perceptor (SIGIL §4.3/§8, C4-C6) — turns a captured Frame into a GROUNDED perception answer and
writes it as an event record. Ceiling A1 (observe; writes only event records).

THE DISCIPLINE (serve-the-quote, reused from SCHOLAR): the frame's captured TEXT is the
authoritative content of the answer — verbatim, what the OCR/accessibility layer actually read off
the owner's screen. The VLM's visual reading is ADVISORY and labelled as unverified, so a divergent
or fabricated reading can never be presented as what is on the screen. If no text was captured
(image-only camera frame), the answer says so and the reading is explicitly the only, unverified,
signal — never dressed up as fact.

Ambient vision (C6) is OPT-IN: `ambient_watch` establishes a baseline frame then escalates (runs the
VLM, writes an event) ONLY when a later frame differs. Unchanged frames never leave the machine and
nothing persists beyond the event records."""
from __future__ import annotations

from typing import List, Optional

from ..agents.base import Agent, AgentResult, Proposal, Tier
from .capture import Frame
from .vision import VisionModel


# Section headers rendered at COLUMN 0. Captured screen text is guard-prefixed (see below) so it can
# never occupy column 0 — therefore an EXACT-LINE match on these headers is an unforgeable boundary,
# even when attacker-controlled screen content contains the header string verbatim (red-pen REDPEN-P5-2).
AUTHORITATIVE_HEADER = "## On-screen text (authoritative — captured verbatim from the frame)"
ADVISORY_HEADER = "## Model's visual reading (ADVISORY — a guess about the image, NOT verified against captured text)"
_GUARD = "  │ "   # every captured line starts here → it can never impersonate a column-0 header


def compose_perception(question: str, frame: Frame, reading: str) -> str:
    """Serve the captured text as authoritative; the VLM reading as ADVISORY. Never merge them.
    The authoritative/advisory boundary is the column-0 header line — unforgeable because every
    captured line is guard-prefixed. Machine consumers should key off the structured payload fields
    (`captured_text` vs `vision_reading_advisory`); this rendering is the human-readable view."""
    lines = [f"# Perception — {question or '(observe)'}", ""]
    captured = (frame.text or "").strip()
    if captured:
        lines.append(AUTHORITATIVE_HEADER)
        for ln in captured.splitlines():
            if ln.strip():
                lines.append(f"{_GUARD}{ln.rstrip()}")   # guard-prefixed: cannot forge the boundary
        lines.append(f"\n(frame: {frame.kind}, sha256 {frame.sha256[:12]}, {len(captured)} chars captured)")
    else:
        lines.append("## No text captured from the frame")
        lines.append(f"(frame: {frame.kind}, sha256 {frame.sha256[:12]}, image-only — nothing OCR-grounded to serve)")
    lines.append("")
    lines.append(ADVISORY_HEADER)
    lines.append(f"- {reading.strip() if reading and reading.strip() else '(no reading available)'}")
    return "\n".join(lines)


class Perceptor(Agent):
    name = "PERCEPTION"
    mandate = "answer screen/camera queries from captured ground truth; VLM reading is advisory"
    ceiling = Tier.A1

    def perceive(self, question: str, frame: Frame, *, vision: Optional[VisionModel] = None) -> AgentResult:
        reading = ""
        if vision is not None:
            try:
                reading = vision.describe(frame, question) or ""
            except Exception:  # noqa: BLE001 — a failing VLM yields no reading, never a crash/guess
                reading = ""
        text = compose_perception(question, frame, reading)
        # The one-line summary must NEVER be a bare VLM reading presented as fact: when there is no
        # captured text, either label the reading unverified or fall back to a neutral placeholder
        # (red-pen RP-PERCEPT-01 / REDPEN-P5-1). A grounded summary is the captured text only.
        captured = frame.text.strip()
        if captured:
            summary = captured[:120]
        elif reading.strip():
            summary = f"(unverified VLM reading) {reading.strip()[:100]}"
        else:
            summary = f"({frame.kind} image, no text)"
        return self._dispatch([Proposal("event", {
            "signal": "perception",
            "subject": question or "observe",
            "summary": summary,
            "text": text,
            "frame_kind": frame.kind,
            "frame_sha256": frame.sha256,
            "captured_text": frame.text,               # authoritative ground truth
            "vision_reading_advisory": reading,        # advisory only
            "grounded": bool(frame.text.strip()),
        }, Tier.A0)])   # observe → A0, auto

    def ambient_watch(self, frames: List[Frame], *, vision: Optional[VisionModel] = None) -> tuple:
        """Opt-in ambient loop (C6). Establish a baseline, then ESCALATE only on a changed frame.
        Returns (escalation_count, [AgentResult]). Emits indicator start/stop markers; unchanged
        frames produce nothing (they never leave the machine).

        Change = BYTE-IDENTITY of the captured frame (sha256). This is a deliberately coarse baseline:
        a real deployment swaps in a perceptual-hash / small-VLM delta so lighting jitter isn't a
        change and a meaningful scene shift is — the escalation LOGIC here is what's under test, not
        the sophistication of the delta metric."""
        self.store.append(kind="event", source="agent", actor=self.name,
                          payload={"signal": "perception.ambient", "tier": "A0", "decision": "auto",
                                   "summary": "ambient watch STARTED (indicator lit — opt-in)"})
        last: Optional[Frame] = None
        escalations: List[AgentResult] = []
        for fr in frames:
            if last is None:
                last = fr                      # baseline: no escalation, nothing leaves the machine
                continue
            if fr.sha256 == last.sha256:
                continue                       # no change → suppressed
            last = fr
            escalations.append(self.perceive("(ambient: scene changed)", fr, vision=vision))
        self.store.append(kind="event", source="agent", actor=self.name,
                          payload={"signal": "perception.ambient", "tier": "A0", "decision": "auto",
                                   "summary": f"ambient watch STOPPED — {len(escalations)} escalation(s)"})
        return len(escalations), escalations
