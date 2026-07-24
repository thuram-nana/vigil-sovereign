"""Perceptor (SIGIL §4.3/§8, C4-C6) — turns a captured Frame into a GROUNDED perception answer and
writes it as an event record. Ceiling A1 (observe; writes only event records).

THE DISCIPLINE (serve-the-quote, reused from SCHOLAR): the frame's captured OCR TEXT is the
authoritative content of the answer — verbatim, what the OCR/accessibility layer read off the
owner's screen. The VLM's visual reading is ADVISORY. An object the VLM names is a LEAD, promoted to
a GROUNDED claim only if the OCR corroborates it (`veracity.corroborate`) — so a divergent or
fabricated reading is never presented as what is on the screen.

CASCADE (WS-A): the local reader (`MoondreamVision`, on-box, A0) runs freely; the FRONTIER reader
uploads private bytes and is gated by `Perceptor.frontier` — classified A2 via the WARDEN oracle and
withheld until a verified owner approval bound to that exact egress exists.

Ambient vision (C6) is OPT-IN: `ambient_watch` establishes a baseline then escalates only on a
PERCEPTUAL change (`delta.changed` over the OCR token set, not raw byte-identity). Unchanged frames
never leave the machine."""
from __future__ import annotations

from typing import List, Optional

from ..agents.base import Agent, AgentResult, Proposal, Tier
from .capture import Frame
from .delta import changed
from .veracity import corroborate
from .vision import VisionModel

# Section headers rendered at COLUMN 0. Captured screen text is guard-prefixed (see below) so it can
# never occupy column 0 — therefore an EXACT-LINE match on these headers is an unforgeable boundary,
# even when attacker-controlled screen content contains the header string verbatim (red-pen REDPEN-P5-2).
AUTHORITATIVE_HEADER = "## On-screen text (authoritative — captured verbatim from the frame)"
CORROBORATED_HEADER = "## Corroborated objects (VLM leads confirmed verbatim by the captured text)"
ADVISORY_HEADER = "## Model's visual reading (ADVISORY — a guess about the image, NOT verified against captured text)"
_GUARD = "  │ "   # every captured line starts here → it can never impersonate a column-0 header


def compose_perception(question: str, frame: Frame, reading: str,
                       grounded: Optional[List[dict]] = None) -> str:
    """Serve the captured text as authoritative; corroborated objects (each with a verbatim OCR
    quote) as grounded; the VLM reading as ADVISORY. Never merge them. The boundary is the column-0
    header line — unforgeable because every captured line is guard-prefixed."""
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
    if grounded:
        lines.append("")
        lines.append(CORROBORATED_HEADER)
        for g in grounded:
            lines.append(f"{_GUARD}'{g['mention']}' — corroborated by on-screen text: \"{g['quote']}\"")
    lines.append("")
    lines.append(ADVISORY_HEADER)
    # GUARD-PREFIX the advisory reading too (red-pen BLOCK-1): the reading is the most attacker-
    # influenceable channel (a compromised local model, or a VLM faithfully transcribing adversarial
    # on-screen text that contains a header string). Line-split + guard so no reading line can occupy
    # column 0 and forge the AUTHORITATIVE/CORROBORATED boundary.
    rd = reading.strip() if reading and reading.strip() else "(no reading available)"
    for ln in rd.splitlines():
        lines.append(f"{_GUARD}{ln.rstrip()}")
    return "\n".join(lines)


class Perceptor(Agent):
    name = "PERCEPTION"
    mandate = "answer screen/camera queries from captured ground truth; VLM reading is advisory"
    ceiling = Tier.A1

    def _emit(self, question: str, frame: Frame, reading: str, *, source_model: str,
              extra: Optional[dict] = None) -> AgentResult:
        """Build + dispatch the A0 perception event (shared by the local and frontier paths). The
        one-line summary NEVER serves a bare VLM reading as fact (red-pen RP-PERCEPT-01)."""
        grounded, leads = corroborate(reading, frame.text)
        captured = frame.text.strip()
        # `summary` is a plaintext label (the C18 audit reads it keyless) — it must NOT carry the raw
        # screen content (audit G1 slice-4): a NON-content descriptor here; the OCR / VLM reading live only
        # in the SEALED `text`/`captured_text`/`vision_reading_advisory` fields.
        if captured:
            summary = f"screen perceived ({len(captured)} chars OCR, {len(grounded)} grounded)"
        elif reading.strip():
            summary = f"({frame.kind} image — unverified {source_model} reading, no OCR)"
        else:
            summary = f"({frame.kind} image, no text)"
        payload = {
            "signal": "perception", "subject": question or "observe", "summary": summary,
            "text": compose_perception(question, frame, reading, grounded),
            "frame_kind": frame.kind, "frame_sha256": frame.sha256,
            "captured_text": frame.text,                    # authoritative ground truth
            "vision_reading_advisory": reading,             # advisory only
            "grounded_objects": grounded, "advisory_leads": leads,
            "grounded": bool(captured), "source_model": source_model,
        }
        if extra:
            payload.update(extra)
        return self._dispatch([Proposal("event", payload, Tier.A0)])   # observe → A0, auto

    def perceive(self, question: str, frame: Frame, *, vision: Optional[VisionModel] = None) -> AgentResult:
        """On-box perception (A0). `vision` is the LOCAL reader (MoondreamVision) or None/a double. An
        EGRESSING (frontier) model is STRUCTURALLY refused here — never uploaded on the auto path; it
        must go through `frontier()` (red-pen BLOCK-2)."""
        reading = ""
        if vision is not None and getattr(vision, "egresses", False):
            return self._emit(question, frame, "", source_model="local",
                              extra={"note": "an egressing (frontier) model was refused on the auto path "
                                             "— use `frontier()` (the egress gate). No upload occurred."})
        if vision is not None:
            try:
                reading = vision.describe(frame, question) or ""
            except Exception:  # noqa: BLE001 — a failing VLM yields no reading, never a crash/guess
                reading = ""
        return self._emit(question, frame, reading, source_model="local")

    def frontier(self, question: str, frame: Frame, *, vision: VisionModel, classifier=None,
                 trusted_pubkey=None, approved_seq: Optional[int] = None) -> AgentResult:
        """Frontier perception, EGRESS-GATED. The upload (`vision.describe`) runs ONLY when
        `approved_seq` names a verified owner approval bound to this exact (frame, question) egress.
        Otherwise the egress is QUEUED (A2) and NOTHING is uploaded."""
        from ..agents.kernel_classify import KernelClassifier
        from ..governor.identity import owner_pubkey
        from .egress import EGRESS_SIGNAL, FRONTIER_TOOL, egress_approved, egress_token
        classifier = classifier or KernelClassifier()
        tp = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        token = egress_token(frame.sha256, question)
        tier = classifier.classify(FRONTIER_TOOL)   # A2 by design (contains "upload") — DERIVED, not declared

        if approved_seq is not None and egress_approved(self.store, approved_seq, token, tp):
            reading = ""
            try:
                reading = vision.describe(frame, question) or ""   # the UPLOAD — only after verified approval
            except Exception:  # noqa: BLE001
                reading = ""
            res = self._emit(question, frame, reading, source_model="frontier",
                             extra={"egress_approved_seq": approved_seq})
            res.notes.append(f"frontier egress APPROVED (seq {approved_seq}, {tier.label()}) — uploaded + served advisory")
            return res

        # no verified approval → QUEUE the egress; upload NOTHING. The tier is DERIVED from the oracle
        # (A2 for "...upload"; A3 if the kernel is unreachable → even more gated) and A2/A3 > ceiling
        # A1 ⇒ the governor queues it. Nothing uploads on this path.
        res = self._dispatch([Proposal("event", {
            "signal": EGRESS_SIGNAL, "subject": f"frontier vision egress (frame {frame.sha256[:12]})",
            "summary": "frontier vision egress requested — upload WITHHELD pending owner approval",
            "egress_token": token, "frame_sha256": frame.sha256, "question": question,
        }, tier)])
        res.notes.append("frontier egress QUEUED — NO image uploaded; `sigil approve <seq>` then re-run "
                         "`perceive --frontier --approved <seq>`")
        return res

    def ambient_watch(self, frames: List[Frame], *, vision: Optional[VisionModel] = None) -> tuple:
        """Opt-in ambient loop (C6). Establish a baseline, then ESCALATE only on a PERCEPTUAL change
        (`delta.changed` — OCR-token-set divergence, so lighting jitter with the same on-screen text
        is not a change). Returns (escalation_count, [AgentResult]); emits indicator start/stop
        markers; unchanged frames produce nothing (they never leave the machine)."""
        if vision is not None and getattr(vision, "egresses", False):
            # ambient must NEVER auto-upload to the frontier — hard refuse (red-pen BLOCK-2).
            self.store.append(kind="refusal", source="agent", actor=self.name,
                                    payload={"signal": "perception.ambient", "tier": "A0", "decision": "refused",
                                             "summary": "ambient watch REFUSED an egressing (frontier) model — "
                                                        "ambient escalation is on-box only; no upload."})
            res = AgentResult(agent=self.name)
            res.notes.append("REFUSED: ambient may not use a frontier/egressing model (on-box only)")
            return 0, [res]
        self.store.append(kind="event", source="agent", actor=self.name,
                          payload={"signal": "perception.ambient", "tier": "A0", "decision": "auto",
                                   "summary": "ambient watch STARTED (indicator lit — opt-in)"})
        last: Optional[Frame] = None
        escalations: List[AgentResult] = []
        for fr in frames:
            if last is None:
                last = fr                      # baseline: no escalation, nothing leaves the machine
                continue
            if not changed(last, fr):
                continue                       # no meaningful change → suppressed
            last = fr
            escalations.append(self.perceive("(ambient: scene changed)", fr, vision=vision))
        self.store.append(kind="event", source="agent", actor=self.name,
                          payload={"signal": "perception.ambient", "tier": "A0", "decision": "auto",
                                   "summary": f"ambient watch STOPPED — {len(escalations)} escalation(s)"})
        return len(escalations), escalations
