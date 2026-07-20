"""ENVOY (SIGIL §4.6) — communications & relationships: triage inbound, DRAFT outbound, track
open loops. Ceiling A2 HARD, and NO PROMOTION PATH — outbound stays human-gated permanently.

This is enforced STRUCTURALLY: ENVOY has no method that transmits anything. It only classifies
inbound and writes `draft` records (A2 → queued, `status: awaiting-approval`). A human reads the
draft and sends it (or not). There is deliberately no `send()`. The inbox is a pluggable source
(a file of messages for tests/offline; IMAP is an optional real source, not built here)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Protocol, runtime_checkable

from .base import Agent, AgentResult, Proposal, Tier

_SPAM = ("unsubscribe", "viagra", "lottery", "prince", "crypto giveaway", "you have won", "click here to claim")
_URGENT = ("urgent", "asap", "as soon as possible", "deadline", "today", "emergency", "overdue", "past due", "final notice")
_FYI = ("no-reply", "noreply", "newsletter", "notification", "digest", "do not reply")


@runtime_checkable
class InboxSource(Protocol):
    def messages(self) -> List[dict]: ...   # each: {from, subject, body, date}


class FileInbox:
    """A JSON file of messages — for tests/offline. Real IMAP is a separate optional source."""
    def __init__(self, path: str):
        self.path = Path(path)

    def messages(self) -> List[dict]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []   # a corrupt/truncated inbox degrades to empty, never crashes the triage pass
        return data if isinstance(data, list) else data.get("messages", [])


def triage(msg: dict) -> str:
    """Classify a message → urgent | normal | fyi | spam (deterministic, keyword-based)."""
    sender = str(msg.get("from", "")).lower()
    text = f"{msg.get('subject', '')} {msg.get('body', '')}".lower()
    if any(k in text for k in _SPAM):
        return "spam"
    if any(k in sender for k in _FYI):
        return "fyi"
    if any(k in text for k in _URGENT):
        return "urgent"
    return "normal"


def draft_reply(msg: dict) -> str:
    """A conservative acknowledgement DRAFT (never sent). A real deployment can swap in an
    agent-composed draft via the cognition cascade; the doctrine (drafts-only) is unchanged."""
    who = str(msg.get("from", "there")).split("@")[0].split("<")[0].strip() or "there"
    subj = msg.get("subject", "your message")
    return (f"Hi {who},\n\nThanks for your message regarding \"{subj}\" — I've received it and "
            f"will follow up shortly.\n\n[DRAFT — SIGIL/ENVOY. Review and send manually; nothing is sent automatically.]")


class Envoy(Agent):
    name = "ENVOY"
    mandate = "triage inbound, DRAFT outbound (never send), track open loops"
    ceiling = Tier.A2  # hard — no promotion to auto, ever

    def run(self, inbox: InboxSource) -> AgentResult:  # type: ignore[override]  # SIGIL agents take domain-specific run() inputs; base run is an abstract placeholder
        proposals: List[Proposal] = []
        open_loops = 0
        for msg in inbox.messages():
            cls = triage(msg)
            # the triage note is a reversible internal record → A1, auto.
            proposals.append(Proposal("interaction", {
                "from": msg.get("from"), "subject": msg.get("subject"),
                "triage": cls, "date": msg.get("date")}, Tier.A1))
            if cls in ("urgent", "normal"):
                open_loops += 1
                # the reply is a DRAFT — A2, ALWAYS queued (never auto-sent).
                proposals.append(Proposal("draft", {
                    "to": msg.get("from"), "subject": f"Re: {msg.get('subject', '')}",
                    "body": draft_reply(msg), "in_reply_to": msg.get("subject"), "triage": cls}, Tier.A2))
        res = self._dispatch(proposals)
        res.notes.append(f"triaged {len(inbox.messages())} messages; {open_loops} open loop(s) drafted (awaiting approval)")
        return res

    # NOTE: there is intentionally no send()/transmit() method. Outbound is human-only, forever.
