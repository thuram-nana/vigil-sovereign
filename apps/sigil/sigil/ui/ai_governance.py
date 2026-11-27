"""Legal/governance S5 — the customer AI / human-in-the-loop GOVERNANCE disclosure.

A pure, READ-ONLY statement of how VIGIL uses AI and the human oversight around it, shown on a settings sub-screen
(``#/ai-governance``, linked from the settings hub) behind ``VIGIL_CUSTOMER_AI_GOVERNANCE`` (default OFF).

WHAT IT SAYS — AND WHERE EVERY WORD COMES FROM. Nothing here is invented. The substantive statements are drawn WORD FOR
WORD from VIGIL's own canonical sources, and each carries its citation so a reader (or counsel) can check it:

  * what AI DOES (assists / advises) — the published Terms of Service, §11 "AI-assisted features"
    (``public_site/terms/index.html``);
  * what AI NEVER does (self-authorise, or decide money / scope) — the Terms §11 and the README's governing invariant
    (``README.md`` — "The AI and every tool only PROPOSE … none of them is the AI");
  * the human-in-the-loop doctrine ("AI proposes, the oracle disposes") — the README ("proof, not findings") and the
    plain-English Safety & Authorization briefing (``docs/plain-english/08-safety-and-authorization.md`` — the AI-free
    danger-tier classifier and the permission tiers);
  * the data-handling boundary — the Terms §11–§12 and the operator's sovereignty-tier control
    (``ui/settings.py`` — ``CRUCIBLE_SOVEREIGNTY_TIER``: AIR_GAPPED refuses every cloud model call before any bytes
    leave the host).

It is a DISPLAY surface only: no new authority, no money control, no mutation, no owner key, no model call, no traffic
to any target. The one negating ``STATEMENT`` below is fixed words, so a test can strip exactly it and prove nothing
else on the screen claims the AI holds authority.

FATAL-2: stdlib only — no framework / strix import, at module scope or anywhere. ``assert_no_offense`` at import.
"""
from __future__ import annotations

from ..reuse import assert_no_offense

assert_no_offense()

# The one sentence every rendering carries (fixed words). It frames the screen and negates the claim the disclosure
# exists to deny — that an AI anywhere in VIGIL holds authority. Everything after it is a cited statement from a source.
STATEMENT = ("VIGIL uses AI to assist and advise — never as an authority. No finding, charge or action takes effect on "
             "an AI's say-so. Every statement below is drawn word for word from VIGIL's published Terms, its README "
             "and its Safety & Authorization briefing, cited so you can check it yourself.")

# The disclosure sections, in display order. Each point is (text, source): the text is a verbatim or source-grounded
# statement, the source is where it comes from. No point asserts anything those sources do not.
_SECTIONS: "tuple[tuple[str, tuple[tuple[str, str], ...]], ...]" = (
    ("What AI does", (
        ("Parts of the Service use AI models: to plan and prioritise testing, to propose what might be a "
         "vulnerability, to summarise results and to answer questions in the assistant.",
         "Terms of Service, §11 — AI-assisted features"),
        ("VIGIL is built so that the AI advises and deterministic checks confirm: a finding is presented as confirmed "
         "only when a deterministic check has re-run it against the evidence and confirmed it. Anything not confirmed "
         "that way is shown as unconfirmed or estimated, and should be treated as such.",
         "Terms of Service, §11 — AI-assisted features"),
    )),
    ("What AI never does", (
        ("AI never decides what you are charged or which hosts you may test.",
         "Terms of Service, §11 — AI-assisted features"),
        ("The AI and every tool only PROPOSE. Only a deterministic oracle mints a signed FACT. Only the conjunctive "
         "gate authorizes an action. Only the egress gate lets a packet leave.",
         "README — the governing invariant of the platform"),
        ("Four separate authorities run the system, and none of them is the AI.",
         "README — the governing invariant of the platform"),
    )),
    ("Human in the loop — AI proposes, the oracle disposes", (
        ("A finding is confirmed for exactly one reason: a deterministic oracle fired over data a real target actually "
         "produced. The AI proposes; the oracle disposes.",
         "README — proof, not findings"),
        ("Every action the AI proposes is sorted by a small, AI-free classifier into a danger tier before anything "
         "happens. Anything visible outside the system waits for a human to approve it, and destructive, financial or "
         "key operations never run automatically, under any setting.",
         "Safety & Authorization briefing, §3 — permission tiers"),
        ("Permission is infrastructure, not prompt: the AI is never the thing that decides what is allowed.",
         "Safety & Authorization briefing — why this chapter exists"),
    )),
    ("Where your data goes", (
        ("To provide these features, relevant content (for example, responses from your hosts and the findings drawn "
         "from them) is sent to the AI model providers we use to run the Service, which are listed in our Privacy "
         "notice. Do not rely on assistant answers as legal, compliance or professional advice.",
         "Terms of Service, §11 — AI-assisted features"),
        ("An operator can bound which model backends VIGIL may call with the sovereignty tier: at AIR_GAPPED, every "
         "cloud model call — including the engine's think step — is refused before any bytes leave the host.",
         "Deployment control — CRUCIBLE_SOVEREIGNTY_TIER (Governance settings)"),
        ("You keep all rights in your Customer Data.",
         "Terms of Service, §12 — Confidentiality and your data"),
    )),
)


def disclosure(org_id: str) -> dict:
    """The AI-governance disclosure for the SESSION's org (``org_id`` resolved server-side by the caller, never a client
    claim). The statements are the same for every workspace — they are VIGIL's platform-wide commitments — so the only
    org-scoped datum is ``org_id`` itself, echoed so the screen can name the workspace the disclosure is shown for; the
    org isolation that gates reaching this read at all is the caller's ``admit_customer``. A fresh structure is built on
    every call (module state is never handed out to mutate)."""
    return {
        "ok": True,
        "org_id": str(org_id or ""),
        "statement": STATEMENT,
        "sections": [
            {"title": title, "points": [{"text": text, "source": source} for (text, source) in points]}
            for (title, points) in _SECTIONS
        ],
    }
