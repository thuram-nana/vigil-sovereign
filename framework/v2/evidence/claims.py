"""
evidence.claims — bind report statements into a finding's evidence certificate.

What a DETERMINISTIC gate can and cannot certify (this boundary is the whole point):

  * IT CAN certify a STRUCTURED claim — "a finding of bug_class X was confirmed by a
    deterministic oracle and re-verifies from the retained evidence." That statement
    re-executes: verify_certificate re-fires the oracle for class X and, because a proof
    is bound to its subject (P3), a statement declaring a class the evidence does NOT
    prove fails the certificate closed. It is also SIGNED with the certificate, so its
    text is tamper-evident.

  * IT CANNOT certify the natural-language CONTENT of free prose. A deterministic gate
    does no entailment: it cannot tell that "SQL injection on q" is backed while "remote
    code execution and fund drainage" is not, when both are stamped with the finding's
    own class. So free prose is NEVER asserted as a machine-verified fact — it is bound
    as LABELLED analyst commentary: retained and tamper-evident, but explicitly the
    producer's assertion, not something the oracle proved.

Accordingly ``claims_for_finding`` emits exactly one ``render_as="fact"`` claim — the
canonical structured statement, which re-grounds by construction — plus one labelled
``analyst-commentary`` claim per sentence of any narrative prose. There is deliberately no
API to stamp arbitrary prose as a fact, so an over-claiming narrative cannot launder into
a governance-signed "proven fact." Decomposition is a deterministic regex (no LLM), so the
gate itself introduces no hallucination.

Distinct-by-design from ``veracity/claims.py`` (do NOT merge — different layer, same name):
this module defines no claim MODEL — it emits ``ReportClaim`` (from ``evidence/models.py``),
a certificate-bound report sentence — whereas ``veracity/claims.py`` owns the firewall's
runtime ``Claim``/``AdmittedClaim`` admission types. The two interoperate one-directionally:
``certify._claims_grounded`` re-admits each ``render_as="fact"`` ``ReportClaim`` through the
veracity firewall, so the evidence layer depends on veracity, never the reverse. They share a
vocabulary (``render_as``, "fact", "analyst-commentary"), not code.
"""

from __future__ import annotations

import re

from .models import ReportClaim

# split on a sentence terminal followed by whitespace; deterministic (no model, no wallclock).
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def decompose_prose(text: str) -> list[str]:
    """Split narrative prose into atomic sentences, deterministically. Empty in → empty
    out; internal whitespace is normalised so producer and verifier agree byte-for-byte."""
    if not text or not text.strip():
        return []
    parts = (s.strip() for s in _SENTENCE_SPLIT.split(text.strip()))
    return [s for s in parts if s]


def canonical_fact_sentence(finding: dict) -> str:
    """The single STRUCTURED statement a certificate can assert as a machine-verified
    fact: it names the finding's bug_class (and surface, when known) and claims only that
    the deterministic oracle confirmed it and re-verifies — nothing the evidence does not
    prove. Deterministic (stable text) so it does not perturb canonical bytes."""
    bug_class = str(finding.get("bug_class", "")) or "vulnerability"
    surface = str(finding.get("insertion_point") or finding.get("surface")
                  or finding.get("param") or "")
    on = f" on {surface}" if surface else ""
    return (f"A {bug_class} finding{on} was confirmed by a deterministic oracle and "
            f"re-verifies from the retained evidence.")


def claims_for_finding(finding: dict, *, commentary_prose: str = "") -> list[ReportClaim]:
    """Build the ``ReportClaim`` set for a finding: ONE canonical structured fact (which
    re-grounds by construction against the finding's own oracle) plus one labelled
    ``analyst-commentary`` claim per sentence of ``commentary_prose``. Commentary is
    retained and signed (tamper-evident) but never asserted as a machine-verified fact —
    the deterministic gate does not read its English. ``bug_class`` is inherited from the
    finding so the fact claim is bound to the right subject."""
    bug_class = str(finding.get("bug_class", ""))
    claims = [ReportClaim(sentence=canonical_fact_sentence(finding),
                          bug_class=bug_class, render_as="fact")]
    claims += [ReportClaim(sentence=s, bug_class=bug_class, render_as="analyst-commentary")
               for s in decompose_prose(commentary_prose)]
    return claims
