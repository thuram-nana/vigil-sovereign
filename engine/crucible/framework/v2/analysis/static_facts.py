"""
analysis.static_facts — the SAST source-code bridge to a re-runnable "static FACT".

The static-analysis path (``analysis/``) emits ``AnalysisFinding`` LEADs. Their only promotion today is a
probabilistic LLM reviewer (``analysis.review_loop``), which — being probabilistic — CANNOT mint a FACT.
This module is the deterministic bridge: it turns ONE LEAD's exact source region into a "static FACT" — a
re-runnable, VIGIL-OWNED deterministic rule over RETAINED SOURCE-CODE BYTES, exactly analogous to how a web
oracle re-fires over retained HTTP bytes.

The contract, mirroring the retained-artifact oracles (``weak_crypto_artifact`` / posture):

  * The LEAD carries its EXACT source region — ``(path, line, source_bytes, rule_id)``. ``rule_id`` is the
    CLOSED vocabulary the ``STATIC_RULE`` oracle knows (:data:`STATIC_RULE_IDS`); the tool that produced the
    LEAD (semgrep / joern / the pattern analyzer) only says WHERE to look and is NEVER trusted for its CWE
    or classification.
  * :func:`from_code_region` builds the RETAINED context (a :class:`FindingContext`) that carries the raw
    source bytes VERBATIM.
  * :func:`confirm_code_region` runs the pure ``STATIC_RULE`` oracle, which RE-PARSES those bytes ITSELF and
    re-derives a CODE PROPERTY. It fires only when the property genuinely holds; a non-Python or unparseable
    region REFUSES (a LEAD, never a FACT), and a tamper that removes the property no longer re-fires.
  * :func:`static_fact_finding` serialises the confirmation into the finding shape the STANDARD certify path
    (``evidence.certify.build_certificate``) consumes — so the mint goes through the same signed-certificate
    machinery every other confirmed finding uses, and re-verifies OFFLINE by re-running the pure oracle over
    the retained bytes (``python3 -m framework.v2 verify``).

Every static FACT is honestly scoped to the PROVEN CODE PROPERTY (a broken-crypto invocation, an
insecure-flag literal, or a direct intra-procedural taint — the THREE FACT-capable tiers), NEVER
"exploitable at runtime". The ``insecure-randomness-sink`` rule_id is a RECOGNISED detection pointer but is
LEAD-only: the ``STATIC_RULE`` oracle is fail-closed for it and never mints a FACT (a sound FACT needs
crypto-provenance dataflow — see docs/capability-matrix blocking_work for ``static_insecure_randomness``).
Inter-procedural / possibly-sanitized / whole-program flows stay a LEAD.

This module reads source and reasons about it; it sends no traffic and makes no LLM call.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..verify.adapter import _STATIC_RULE_BUG_CLASS, FindingContext
from ..verify.verifier import OracleVerifier
from .models import AnalysisFinding

# The CLOSED rule-id vocabulary a static FACT may be minted under — the SAME map the adapter uses to derive
# the canonical bug_class. A rule_id outside this set has no bug_class and the oracle REFUSES it, so a static
# context can never be built under an unknown rule. (A test asserts this equals the oracle's own
# ``_STATIC_RULE_IDS`` closed set, so the two can never drift.)
STATIC_RULE_IDS: frozenset[str] = frozenset(_STATIC_RULE_BUG_CLASS)


def bug_class_for_rule(rule_id: str) -> str:
    """The canonical static bug_class for a CLOSED-vocabulary ``rule_id``, or ``""`` if it is out of
    vocabulary (a lead the oracle would REFUSE)."""
    return _STATIC_RULE_BUG_CLASS.get((rule_id or "").strip(), "")


class StaticFact(BaseModel):
    """The result of adjudicating one source region with the ``STATIC_RULE`` oracle.

    ``confirmed`` is True only when the pure oracle re-derived the code property from the retained bytes.
    ``oracle_context`` is the JSON-safe retained context the certify path binds and offline re-verify
    re-runs — so a confirmed static FACT is independently re-executable."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    rule_id: str
    path: str
    line: int = Field(ge=0)
    confirmed: bool
    confirmed_by: str = ""
    confidence: float = 0.0
    evidence: str = ""
    oracle_context: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_fact(self) -> bool:
        return self.confirmed


def from_code_region(
    path: str,
    line: int,
    source_bytes: str | bytes,
    rule_id: str,
    *,
    language: str = "python",
) -> FindingContext:
    """Build the RETAINED context for one source region — the SAST bridge's entry point. Thin, deliberate
    wrapper over :meth:`FindingContext.from_code_region` so a caller (an orchestrator, a promoter, a test)
    turns a LEAD's ``(path, line, source_bytes, rule_id)`` into the context the ``STATIC_RULE`` oracle
    re-parses. The canonical bug_class is DERIVED from ``rule_id``."""
    return FindingContext.from_code_region(path, line, source_bytes, rule_id, language=language)


def confirm_code_region(
    path: str,
    line: int,
    source_bytes: str | bytes,
    rule_id: str,
    *,
    language: str = "python",
    verifier: Optional[OracleVerifier] = None,
) -> StaticFact:
    """Adjudicate one source region: build the retained context, run the pure ``STATIC_RULE`` oracle, and
    return a :class:`StaticFact`. ``confirmed`` is True only when the oracle re-derived the code property
    from the retained bytes at or above the verifier threshold — an unknown rule_id, a non-Python or
    unparseable region, or a region where the property does not hold all yield ``confirmed=False`` (a LEAD)."""
    ctx = from_code_region(path, line, source_bytes, rule_id, language=language)
    oracle_context = ctx.to_verifier_context()
    result = (verifier or OracleVerifier()).confirm(oracle_context)
    confirming = result.confirming_signals
    top = max(confirming, key=lambda s: s.confidence) if confirming else None
    return StaticFact(
        bug_class=ctx.bug_class,
        rule_id=(rule_id or "").strip(),
        path=(ctx.static_rule or {}).get("path", ""),
        line=int((ctx.static_rule or {}).get("line", 0) or 0),
        confirmed=result.confirmed,
        confirmed_by=(top.kind.value if top else ""),
        confidence=(top.confidence if top else 0.0),
        evidence=(top.evidence if top else result.rationale),
        oracle_context=oracle_context,
    )


def confirm_analysis_finding(
    finding: AnalysisFinding,
    source_bytes: str | bytes,
    rule_id: str,
    *,
    language: str = "python",
    verifier: Optional[OracleVerifier] = None,
) -> StaticFact:
    """Adjudicate an ``AnalysisFinding`` LEAD given its RETAINED source region + the CLOSED-vocabulary
    ``rule_id`` the caller resolved for it. The tool's own ``finding.rule_id`` / ``finding.cwe`` are NEVER
    consulted for the verdict — only ``path`` and ``line`` are read for provenance; the CODE PROPERTY is
    re-derived from ``source_bytes`` by the pure oracle."""
    return confirm_code_region(
        finding.path, finding.line, source_bytes, rule_id, language=language, verifier=verifier)


def static_fact_finding(fact: StaticFact, *, check_id: str = "") -> dict:
    """Serialise a CONFIRMED :class:`StaticFact` into the finding dict the STANDARD certify path
    (``evidence.certify.build_certificate``) consumes: ``bug_class`` + ``confirmed_by`` + ``confidence`` +
    the retained ``oracle_context`` (which the certificate binds and offline re-verify re-runs). Raises
    ``ValueError`` for an unconfirmed fact — a LEAD is never minted into a certificate."""
    if not fact.confirmed:
        raise ValueError("static_fact_finding requires a CONFIRMED static fact — a LEAD is never minted")
    slug = check_id or f"static:{fact.rule_id}:{fact.path}:{fact.line}"
    return {
        "check_id": slug,
        "bug_class": fact.bug_class,
        "confirmed_by": fact.confirmed_by,
        "confidence": fact.confidence,
        "insertion_point": f"{fact.path}:{fact.line}",
        "oracle_context": fact.oracle_context,
    }
