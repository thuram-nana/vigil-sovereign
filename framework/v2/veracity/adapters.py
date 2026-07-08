"""
veracity.adapters — build a `Claim` from the system's own findings, so the firewall
can actually RUN over live output (not just its own tests).

An oracle-confirmed finding already carries everything a claim needs: a bug_class (the
subject a ground binds to), an oracle_context (the ORACLE ground — the retained evidence
that re-fires), and a surface that maps to a world-model node (the entity the claim is
about). `claim_from_finding` assembles those into a `Claim`; `admit_finding` runs it
through `admit()` against the chained world-model, yielding a per-finding veracity verdict
— GROUNDED (fact) when the finding's own oracle_context RE-FIRES for its bug_class,
UNGROUNDED when it does not (a finding marked active whose proof no longer reproduces —
exactly the tampering/dry-run case the firewall exists to catch), and CONTRADICTED when
the graph holds the finding's surface at a net-refuted belief.

This is the firewall applied to real findings in the live engage loop; the reporting gate
(P4) renders these verdicts. It is deliberately best-effort and read-only: it re-verifies
what the oracle already decided and never promotes anything the oracle refused.
"""

from __future__ import annotations

from typing import Any

from .claims import AdmittedClaim, Claim
from .tokens import GroundingToken


def _get(finding: Any, key: str, default: Any = None) -> Any:
    """Read a field from a finding that may be a pydantic model or a plain dict."""
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _endpoint_node_id(finding: Any) -> str:
    """The world-model node a finding is about — MIRRORS the chainer's key exactly:
    both ``populate_worldmodel`` (campaign.py) and the orchestrator mint the endpoint
    node as ``f"endpoint:{f.param}"``, unconditionally, from ``param`` alone. We reproduce
    that same expression (no ``insertion_point`` fallback), so an empty-param finding binds
    to the real ``"endpoint:"`` node the chainer created rather than a phantom id the graph
    never holds — which would silently skip the contradiction + existence checks. Only a
    finding with NO param field at all (a hand-built dict) names no surface."""
    param = _get(finding, "param")
    if param is None:
        return ""
    return f"endpoint:{param}"


def claim_from_finding(finding: Any, *, source: str = "finding",
                       from_dryrun: bool = False, match_confidence: bool = True) -> Claim:
    """Build a Claim from an ``AuditFinding`` (or an equivalent dict). An oracle_context
    becomes an ORACLE token bound to the finding's bug_class; the finding's endpoint
    becomes the named entity the graph is consulted about.

    ``match_confidence`` (default True) threads the finding's recorded confidence into the
    token as a tamper-check claim — correct when that number is the RAW oracle confidence
    (a scanner AuditFinding). Set it False when the recorded confidence has been
    post-processed/CALIBRATED (a blackboard finding), so re-verification checks that the
    oracle re-fires for the bound bug_class WITHOUT falsely demoting on a legitimate
    calibration delta between the stored value and the raw re-fire."""
    bug_class = str(_get(finding, "bug_class", "") or "")
    tokens: list[GroundingToken] = []
    oc = _get(finding, "oracle_context")
    if isinstance(oc, dict) and oc:
        tokens.append(GroundingToken.oracle(
            oc, bug_class=bug_class,
            confirmed_by=_get(finding, "confirmed_by"),
            confidence=_get(finding, "confidence") if match_confidence else None,
            from_dryrun=from_dryrun))
    entity = _endpoint_node_id(finding)
    ipoint = _get(finding, "insertion_point", "") or ""
    return Claim(
        text=f"{bug_class} @ {ipoint}".strip(),
        source=source, bug_class=bug_class, tokens=tokens,
        entity_refs=[entity] if entity else [],
        proposed_confidence=_get(finding, "confidence"), from_dryrun=from_dryrun)


def admit_finding(finding: Any, world=None, *, verifier=None,
                  trust_root=None) -> AdmittedClaim:
    """Run a finding through the veracity firewall against ``world``. The world-model is
    consulted only for contradiction + entity existence; a finding whose endpoint the
    chainer has not projected is not treated as fabricated (entity existence is enforced
    only when the world actually models that node, so a finding assessed before/without
    chaining still grounds on its re-executed oracle)."""
    from .firewall import admit

    claim = claim_from_finding(finding)
    require = bool(world is not None and claim.entity_refs
                   and any(world.has_node(e) for e in claim.entity_refs))
    return admit(claim, world=world, verifier=verifier, trust_root=trust_root,
                 require_entities=require)
