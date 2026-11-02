"""
jobs.findings_crossing — K4-4: cross a completed CUSTOMER run's confirmed FACTs to the sovereign spine.

A keyless POST-RUN step for a ``cust_`` engagement. A bare ``run_engagement`` (the engage_worker path)
produces its confirmed FACTs only as in-memory ``EngagementResult.report.active_findings`` with re-verifiable
``oracle_context`` certificates that are NOT governance-signed, so nothing crosses to the sovereign plane on
its own. This step closes that gap:

  for each oracle-confirmed FACT, RE-ADJUDICATE the retained ``oracle_context`` via
  ``oracle_adapter.confirm_and_certify(provenance="reproduced")`` — the deterministic oracle MUST re-fire
  over the executor-captured raw target bytes BEFORE anything is signed, so a finding that does not re-fire
  degrades to a LEAD and is NEVER crossed (identical soundness to the Proof Studio mint; no fabricated signed
  FACTs) — mint an owner-delegated offense-governance m-of-n ``SignedEvidence`` bound to the ``cust_``
  engagement slug, and emit ONE inert envelope per FACT to the cross-plane finding spool
  (``KeylessOffenseWorker.emit_finding_envelope`` → ``finding_spool.spool_envelope``).

The sovereign ``SpoolWatcher`` + ``FindingReceiver.from_delegation(scope=cust_slug).ingest`` then verify the
m-of-n signature against the owner-signed ``OFFENSE_GOVERNANCE_ROLE`` delegation, scope-bind each FACT's own
signed ``engagement_slug``, and ``assessment_findings`` projects it to the OWNING org only — the one-way
``cust_`` slug hash (``_customer_slug(org, host)``) makes cross-tenant projection structurally impossible.

KEYLESS + FATAL-2: this holds NO owner key. ``signers`` are the owner-DELEGATED offense-governance
authorisers (distinct from the owner key), so it can sign FACTs the sovereign plane verifies against the
owner's delegation without ever holding the owner key. ``framework``/CRUCIBLE is imported LAZILY inside the
function; module scope is stdlib + the two import-clean integration seams (offense_worker, finding_spool).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..finding_spool import spool_envelope
from ..offense_worker import KeylessOffenseWorker


@dataclass(frozen=True)
class CrossingResult:
    """Outcome of crossing a run's findings: how many became signed-and-spooled FACTs, how many degraded to
    LEADs (did not re-fire — NOT crossed), how many errored (counted + skipped), and the spool paths written."""

    crossed: int = 0
    leads: int = 0
    errors: int = 0
    envelope_paths: "list[str]" = field(default_factory=list)


def findings_from_report(report: Any) -> "list[dict]":
    """Duck-typed, framework-free: the JSON finding dicts from an ``EngagementResult.report``'s
    ``active_findings`` (each an ``AuditFinding`` carrying ``check_id`` / ``bug_class`` / ``oracle_context``).
    Total — a report without ``active_findings`` yields ``[]``, a finding without ``model_dump`` is skipped."""
    out: "list[dict]" = []
    for f in getattr(report, "active_findings", None) or []:
        try:
            out.append(f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f))
        except Exception:  # noqa: BLE001 — a malformed finding is skipped, never crashes the crossing
            continue
    return out


def cross_confirmed_findings(
    findings: "list[dict]",
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    spool_dir: Any,
) -> CrossingResult:
    """Cross each oracle-confirmed FACT finding dict (carrying its retained ``oracle_context`` + ``bug_class``)
    to the sovereign finding spool as a governance-signed inert envelope bound to ``engagement_slug`` (the
    ``cust_`` slug). RE-ADJUDICATES with ``provenance="reproduced"`` (the oracle must re-fire over the retained
    bytes; a non-re-firing finding becomes a LEAD and is NOT crossed). ``signers`` = the owner-delegated
    offense-governance authorisers ``[(key_id, priv_b64)]`` whose pubkeys the sovereign OFFENSE_GOVERNANCE_ROLE
    delegation covers. Total: a per-finding error is counted + skipped, never raised."""
    if not engagement_slug:
        raise ValueError("cross_confirmed_findings requires the cust_ engagement slug")
    if not signers:
        raise ValueError(
            "cross_confirmed_findings requires owner-delegated offense-governance signers; it will not "
            "cross an unsigned finding (fail-closed — a LEAD can never cross the sovereignty seam)")
    from ..oracle_adapter import confirm_and_certify   # lazy (keeps module scope framework-clean; FATAL-2)

    worker = KeylessOffenseWorker(engagement_slug=engagement_slug)   # refuses an owner key by construction
    crossed = leads = errors = 0
    paths: "list[str]" = []
    for i, finding in enumerate(findings):
        try:
            res = confirm_and_certify(dict(finding), engagement_slug=engagement_slug, signers=signers,
                                      seq=i, provenance="reproduced")
            if getattr(res, "is_fact", False) and res.signed is not None:
                envelope = worker.emit_finding_envelope(res.signed)   # refuses an UNSIGNED finding
                paths.append(str(spool_envelope(spool_dir, envelope)))
                crossed += 1
            else:
                leads += 1                                            # did not re-fire / unmapped ⇒ not crossed
        except Exception:  # noqa: BLE001 — one bad finding never sinks the batch (count + skip)
            errors += 1
    return CrossingResult(crossed=crossed, leads=leads, errors=errors, envelope_paths=paths)