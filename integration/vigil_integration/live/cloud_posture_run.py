"""cloud_posture_run — Wave B.2: the FIRST real AWS end-to-end, as pure GLUE over already-merged seams.

The one orchestration home that strings together the four seams Wave B.1 (and earlier) already landed, with
NO new oracle / sensor / evidence / report / mint logic of its own:

    minted read-only customer session (DATA)
        -> the VIGIL-owned read-only collector (``sensors.cloud_live.CloudLiveSensor``) captures the real
           inventory as THAT identity (never VIGIL's ambient one — ``require_injected_credentials=True``)
        -> the EXISTING ``cloud_live_verify`` D5-scope-gates the capture and re-fires the deterministic
           ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export, minting a signed FACT per
           confirmed insecure subject (the collector's say-so is never trusted — criterion 6)
        -> a tiny report-line adapter renders each FACT through the EXISTING report grounding + renderer.

CONSUMES THE SESSION AS DATA. ``session_data`` is a DUCK-TYPED object (``provider`` / ``access_key_id`` /
``secret_access_key`` / ``session_token`` / ``region`` / ``account_id``) — the shape a
``vigil_core.cloud_session.MintedSession`` satisfies. This module NEVER imports the mint: the real
sovereign-subprocess + spool crossing of a minted session is DEFERRED to a later wave, and is modelled
in-process here by any object with those attributes (a fake duck-typed session in tests). Handing the
collector DATA, never a governor object, is the FATAL-2 boundary.

FATAL-2. Every ``framework`` import is FUNCTION-LOCAL (mirrors ``cloud_live_posture`` and
``cloud_live.py``'s module docstring "every framework import is FUNCTION-LOCAL"); the module imports NO
``apps/sigil`` / governor and NO ``vigil_core`` governor surface at module scope, so importing it co-loads
no offense engine and does not breach the sovereign env's offense-free boundary. The only module-scope
imports are stdlib + the sovereign ``cloud_live_posture`` sibling (itself framework-clean at module scope).
"""

from __future__ import annotations

from typing import Any

from .cloud_live_posture import CloudLivePostureResult, cloud_live_verify


def run_cloud_posture_live(
    session_data: Any,
    *,
    scope_gate,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    region: str = "",
    resource: str = "",
    collector_id: str = "cloud-live",
    capture_time_epoch: "int | None" = None,
    tool_context: Any = None,
    sink: Any = None,
) -> CloudLivePostureResult:
    """Collect LIVE cloud posture as the minted customer identity and re-derive signed FACTs over it.

    Builds :class:`~framework.v2.sensors.cloud_live.CloudLiveSensor` scoped to the injected
    ``session_data`` (``require_injected_credentials=True`` — the collector FAILS CLOSED rather than fall
    back to VIGIL's ambient boto3 identity), runs it THROUGH the gated ``invoke_tool`` chain (kill-switch /
    entitlement / charter scope / egress allowlist + the audit spine — a bare call is still fully gated;
    pass ``sink`` for the audit spine and ``tool_context`` for the engagement's posture), then hands the
    collector's retained native export (``output['export']``, ``format='native'``) to the EXISTING
    :func:`cloud_live_posture.cloud_live_verify` verbatim — which D5-scope-gates the capture against the
    signed charter and mints a signed FACT per confirmed insecure subject. Returns the
    :class:`CloudLivePostureResult`.

    ``provider`` / ``account`` are read off the session (``session_data.provider`` /
    ``session_data.account_id``) — the FACT's tenant identity, matched EXACTLY by the scope gate. A
    collector that could not run to completion (no identity substitution, account-drift refusal, or boto3
    absent) yields a no-FACT, INCONCLUSIVE result carrying the collector's reason — never a clean negative.

    ``capture_time_epoch`` (optional, extends the brief for determinism): an OPERATOR-supplied capture time
    bound into the signed certificate as evidence. It is never a wall-clock read here; pass a fixed value
    for byte-reproducible signed bytes, or leave it ``None`` (no capture time bound). The oracle's own
    signal confidence — never a hand-set value — backs every FACT (``cloud_live_verify`` is the authority).

    FATAL-2: the only ``framework`` symbols (the gated-invocation chain + ``CloudLiveSensor``) are
    imported function-locally.
    """
    from framework.v2.agents.tools import (  # noqa: PLC0415 (FATAL-2: function-local)
        ToolContext,
        ToolRegistry,
        invoke_tool,
    )
    from framework.v2.sensors.cloud_live import CloudLiveSensor  # noqa: PLC0415 (FATAL-2: function-local)

    provider = str(getattr(session_data, "provider", "") or "")
    account = str(getattr(session_data, "account_id", "") or "")

    # GATE + AUDIT the live collection through the W1.4 fail-closed chain (kill-switch / entitlement /
    # charter scope / destructive / egress allowlist) and the event spine — NEVER call ``sensor.run()``
    # directly: that would reach the customer's cloud control plane ungated (a tripped kill-switch could not
    # abort it; a missing ACTIVE_RECON entitlement or an un-allowlisted control-plane host would not stop it)
    # and unrecorded. ``invoke_tool`` runs every gate BEFORE the collector touches boto3, refuses fail-closed,
    # and records tool_call / tool_result / refusal. ``ctx.slug`` is authoritative for gating; the
    # engagement's spine sink + posture (prompt_callback / dry_run / world) are inherited from
    # ``tool_context`` when the caller supplies one (a bare call is still fully gated, just unaudited).
    sensor = CloudLiveSensor(credentials=session_data, require_injected_credentials=True)
    registry = ToolRegistry()
    registry.register(sensor)
    if isinstance(tool_context, ToolContext):
        ctx = ToolContext(slug=engagement_slug or tool_context.slug,
                          world=getattr(tool_context, "world", None),
                          prompt_callback=tool_context.prompt_callback, dry_run=tool_context.dry_run)
    else:
        ctx = ToolContext(slug=engagement_slug,
                          prompt_callback=getattr(tool_context, "prompt_callback", None),
                          dry_run=bool(getattr(tool_context, "dry_run", False)))
    # The audit sink for the event spine (tool_call / tool_result / refusal). ``invoke_tool`` takes it as a
    # SEPARATE argument (a ToolContext carries no sink), so accept it explicitly; fall back to one carried on
    # a duck-typed ``tool_context`` for convenience. ``None`` simply omits events — the gating is unaffected.
    audit_sink = sink if sink is not None else (
        getattr(tool_context, "sink", None) or getattr(tool_context, "spine_sink", None))
    result = invoke_tool(registry, sensor.name, {}, ctx, sink=audit_sink)

    if not getattr(result, "ok", False):
        # A GATE refused (kill-switch / entitlement / scope / egress) OR the collector itself fail-closed
        # (no identity substitution, account-drift, boto3 absent): nothing was captured, so nothing is
        # adjudicated. Surface a no-FACT result that is NEVER a clean negative, carrying the gate/collector
        # reason (the oracle authority never runs on an un-captured target).
        res = CloudLivePostureResult(provider=provider, account=account)
        reason = str(getattr(result, "note", "") or getattr(result, "refusal_reason", "") or "no detail")
        gate = str(getattr(result, "gate", "") or "")
        res.notes.append(
            "live collection did not run to completion (gated / fail-closed, nothing captured"
            + (f"; gate={gate}" if gate else "") + "): " + reason)
        return res

    out = getattr(result, "output", None) or {}
    export = out.get("export")
    if not isinstance(export, str) or not export.strip():
        res = CloudLivePostureResult(provider=provider, account=account)
        res.notes.append("live collector returned no native export to adjudicate (nothing captured)")
        return res

    # The EXISTING verify path, verbatim: D5 scope gate -> deterministic oracle re-fire -> signed FACT.
    # The collector emits ``export`` as a JSON string (the native inventory); cloud_live_verify parses it
    # through its resource-governed ``_canonical_capture`` and binds the canonical bytes every FACT recheck
    # recomputes (BLOCK #3). ``provider`` / ``account`` come from the minted session, matched by the gate.
    return cloud_live_verify(
        export,
        provider=provider,
        account=account,
        scope_gate=scope_gate,
        engagement_slug=engagement_slug,
        signers=signers,
        region=region,
        resource=resource,
        collector_id=collector_id,
        capture_time_epoch=capture_time_epoch,
    )


def _fact_to_finding(fact: Any, oracle_context: "dict | None") -> Any:
    """Build ONE report ``FindingPayload`` from an oracle-confirmed FACT (an
    :class:`~vigil_integration.oracle_adapter.AdapterResult`). The retained ``oracle_context`` is the SAME
    dict the certificate bound, so report-time grounding re-fires the deterministic oracle and grades it a
    FACT (not an LLM lead). FATAL-2: the model import is function-local.

    No new finding content is invented — the bug class, confirming oracle kind, calibrated confidence and
    bound subject are READ off the signed FACT; only presentational scaffolding (slug/title/summary) is
    synthesised deterministically so the renderer has a row to draw."""
    from framework.v2.agents.models import FindingPayload  # noqa: PLC0415 (FATAL-2: function-local)

    import hashlib  # noqa: PLC0415 (stdlib, kept local to the adapter)

    bug_class = str(getattr(fact, "bug_class", "") or "")
    finding_ref = str(getattr(fact, "finding_ref", "") or "")
    provider = account = subject = ""
    try:
        scope = (fact.signed.certificate.bound_identity or {}).get("resource_scope") or {}
        provider = str(scope.get("provider", "") or "")
        account = str(scope.get("account", "") or "")
        subject = str(scope.get("resource", "") or "")
    except Exception:  # noqa: BLE001 — a FACT with no readable subject still renders (scaffolding only)
        provider = account = subject = ""

    # Deterministic, stable slug over the finding_ref (no counter, no clock) so the renderer's sort is
    # reproducible and two runs over the same capture render byte-identically.
    digest = hashlib.sha256(finding_ref.encode("utf-8")).hexdigest()[:8]
    slug = f"cl-{(bug_class or 'cloud').replace('_', '-')}-{digest}"
    subject_label = subject or finding_ref or "(cloud subject)"

    return FindingPayload(
        finding_slug=slug,
        title=f"Confirmed insecure live cloud state: {subject_label}",
        severity="High",
        bug_class=bug_class,
        surface=f"cloud:{provider or 'aws'}:{account or '?'}",
        summary=(
            f"The live-capture {bug_class or 'cloud_posture'} oracle re-fired over the scoped, retained "
            f"capture of {subject_label}, confirming an insecure achieved state / anonymous grant path."),
        impact=(
            "An anonymous or over-broad principal can reach this resource as captured; the claim is bounded "
            "to the scoped live state, proven by a re-runnable certificate."),
        oracle_context=dict(oracle_context or {}),
        verified_by_oracle=True,
        confidence=float(getattr(fact, "confidence", 0.0) or 0.0),
        oracle_kind=str(getattr(fact, "confirmed_by", "") or ""),
    )


def render_cloud_posture_report(
    result: CloudLivePostureResult,
    *,
    target: str = "",
    executive: bool = False,
) -> str:
    """Render a Markdown report line for every oracle-confirmed FACT in ``result`` through the EXISTING
    report grounding + renderer (``framework.v2.report``). Each FACT is turned into a ``GradedFinding`` by
    the platform's own grounding grader (which re-fires the retained proof), so a FACT appears as a
    "PROVEN FACT" with its re-runnable ``sha256:`` certificate reference — never dressed up, never faked.

    FATAL-2: every ``framework`` import is function-local.
    """
    from framework.v2.report.generate import (  # noqa: PLC0415 (FATAL-2: function-local)
        ReportMeta,
        render_executive,
        render_technical,
    )
    from framework.v2.report.grounding import grade_finding  # noqa: PLC0415 (FATAL-2: function-local)

    graded = [
        grade_finding(_fact_to_finding(f, result.contexts.get(f.finding_ref)))
        for f in result.facts
    ]
    meta = ReportMeta(target=target or f"{result.provider}:{result.account}")
    return render_executive(graded, meta) if executive else render_technical(graded, meta)
