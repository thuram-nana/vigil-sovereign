"""cloud_posture_run — Wave B.2/B.3: the real multi-provider cloud end-to-end, as pure GLUE over merged seams.

The one orchestration home that strings together the seams Wave B.1 (and earlier) already landed, with
NO new oracle / sensor / evidence / report / mint logic of its own — only a PROVIDER DISPATCH over the
already-merged collectors:

    minted read-only customer session (DATA)
        -> DISPATCH on ``session_data.provider``: the VIGIL-owned read-only collector
           (``aws`` -> ``sensors.cloud_live.CloudLiveSensor``; ``gcp`` -> ``sensors.gcp_live.GcpLiveSensor``)
           captures the real inventory as THAT identity (never VIGIL's ambient one —
           ``require_injected_credentials=True``)
        -> the EXISTING provider-GENERIC ``cloud_live_verify`` D5-scope-gates the capture and re-fires the
           deterministic ``cloud_posture`` + ``policy_path`` oracles over the RETAINED export, minting a signed
           FACT per confirmed insecure subject (the collector's say-so is never trusted — criterion 6)
        -> a tiny report-line adapter renders each FACT through the EXISTING report grounding + renderer.

CONSUMES THE SESSION AS DATA. ``session_data`` is a DUCK-TYPED object whose shape a
``vigil_core.cloud_session.MintedSession`` satisfies: always ``provider`` / ``account_id`` (the account for
AWS, the PROJECT for GCP), plus the provider's credential parts — AWS ``access_key_id`` /
``secret_access_key`` / ``session_token`` (+ optional ``region``), or GCP ``bearer_token`` (a short-lived
OAuth2 access token). This module NEVER imports the mint: the real sovereign-subprocess + spool crossing of a
minted session is DEFERRED to a later wave, and is modelled in-process here by any object with those
attributes (a fake duck-typed session in tests). Handing the collector DATA, never a governor object, is the
FATAL-2 boundary.

FATAL-2. Every ``framework`` import is FUNCTION-LOCAL (mirrors ``cloud_live_posture`` and
``cloud_live.py``'s module docstring "every framework import is FUNCTION-LOCAL"); the module imports NO
``apps/sigil`` / governor and NO ``vigil_core`` governor surface at module scope, so importing it co-loads
no offense engine and does not breach the sovereign env's offense-free boundary. The only module-scope
imports are stdlib + the sovereign ``cloud_live_posture`` sibling (itself framework-clean at module scope).
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

    DISPATCHES the collector on ``session_data.provider`` — ``aws`` ->
    :class:`~framework.v2.sensors.cloud_live.CloudLiveSensor` (STS temporary credentials); ``gcp`` ->
    :class:`~framework.v2.sensors.gcp_live.GcpLiveSensor` (a short-lived OAuth2 bearer) — each scoped to the
    injected ``session_data`` with ``require_injected_credentials=True`` (the collector FAILS CLOSED rather than
    fall back to VIGIL's ambient identity — never AWS's ambient boto3 chain, never GCP's ambient ADC). The
    chosen collector is run THROUGH the gated ``invoke_tool`` chain (kill-switch / entitlement / charter scope /
    egress allowlist + the audit spine — a bare call is still fully gated; pass ``sink`` for the audit spine and
    ``tool_context`` for the engagement's posture), then its retained native export (``output['export']``,
    ``format='native'``) is handed to the EXISTING provider-GENERIC :func:`cloud_live_posture.cloud_live_verify`
    verbatim — which D5-scope-gates the capture against the signed charter and mints a signed FACT per confirmed
    insecure subject. Returns the :class:`CloudLivePostureResult`.

    ``provider`` / ``account`` are read off the session (``session_data.provider`` /
    ``session_data.account_id``) — the FACT's tenant identity, matched EXACTLY by the scope gate (for GCP the
    ``account`` IS the project id). A collector that could not run to completion (no identity substitution,
    account/project-drift refusal, or the cloud SDK absent) yields a no-FACT, INCONCLUSIVE result carrying the
    collector's reason — never a clean negative.

    ``capture_time_epoch`` (optional, extends the brief for determinism): an OPERATOR-supplied capture time
    bound into the signed certificate as evidence. It is never a wall-clock read here; pass a fixed value
    for byte-reproducible signed bytes, or leave it ``None`` (no capture time bound). The oracle's own
    signal confidence — never a hand-set value — backs every FACT (``cloud_live_verify`` is the authority).

    FATAL-2: the only ``framework`` symbols (the gated-invocation chain + the dispatched collector) are
    imported function-locally.
    """
    from framework.v2.agents.tools import (  # noqa: PLC0415 (FATAL-2: function-local)
        ToolContext,
        ToolRegistry,
        invoke_tool,
    )

    provider = str(getattr(session_data, "provider", "") or "")
    account = str(getattr(session_data, "account_id", "") or "")

    # PROVIDER DISPATCH — the ONLY provider-specific seam. The collector is provider-specific; everything
    # downstream (the gated ``invoke_tool`` chain, ``cloud_live_verify``, the report adapter) is provider-
    # GENERIC. ``aws`` -> ``CloudLiveSensor`` (STS temporary credentials); ``gcp`` ->
    # ``GcpLiveSensor`` (a short-lived OAuth2 bearer, the GCP twin of Wave B.1). BOTH consume the minted session
    # as DATA with ``require_injected_credentials=True`` (the collector FAILS CLOSED rather than fall back to
    # VIGIL's ambient identity — never AWS's ambient boto3 chain, never GCP's ambient ADC), expose the SAME
    # gated-tool contract (``name`` / ``run`` / ``egress_hosts`` / ``capability=ACTIVE_RECON``), and emit the
    # SAME ``{export, format:'native'}`` the downstream verify + report consume. For GCP, ``account`` IS the
    # project id (``session_data.account_id``), matched EXACTLY by the D5 scope gate. FATAL-2: each sensor
    # import is function-local (no offense engine co-loads at module scope).
    if provider == "gcp":
        from framework.v2.sensors.gcp_live import GcpLiveSensor  # noqa: PLC0415 (FATAL-2: function-local)
        sensor: Any = GcpLiveSensor(credentials=session_data, require_injected_credentials=True)
    elif provider in ("azure", "az"):
        from framework.v2.sensors.azure_live import AzureLiveSensor  # noqa: PLC0415 (FATAL-2: function-local)
        sensor = AzureLiveSensor(credentials=session_data, require_injected_credentials=True)
    elif provider == "cloudflare":
        from framework.v2.sensors.cloudflare_live import CloudflareLiveSensor  # noqa: PLC0415 (FATAL-2: function-local)
        sensor = CloudflareLiveSensor(credentials=session_data, require_injected_credentials=True)
    else:
        from framework.v2.sensors.cloud_live import CloudLiveSensor  # noqa: PLC0415 (FATAL-2: function-local)
        sensor = CloudLiveSensor(credentials=session_data, require_injected_credentials=True)

    # GATE + AUDIT the live collection through the W1.4 fail-closed chain (kill-switch / entitlement /
    # charter scope / destructive / egress allowlist) and the event spine — NEVER call ``sensor.run()``
    # directly: that would reach the customer's cloud control plane ungated (a tripped kill-switch could not
    # abort it; a missing ACTIVE_RECON entitlement or an un-allowlisted control-plane host would not stop it)
    # and unrecorded. ``invoke_tool`` runs every gate BEFORE the collector touches the cloud SDK, refuses
    # fail-closed, and records tool_call / tool_result / refusal. ``ctx.slug`` is authoritative for gating; the
    # engagement's spine sink + posture (prompt_callback / dry_run / world) are inherited from
    # ``tool_context`` when the caller supplies one (a bare call is still fully gated, just unaudited).
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


# ===========================================================================================================
# UNIFIED cross-provider layer (Wave B.4): one entry point that assesses a customer across ALL providers and
# produces ONE consolidated posture report. PURE GLUE over the per-provider single-provider path above — no
# new oracle / mint / evidence / report logic; it iterates the minted per-provider sessions, runs the EXISTING
# ``run_cloud_posture_live`` once per session, and AGGREGATES the per-provider ``CloudLivePostureResult``s as
# DATA. FATAL-2: this layer makes NO ``framework`` import of its own (module- or function-scope) — every
# framework touch is DEFERRED to ``run_cloud_posture_live`` / ``render_cloud_posture_report``, which import
# function-locally. Determinism: input order is preserved end to end (no wall-clock, no RNG). Fail-closed: one
# provider's refusal / inconclusive / crash never masks another's FACTs and never reads as CLEAN.
# ===========================================================================================================


@dataclass
class MultiCloudPostureResult:
    """The consolidated outcome of ONE unified multi-provider posture pass — pure AGGREGATION over the
    per-provider :class:`CloudLivePostureResult`s, computed as DATA.

    ``results`` keys each per-provider result by its provider token, in the INPUT order of the sessions (a
    plain ``dict`` preserves insertion order, so iteration is deterministic). A provider-key collision (two
    sessions for the SAME provider — e.g. two AWS accounts) is disambiguated deterministically
    (``provider#account`` then ``provider#<index>``) so that NO per-provider result is ever dropped: a dropped
    result could mask one tenant's FACTs or launder a refusal into silence (a MEDIUM+ fail-closed blocker).

    ``notes`` carries ORCHESTRATION-level detail — in particular an isolated per-provider error (a raised run
    that was captured so the others still assessed). It is surfaced in the report, never swallowed.

    Every aggregate is DERIVED (a property / method over ``results``), never a stored count that could drift
    from the per-provider results it summarises. The combined verdict is only ever ``FACT`` or ``INCONCLUSIVE``
    — NEVER ``CLEAN``: each per-provider ``family_verdict`` is itself FACT|INCONCLUSIVE (a scoped partial live
    capture cannot prove absence), so the aggregate inherits that, and a refused/inconclusive provider can
    never be reported as a clean tenant."""

    results: "dict[str, CloudLivePostureResult]" = field(default_factory=dict)
    notes: list = field(default_factory=list)

    @property
    def providers_assessed(self) -> "list[str]":
        """The provider keys that produced a result, in input order (one entry per session)."""
        return list(self.results.keys())

    @property
    def total_facts(self) -> int:
        """Total PROVEN (oracle-confirmed) FACTs across every provider — the sum of the per-provider
        ``n_facts``. Each is a signed FACT the oracle re-fired; nothing here is fabricated."""
        return sum(r.n_facts for r in self.results.values())

    def facts_by_provider(self) -> "dict[str, int]":
        """Per-provider confirmed-FACT count, in input order."""
        return {k: r.n_facts for k, r in self.results.items()}

    @property
    def providers_with_facts(self) -> "list[str]":
        """Providers that confirmed at least one FACT."""
        return [k for k, r in self.results.items() if r.n_facts > 0]

    @property
    def providers_refused(self) -> "list[str]":
        """Providers whose D5 scope gate / pre-flight REFUSED — nothing was adjudicated. Surfaced distinctly;
        NEVER folded into a clean result."""
        return [k for k, r in self.results.items() if getattr(r, "refused", False)]

    @property
    def providers_inconclusive(self) -> "list[str]":
        """Providers that were assessed (not a hard scope refusal) but confirmed NO FACT — a partial, empty,
        or failed/ isolated-error capture. INCONCLUSIVE, never CLEAN: surfaced distinctly so an empty provider
        is never read as a clean bill of health. Disjoint from both ``providers_with_facts`` (n_facts>0) and
        ``providers_refused`` (refused=True), so the three sets partition the assessed providers."""
        return [k for k, r in self.results.items()
                if not getattr(r, "refused", False) and r.n_facts == 0]

    def family_verdict(self) -> str:
        """The COMBINED cross-provider verdict. ``FACT`` iff ANY provider confirmed a FACT; otherwise
        ``INCONCLUSIVE``. NEVER ``CLEAN`` — a refused / inconclusive provider can never launder the tenant
        into a clean verdict (a scoped live capture cannot prove absence)."""
        return "FACT" if self.total_facts > 0 else "INCONCLUSIVE"


def _provider_key(result: CloudLivePostureResult, index: int, existing: "dict[str, Any]") -> str:
    """A deterministic, COLLISION-FREE key for ``result`` within ``existing`` (the results accumulated so far).
    Prefers the bare provider token; on a collision falls back to ``provider#account`` then ``provider#<index>``
    (``index`` is unique per session, so a key is always found). Dropping a colliding result is NOT an option —
    that would mask a tenant's FACTs; disambiguation keeps every result addressable and counted."""
    base = (str(getattr(result, "provider", "") or "").strip()) or f"provider-{index}"
    if base not in existing:
        return base
    account = str(getattr(result, "account", "") or "").strip()
    cand = f"{base}#{account}" if account else f"{base}#{index}"
    if cand not in existing:
        return cand
    return f"{base}#{index}"  # index is unique within one run -> guaranteed unique, deterministic


def run_multicloud_posture(
    sessions: Any,
    *,
    scope_gate,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    capture_time_epoch: "int | None" = None,
    tool_context: Any = None,
    sink: Any = None,
) -> MultiCloudPostureResult:
    """Assess a customer across ALL provided per-provider minted sessions and aggregate the results.

    ``sessions`` is a list of per-provider minted read-only sessions (each the duck-typed DATA shape
    :func:`run_cloud_posture_live` consumes — ``provider`` / ``account_id`` + the provider's credential parts).
    For EACH session, in INPUT ORDER, this runs the EXISTING :func:`run_cloud_posture_live` once (which
    dispatches to the right collector, gates the live read through the W1.4 fail-closed chain, and mints signed
    FACTs over the retained capture), then keys the returned :class:`CloudLivePostureResult` into a
    :class:`MultiCloudPostureResult`.

    PURE GLUE / FATAL-2: this function makes NO ``framework`` import (the per-provider call owns every framework
    touch, function-locally). DETERMINISM: sessions are iterated in input order, the results dict preserves that
    order, and nothing reads a wall-clock or RNG.

    FAIL-CLOSED ISOLATION: a per-provider run that RAISES is captured as THAT provider's no-FACT, never-CLEAN
    result carrying the error detail (type + message) in its notes AND in the multi-result ``notes`` — the
    others are still assessed, the whole run never crashes, and the error is SURFACED, never silently swallowed.
    A provider's refusal / inconclusive never suppresses another provider's FACTs (each result is counted
    independently) and the combined verdict is never CLEAN. ``scope_gate`` / ``signers`` / ``engagement_slug`` /
    ``capture_time_epoch`` / ``tool_context`` / ``sink`` are passed through UNCHANGED to every per-provider run."""
    results: "dict[str, CloudLivePostureResult]" = {}
    notes: list = []
    for index, session_data in enumerate(sessions):
        provider = str(getattr(session_data, "provider", "") or "")
        account = str(getattr(session_data, "account_id", "") or "")
        try:
            res = run_cloud_posture_live(
                session_data,
                scope_gate=scope_gate,
                engagement_slug=engagement_slug,
                signers=signers,
                capture_time_epoch=capture_time_epoch,
                tool_context=tool_context,
                sink=sink,
            )
        except Exception as exc:  # noqa: BLE001 — per-provider ISOLATION: one provider's crash must not
            # crash the whole multi-run nor mask the other providers. The error is NOT swallowed silently:
            # the exception type + message are recorded in BOTH this provider's result notes and the
            # multi-result notes (surfaced in the report), and the result stays a no-FACT, never-CLEAN
            # INCONCLUSIVE. A signer / scope misconfiguration therefore surfaces loudly on every provider it
            # breaks and can never be laundered into a clean tenant verdict.
            res = CloudLivePostureResult(provider=provider, account=account)
            detail = f"{type(exc).__name__}: {exc}"
            res.notes.append(
                "multicloud: the per-provider live posture run RAISED (isolated — nothing captured, NOT a "
                "clean negative): " + detail)
            notes.append(f"provider {provider or '(unknown)'} [session #{index}] raised (isolated): {detail}")
        key = _provider_key(res, index, results)
        results[key] = res
    return MultiCloudPostureResult(results=results, notes=notes)


def render_multicloud_posture_report(
    multi_result: MultiCloudPostureResult,
    *,
    target: "str | None" = None,
    executive: bool = False,
) -> str:
    """Render ONE consolidated Markdown report across every assessed provider.

    A top-line aggregate summary (providers assessed, total confirmed FACTs, per-provider FACT counts, and —
    surfaced DISTINCTLY — any refused / inconclusive providers and the combined verdict) is followed by each
    provider's section, rendered by the EXISTING single-provider :func:`render_cloud_posture_report` (REUSED,
    not reinvented) so every PROVEN FACT keeps its re-runnable ``sha256:`` certificate reference. The executive
    variant additionally surfaces the aggregate (total oracle-confirmed fact(s) across the providers) and
    renders each section in its executive form.

    EMPTY-SAFE: a provider that refused or minted nothing renders through the single-provider renderer WITHOUT
    a PROVEN FACT line (a refusal is never dressed up as a finding), and the aggregate header never prints the
    literal ``PROVEN FACT`` marker — so an all-refused multi-run contains no PROVEN FACT and a never-CLEAN
    aggregate. FATAL-2: no ``framework`` import here; the reused renderer owns its framework touch
    function-locally."""
    assessed = multi_result.providers_assessed
    by_provider = multi_result.facts_by_provider()
    refused = multi_result.providers_refused
    inconclusive = multi_result.providers_inconclusive
    with_facts = multi_result.providers_with_facts
    verdict = multi_result.family_verdict()
    hdr_target = target or "multi-cloud"

    lines: "list[str]" = [f"# Unified Cloud Posture Report — `{hdr_target}`", ""]
    lines.append(
        f"**Providers assessed:** {len(assessed)}"
        + (f" ({', '.join(assessed)})" if assessed else "")
    )
    # NB: the literal string "PROVEN FACT" is deliberately NOT used in this aggregate header — it would make an
    # all-refused (zero-FACT) report contain the marker and read as if it held a proven finding. The per-FACT
    # "PROVEN FACT" marker comes ONLY from the per-provider sections below, for providers that truly have FACTs.
    lines.append(f"**Total confirmed FACTs:** {multi_result.total_facts}")
    if by_provider:
        lines.append(
            "**Confirmed FACTs per provider:** "
            + ", ".join(f"{k}={v}" for k, v in by_provider.items())
        )
    # Refused / inconclusive providers are surfaced DISTINCTLY so an empty provider is never read as clean.
    if refused:
        lines.append(
            "**Providers refused (out of scope / gated — nothing adjudicated):** "
            f"{len(refused)} ({', '.join(refused)})"
        )
    if inconclusive:
        lines.append(
            "**Providers inconclusive (assessed, no confirmed FACT — NOT clean):** "
            f"{len(inconclusive)} ({', '.join(inconclusive)})"
        )
    lines.append(f"**Combined verdict:** {verdict}")
    lines += [
        "",
        ("> A provider with no confirmed FACT is INCONCLUSIVE, never CLEAN: a scoped live capture cannot prove "
         "absence. A refused or inconclusive provider is surfaced above and is NOT a clean bill of health."),
        "",
    ]
    if executive:
        # Executive surface of the AGGREGATE: the confirmed-fact total across the assessed providers.
        lines += [
            (f"**{multi_result.total_facts}** oracle-confirmed fact(s) across "
             f"{len(with_facts)} of {len(assessed)} provider(s) assessed."),
            "",
        ]

    # Per-provider sections — rendered by the EXISTING single-provider renderer (reused, empty-safe).
    for key, res in multi_result.results.items():
        section_target = f"{res.provider or key}:{res.account}" if res.account else (res.provider or key)
        lines += [
            "---",
            "",
            f"## {key} — `{section_target}`",
            "",
            render_cloud_posture_report(res, target=section_target, executive=executive),
            "",
        ]

    # Orchestration notes (e.g. an isolated per-provider error) are surfaced, never hidden.
    if multi_result.notes:
        lines += ["---", "", "### Orchestration notes", ""]
        lines += [f"- {n}" for n in multi_result.notes]
        lines.append("")

    return "\n".join(lines) + "\n"
