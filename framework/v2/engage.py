"""
framework.v2.engage — the authorized, gated, end-to-end engagement runner.

`scan` (Wave 1) is loopback-only because it issues traffic through a plain local
client. `engage` is its authorized-remote counterpart: it runs the SAME Wave-1
arsenal (crawl + point checks + request-level checks + self-learning bandit), but
every single request flows through the fail-closed safety stack in
`agents.http_executor.HttpExecutor` — authority/kill-switch -> scope -> destructive
-confirm -> per-engagement budget -> posture rate-limit -> egress allowlist. The
scanner's injected `send` IS the gated executor (`HttpExecutor.gated_fetch`), so
the docstring claim the campaign always made becomes literally true here.

Fail-closed by construction:
  * A tripped kill-switch or an out-of-scope seed is refused BEFORE any traffic
    (and every per-request gate still enforces it on every hop).
  * Confirmation stays with the oracle: each finding carries its serialized
    FindingContext (`oracle_context`) so it is independently re-verifiable
    (the Wave-3 `verify` re-verifier).
  * The opt-in operator-hosted OOB relay is used only after its host is checked
    against the charter scope; default stays loopback-only.

    python3 -m framework.v2 engage <slug> <https://authorized-target/seed>
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .agents.http_executor import HttpExecutor, PromptCallback, parse_posture, stdin_prompt_with_timeout
from .agents.scope_gate import validate_action
from .authority.killswitch import KillSwitch
from .scanner.campaign import ScanReport, WebScanCampaign
from .scanner.orchestrator import AttackPath, AutonomousCampaign, ChainedConclusion
from .worldmodel.graph import WorldModel

if TYPE_CHECKING:  # intel types are only referenced in annotations on the default path
    from .intel.predict import AssetHypothesis
    from .intel.resolve import Entity
    from .scanner.access_control import AccessControlConfig


class EngagementRefused(RuntimeError):
    """The engagement could not start: kill-switch tripped, seed out of scope, or
    a relay host not on the charter allowlist."""


@dataclass
class EngagementResult:
    """The full outcome of an engagement: the oracle-confirmed scan report AND the
    forward reasoning over it. The scan is the hands; ``attack_paths`` are what the
    confirmed facts unlock — the multi-hop routes from the attacker to a crown-jewel
    node, each hop tagged with the technique that established it. Chaining is pure
    reasoning over the report (it sends no traffic), and is best-effort: a chaining
    failure never sinks the engagement, so ``attack_paths`` may be empty while the
    report still stands."""

    report: ScanReport
    attack_paths: list[AttackPath] = field(default_factory=list)
    path_portfolio: list[AttackPath] = field(default_factory=list)
    chained_conclusions: list[ChainedConclusion] = field(default_factory=list)
    # Intelligence Engine (opt-in ``enable_recon``): the resolved asset inventory this
    # engagement observed/discovered, and the GATED prediction queue (where-to-look-next
    # hypotheses — never facts, never auto-scanned). ``world`` is the shared graph the
    # intel recon and the finding-chaining both project onto.
    entities: list["Entity"] = field(default_factory=list)
    predictions: list["AssetHypothesis"] = field(default_factory=list)
    world: WorldModel | None = None
    # Per-finding scientific confidence, INDEX-ALIGNED with report.active_findings (a
    # None entry means that finding could not be assessed). Each is a hypothesis assessed
    # against its benign alternatives (posterior + credible interval + most-decisive next
    # test). Pure reasoning over the oracle's own verdicts — the oracle stays authoritative.
    finding_confidence: list = field(default_factory=list)
    # Per-finding VERACITY verdict from the anti-hallucination firewall, INDEX-ALIGNED with
    # report.active_findings. Each is an `AdmittedClaim`: the firewall re-fires the
    # finding's own retained oracle_context (never trusting the recorded verdict) and labels
    # the result GROUNDED (fact) / UNGROUNDED / CONTRADICTED. A shipped "active" finding
    # whose proof no longer reproduces surfaces here as not-a-fact — the firewall running
    # live over real output, not just its tests. Best-effort; the layer only ever demotes.
    grounding: list = field(default_factory=list)
    # DEFENSIVE / purple-team deliverable (opt-in ``enable_defender``, default None → the
    # engagement is byte-identical). A `defender.DefenseReport`: for each confirmed action, whether
    # the operator's detection ruleset catches it (+ a synthesized candidate Sigma rule for each
    # miss), the detection-EFFICACY of an operator Sigma ruleset over what the scan DID (mapped to
    # ATT&CK), and Sigma evaluated over any operator-supplied OFFLINE logs. Derived purely from the
    # oracle-confirmed findings (prove-don't-guess); it NEVER changes the scan or an oracle verdict.
    defense: object = None
    # OPT-IN sensor fusion (``--fuse-sensors``, default OFF → these stay 0 and the engagement is
    # byte-identical). Counts of the offline sensor LEADS folded into ``world`` and the promotions the
    # deterministic oracles confirmed from the sensors' OWN retained evidence (k8s-posture / policy-path
    # / gated reachability). The world-model carries them; under ``--spine`` the leads also reach the
    # report (graded as leads). Fusion NEVER changes report.active_findings or any oracle verdict.
    fused_leads: int = 0
    fused_facts: int = 0


def _no_send(request: object) -> dict:  # pragma: no cover - chaining never sends
    """A send that must never be called: chaining is pure reasoning over an already
    -collected report. If the reasoning ever tries to issue traffic, fail loudly
    rather than silently sending ungated requests."""
    raise RuntimeError("chaining must not issue traffic")


def _origin(url: str) -> str:
    p = urlsplit(url)
    if not p.scheme or not p.netloc:
        raise EngagementRefused(f"seed url must be absolute (scheme://host/...), got {url!r}")
    return f"{p.scheme}://{p.netloc}/"


def preflight(slug: str, seed_url: str) -> None:
    """Fail closed BEFORE any traffic: refuse a tripped kill-switch or an
    out-of-scope seed with a legible reason. The per-request gates still enforce
    this on every hop; this is an early, honest refusal."""
    ks = KillSwitch(slug)
    if ks.is_tripped():
        raise EngagementRefused(f"kill-switch tripped: {ks.reason()}")
    posture = parse_posture(slug)
    decision = validate_action(slug=slug, method="GET", target_url=seed_url, posture=posture)
    if not decision.allowed:
        raise EngagementRefused(
            f"seed out of scope ({decision.refusal_kind}): {decision.reason}")


def _intel_recon(world: WorldModel, slug: str, seed_url: str, *,
                 fixtures_dir: str | None, max_depth: int) -> object:
    """Best-effort intel recon bound to the run's SHARED world-model. Returns the
    `IntelIngest` (bound to ``world``) so the caller can finalize + read the seq
    high-water mark. Pre-scan collector discovery runs only when an offline fixtures
    dir is supplied, in the ReconPlanner's value-of-information order. Collectors query
    THIRD-PARTY sources (never the target), and nothing predicted is ever projected."""
    from .intel.collectors import DEFAULT_COLLECTORS
    from .intel.from_scan import host_ref
    from .intel.ingest import IntelIngest
    from .intel.planner import ReconPlanner
    from .intel.transport import FixtureTransport

    ingest = IntelIngest(world, engagement_slug=slug)
    host = urlsplit(seed_url).hostname or ""
    if fixtures_dir and host:
        try:
            from .intel.ingest import RECON_MAX_WORKERS
            ingest.run_collectors(
                [host_ref(host)], list(DEFAULT_COLLECTORS), FixtureTransport(fixtures_dir),
                seq=0, max_depth=max_depth, planner=ReconPlanner(list(DEFAULT_COLLECTORS)),
                max_workers=RECON_MAX_WORKERS)
        except Exception:
            # a partial recon failure keeps whatever already projected AND the ingest
            # handle — never discard it (discarding it would collapse the seq base and
            # invert the shared clock when findings project next).
            pass
    return ingest


def _intel_finalize(ingest: object, report: ScanReport) -> tuple[list, list]:
    """Post-scan: register the target + fingerprinted stack the scan observed, resolve
    the asset inventory, and produce the GATED prediction queue. Predictions are never
    projected onto the world-model and never auto-scanned — a where-to-look-next queue."""
    from .intel.from_scan import observations_from_report
    from .intel.predict import AssetPredictor
    from .worldmodel.models import NodeKind

    from .intel.infer import derive_and_project

    ingest.ingest(observations_from_report(report, seq=ingest.high_water() + 1))  # type: ignore[attr-defined]
    # DERIVE over the accreted asset graph (transitive ownership, co-hosting, shared
    # registrant) before resolving — inference enriches the graph it reasons over.
    derive_and_project(ingest.world, seq=ingest.high_water() + 1)                   # type: ignore[attr-defined]
    entities = ingest.resolve(seq=ingest.high_water()).entities                    # type: ignore[attr-defined]
    domains = sorted({m.key for e in entities for m in e.members if m.kind is NodeKind.DOMAIN})
    predictions = AssetPredictor().predict(observed_domains=domains) if domains else []
    return entities, predictions


def _assess_findings(report: ScanReport) -> list:
    """Score each confirmed finding as a scientific hypothesis (posterior + competing
    benign explanation + most-decisive next test). Pure reasoning over the oracle's
    verdicts; best-effort."""
    from .confidence.decision import assess_finding

    reports = []
    for f in report.active_findings:
        try:
            reports.append(assess_finding(f))
        except Exception:
            reports.append(None)   # keep index-aligned with active_findings
    return reports


def _assess_grounding(report: ScanReport, world: "WorldModel") -> list:
    """Run each active finding through the veracity firewall against the chained world —
    the anti-hallucination layer applied to LIVE output. The firewall re-fires the
    finding's OWN retained oracle_context (never trusting the recorded verdict): a finding
    that still re-confirms is labelled a fact; one that no longer reproduces (altered
    evidence, a dry-run stub) is demoted to UNGROUNDED even though the scan marked it
    active; one whose surface the graph net-refutes is CONTRADICTED. Index-aligned with
    report.active_findings; a None entry means that finding could not be assessed. Pure,
    read-only, best-effort — the layer only ever demotes, never promotes."""
    from .veracity import admit_finding

    verdicts = []
    for f in report.active_findings:
        try:
            verdicts.append(admit_finding(f, world))
        except Exception:
            verdicts.append(None)   # keep index-aligned with active_findings
    return verdicts


def _ingest_defender_logs(slug: str, log_path: str, log_format: str | None, sink) -> list:
    """Read an operator-supplied OFFLINE log/alert file through the gated ``log_source`` sensor
    (Tier-1, kill-switch-only) and return the normalized ``LogEvent``s. UNTRUSTED input: the parser
    is bounded and total, and the read runs through ``invoke_tool``'s fail-closed chain so a tripped
    kill-switch REFUSES it (recorded on the spine). A missing/oversized/unreadable file degrades to
    ``[]`` — a clean skip, never a crash. Best-effort throughout."""
    try:
        from .agents.tools import ToolContext, ToolRegistry
        from .agents.tools.invoker import invoke_tool
        from .defender.logsource import LogEvent, LogSourceSensor

        registry = ToolRegistry()
        registry.register(LogSourceSensor())
        result = invoke_tool(registry, "log_source",
                             {"log": log_path, "format": log_format or "auto"},
                             ToolContext(slug=slug), sink=sink)
        if not result.ok or result.refused:
            return []
        events: list = []
        for e in (result.output or {}).get("events", []) or []:
            try:
                events.append(LogEvent(channel=str(e.get("channel", "")),
                                       fields=dict(e.get("fields") or {}),
                                       source_format=str(e.get("source_format", "")),
                                       raw=str(e.get("raw", ""))))
            except Exception:
                continue
        return events
    except Exception:
        return []


def _run_defender_pass(report, *, ruleset_path, sigma_dir, log_path, log_format, slug, sink):
    """Build the DEFENSIVE purple-team ``DefenseReport`` (opt-in). READ-ONLY over the authoritative
    scan: it reasons over the oracle-confirmed findings (prove-don't-guess), sends no traffic, and
    NEVER changes a finding or an oracle verdict. It (1) runs each confirmed action through the
    operator's detection ruleset and synthesizes a candidate Sigma rule for each MISS, (2) evaluates
    an operator Sigma ruleset (``--defender-sigma``) over what the scan DID → a detection-efficacy
    signal mapped to ATT&CK, and (3) evaluates that ruleset over any operator-supplied OFFLINE logs
    (``--defender-log``, kill-switch-gated). Best-effort; returns a DefenseReport or None."""
    try:
        from .defender.efficacy import build_defense_report
        from .defender.rules import DetectionRuleset
        from .defender.sigma import load_sigma_dir

        ruleset = None
        if ruleset_path:
            try:
                ruleset = DetectionRuleset.from_file(ruleset_path)
            except Exception:
                ruleset = None   # a bad ruleset file falls back to the DEL default — never a crash

        sigma_rules = load_sigma_dir(sigma_dir) if sigma_dir else []
        ingested = _ingest_defender_logs(slug, log_path, log_format, sink) if log_path else []

        return build_defense_report(
            report, ruleset=ruleset,
            sigma_rules=sigma_rules or None,
            ingested_events=ingested or None)
    except Exception:
        return None


def _mirror_defense(sink, defense) -> None:
    """Mirror the DefenseReport onto the event spine (existing observation/decision kinds).
    Best-effort — a spine write never perturbs the engagement."""
    try:
        sink.defender_report(defense)
    except Exception:
        pass


def _make_spine_sink(spine: object, slug: str):
    """Build a best-effort SpineSink over a caller-supplied Blackboard, or None. Never raises
    — spine emission is opt-in and must never perturb the engagement."""
    if spine is None:
        return None
    try:
        from .agents.spine_sink import SpineSink
        return SpineSink(spine, slug)  # type: ignore[arg-type]
    except Exception:
        return None


def _spine_finding_payload(f, admitted) -> dict:
    """A FindingPayload-shaped mirror of an AuditFinding, tagged with its LIVE grounding
    verdict (P3). Oracle authority preserved: ``critique_status='confirmed'`` /
    ``verified_by_oracle=True`` ONLY when the finding re-grounds as a fact under live
    re-execution. When the grounding verdict is unavailable (``admitted is None`` — the pass
    was skipped or could not assess) or the finding was demoted, it mirrors conservatively as
    ``llm_advisory`` / not-verified — never asserting confirmation from the mere PRESENCE of a
    certificate (that would launder an un-re-verified finding onto the immutable stream). The
    ``oracle_context`` is retained so downstream can re-verify. This matches the honest
    ``scanner.report._grounding_label`` (``admitted is None → not fact``). Severity is a coarse
    mirror — the authoritative severity is rendered by scanner.report."""
    is_fact = bool(getattr(admitted, "is_fact", False))
    return {
        "finding_slug": (f"{f.bug_class}:{f.insertion_point}"[:120]) or f.bug_class,
        "title": f"{f.bug_class} confirmed at {f.param}",
        "severity": "High",
        "bug_class": f.bug_class,
        "surface": f.insertion_point,
        "summary": f.rationale or f"{f.bug_class} at {f.param}",
        "critique_status": "confirmed" if is_fact else "llm_advisory",
        "oracle_context": f.oracle_context,
        "verified_by_oracle": is_fact,
        "confidence": f.confidence,
        "oracle_kind": f.confirmed_by,
        "oracle_rationale": f.rationale,
    }


def _passive_finding_payload(pf) -> dict:
    """A FindingPayload-shaped mirror of a scanner PASSIVE finding, graded as a LEAD.

    A passive finding is a deterministic hygiene OBSERVATION (a missing header, a cookie flag) —
    real, but NOT an oracle-confirmed attacker capability. So it carries NO ``oracle_context`` and
    ``verified_by_oracle=False``, and the report grader renders it a LEAD, never a fact. This is
    how the unified report composes the passive producer WITHOUT diluting prove-don't-guess.
    ``critique_status='llm_advisory'`` is the reportable-but-lead bucket. Pure; no wallclock."""
    sev = str(getattr(pf, "severity", "") or "").strip().title()
    if sev not in ("Critical", "High", "Medium", "Low", "Info"):
        sev = "Info"
    check = str(getattr(pf, "check_id", "") or "passive")
    url = str(getattr(pf, "url", "") or "")
    title = str(getattr(pf, "title", "") or check)
    return {
        "finding_slug": (f"passive:{check}"[:120]) or check,
        "title": title,
        "severity": sev,
        "bug_class": check,
        "surface": url or "(response)",
        "summary": str(getattr(pf, "evidence", "") or title),
        "critique_status": "llm_advisory",
        "critique_dryrun": False,
        "oracle_context": None,
        "verified_by_oracle": False,
        "confidence": None,
        "oracle_kind": None,
        "oracle_rationale": "",
    }


def _distinct_confirming_kinds(f) -> int:
    """How many DISTINCT oracle kinds independently confirmed this finding — the reward-bus
    corroboration signal (the non-circular bar for an autonomous EXPLOITABLE label is >= 2
    distinct kinds). A scanner finding confirmed by a single oracle is ONE kind — honest: not
    cross-corroborated. Counts a retained corroboration set when the finding carries one."""
    for attr in ("corroborating_kinds", "confirmed_by_kinds", "confirmations"):
        kinds = getattr(f, attr, None)
        if kinds:
            try:
                return max(1, len({str(k) for k in kinds}))
            except Exception:
                return 1
    return 1 if getattr(f, "confirmed_by", None) else 0


def _scanner_verification_claim(f) -> dict:
    """The finding AS THE SCAN CONCLUDED IT — asserting the scan's OWN oracle-verification claim
    (a retained certificate = ``oracle_context``). This is what ``epistemic_refusal`` must be fed,
    NOT the post-grounding mirror from ``_spine_finding_payload``: that mirror's
    ``verified_by_oracle`` is the ALREADY-demoted live verdict, so feeding it would make the
    refusal a no-op on exactly the findings it must catch (the ones that fail to re-ground).

    Carries NO ``param`` on purpose: the refusal turns on the oracle RE-EXECUTION (does the
    retained certificate still re-fire?), not world-membership. Naming an entity would make
    ``admit``'s ``require_entities`` demote a perfectly good finding whose endpoint node the
    chainer never modelled — a false refusal. So we ground the refusal purely on re-execution."""
    return {
        "bug_class": getattr(f, "bug_class", ""),
        "verified_by_oracle": bool(getattr(f, "oracle_context", None)),
        "oracle_context": getattr(f, "oracle_context", None),
        "confidence": getattr(f, "confidence", None),
        "confirmed_by": getattr(f, "confirmed_by", None),
        "insertion_point": getattr(f, "insertion_point", ""),
    }


def _advise_critics(sink, finding: dict, finding_event_id: int | None) -> None:
    """Run the deterministic multi-critic panel over one mirrored finding and record each
    verdict + the aggregate quorum on the spine. ADVISORY ONLY: a critic can endorse / object /
    abstain — NEVER confirm (only a fired oracle confirms; agents.critics enforces this at the
    type level). No LLM, no egress — safe on every finding."""
    if finding_event_id is None:
        return
    from .agents.critics import aggregate_panel, run_panel
    verdicts = run_panel(finding)
    for v in verdicts:
        sink.critic_verdict(v.critic, finding_event_id, v.verdict,
                            severity=v.severity, rationale=v.rationale)
    panel = aggregate_panel(verdicts)
    sink.decision(f"critic panel: {finding.get('bug_class', '?')}", panel.verdict,
                  rationale=f"{panel.rationale} (agreement={panel.agreement}, entropy={panel.entropy})")


def _run_reasoning_pass(sink, spine, slug, report, result, world) -> None:
    """W1.1 — the nervous system, ADVISORY-ONLY, over the authoritative findings.

    Runs ONLY when the event spine is attached (opt-in telemetry). It NEVER alters
    ``report.active_findings`` nor any oracle verdict — it mirrors each finding, then re-grounds
    (critic panel), refuses-to-conclude (cognitive refusal), and credits the outcome (reward
    bus), recording each on the immutable stream. Because ``make gate`` runs WITHOUT a spine,
    this path never executes during the eval gate, so the gate stays byte-identical. Best-effort
    throughout — a reasoning failure never sinks the engagement."""
    try:
        from .agents.cognitive_refusal import emit_refusal, epistemic_refusal
        from .agents.reflection import reflect
        from .calibration.reward_bus import credit_outcome

        grounding = result.grounding or []
        for i, f in enumerate(report.active_findings):
            g = grounding[i] if i < len(grounding) else None
            finding = _spine_finding_payload(f, g)
            fe = sink.finding_event(finding)

            # (1) multi-critic panel — re-ground / provenance / calibration lenses, advisory.
            _advise_critics(sink, finding, fe)

            # (2) cognitive refusal — feed the finding AS THE SCAN CONCLUDED IT (its retained
            # certificate), so the primitive independently RE-EXECUTES that certificate and
            # refuses to conclude when it no longer re-fires. Feeding the post-grounding mirror
            # would make this inert (its verified_by_oracle is the already-demoted verdict).
            emit_refusal(sink, epistemic_refusal(_scanner_verification_claim(f), world=world))

            # (3) reward-bus fan-out — the NON-CIRCULAR outcome label + reward on the unified
            # stream (replaces the flat 1.0). oracle_fired iff the finding re-grounds as a fact;
            # spine-only (no persistent learner mutation here) keeps behaviour default-safe.
            credit_outcome(
                oracle_fired=bool(finding.get("verified_by_oracle")),
                distinct_confirming_kinds=_distinct_confirming_kinds(f),
                seq=fe or 0, spine_sink=sink, target_event_id=fe,
                arm=str(f.bug_class), bug_class=str(f.bug_class))

        # (3b) PRODUCER UNIFICATION — the scanner's PASSIVE findings also reach the unified
        # report, as LEADS. Honest grading: a passive hygiene observation is not an
        # oracle-confirmed attacker capability, so its finding event carries no oracle_context and
        # the report grader renders it a lead, never a fact (the active-finding events above are
        # unchanged). Spine-only (this whole pass runs only with a spine) → gate byte-identical.
        for pf in getattr(report, "passive_findings", None) or []:
            sink.finding_event(_passive_finding_payload(pf))

        # (4) reflection — dead-thread / stall re-orientation over the spine's own state. A
        # graceful no-op on the pure-scanner spine (no hypothesis/action events yet); it lights
        # up automatically as richer producers land on the stream in later waves.
        for r in reflect(spine, slug):
            sink.reflection(r.get("trigger", "reflection"), r.get("observations", []),
                            reorientation=r.get("reorientation", ""),
                            rationale=r.get("rationale", ""))

        sink.decision(
            "engagement summary",
            f"{len(report.active_findings)} finding(s), {len(result.attack_paths)} attack path(s)",
            rationale=f"target={report.target}")
    except Exception:
        pass


def _run_fusion(world: "WorldModel", slug: str, *, seq_base: int, sink) -> tuple[int, int]:
    """Opt-in (``--fuse-sensors``) sensor fusion over the run world-model. Folds the operator's declared
    OFFLINE sensor LEADS (``targets/<slug>/fusion.json``: declared_service / sbom_vuln / kube_bench /
    cloud_import) into ``world`` through the GATED pipeline, and lets the deterministic promotion oracles
    re-fire over each sensor's OWN retained evidence (version-range / k8s-posture / policy-path, plus the
    opt-in GATED reachability handshake). Returns ``(leads_folded, facts_promoted)``.

    Additive + default-OFF: nothing calls this unless ``--fuse-sensors`` is set, so the default engage
    path (and ``make gate``, which never sets it) is byte-identical. Best-effort — a fusion failure
    never sinks the engagement. Under ``--spine`` the folded LEADS also reach the report (graded as
    leads, never facts). The promotions are oracle-grounded FACTS in ``world`` (``oracle:`` provenance)."""
    try:
        from .engage_fusion import fuse_sensors
    except Exception:
        return (0, 0)
    from types import SimpleNamespace

    def _oracle_nodes() -> set:
        try:
            return {n.id for n in world.all_nodes() if str(getattr(n, "provenance", "")).startswith("oracle:")}
        except Exception:
            return set()

    before = _oracle_nodes()
    # ctx carries the fusion clock base (so fusion's seq continues after the run) + the spine sink; it
    # carries NO explicit plan, so fuse_sensors resolves the operator's targets/<slug>/fusion.json.
    ctx = SimpleNamespace(base_seq=seq_base, sink=sink)
    try:
        minted = fuse_sensors(world, slug, ctx)
    except Exception:
        return (0, 0)
    facts = len(_oracle_nodes() - before)
    # Under --spine, mirror the folded LEADS onto the unified report (graded as leads, never facts).
    if sink is not None and minted:
        try:
            from .engage_autonomous import _emit_fused_leads
            _emit_fused_leads(sink, minted, set())
        except Exception:
            pass
    return (len(minted), facts)


def run_engagement(
    slug: str,
    seed_url: str,
    *,
    request_budget: int = 200,
    max_pages: int = 100,
    max_audit_requests: int = 0,
    bandit_path: str | None = None,
    enable_domxss: bool = False,
    enable_oob: bool = True,
    enable_browser_xss: bool = False,
    enable_spa_crawl: bool = False,
    oob_advertise_base_url: str | None = None,
    oob_relay_url: str | None = None,
    oob_relay_secret: str | None = None,
    enable_chaining: bool = True,
    enable_recon: bool = False,
    recon_fixtures: str | None = None,
    recon_depth: int = 2,
    detection_budget: float = 2.0,
    waf_adaptive: bool = False,
    grammar_fuzz: int = 0,
    enable_arsenal: bool = False,
    arsenal_race_targets: "tuple[tuple[str, int], ...]" = (),
    enable_sso: bool = False,
    enable_graphql_dos: bool = False,
    use_library: bool = False,
    enable_access_control: bool = False,
    access_control_config: "AccessControlConfig | None" = None,
    access_control_victim_headers: "tuple[str, ...]" = (),
    access_control_refs: "tuple[str, ...]" = (),
    priors: object = None,
    transfer_archetype: str | None = None,
    prompt_callback: PromptCallback | None = None,
    spine: object = None,
    enable_defender: bool = False,
    defender_ruleset: str | None = None,
    defender_sigma_dir: str | None = None,
    defender_log: str | None = None,
    defender_log_format: str | None = None,
    fuse_sensors: bool = False,
) -> EngagementResult:
    """Run one authorized engagement end to end and return an
    :class:`EngagementResult` — the oracle-confirmed :class:`ScanReport` plus the
    forward reasoning over it (the attack paths the confirmed facts unlock). Every
    request passes the full gate chain; raises EngagementRefused if the engagement
    may not start.

    With ``enable_chaining`` (default) the confirmed findings are written into a
    world-model and the technique operators are run to a fixpoint to extract
    attacker→crown-jewel attack paths. Chaining sends NO traffic and is best-effort:
    if it fails, the engagement still returns its report with empty paths."""
    # Opt-in event-spine sink (default None → byte-identical behaviour). When present, every
    # gate refusal is recorded as evidence on the spine before it propagates.
    sink = _make_spine_sink(spine, slug)

    try:
        preflight(slug, seed_url)
    except EngagementRefused as e:
        if sink is not None:
            sink.refusal("preflight", seed_url, reason=str(e), fatal=True)
        raise

    # Any OOB callback base the target will contact — the advertise host or the
    # collaborator relay — must itself be on the charter allowlist.
    for label, relay in (("advertise", oob_advertise_base_url), ("relay", oob_relay_url)):
        if relay is None:
            continue
        posture = parse_posture(slug)
        d = validate_action(slug=slug, method="GET", target_url=relay, posture=posture)
        if not d.allowed:
            if sink is not None:
                sink.refusal("scope", f"OOB {label} host {relay}",
                             reason=f"{d.refusal_kind}: {d.reason}", fatal=True)
            raise EngagementRefused(
                f"OOB {label} host not on charter allowlist ({d.refusal_kind}): {d.reason}")

    # The dynamic browser passes navigate DIRECTLY (not via the gated executor),
    # so on a remote target the browser is confined at the resolver layer to the
    # in-scope host — it cannot pull the browser off to third-party hosts.
    browser_allowed_hosts = {urlsplit(seed_url).hostname} if (enable_browser_xss or enable_spa_crawl) else None
    browser_allowed_hosts = {h for h in (browser_allowed_hosts or set()) if h}

    # The single run-owned world-model: intel recon projects assets onto it, and finding
    # chaining accretes attack facts onto the SAME graph (disjoint id namespaces). Built
    # even when recon is off, so chaining shares it and the result exposes it.
    world = WorldModel()
    ingest = None
    if enable_recon:
        try:
            ingest = _intel_recon(world, slug, seed_url,
                                  fixtures_dir=recon_fixtures, max_depth=recon_depth)
        except Exception:
            ingest = None   # recon is value-add; a recon failure never sinks the engagement

    # W1.3 cross-engagement TRANSFER (opt-in): when an archetype is named and no explicit
    # priors were supplied, warm-start this run's check-ordering bandit from SMOOTHED priors
    # for that archetype — blended from lexically SIMILAR past archetypes and evidence-gated
    # (memory.priors.smoothed_priors_for). Best-effort; default (no archetype) leaves
    # priors=None so behaviour — and `make gate`, which never names an archetype — is
    # byte-identical. The bandit only ORDERS effort, so transfer never gates a surface.
    if priors is None and transfer_archetype:
        try:
            from .common import paths as _paths
            _db = _paths.memory_db()
            # Read-only: only consult an EXISTING memory store — never create one just
            # because transfer was requested on a system with no engagement history yet.
            if _db.exists():
                from .memory import priors as _priors_mod
                from .memory.store import open_store
                _store = open_store(_db)
                try:
                    transferred = _priors_mod.smoothed_priors_for(_store, transfer_archetype)
                finally:
                    _store.close()
                priors = transferred or None
        except Exception:
            priors = None   # transfer is value-add; never sink the engagement on it

    # Opt-in advanced arsenal (default OFF → byte-identical). Its RAW-SOCKET modules
    # (smuggling/CSWSH/race) speak bytes on the wire directly, so they cannot ride the
    # gated executor's `send`. Gate them fail-closed with the SAME chain the executor
    # uses — kill-switch + charter/scope/posture — evaluated per host with NO traffic.
    # A tripped kill-switch or an out-of-scope host means no probe leaves the box.
    arsenal_authz = None
    if enable_arsenal:
        _posture = parse_posture(slug)
        _killswitch = KillSwitch(slug)

        def arsenal_authz(url: str) -> bool:
            if _killswitch.is_tripped():
                return False
            return validate_action(
                slug=slug, method="GET", target_url=url, posture=_posture).allowed

    ex = HttpExecutor(
        engagement_slug=slug,
        base_url=_origin(seed_url),
        auto_load_authority=True,
        request_budget=request_budget,
        prompt_callback=prompt_callback or stdin_prompt_with_timeout,
    )
    # Opt-in access-control pack: an explicit config wins; otherwise build one from the CLI
    # refs/victim-headers, wrapping the GATED executor as the victim identity so the second
    # identity's requests still pass the full safety stack. No refs => None (documented no-op).
    ac_config = access_control_config
    if enable_access_control and ac_config is None and access_control_refs:
        from .scanner.access_control import config_from_cli
        ac_config = config_from_cli(
            ex.gated_fetch, access_control_victim_headers, access_control_refs)
    try:
        report = WebScanCampaign(
            ex.gated_fetch,
            max_pages=max_pages,
            max_audit_requests=max_audit_requests,
            enable_oob=enable_oob,
            enable_domxss=enable_domxss,
            enable_browser_xss=enable_browser_xss,
            enable_spa_crawl=enable_spa_crawl,
            browser_allowed_hosts=browser_allowed_hosts or None,
            bandit_path=bandit_path,
            bandit_context=slug,
            oob_advertise_base_url=oob_advertise_base_url,
            oob_relay_url=oob_relay_url,
            oob_relay_secret=oob_relay_secret,
            waf_adaptive=waf_adaptive,
            grammar_fuzz=grammar_fuzz,
            enable_arsenal=enable_arsenal,
            arsenal_authz=arsenal_authz,
            arsenal_race_targets=arsenal_race_targets,
            enable_sso=enable_sso,
            enable_graphql_dos=enable_graphql_dos,
            use_library=use_library,
            enable_access_control=enable_access_control,
            access_control_config=ac_config,
            priors=priors,
            progress=sink,   # opt-in: mirror scan phases/findings onto the spine (None → off)
        ).run(seed_url)
    finally:
        ex.close()

    # Post-scan intel: register the observed target + stack, resolve the asset
    # inventory, and produce the gated prediction queue. Best-effort.
    result = EngagementResult(report=report, world=world)
    if enable_recon and ingest is not None:
        try:
            result.entities, result.predictions = _intel_finalize(ingest, report)
        except Exception:
            pass
    # Scientific confidence per finding — pure reasoning over the oracle's verdicts,
    # never traffic; best-effort so it can never sink the engagement.
    try:
        result.finding_confidence = _assess_findings(report)
    except Exception:
        pass
    # Findings project ABOVE the intel recon band on the shared clock, so the monotonic
    # world-model time never inverts across the recon→scan handoff. Derived from the
    # SHARED WORLD itself (not the ingest handle), so it is correct even if recon
    # partially failed and left nodes behind — and is exactly 1 when recon is off (empty
    # world), reproducing the standalone behaviour.
    seq_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1

    # Forward reasoning over the confirmed facts (no traffic). Best-effort: the
    # scan result is authoritative and must survive any chaining error.
    if enable_chaining:
        try:
            from .worldmodel.impact import ImpactModel
            auto = AutonomousCampaign(
                _no_send, detection_budget=detection_budget,
                impact_model=ImpactModel.from_slug(slug),   # mission-aware path/portfolio value
            ).chain_findings(report, world=world, seq_base=seq_base)
            result.attack_paths = auto.attack_paths
            result.path_portfolio = auto.path_portfolio
            result.chained_conclusions = auto.chained_conclusions
        except Exception:
            # chaining is value-add; a reasoning failure never sinks the engagement
            pass
    # Veracity firewall over the live findings — re-execute each finding's own oracle
    # against the (now chained) world-model and label GROUNDED/UNGROUNDED/CONTRADICTED.
    # Runs AFTER chaining so the world holds the endpoint nodes the check consults.
    # Best-effort: the anti-hallucination pass can only demote, never sink the engagement.
    try:
        result.grounding = _assess_grounding(report, world)
    except Exception:
        pass
    # OPT-IN sensor fusion (``fuse_sensors``, default OFF → this whole block is skipped and the
    # engagement — and ``make gate`` — is byte-identical). Fold the operator's declared OFFLINE sensor
    # LEADS into the SHARED world-model and let the deterministic promotion oracles re-fire over each
    # sensor's OWN retained evidence. Runs AFTER chaining/grounding so it folds onto the final world;
    # the fusion clock continues after the run's high-water so time never inverts. Best-effort — a
    # fusion failure never sinks the engagement, and it NEVER changes a finding or an oracle verdict.
    if fuse_sensors:
        try:
            fusion_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1
            result.fused_leads, result.fused_facts = _run_fusion(
                world, slug, seq_base=fusion_base, sink=sink)
        except Exception:
            pass
    # DEFENSIVE / purple-team pass (opt-in ``enable_defender``, default OFF → this whole block is
    # skipped and the engagement is byte-identical). It reasons over the confirmed findings to tell
    # the blue team where their detection coverage has holes: candidate Sigma rules for the misses,
    # a detection-efficacy signal (would the operator's Sigma ruleset have caught what CRUCIBLE did?)
    # mapped to ATT&CK, and Sigma over any operator-supplied OFFLINE logs (kill-switch-gated read).
    # READ-ONLY over the authoritative scan — it changes no finding and no oracle verdict.
    if enable_defender:
        try:
            result.defense = _run_defender_pass(
                report, ruleset_path=defender_ruleset, sigma_dir=defender_sigma_dir,
                log_path=defender_log, log_format=defender_log_format, slug=slug, sink=sink)
            if sink is not None and result.defense is not None:
                _mirror_defense(sink, result.defense)
        except Exception:
            # the defensive pass is value-add; a failure never sinks the engagement
            pass
    # Mirror the authoritative findings onto the event spine AND run the reasoning pass over
    # them (W1.1: multi-critic panel + cognitive refusal + reward-bus credit + reflection) —
    # ADVISORY ONLY. This never alters report.active_findings nor the oracle verdict, and it
    # runs only when a spine is attached (so `make gate`, which uses no spine, is byte-identical).
    if sink is not None:
        _run_reasoning_pass(sink, spine, slug, report, result, world)
    return result


def _resolve_oob_relay_secret(args: argparse.Namespace) -> str | None:
    """Resolve the collaborator-relay poll secret WITHOUT leaking it on argv (X6). Preference:
    a file (--oob-relay-secret-file), then the CRUCIBLE_OOB_RELAY_SECRET env var, then the
    deprecated --oob-relay-secret argv flag (warned — it is visible in `ps` / shell history)."""
    path = getattr(args, "oob_relay_secret_file", None)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip() or None
        except OSError as e:
            print(f"warning: could not read --oob-relay-secret-file {path}: {e}")
    env = os.environ.get("CRUCIBLE_OOB_RELAY_SECRET")
    if env and env.strip():
        return env.strip()
    if getattr(args, "oob_relay_secret", None):
        print("warning: --oob-relay-secret is visible in `ps` / shell history; prefer "
              "CRUCIBLE_OOB_RELAY_SECRET or --oob-relay-secret-file")
        return args.oob_relay_secret
    return None


def _run_autonomous(args: argparse.Namespace, result: EngagementResult, spine: object) -> object:
    """Opt-in AUTONOMOUS OODA cycle over the authoritative engagement result. Additive and default-
    OFF (runs only under ``--autonomous``), so the default engage path never imports this module and
    stays byte-identical. Best-effort: the cycle is telemetry over the already-authoritative scan —
    a failure here never changes the report, the findings, or the exit status. Returns the
    ``engage_autonomous.AutonomyResult`` (or None on any error).

    The A/B/F seam: ``run_autonomous_cycle`` optionally calls ``engage_fusion.fuse_sensors`` (WS-B)
    and ``engage_reasoning.reason_step`` (WS-F), each with a graceful no-op fallback, so this works
    standalone today and composes automatically when those land."""
    try:
        from .engage_autonomous import render_summary, run_autonomous_cycle
    except Exception:
        return None
    try:
        out = run_autonomous_cycle(
            result, slug=args.slug,
            max_cycles=max(1, int(getattr(args, "autonomous_cycles", 1))),
            request_budget=max(1, int(getattr(args, "autonomous_budget", 8))),
            prompt_callback=prompt_callback_from_args(args),
            blackboard=spine,   # reuse the --spine blackboard as planning substrate + tool sink
            # LEARN — opt in (default OFF) to writing this run's confirm/refute outcomes to the
            # operator's targets/<slug>/outcomes.json, closing the learning loop the meta-monitor
            # reads next run. Explicit because it mutates the operator's target dir.
            persist_learning=bool(getattr(args, "learn", False)),
        )
        for line in render_summary(out):
            print(line)
        return out
    except Exception:
        # the autonomous cycle is value-add telemetry; a failure never sinks the engagement
        return None


def prompt_callback_from_args(args: argparse.Namespace) -> PromptCallback | None:
    """The operator-confirmation callback the autonomous cycle threads into destructive-confirm.
    None → the invoker's default-deny (a destructive tool is refused unless explicitly approved)."""
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 engage",
        description="Authorized, fully-gated end-to-end web engagement (the Wave-1 "
                    "arsenal through the charter/scope/kill-switch/egress stack).",
    )
    parser.add_argument("slug", help="Engagement slug (directs charter, scope, evidence, log).")
    parser.add_argument("seed_url", help="Absolute seed URL on an in-scope host.")
    parser.add_argument("--request-budget", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-audit-requests", type=int, default=0)
    parser.add_argument("--bandit-file", default=None,
                        help="Persist/warm-start the self-learning check-ordering bandit.")
    parser.add_argument("--domxss", action="store_true", help="Also emit static DOM-XSS leads.")
    parser.add_argument("--browser-xss", action="store_true",
                        help="Confirm DOM-XSS by real execution in a headless browser "
                             "(browser confined to the in-scope host at the resolver layer).")
    parser.add_argument("--spa", action="store_true",
                        help="Run the SPA crawler to capture fetch/XHR endpoints (browser confined to scope).")
    parser.add_argument("--oob-relay", default=None,
                        help="Operator-hosted, charter-allowlisted OOB callback base URL to ADVERTISE "
                             "(tunnel model; hits delivered to a loopback receiver).")
    parser.add_argument("--oob-relay-url", default=None,
                        help="Operator-hosted OOB COLLABORATOR relay base URL to poll "
                             "(run `collaborator serve`; unlocks blind confirmation on remote targets).")
    parser.add_argument("--oob-relay-secret", default=None,
                        help="Shared secret for the collaborator relay's poll endpoint. INSECURE "
                             "(visible in `ps`/shell history) — prefer CRUCIBLE_OOB_RELAY_SECRET "
                             "or --oob-relay-secret-file.")
    parser.add_argument("--oob-relay-secret-file", default=None,
                        help="Read the collaborator relay poll secret from this file (kept off "
                             "argv). Takes precedence over the env var and --oob-relay-secret.")
    parser.add_argument("--no-chaining", action="store_true",
                        help="Skip the forward reasoning pass (do not derive attack paths "
                             "from the confirmed findings). Chaining sends no traffic.")
    parser.add_argument("--waf-adaptive", action="store_true",
                        help="On a filtered/blocked probe, synthesize a bypassing form "
                             "(evasion ladder, then a small GA) that still fires the oracle. "
                             "Spends extra requests; confirmation stays oracle-gated.")
    parser.add_argument("--grammar-fuzz", type=int, default=0, metavar="N",
                        help="Induce a request grammar from the crawl and audit N extra "
                             "structurally-valid synthesized requests (in-scope, deduped).")
    parser.add_argument("--arsenal", action="store_true",
                        help="Run the advanced web arsenal after the audit: content/JS "
                             "discovery (leads via the gated executor), HTTP request-smuggling "
                             "detection, and Cross-Site WebSocket Hijacking. Raw-socket modules "
                             "are host-gated through the full authority/scope/kill-switch chain "
                             "(fail-closed); every finding stays oracle-confirmed. Off = "
                             "byte-identical. The destructive race engine is NOT auto-run.")
    parser.add_argument("--sso", action="store_true",
                        help="Also run the SSO/SAML/OIDC request checks (scanner.sso) against the "
                             "operator's OWN SP/RP: each fires only when a request actually carries an "
                             "SSO artifact (SAMLResponse/id_token/redirect_uri) and confirms via the "
                             "achieved-state oracle. Off by default (0 SSO requests); never the IdP.")
    parser.add_argument("--graphql-dos", action="store_true",
                        help="Also run the GraphQL DoS/abuse pass (scanner.graphql) against each "
                             "discovered /graphql endpoint: depth/alias/batching amplifications confirm "
                             "via the predicate oracle; cost / introspection-off signals are honest "
                             "leads. One bounded probe per check through the gated executor (it "
                             "demonstrates a missing guard, it does not flood). Off by default.")
    parser.add_argument("--library", action="store_true",
                        help="Fingerprint the target from the crawl and also run the declarative check "
                             "LIBRARY (scanner.library) whose applicability predicate matches the "
                             "detected stack. Oracle-anchored exactly like the built-ins; scoped so a "
                             "stack-specific payload never fires off-stack. Off by default.")
    parser.add_argument("--access-control", action="store_true",
                        help="Enable the two-identity access-control pack (scanner.access_control: "
                             "idor/bola/bfla/authorization/privilege_escalation/mass_assignment). It "
                             "needs OPERATOR input — a victim identity and object references — supplied "
                             "with --ac-ref (repeatable) and, for an authenticated victim, "
                             "--ac-victim-header. The victim identity rides the SAME gated executor. "
                             "Confirms via the achieved-state oracle (a 403 never fires); with no "
                             "--ac-ref it runs nothing (documented no-op). Off by default.")
    parser.add_argument("--ac-ref", action="append", default=None, metavar="BUGCLASS:PARAM:VICTIMREF",
                        help="An access-control cross-read target, e.g. 'idor:id:42'. Repeatable. "
                             "Requires --access-control. VICTIMREF may contain ':'.")
    parser.add_argument("--ac-victim-header", action="append", default=None, metavar="NAME: VALUE",
                        help="A header authenticating the VICTIM identity (the ground truth), e.g. "
                             "'Cookie: session=BOB'. Repeatable; replaces the same-named header on "
                             "the victim probe.")
    parser.add_argument("--recon", action="store_true",
                        help="Run the Intelligence Engine alongside the scan: resolve an "
                             "asset inventory into the shared world-model and produce a "
                             "GATED prediction queue. Sends no traffic to the target "
                             "(collectors query third-party sources; predictions are never "
                             "auto-scanned).")
    parser.add_argument("--transfer-archetype", default=None, metavar="NAME",
                        help="Cross-engagement transfer (opt-in): warm-start the check-ordering "
                             "bandit from smoothed priors for this archetype, blended from "
                             "lexically similar past archetypes. Off (default) = byte-identical.")
    parser.add_argument("--recon-fixtures", default=None, metavar="DIR",
                        help="Offline collector fixtures dir for --recon (DNS/CT/RDAP/ASN). "
                             "Without it, --recon still registers the scanned target + stack.")
    parser.add_argument("--spine", action="store_true",
                        help="Mirror the whole engagement onto the immutable blackboard event "
                             "spine (phases, findings with their live grounding verdict, "
                             "refusals). Opt-in, best-effort; off by default (zero impact).")
    parser.add_argument("--defender", action="store_true",
                        help="DEFENSIVE / purple-team pass (opt-in; off = byte-identical). Over the "
                             "confirmed findings: report detection GAPS in the operator's ruleset and "
                             "synthesize a candidate Sigma rule for each miss, score detection EFFICACY "
                             "of an operator Sigma ruleset over what the scan did (mapped to ATT&CK), "
                             "and evaluate that ruleset over operator-supplied OFFLINE logs. Read-only: "
                             "sends no traffic and never changes a finding or an oracle verdict.")
    parser.add_argument("--defender-ruleset", default=None, metavar="FILE",
                        help="JSON detection ruleset (DEL DetectionRule list) for the gap report. "
                             "Default: the DEL built-in baseline ruleset.")
    parser.add_argument("--defender-sigma", default=None, metavar="DIR",
                        help="Directory of Sigma rules (*.yml/*.yaml) to evaluate for the "
                             "detection-efficacy signal + ATT&CK mapping. Missing dir = clean skip.")
    parser.add_argument("--defender-log", default=None, metavar="FILE",
                        help="Operator-supplied OFFLINE log/alert file (syslog/CEF/EVTX-JSON) to "
                             "ingest and evaluate the Sigma ruleset against. UNTRUSTED input, read "
                             "through the kill-switch-gated log_source sensor; missing file = skip.")
    parser.add_argument("--defender-log-format", default="auto",
                        choices=["auto", "syslog", "cef", "evtx_json"],
                        help="Format of --defender-log (default: auto-detect).")
    parser.add_argument("--fuse-sensors", action="store_true",
                        help="Fold the operator's declared OFFLINE sensor LEADS "
                             "(targets/<slug>/fusion.json: declared_service/sbom_vuln/kube_bench/"
                             "cloud_import) into the run world-model, and let the deterministic "
                             "promotion oracles re-fire over each sensor's OWN retained evidence "
                             "(version-range / k8s-posture / policy-path; plus an OPT-IN, GATED live "
                             "reachability handshake for a declared_service task with "
                             "confirm_reachable). Each sensor is still gated at run time (kill-switch/"
                             "entitlement/scope/egress); a LEAD becomes a FACT only when an oracle "
                             "confirms it. Off by default (0 sensors) = byte-identical.")
    parser.add_argument("--autonomous", action="store_true",
                        help="AUTONOMOUS OODA cycle (opt-in; off = byte-identical). After the "
                             "authoritative scan, construct the Planner over the run world-model, "
                             "pick the next action (a leaf on the highest-value route to a crown "
                             "jewel), drive it as a GATED tool call (fail-closed: kill-switch/"
                             "entitlement/scope/destructive/egress), fold the observation back into "
                             "the world-model, and let the planner re-orient. Localhost/authorized "
                             "only; never mutates a finding or an oracle verdict.")
    parser.add_argument("--autonomous-cycles", type=int, default=1, metavar="N",
                        help="Bounded number of OODA cycles for --autonomous (default 1).")
    parser.add_argument("--autonomous-budget", type=int, default=8, metavar="N",
                        help="Request budget the autonomous planner is constructed with (default 8).")
    parser.add_argument("--learn", action="store_true",
                        help="LEARN (opt-in; requires --autonomous): write this run's confirm/refute "
                             "outcomes to targets/<slug>/outcomes.json, closing the learning loop the "
                             "meta-monitor reads next run. Off by default (it mutates the target dir). "
                             "Labels stay non-circular: a single-oracle reverify is DISPUTED, never a "
                             "fact.")
    args = parser.parse_args(argv)

    if args.access_control and not args.ac_ref:
        print("note: --access-control set but no --ac-ref supplied; the access-control pack "
              "needs operator victim references (bug_class:ref_param:victim_ref) and runs no "
              "checks without them.")

    spine = None
    if args.spine:
        try:
            from .agents.blackboard import open_blackboard
            spine = open_blackboard()
        except Exception:
            spine = None   # spine is opt-in telemetry; never block the engagement on it

    try:
        result = run_engagement(
            args.slug, args.seed_url,
            spine=spine,
            request_budget=args.request_budget,
            max_pages=args.max_pages,
            max_audit_requests=args.max_audit_requests,
            bandit_path=args.bandit_file,
            enable_domxss=args.domxss,
            enable_browser_xss=args.browser_xss,
            enable_spa_crawl=args.spa,
            oob_advertise_base_url=args.oob_relay,
            oob_relay_url=args.oob_relay_url,
            oob_relay_secret=_resolve_oob_relay_secret(args),
            enable_chaining=not args.no_chaining,
            enable_recon=args.recon,
            recon_fixtures=args.recon_fixtures,
            transfer_archetype=args.transfer_archetype,
            waf_adaptive=args.waf_adaptive,
            grammar_fuzz=args.grammar_fuzz,
            enable_arsenal=args.arsenal,
            enable_sso=args.sso,
            enable_graphql_dos=args.graphql_dos,
            use_library=args.library,
            enable_access_control=args.access_control,
            access_control_victim_headers=tuple(args.ac_victim_header or ()),
            access_control_refs=tuple(args.ac_ref or ()),
            enable_defender=args.defender,
            defender_ruleset=args.defender_ruleset,
            defender_sigma_dir=args.defender_sigma,
            defender_log=args.defender_log,
            defender_log_format=args.defender_log_format,
            fuse_sensors=args.fuse_sensors,
        )
    except EngagementRefused as e:
        print(f"engagement refused: {e}")
        return 2

    report = result.report
    print(f"engage {args.slug}  {report.target}")
    print(f"  pages crawled     : {report.pages_crawled}")
    print(f"  requests audited  : {report.requests_audited} ({report.audit_requests_sent} sent)")
    print(f"  confirmed findings: {len(report.active_findings)}")
    for i, f in enumerate(report.active_findings):
        cert = "cert" if f.oracle_context else "no-cert"
        line = f"    [{f.confirmed_by}/{cert}] {f.bug_class} @ {f.insertion_point} (conf {f.confidence:.2f})"
        # per-finding report, paired by INDEX (bug_class is not unique across findings)
        cr = result.finding_confidence[i] if i < len(result.finding_confidence) else None
        if cr is not None:
            line += f"  → posterior {cr.focal.posterior:.3f}" + (" ✓target" if cr.reaches_target else "")
        # veracity firewall verdict: flag any active finding whose own oracle did NOT
        # re-fire (a fact demoted to commentary) — the anti-hallucination catch made visible.
        gv = result.grounding[i] if i < len(result.grounding) else None
        if gv is not None and not gv.is_fact:
            line += f"  ⚠ {gv.render_as} ({gv.verdict.value}: {gv.reason})"
        print(line)
    if report.passive_findings:
        print(f"  passive findings  : {len(report.passive_findings)}")
    if report.dom_xss_candidates:
        print(f"  dom-xss leads     : {len(report.dom_xss_candidates)} (candidates)")
    if report.discovered_paths:
        print(f"  discovered paths  : {len(report.discovered_paths)} (arsenal leads)")
    if report.js_secrets:
        print(f"  js secrets        : {len(report.js_secrets)} (arsenal leads)")
    if report.arsenal_leads:
        print(f"  arsenal leads     : {len(report.arsenal_leads)}")
        for lead in report.arsenal_leads[:10]:
            print(f"    {lead}")
    # Forward reasoning: the multi-hop attack paths the confirmed facts unlock.
    if result.attack_paths:
        print(f"  attack paths      : {len(result.attack_paths)} (attacker -> crown jewel)")
        for ap in result.attack_paths[:5]:
            print(f"    [{ap.detection_cost:.2f} detect] {ap.describe()}")
    elif result.chained_conclusions:
        print(f"  chained facts     : {len(result.chained_conclusions)} derived (no full path to a crown jewel)")
    # Intelligence Engine: the asset inventory + the gated prediction queue.
    if result.entities:
        owned = [e for e in result.entities if e.owned_by]
        print(f"  intel entities    : {len(result.entities)} resolved"
              + (f", {len(owned)} owner-attributed" if owned else ""))
        for e in result.entities[:5]:
            own = f" owned_by={e.owned_by}" if e.owned_by else ""
            print(f"    [{e.confidence:.2f}] {e.canonical_id} ({len(e.members)} refs){own}")
    if result.predictions:
        print(f"  predictions       : {len(result.predictions)} GATED (never auto-scanned)")
        for p in result.predictions[:5]:
            print(f"    [prior {p.prior:.2f}] {p.node_id} ({p.pattern}) — awaiting operator approval")
    # DEFENSIVE / purple-team: detection gaps, candidate Sigma rules, and detection efficacy.
    defense = getattr(result, "defense", None)
    if defense is not None:
        uncovered = defense.uncovered
        print(f"  detection gaps    : {len(uncovered)}/{len(defense.gaps)} action(s) uncovered"
              f" ({len(defense.candidate_sigma)} candidate Sigma rule(s))")
        for g in uncovered[:5]:
            cand = g.candidate_rule.id if g.candidate_rule else "no candidate (generic telemetry)"
            print(f"    [gap] {g.label} → {cand}")
        if defense.efficacy is not None:
            eff = defense.efficacy
            print(f"  detection efficacy: {eff.detected_count}/{eff.total} caught "
                  f"(efficacy {eff.efficacy:.2f}); ATT&CK covered "
                  f"{eff.techniques_covered or 'none'}, missed {eff.techniques_missed or 'none'}")
        if defense.ingested is not None:
            print(f"  ingested logs     : {defense.ingested_events} event(s); "
                  f"{len(defense.ingested.matched_rule_ids)} Sigma rule(s) fired "
                  f"(ATT&CK {defense.ingested.techniques_detected or 'none'})")
    # Opt-in sensor fusion summary (default OFF → not printed; the engagement is byte-identical).
    if getattr(args, "fuse_sensors", False):
        print(f"  fused sensors     : {result.fused_leads} lead(s) folded, "
              f"{result.fused_facts} oracle-promoted fact(s) "
              f"(from targets/{args.slug}/fusion.json; leads stay leads, oracles prove facts)")
    # Opt-in AUTONOMOUS OODA cycle (default OFF → this whole block is skipped and the engagement is
    # byte-identical). It runs AFTER the authoritative scan/report is printed and never changes it.
    if getattr(args, "autonomous", False):
        _run_autonomous(args, result, spine)
    return 0
