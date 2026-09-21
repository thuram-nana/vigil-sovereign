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

from .agents.egress_guard import build_engagement_allowlist
from .agents.http_executor import (
    HttpExecutor,
    PromptCallback,
    parse_destructive_prompt,
    parse_posture,
    stdin_prompt_with_timeout,
)
from .agents.scope_gate import validate_action
from .authority.killswitch import KillSwitch
from .phase_ledger import (
    P_ASSESS_FINDINGS,
    P_CHAINING,
    P_DEFENDER,
    P_FUSION,
    P_GROUNDING,
    P_INTEL_FINALIZE,
    P_INTEL_RECON,
    P_PREFLIGHT,
    P_REASONING,
    P_SCAN,
    P_TRANSFER,
    PhaseLedger,
)
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
    # C4 — internal attack paths over the FUSED world (opt-in ``fuse_sensors``). The lateral-
    # movement routes that only exist once the cloud / IAM oracle facts are folded in: the pre-
    # fusion ``attack_paths`` are computed BEFORE fusion, so they never see the cloud posture.
    # Empty on the default (no-fuse) path — byte-identical to before.
    lateral_paths: list[AttackPath] = field(default_factory=list)
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


# =============================================================================
# Engagement profiles (slice 0.2) — a PURE, NO-new-oracle, NO-gate-relaxing flag expansion
# =============================================================================
# ``--profile {surface,deep,full}`` is a convenience roster selector and NOTHING MORE: it only flips
# EXISTING ``enable_*`` opt-in flags ON. It adds no oracle, relaxes no safety gate, and fabricates no
# finding — the operator-spec-gated packs it turns on (e.g. access-control) still run NOTHING without the
# operator's specs (a documented no-op), so enabling the machinery cannot manufacture a result. The
# resolved profile + the exact expanded flag set are recorded to a run-dir manifest so the roster is
# auditable. A profile only ever ADDS flags (union with any explicit --flag), never removes one.
ENGAGEMENT_PROFILES = ("surface", "deep", "full")

# profile -> the argparse dests it turns ON. Each name is an ``args`` attribute that maps 1:1 to a
# ``run_engagement`` ``enable_*`` kwarg. Only flags that ALREADY EXIST are expanded; a plan-named pack
# with no flag yet is DEFERRED (see ``_PROFILE_DEFERRED``), never invented.
#   surface = today's default roster (flips nothing → unchanged behaviour)
#   deep    = the FACT-capable opt-in browser passes + the packs whose flags already exist
#   full    = deep + the operator-spec-gated packs whose flags already exist (access-control)
_PROFILE_FLAGS: dict[str, tuple[str, ...]] = {
    "surface": (),
    "deep": ("domxss", "browser_xss", "sso", "graphql_dos"),
    "full": ("domxss", "browser_xss", "sso", "graphql_dos", "access_control"),
}

# Plan-named packs a profile WOULD enable but that have NO ``enable_*`` flag yet (a later wave adds the
# flag + the pack). The profile expands to NOTHING for these — it never invents a pack — and they are
# surfaced in the manifest + an operator note so the gap is visible and auditable.
#   deep names time-based / NoSQL / LDAP / XPath (no dedicated flag or pack exists — error-based SQLi is
#   the only injection pack in DEFAULT_CHECKS); full additionally names business-logic + race (no flag).
_PROFILE_DEFERRED: dict[str, tuple[str, ...]] = {
    "surface": (),
    "deep": ("time_based_sqli", "nosqli", "ldap", "xpath"),
    "full": ("time_based_sqli", "nosqli", "ldap", "xpath", "bizlogic", "race"),
}

# The dest -> run_engagement enable_* kwarg name, for building the auditable roster map. Only the flags a
# profile can flip need appear here; the manifest records the resolved value of each.
_PROFILE_FLAG_KWARG: dict[str, str] = {
    "domxss": "enable_domxss",
    "browser_xss": "enable_browser_xss",
    "sso": "enable_sso",
    "graphql_dos": "enable_graphql_dos",
    "access_control": "enable_access_control",
}


def resolve_profile(profile: str, args: "argparse.Namespace") -> tuple[list[str], list[str]]:
    """PURE flag-expansion for ``--profile``. Turn ON (never off — an explicit ``--flag`` always survives)
    every EXISTING ``args`` dest the profile names, and return ``(enabled_dests, deferred_packs)``.

    ``surface`` flips nothing (the default roster is byte-identical). A plan-named dest that does not exist
    on ``args`` yet is skipped and reported via ``deferred_packs`` — the profile never invents a pack. No
    oracle, no gate change; the campaign roster is the only thing that moves."""
    name = (profile or "surface").lower()
    enabled: list[str] = []
    for dest in _PROFILE_FLAGS.get(name, ()):
        if not hasattr(args, dest):
            continue   # a plan-named flag not wired yet is DEFERRED (never fabricated)
        setattr(args, dest, True)
        enabled.append(dest)
    return enabled, list(_PROFILE_DEFERRED.get(name, ()))


def _profile_deferred_packs(profile: str) -> list[str]:
    """The plan-named packs a profile names but has no flag for yet (recorded in the run manifest)."""
    return list(_PROFILE_DEFERRED.get((profile or "surface").lower(), ()))


def _record_engagement_profile(run_dir: "str | None", profile: str, flags: dict, deferred: list) -> None:
    """Record the resolved profile + the exact ``enable_*`` roster + the deferred plan-named packs to
    ``<run_dir>/_engagement_profile.json`` so the roster is auditable. Run-dir-gated + best-effort: no run
    dir => nothing written => byte-identical (``make gate`` sets none). Never raises into the engage pass."""
    try:
        from . import profile_manifest
        profile_manifest.write_profile_manifest(run_dir, profile, flags, deferred)
    except Exception:
        pass


# =============================================================================
# Runtime browser gate (slice 0.2) — installed != usable; a browserless browser pass is INCONCLUSIVE
# =============================================================================
def _headless_browser_usable() -> bool:
    """True iff the headless browser is usable FOR THE ENGAGE BROWSER PASSES at runtime — meaning BOTH the
    stdlib render smoke (``scanner.browser.browser_usable`` — the check this slice is specified on) AND the
    CDP driver those passes actually drive (``scanner.cdp.cdp_available``). A binary on PATH is not proof it
    can render (``browser_usable``), and the CDP path can fail even when a ``--dump-dom`` render works, so
    requiring both is what stops a browserless pass being SILENTLY SKIPPED and then read as CLEAN. Cached by
    the underlying probes; called only when a browser pass is enabled, so the default roster pays nothing."""
    from .scanner.browser import browser_usable
    if not browser_usable():
        return False
    from .scanner.cdp import cdp_available
    return cdp_available()


def browser_surfaces_if_unusable(
    *, enable_browser_xss: bool, enable_spa_crawl: bool, usable_check=None
) -> list[tuple[str, str]]:
    """The runtime browser gate's DECISION half (no I/O to the run dir). When a browser-dependent pass is
    enabled but the headless browser is NOT usable at runtime, return the ``(surface, missing_prerequisite)``
    pairs to record as INCONCLUSIVE + print a clear operator line. Returns ``[]`` when no browser pass is
    enabled (nothing to gate → byte-identical default path) OR the browser IS usable (the passes then run
    and confirm/deny per the oracle). ``usable_check`` overrides the real probe (tests inject a fake).

    Only the browser-DRIVEN surfaces are gated — ``enable_domxss`` is a STATIC lead pass (no browser) and is
    never gated here. No oracle, no gate change: this only prevents a silent skip masquerading as clean."""
    enabled_surfaces: list[str] = []
    if enable_browser_xss:
        enabled_surfaces.append("browser_xss")
    if enable_spa_crawl:
        enabled_surfaces.append("spa_crawl")
    if not enabled_surfaces:
        return []
    check = usable_check or _headless_browser_usable
    try:
        usable = bool(check())
    except Exception:          # a probe that itself blows up means the browser is not usable → INCONCLUSIVE
        usable = False
    if usable:
        return []
    print("  browser gate      : headless browser NOT usable at runtime (installed != usable) — recording "
          f"{', '.join(enabled_surfaces)} as INCONCLUSIVE (never clean, never a silent skip). Install a "
          "headless Chromium (bootstrap.sh bundles a pinned one) to assess these surfaces.")
    return [(s, "headless_browser_unusable") for s in enabled_surfaces]


def persist_browser_inconclusive(surfaces: list[tuple[str, str]], *, run_dir: "str | None") -> bool:
    """The runtime browser gate's PERSIST half. Record the browser INCONCLUSIVE ``surfaces`` to the run-dir
    ``_inconclusive.json`` artifact via the SAME framework-owned mechanism fusion uses, so the dossier's
    clean/verdict determination MUST consult the unassessed browser surface and can never round it to CLEAN.

    MERGES with any surfaces already on disk (the fusion pass writes the same artifact) rather than
    clobbering them, and preserves each existing surface's count. Run-dir-gated + best-effort: no surfaces
    or no run dir => no write (byte-identical). Returns True iff the artifact was (re)written."""
    if not surfaces or not run_dir:
        return False
    try:
        from . import inconclusive_manifest as _im
        combined: list[tuple[str, str]] = []
        existing = _im.read_manifest(run_dir)
        for s in existing.get("surfaces", ()):
            pair = (s.get("sensor", ""), s.get("missing_prerequisite", ""))
            combined.extend([pair] * max(1, int(s.get("count", 1) or 1)))
        combined.extend(surfaces)
        return _im.write_manifest(run_dir, combined)
    except Exception:
        return False


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


def preflight_fusion(slug: str) -> None:
    """Fail closed BEFORE any fusion for a SEEDLESS (cloud / Kubernetes / infra POSTURE) engagement:
    refuse a tripped kill-switch, or a slug whose charter is missing OR UNSIGNED. A fusion-only run
    carries no seed URL, so per-request URL scope cannot be validated here — and the offline importer
    sensors (cloud_import / kube_bench) carry no host/target, so the per-sensor scope step (the only
    place ``require_charter_signed`` otherwise runs) is skipped for them. So this preflight is the SOLE
    charter authority on the fusion-only path, and it enforces the SAME signed-charter bar as a remote
    engage's ``preflight`` (``ethics.is_charter_signed`` — an unfilled ``<name>`` placeholder is NOT a
    signature). Every fused sensor is still additionally gated at ``run_sensor`` time (kill-switch /
    entitlement / scope / egress)."""
    ks = KillSwitch(slug)
    if ks.is_tripped():
        raise EngagementRefused(f"kill-switch tripped: {ks.reason()}")
    # `from` at call time (not a module-top import) so a test's monkeypatch of paths.charter_path is
    # honoured — mirrors _fusion_manifest_present's target_dir lookup.
    from .common.ethics import is_charter_signed
    signed, reason = is_charter_signed(slug)
    if not signed:
        raise EngagementRefused(
            f"charter for {slug!r} is not signed ({reason}) — a cloud/Kubernetes/infra posture "
            f"engagement needs a SIGNED charter (targets/{slug}/charter.md), exactly like a remote "
            "engage; fill the 'Signed:' line before launching")


def _engage_authority_trust_root(slug: str) -> object | None:
    """Discover the governance trust root to PIN on the production ``engage`` path so a
    provisioned :class:`~.authority.models.EngagementAuthority` is loaded VERIFIED
    (``load_verified_authority``) rather than trusted UNSIGNED — closing W16-2 and matching
    the VIGIL plane, whose ``conjunctive_gate.build_offense_gate`` refuses a ``None`` trust
    root outright ("a None trust_root loads the CRUCIBLE authority UNSIGNED").

    The engage path used to build ``HttpExecutor(auto_load_authority=True)`` with NO
    ``trust_root``, so the executor's ``_authority_gate`` fail-closed branch (which fires only
    when a trust root is pinned) never engaged: a tampered authority widening the validity
    window / ``allow_destructive`` / ``live_destructive_acknowledged`` / ``max_actions`` was
    trusted. This resolver pins the trust root so that branch enforces:

    - GREENFIELD (no authority document provisioned for this engagement) -> ``None``: the
      executor keeps its documented kill-switch-only path, so no greenfield run is broken.
    - An authority IS provisioned AND a governance trust root is discoverable -> the
      :class:`~.entitlement.models.TrustRoot`: ``_authority_gate`` then REQUIRES a valid signed
      document — an UNSIGNED or TAMPERED authority fails the verified load, leaving ``authority``
      unset, and the gate refuses BEFORE any network I/O.
    - An authority IS provisioned but NO trust root is discoverable -> ``EngagementRefused``:
      an UNPINNED authority must never be applied unsigned (the exact fail-open this closes).
      Provision the governance trust root, or remove the stale authority document to run
      greenfield (kill-switch only).
    """
    from .common import paths as _paths
    if not _paths.authority_path(slug).is_file():
        return None  # greenfield: no authority provisioned -> kill-switch-only path preserved
    # DECOUPLED STORE (Phase 0.1 fix): the governance AUTHORITY trust root is loaded from the DEDICATED
    # authority-root store, NOT the entitlement store — so provisioning an authority never trips entitlement
    # capability enforcement (which keys on `.entitlement/trust-root.json`). This read MUST point at the same
    # store `wiring.provision_authority` writes, else a provisioned authority is not found here.
    from .authority.store import load_authority_root
    trust_root = load_authority_root()  # None iff the authority trust root is absent (present-but-
    # malformed raises AuthorityError, which propagates as a fail-closed refusal, not a silent load)
    if trust_root is None:
        raise EngagementRefused(
            f"an EngagementAuthority is provisioned for {slug!r} ({_paths.authority_path(slug)}) but "
            f"no governance authority trust root is discoverable ({_paths.authority_root_path()}) — refusing "
            "to apply an UNVERIFIABLE authority on the engage path (W16-2). Provision the authority root, or "
            "remove the authority document to run greenfield (kill-switch only).")
    return trust_root


def _engage_oob_authority(slug: str) -> dict:
    """The OUT-OF-BAND OOB material (collector pins + owner-signed TTL/skew replay policy) from the SIGNED
    engagement authority, as WebScanCampaign kwargs. This CONSUMES ``authority.oob_collector_pubkey`` and
    ``authority.oob_dns_collector_pubkey`` (no longer dead config): they are threaded onto the verifier so a
    VF-2b HTTP/DNS finding is re-verified against the pinned key with an authority-bound window — NEVER trusted
    from the producer context. Greenfield (no provisioned/verifiable authority) ⇒ ``{}`` (VF-2a byte-identical
    path preserved). A provisioned-but-unverifiable authority already fails closed via
    ``_engage_authority_trust_root``, so this is best-effort over an already-pinned root."""
    trust_root = _engage_authority_trust_root(slug)
    if trust_root is None:
        return {}
    from .authority.store import AuthorityError, load_verified_authority
    try:
        authority = load_verified_authority(slug, trust_root)
    except AuthorityError:
        return {}   # unverifiable authority is refused on the traffic path itself; do not pin from it here
    kwargs: dict = {}
    http_pin = (authority.oob_collector_pubkey or "").strip()
    dns_pin = (authority.oob_dns_collector_pubkey or "").strip()
    if http_pin:
        kwargs["oob_collector_pubkey"] = http_pin
    if dns_pin:
        kwargs["oob_dns_collector_pubkey"] = dns_pin
    if http_pin or dns_pin:
        # The owner-signed replay policy only matters once a receipt is being verified.
        kwargs["oob_ttl_seconds"] = float(authority.oob_ttl_seconds)
        kwargs["oob_skew_seconds"] = float(authority.oob_skew_seconds)
    return kwargs


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


def _advise_learner_health(sink, slug) -> None:
    """W2.2a — schedule the learner-health META-MONITOR as advisory telemetry on the ``--spine``
    reasoning pass (it used to run only under ``--autonomous``). It reads the operator's outcome
    ledger READ-ONLY (``targets/<slug>/outcomes.json``; a missing ledger is an empty one → an
    honest 'gather_evidence'), diagnoses whether the learners (calibrator / conformal bands) are
    trustworthy, and records ONE advisory ``decision`` event.

    CAUTION-ONLY, by construction: the meta-monitor can only recommend MORE caution (order effort /
    abstain more) — it NEVER gates a surface, promotes a finding, mutates the report, or feeds a
    deterministic oracle/SCE/calibration input. Spine-only (no sink → no-op) and off the gate path
    (``make gate`` attaches no spine), so the default engage/scan report stays byte-identical.
    Best-effort/total — a meta-monitor failure never perturbs the engagement."""
    if sink is None:
        return
    try:
        from .calibration.ledger import OutcomeLedger
        from .calibration.meta_monitor import assess_learner_health
        from .common.paths import target_dir

        path = target_dir(slug) / "outcomes.json"
        ledger = OutcomeLedger.load(path) if path.is_file() else OutcomeLedger()
        sig = assess_learner_health(ledger)
        sink.decision(
            "learner health",
            str(getattr(sig, "recommend", "") or "unknown"),
            rationale=(f"{getattr(sig, 'notes', '')} "
                       f"(n_labels={getattr(sig, 'n_labels', 0)}, "
                       f"ece={getattr(sig, 'ece', 0.0):.3f}) — advisory: orders effort, "
                       f"never gates a surface or promotes a finding"))
    except Exception:
        pass


def _persist_plan_input(slug, report, world) -> None:
    """W2.2c — persist a compact READ-ONLY projection input (the run world-model + the confirmed
    findings' goal-tree seeds) so ``plan <slug>`` can reconstruct the planner's route/goal-tree over
    this engagement OFFLINE. Written ONLY when a spine is attached (opt-in ``--spine``), so the
    default engage path and the gate stay byte-identical. Owner-only on disk (``secure_write``, it
    can hold intel/surface detail). Best-effort/total — a persist failure never sinks the run."""
    try:
        import json

        from .common import paths as _paths
        from .worldmodel import store as world_store

        findings = [
            {"bug_class": str(getattr(f, "bug_class", "") or ""),
             "insertion_point": str(getattr(f, "insertion_point", "") or ""),
             "param": str(getattr(f, "param", "") or ""),
             "endpoint": str(getattr(f, "endpoint", "") or ""),
             "confidence": float(getattr(f, "confidence", 0.0) or 0.0),
             "has_oracle_context": bool(getattr(f, "oracle_context", None))}
            for f in report.active_findings
        ]
        world_doc = (world_store.to_dict(world) if world is not None
                     else {"schema_version": 1, "nodes": [], "edges": []})
        doc = {"schema_version": 1, "target": report.target,
               "findings": findings, "world": world_doc}
        _paths.secure_write(_paths.target_dir(slug) / "plan-input.json",
                            json.dumps(doc, indent=2, sort_keys=True))
    except Exception:
        pass


def _run_reasoning_pass(sink, spine, slug, report, result, world) -> None:
    """W1.1 — the nervous system, ADVISORY-ONLY, over the authoritative findings.

    Runs ONLY when the event spine is attached (opt-in telemetry). It NEVER alters
    ``report.active_findings`` nor any oracle verdict — it mirrors each finding, then re-grounds
    (critic panel), refuses-to-conclude (cognitive refusal), credits the outcome (reward bus), and
    (W2.2a) records the learner-health meta-monitor's advisory — recording each on the immutable
    stream. Because ``make gate`` runs WITHOUT a spine, this path never executes during the eval
    gate, so the gate stays byte-identical. Best-effort throughout — a reasoning failure never
    sinks the engagement."""
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

        # (5) W2.2a — the learner-health meta-monitor, scheduled here as ADVISORY telemetry
        # (previously it ran only under --autonomous). Orders effort only; never gates a surface,
        # promotes a finding, or touches the authoritative report. Spine-only → gate byte-identical.
        _advise_learner_health(sink, slug)

        sink.decision(
            "engagement summary",
            f"{len(report.active_findings)} finding(s), {len(result.attack_paths)} attack path(s)",
            rationale=f"target={report.target}")
    except Exception:
        pass


def _engage_run_dir() -> "str | None":
    """The AUTHORITATIVE run dir for THIS engage process, resolved ONCE the way the run's own artifacts are
    located: ``$VIGIL_PROOF_RUN_DIR`` — the exact handle the console exports on every fusion-capable engage
    spawn and the same one the proof subsystem writes ``proofs/_degraded.json`` / ``reverifiable.json`` under.
    The engage flow resolves it here and THREADS it explicitly into fusion (``_run_fusion`` / the autonomous
    seam), so persistence never depends on a leaf re-reading the environment. Absent (a hand-run CLI engage
    with no console) => there is no run dir to attach an artifact to and nothing is written."""
    rd = os.environ.get("VIGIL_PROOF_RUN_DIR")
    return rd or None


def _run_fusion(world: "WorldModel", slug: str, *, seq_base: int, sink,
                run_dir: "str | None" = None) -> tuple[int, int]:
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
        from .engage_fusion import fuse_sensors, persist_inconclusive_surfaces
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
    # Resolve the run dir ONCE, the authoritative way (explicit thread first, env only as last resort), and
    # carry it ON the ctx so the persist below is env-INDEPENDENT — it uses the threaded value, not a leaf
    # os.environ read. On a hand-run CLI engage with no run dir this stays None and nothing is written.
    rd = run_dir or _engage_run_dir()
    ctx = SimpleNamespace(base_seq=seq_base, sink=sink, run_dir=rd)
    try:
        minted = fuse_sensors(world, slug, ctx)
    except Exception:
        return (0, 0)
    # A fusion sensor may have returned INCONCLUSIVE (a declared surface it could NOT assess — a missing
    # cloud/K8s prerequisite). fuse_sensors collected these onto ctx.inconclusive_surfaces; persist them to
    # a FRAMEWORK-OWNED run-dir artifact (<run_dir>/_inconclusive.json) using the run dir THREADED into this
    # function (env only as last resort) so the dossier's clean/verdict determination MUST consult a not-
    # assessed surface — a "0 findings" run over an unassessed surface is NEVER reported clean. Written ONLY
    # on a genuine inconclusive (no surface or no run dir => nothing written => byte-identical). Best-effort.
    persist_inconclusive_surfaces(ctx, run_dir=rd)
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
    resume: bool = False,
    run_dir: "str | None" = None,
    profile: str = "surface",
) -> EngagementResult:
    """Run one authorized engagement end to end and return an
    :class:`EngagementResult` — the oracle-confirmed :class:`ScanReport` plus the
    forward reasoning over it (the attack paths the confirmed facts unlock). Every
    request passes the full gate chain; raises EngagementRefused if the engagement
    may not start.

    With ``enable_chaining`` (default) the confirmed findings are written into a
    world-model and the technique operators are run to a fixpoint to extract
    attacker→crown-jewel attack paths. Chaining sends NO traffic and is best-effort:
    if it fails, the engagement still returns its report with empty paths.

    Every phase is checkpointed to an append-only :class:`~framework.v2.phase_ledger.PhaseLedger`
    (fail-open: a checkpoint IO failure is a recorded no-op, never a raise). With ``resume=True``
    a resumed run RELOADS the prior run's snapshotted scan report and skips the traffic-sending
    crawl/audit — but it is NOT a "skip every completed phase" shortcut. The scan is the only phase
    whose WORK is skipped (its report is reloaded, not re-crawled; see
    ``phase_ledger.RESUMABLE_PHASES``, which also lists the reasoning pass). Every PURE, no-traffic
    reasoning phase — intel finalize, finding-confidence, chaining, the GROUNDING veracity firewall,
    fusion, the defender pass — ALWAYS re-runs on resume, deriving its in-memory result fresh from
    the reloaded report. Re-firing the grounding firewall is REQUIRED, not optional: a finding is
    presented as a fact only if its retained oracle_context RE-FIRES (CRUCIBLE invariant #3), and the
    firewall can only demote — so a resumed report is as authoritative as a fresh one, never a stale
    snapshot presented without re-verification.

    The phases that re-run but ALSO write to the append-only event spine — the reasoning pass
    (skipped outright), sensor fusion, and the defender pass — must not double-count their events on
    a resume. The reasoning pass is skipped when completed (its re-emit is its only effect). Fusion
    and defender re-run to recompute their derived fields but hand their spine-EMITTING steps a NULL
    sink whenever the prior run already recorded that phase on the spine (see ``_emit_sink``), so the
    fused-lead findings and the defender gap-report/efficacy events appear ONCE across fresh+resume
    while ``result.fused_leads``/``fused_facts``/``defense`` are still recomputed. ``resume=False``
    (the default) only ever RECORDS state, so the control flow — and ``make gate`` — is
    byte-identical."""
    # Opt-in event-spine sink (default None → byte-identical behaviour). When present, every
    # gate refusal is recorded as evidence on the spine before it propagates.
    sink = _make_spine_sink(spine, slug)

    # Append-only PHASE LEDGER + resume (default resume=False → the ledger only ever RECORDS;
    # it changes no control flow, so the non-resume path is byte-identical). Every ledger write
    # is fail-open: a checkpoint IO failure is a recorded no-op, never a raise. Under --resume it
    # reloads the scan's snapshotted report and skips ONLY the scan + the spine-emitting reasoning
    # pass (RESUMABLE_PHASES); every pure-reasoning phase — including the grounding veracity
    # firewall — re-runs, so a resumed report is re-verified, never a stale snapshot.
    ledger = PhaseLedger(slug, resume=resume, sink=sink)

    # Suppress the SPINE RE-EMIT of a pure-reasoning phase that ALSO writes to the append-only
    # event spine and that a PRIOR run already recorded there. Two re-run phases emit: FUSION
    # (each fused-sensor LEAD becomes a `finding` event via _emit_fused_leads, and the gated
    # sensor invocations emit tool_call/tool_result) and DEFENDER (_mirror_defense posts the
    # gap-report observation + efficacy decision). They are correctly NOT in RESUMABLE_PHASES —
    # they MUST re-run so a resumed result recomputes its in-memory derived fields (fused_leads/
    # fused_facts, defense) and is as complete as a fresh one. But re-running them verbatim would
    # DOUBLE-COUNT their events on the immutable stream every resume. Fix: a re-run phase whose
    # prior run already recorded it on the spine hands its EMITTING steps a NULL sink — it still
    # recomputes in-memory, it just does not re-append the same events. A phase the prior run did
    # NOT complete (never emitted, or crashed mid-emit) keeps the real sink, so its events are
    # emitted exactly once. Grounding/finding-confidence/chaining/intel emit NOTHING to the spine,
    # so they are already re-emit-idempotent and untouched. Empty unless resuming → fresh runs
    # (and `make gate`, which uses no spine) are byte-identical.
    _completed_prior = ledger.completed_prior()

    def _emit_sink(phase: str):
        """The sink a re-runnable phase hands to its spine-EMITTING steps: the real ``sink``
        normally, but ``None`` when resuming a phase the prior run already recorded on the spine
        (so it recomputes its in-memory result WITHOUT re-appending the same events)."""
        return None if (resume and phase in _completed_prior) else sink

    # Preflight is the fail-closed AUTHORIZATION gate — it ALWAYS runs, even on resume:
    # re-validating the kill-switch + seed scope on every launch is a safety feature, never a
    # cost to skip. Recorded (started/completed) purely for the process box + audit trail.
    ledger.start(P_PREFLIGHT)
    try:
        preflight(slug, seed_url)
    except EngagementRefused as e:
        ledger.fail(P_PREFLIGHT)
        if sink is not None:
            sink.refusal("preflight", seed_url, reason=str(e), fatal=True)
        raise
    ledger.complete(P_PREFLIGHT)

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

    # Slice 0.2 — the run dir for THIS engage process (explicit thread first, env last resort), used for
    # both the auditable PROFILE roster and the browser INCONCLUSIVE-coverage artifact. Absent (hand-run
    # CLI, no console) => nothing is written and the path is byte-identical (``make gate`` sets none).
    rd = run_dir or _engage_run_dir()

    # Record the resolved engagement PROFILE + the EXACT resolved enable_* roster to a run-dir manifest so
    # the roster is auditable after the fact. PURE record — it flips no flag and changes no verdict.
    _record_engagement_profile(rd, profile, {
        "enable_domxss": enable_domxss,
        "enable_oob": enable_oob,
        "enable_browser_xss": enable_browser_xss,
        "enable_spa_crawl": enable_spa_crawl,
        "enable_chaining": enable_chaining,
        "enable_recon": enable_recon,
        "enable_arsenal": enable_arsenal,
        "enable_sso": enable_sso,
        "enable_graphql_dos": enable_graphql_dos,
        "use_library": use_library,
        "enable_access_control": enable_access_control,
        "enable_defender": enable_defender,
        "fuse_sensors": fuse_sensors,
    }, _profile_deferred_packs(profile))

    # RUNTIME browser gate: decide it HERE (early — the operator sees the log line up front and the
    # capability probe caches), but PERSIST it after the fusion phase so it MERGES with (never clobbers)
    # any _inconclusive.json fusion wrote. installed != usable → a browser pass whose browser cannot render
    # is recorded INCONCLUSIVE, never CLEAN, never a silent skip. Empty when no browser pass is enabled or
    # the browser is usable → the passes run and adjudicate per the oracle (byte-identical default path).
    _browser_inconclusive = browser_surfaces_if_unusable(
        enable_browser_xss=enable_browser_xss, enable_spa_crawl=enable_spa_crawl)

    # The single run-owned world-model: intel recon projects assets onto it, and finding
    # chaining accretes attack facts onto the SAME graph (disjoint id namespaces). Built
    # even when recon is off, so chaining shares it and the result exposes it.
    world = WorldModel()
    # Best-effort intel recon under the ledger. It is NOT a RESUMABLE_PHASE, so it re-runs on
    # resume — rebuilding the in-memory ingest handle that intel_finalize consumes (its collectors
    # only read OFFLINE fixtures via FixtureTransport, so a re-run sends no live traffic). Were it
    # skipped, its ingest handle — which lives only in the prior process — would be lost and
    # intel_finalize would silently produce nothing, exactly the derived-field drop this slice fixes.
    ingest = ledger.run_phase(
        P_INTEL_RECON,
        lambda: _intel_recon(world, slug, seed_url,
                             fixtures_dir=recon_fixtures, max_depth=recon_depth),
        enabled=enable_recon, default=None)

    # W1.3 cross-engagement TRANSFER (opt-in): when an archetype is named and no explicit
    # priors were supplied, warm-start this run's check-ordering bandit from SMOOTHED priors
    # for that archetype — blended from lexically SIMILAR past archetypes and evidence-gated
    # (memory.priors.smoothed_priors_for). Best-effort; default (no archetype) leaves
    # priors=None so behaviour — and `make gate`, which never names an archetype — is
    # byte-identical. The bandit only ORDERS effort, so transfer never gates a surface.
    def _do_transfer() -> object:
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
            return transferred or None
        return None

    _transfer_enabled = priors is None and bool(transfer_archetype)
    _transferred = ledger.run_phase(P_TRANSFER, _do_transfer,
                                    enabled=_transfer_enabled, default=None)
    if _transfer_enabled:
        priors = _transferred   # None on skip/fail — identical to the old value-add degrade

    def _do_scan() -> ScanReport:
        """Build the gated executor (+ optional fail-closed arsenal-authz + access-control pack)
        and run the Wave-1 campaign to a ScanReport, always closing the executor. Extracted so a
        --resume run can RELOAD a snapshotted report and skip this entire traffic-sending phase."""
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
            # W16-2: PIN the governance trust root when an authority is provisioned, so a
            # signed authority is REQUIRED and verified (an unsigned/tampered doc is refused
            # before any I/O). None for greenfield -> the kill-switch-only path is preserved.
            trust_root=_engage_authority_trust_root(slug),
            request_budget=request_budget,
            prompt_callback=prompt_callback or stdin_prompt_with_timeout,
            # W10-1 (#473): install the runtime egress allowlist on the target-traffic path
            # (built from THIS engagement's charter scope). Under sovereign mode the transport
            # refuses any non-allowlisted host before bytes leave the box — the belt-and-braces
            # backstop behind the always-on scope gate; under permissive it passes through
            # (byte-identical). Without this the "6th gate" was never installed on any real
            # caller and the README's egress claim was false for target traffic.
            egress_allowlist=build_engagement_allowlist(slug=slug),
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
            return WebScanCampaign(
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
                # Consume the SIGNED authority's OOB pins + owner-signed TTL/skew (out-of-band, never producer):
                # a VF-2b HTTP/DNS finding is re-verified against the pinned collector key with a bound window.
                **_engage_oob_authority(slug),
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

    # SCAN phase — the one traffic-sending phase, so resume matters most here. On --resume, if a
    # prior run COMPLETED the scan, reload its snapshotted authoritative report and SKIP re-
    # crawling/re-auditing the target (idempotent: the target sees no repeat traffic, and findings
    # are never re-counted). A missing/corrupt snapshot falls through and re-runs (fail-open). A
    # scan exception propagates exactly as before (the phase is NOT completed → retried on resume).
    report: ScanReport | None = None
    if not ledger.should_run(P_SCAN):
        report = ledger.load_report()
        if report is not None:
            ledger.skip(P_SCAN)
    if report is None:
        ledger.start(P_SCAN)
        report = _do_scan()
        ledger.complete(P_SCAN)
        ledger.persist_report(report)

    # Post-scan intel: register the observed target + stack, resolve the asset
    # inventory, and produce the gated prediction queue. Best-effort.
    result = EngagementResult(report=report, world=world)

    def _do_intel_finalize() -> None:
        result.entities, result.predictions = _intel_finalize(ingest, report)
    ledger.run_phase(P_INTEL_FINALIZE, _do_intel_finalize,
                     enabled=(enable_recon and ingest is not None))

    # Scientific confidence per finding — pure reasoning over the oracle's verdicts,
    # never traffic; best-effort so it can never sink the engagement.
    def _do_assess_findings() -> None:
        result.finding_confidence = _assess_findings(report)
    ledger.run_phase(P_ASSESS_FINDINGS, _do_assess_findings)

    # Findings project ABOVE the intel recon band on the shared clock, so the monotonic
    # world-model time never inverts across the recon→scan handoff. Derived from the
    # SHARED WORLD itself (not the ingest handle), so it is correct even if recon
    # partially failed and left nodes behind — and is exactly 1 when recon is off (empty
    # world), reproducing the standalone behaviour.
    seq_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1

    # Forward reasoning over the confirmed facts (no traffic). Best-effort: the
    # scan result is authoritative and must survive any chaining error.
    def _do_chaining() -> None:
        from .worldmodel.impact import ImpactModel
        auto = AutonomousCampaign(
            _no_send, detection_budget=detection_budget,
            impact_model=ImpactModel.from_slug(slug),   # mission-aware path/portfolio value
        ).chain_findings(report, world=world, seq_base=seq_base)
        result.attack_paths = auto.attack_paths
        result.path_portfolio = auto.path_portfolio
        result.chained_conclusions = auto.chained_conclusions
    ledger.run_phase(P_CHAINING, _do_chaining, enabled=enable_chaining)

    # Veracity firewall over the live findings — re-execute each finding's own oracle
    # against the (now chained) world-model and label GROUNDED/UNGROUNDED/CONTRADICTED.
    # Runs AFTER chaining so the world holds the endpoint nodes the check consults.
    # Best-effort: the anti-hallucination pass can only demote, never sink the engagement.
    # NOT a RESUMABLE_PHASE — it ALWAYS re-runs on resume (its verdict list lives only in the
    # prior process, and CRUCIBLE invariant #3 requires the oracle to re-fire before findings
    # are presented as facts; re-running over the reloaded report sends no traffic and is free).
    def _do_grounding() -> None:
        result.grounding = _assess_grounding(report, world)
    ledger.run_phase(P_GROUNDING, _do_grounding)

    # OPT-IN sensor fusion (``fuse_sensors``, default OFF → this phase is skipped and the
    # engagement — and ``make gate`` — is byte-identical). Fold the operator's declared OFFLINE sensor
    # LEADS into the SHARED world-model and let the deterministic promotion oracles re-fire over each
    # sensor's OWN retained evidence. Runs AFTER chaining/grounding so it folds onto the final world;
    # the fusion clock continues after the run's high-water so time never inverts. Best-effort — a
    # fusion failure never sinks the engagement, and it NEVER changes a finding or an oracle verdict.
    def _do_fusion() -> None:
        # On a resume where fusion already completed, hand _run_fusion a NULL sink: the world-fold
        # + oracle re-verification (and thus result.fused_leads/fused_facts) recompute identically,
        # but the fused-lead `finding` events + gated-sensor tool events are NOT re-appended to the
        # spine (the prior run already recorded them). Otherwise the real sink emits them once.
        fusion_sink = _emit_sink(P_FUSION)
        try:
            fusion_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1
            result.fused_leads, result.fused_facts = _run_fusion(
                world, slug, seq_base=fusion_base, sink=fusion_sink,
                run_dir=(run_dir or _engage_run_dir()))
        except Exception:
            pass
        # C4 — internal attack paths over the NOW-FUSED world. Bridge the GROUNDED cloud oracle
        # facts (policy_path / active_exposure) into attacker-traversable edges and re-run the
        # deterministic path search, surfacing lateral routes that only exist once the cloud
        # posture is folded in. Only under fuse_sensors (default path byte-identical). Mints no
        # fact — every bridged edge restates a fired oracle; best-effort, never sinks the run.
        try:
            from .scanner.lateral import lateral_paths
            from .worldmodel.impact import ImpactModel
            lateral_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1
            result.lateral_paths = lateral_paths(
                world, impact_model=ImpactModel.from_slug(slug), seq_base=lateral_base)
        except Exception:
            pass
    ledger.run_phase(P_FUSION, _do_fusion, enabled=fuse_sensors)

    # Slice 0.2 — PERSIST the runtime browser gate's INCONCLUSIVE surfaces LAST (after the fusion phase's
    # own _inconclusive.json write) so a browserless browser-pass run is never rounded to CLEAN and never a
    # silent skip. Merges with (never clobbers) any fusion surfaces already on disk. No-op when the browser
    # was usable / no browser pass was enabled (empty list → byte-identical).
    persist_browser_inconclusive(_browser_inconclusive, run_dir=rd)

    # DEFENSIVE / purple-team pass (opt-in ``enable_defender``, default OFF → this phase is
    # skipped and the engagement is byte-identical). It reasons over the confirmed findings to tell
    # the blue team where their detection coverage has holes: candidate Sigma rules for the misses,
    # a detection-efficacy signal (would the operator's Sigma ruleset have caught what CRUCIBLE did?)
    # mapped to ATT&CK, and Sigma over any operator-supplied OFFLINE logs (kill-switch-gated read).
    # READ-ONLY over the authoritative scan — it changes no finding and no oracle verdict.
    def _do_defender() -> None:
        # On a resume where the defender pass already completed, hand it a NULL sink: the
        # DefenseReport (result.defense) is rebuilt identically from the reloaded report, but the
        # gap-report observation + efficacy decision (and any gated log-ingest tool events) are NOT
        # re-appended to the spine (the prior run already recorded them). Otherwise emit them once.
        defender_sink = _emit_sink(P_DEFENDER)
        result.defense = _run_defender_pass(
            report, ruleset_path=defender_ruleset, sigma_dir=defender_sigma_dir,
            log_path=defender_log, log_format=defender_log_format, slug=slug, sink=defender_sink)
        if defender_sink is not None and result.defense is not None:
            _mirror_defense(defender_sink, result.defense)
    ledger.run_phase(P_DEFENDER, _do_defender, enabled=enable_defender)

    # Mirror the authoritative findings onto the event spine AND run the reasoning pass over
    # them (W1.1: multi-critic panel + cognitive refusal + reward-bus credit + reflection) —
    # ADVISORY ONLY. This never alters report.active_findings nor the oracle verdict, and it
    # runs only when a spine is attached (so `make gate`, which uses no spine, is byte-identical).
    # Skipping this on resume (a prior run completed it) is exactly what stops the append-only spine
    # from double-counting the SAME findings' events on a re-run.
    def _do_reasoning() -> None:
        _run_reasoning_pass(sink, spine, slug, report, result, world)
        # W2.2c — persist a compact READ-ONLY projection input so `plan <slug>` can reconstruct the
        # planner's route/goal-tree over this engagement offline. Spine-only (opt-in), so the default
        # engage path and the gate stay byte-identical. Best-effort — never sinks the run.
        _persist_plan_input(slug, report, world)
    ledger.run_phase(P_REASONING, _do_reasoning, enabled=(sink is not None))
    return result


def run_fusion_only(slug: str, *, spine: object = None, run_dir: "str | None" = None) -> EngagementResult:
    """FUSION-ONLY engagement (slice C2b): NO seed URL, NO web crawl / recon / scan. Build the run
    world-model and fold ONLY the operator's declared sensor LEADS (``targets/<slug>/fusion.json``)
    through the GATED pipeline, letting the deterministic promotion oracles re-fire over each sensor's
    OWN retained evidence — the CLOUD / KUBERNETES / INFRA POSTURE path, whose sensors (``cloud_import``,
    ``kube_bench``, ``declared_service`` …) need no web seed.

    Same fail-closed authorization as a remote engage (``preflight_fusion``: kill-switch + a signed
    charter for the slug); an absent/empty/malformed ``fusion.json``, or sensors that no-op, yield an
    HONEST empty result (0 leads, 0 facts) — nothing is fabricated. Best-effort: a fusion failure never
    raises out of the run, and every sensor is STILL gated at ``run_sensor`` time (kill-switch /
    entitlement / scope / egress). Returns an :class:`EngagementResult` whose report is an empty shell
    (nothing was crawled or audited) carrying the fused lead/fact counts + the shared world-model.

    This is the exact ``fuse_sensors`` pass ``run_engagement(..., fuse_sensors=True)`` runs, MINUS the
    seed-dependent web pass — so it changes no oracle verdict and adds only oracle-grounded facts +
    intel leads, never a scanner finding. It also runs the C4 lateral-path pass over the fused world."""
    sink = _make_spine_sink(spine, slug)
    try:
        preflight_fusion(slug)
    except EngagementRefused as e:
        if sink is not None:
            sink.refusal("preflight", f"fuse-only:{slug}", reason=str(e), fatal=True)
        raise

    # A fresh run world-model + an empty report shell (a fusion-only run crawled nothing / audited
    # nothing — the report.target is an honest fusion:// marker, never a URL that was fetched).
    world = WorldModel()
    report = ScanReport(target=f"fusion://{slug}")
    result = EngagementResult(report=report, world=world)
    try:
        # seq_base=1 over a fresh (empty) world — the fusion clock starts at 1, exactly as the default
        # engage's post-scan fusion does over an empty world.
        result.fused_leads, result.fused_facts = _run_fusion(world, slug, seq_base=1, sink=sink,
                                                             run_dir=(run_dir or _engage_run_dir()))
    except Exception:
        pass   # fusion is the whole point, but a failure is an honest empty, never a crash

    # C4 — internal attack paths over the fused world (the SAME lateral pass the web-engage fuse hook
    # runs). Best-effort; mints no fact — every bridged edge restates a fired oracle.
    try:
        from .scanner.lateral import lateral_paths
        from .worldmodel.impact import ImpactModel
        lateral_base = max((n.last_seen for n in world.all_nodes()), default=0) + 1
        result.lateral_paths = lateral_paths(
            world, impact_model=ImpactModel.from_slug(slug), seq_base=lateral_base)
    except Exception:
        pass

    # Opt-in event-spine mirror (only when --spine attached). Best-effort; never sinks the run.
    if sink is not None:
        try:
            _run_reasoning_pass(sink, spine, slug, report, result, world)
            _persist_plan_input(slug, report, world)
        except Exception:
            pass
    return result


def _run_fuse_only_cli(args: argparse.Namespace, spine: object) -> int:
    """CLI leg for ``engage <slug> --fuse-only`` — a seedless cloud/K8s/infra posture run. Refuses a
    stray seed URL (a fusion-only run has no web seed), runs the fusion-only engagement, and prints an
    honest summary (an explicit empty note when nothing fused)."""
    if args.seed_url:
        print(f"engage --fuse-only takes NO seed url (a cloud/Kubernetes/infra posture run has no web "
              f"seed); got {args.seed_url!r}. Drop the URL, or run a normal web engage.")
        return 2
    try:
        result = run_fusion_only(args.slug, spine=spine)
    except EngagementRefused as e:
        print(f"engagement refused: {e}")
        return 2
    print(f"engage {args.slug}  (fusion-only, no web seed)")
    print(f"  fused sensors     : {result.fused_leads} lead(s) folded, "
          f"{result.fused_facts} oracle-promoted fact(s) "
          f"(from targets/{args.slug}/fusion.json; leads stay leads, oracles prove facts)")
    if result.lateral_paths:
        print(f"  lateral paths     : {len(result.lateral_paths)} internal attack path(s) over the "
              "fused world (C4)")
    if result.fused_leads == 0 and result.fused_facts == 0:
        print(f"  (honest empty — author targets/{args.slug}/fusion.json with a sensor task and drop "
              "the provider export it points at; nothing was fabricated)")
    return 0


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


def _fusion_manifest_present(slug: str) -> bool:
    """True iff the operator authored a ``targets/<slug>/fusion.json`` manifest — the NW-3
    opt-in-by-presence signal that auto-activates sensor fusion. Defensive and total: no slug or any
    path trouble yields False, so the default (manifest-absent) engage path — and ``make gate``, whose
    in-process benchmark corpus carries no target-dir slug and never reaches this function at all —
    stays byte-identical."""
    if not slug:
        return False
    try:
        from .common.paths import target_dir
        return (target_dir(slug) / "fusion.json").is_file()
    except Exception:
        return False


def _resolve_fuse_sensors(slug: str, *, fuse_sensors: bool, no_fuse_sensors: bool) -> tuple[bool, bool]:
    """NW-3 fusion activation resolution → ``(enabled, auto_activated)``.

    Auto-enable-by-manifest-presence: fusion turns ON when the operator has authored a
    ``targets/<slug>/fusion.json`` manifest, even without an explicit ``--fuse-sensors``.
    ``--no-fuse-sensors`` is the explicit opt-OUT and wins over a present manifest. With neither flag
    and no manifest, fusion stays OFF and the engage path is byte-identical (and ``fuse_sensors`` still
    no-ops without a manifest even if forced on, so this only ever ADDS oracle-grounded facts + leads —
    never a finding or an oracle verdict).

    ``auto_activated`` is True only when a present manifest (not an explicit flag) is what enabled
    fusion — used purely to print the operator-facing 'fusion active' summary note."""
    manifest_present = _fusion_manifest_present(slug)
    enabled = (fuse_sensors or manifest_present) and not no_fuse_sensors
    auto_activated = bool(enabled and manifest_present and not fuse_sensors)
    return enabled, auto_activated


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

    # W-C — opt-in DISCOVERY. When --autonomous-discover is set, build a FRESH gated executor for the
    # discovery probes (the engagement's own executor was already closed after the scan). Its
    # `gated_fetch` is the probe I/O: every probe_surface request still funnels through the FULL
    # charter/scope/kill-switch/egress/rate stack, so an out-of-scope endpoint or a tripped kill-
    # switch refuses it. Default off → no executor is built and discovery never runs (byte-identical).
    discover_send = None
    discover_ex = None
    if getattr(args, "autonomous_discover", False):
        # W16-2 (LOW): resolve the signed-authority trust root OUTSIDE the best-effort try below.
        # An EngagementRefused here (an authority IS provisioned but no governance trust root is
        # discoverable to VERIFY it) is an AUTHORIZATION refusal, not a value-add build hiccup — it
        # must be SURFACED (propagated to the caller's fail-closed handler), never swallowed into a
        # silent discovery-skip that would proceed as if no authority were provisioned. Only a
        # genuine executor build error stays best-effort-skipped inside the try.
        discover_trust_root = _engage_authority_trust_root(args.slug)
        try:
            discover_ex = HttpExecutor(
                engagement_slug=args.slug,
                base_url=_origin(args.seed_url),
                auto_load_authority=True,
                # W16-2: same signed-authority pin as the scan executor above.
                trust_root=discover_trust_root,
                request_budget=max(1, int(getattr(args, "autonomous_budget", 8))),
                prompt_callback=prompt_callback_from_args(args) or stdin_prompt_with_timeout,
                # W10-1 (#473): same target-traffic egress allowlist as the scan executor.
                egress_allowlist=build_engagement_allowlist(slug=args.slug),
            )
            discover_send = discover_ex.gated_fetch
        except Exception:
            discover_send = None   # discovery is value-add; a build failure just skips it

    try:
        out = run_autonomous_cycle(
            result, slug=args.slug,
            max_cycles=max(1, int(getattr(args, "autonomous_cycles", 1))),
            request_budget=max(1, int(getattr(args, "autonomous_budget", 8))),
            prompt_callback=prompt_callback_from_args(args),
            # W2.2b — opt-in bounded MULTI-STEP lookahead (default depth-1 = greedy, so the existing
            # autonomous behaviour is byte-identical). --autonomous-lookahead switches selection to
            # depth-2 lookahead toward the crown-jewel objectives (still gated, still deterministic).
            lookahead_depth=(2 if getattr(args, "autonomous_lookahead", False) else 1),
            # W2.2d — opt-in SECOND gated tool: a `declared_service` reachability re-check driven
            # through the full fail-closed invoke_tool chain, folding a LEAD into the world-model.
            # Default off → byte-identical; localhost/authorized-only (an out-of-scope host refuses).
            enable_reachability=bool(getattr(args, "autonomous_reachability", False)),
            # W-C — opt-in DISCOVERY: seed low-prior probe-leaves from world-model ENDPOINT nodes and
            # drive the gated probe_surface tool over them, minting a NEW oracle-confirmed finding
            # only when the wrapped check's oracle fires. Off (no send) → byte-identical.
            enable_discover=bool(getattr(args, "autonomous_discover", False)),
            discover_send=discover_send,
            # Slice-2/3/4 — opt-in discovery depth (all default OFF → byte-identical). --autonomous-
            # crawl-expand crawls each promoted root for its real param-bearing surfaces; --autonomous-
            # multi-probe wraps the curated near-zero-FP multi-class check set; --autonomous-posture
            # chooses whether a probe-leaf is TESTED now (auto-test) or PARKED for operator approval
            # (discover-queue, the SAFE default). --discover-autotest is the explicit opt-in shortcut.
            enable_crawl_expand=bool(getattr(args, "autonomous_crawl_expand", False)),
            enable_multi_probe=bool(getattr(args, "autonomous_multi_probe", False)),
            probe_posture=("auto-test" if getattr(args, "discover_autotest", False)
                           else str(getattr(args, "autonomous_posture", "discover-queue"))),
            blackboard=spine,   # reuse the --spine blackboard as planning substrate + tool sink
            # S9c: thread the run's authoritative dir so the autonomous fusion seam persists any
            # INCONCLUSIVE-COVERAGE manifest under THIS run's dir (env-independent; env is last resort).
            run_dir=_engage_run_dir(),
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
    finally:
        if discover_ex is not None:
            try:
                discover_ex.close()
            except Exception:
                pass


def prompt_callback_from_args(args: argparse.Namespace) -> PromptCallback | None:
    """The operator-confirmation callback the engage destructive-confirm gate uses for a state-changing
    (POST/PUT/DELETE/PATCH — or destructive-by-path) HTTP action.

    DEFAULT (fail-closed): ``--approve-mutations`` absent OR no owner approval authority provisioned ⇒ return
    ``None``. The caller then falls back to its default-deny (``stdin_prompt_with_timeout`` on a non-tty
    returns False, ``run_autonomous_cycle`` treats None as deny), so a destructive action is DENIED and never
    issued. GET (non-destructive) never reaches this callback — it is never gated. This None path is the
    unchanged, safe default.

    APPROVED (opt-in): ``--approve-mutations`` set AND an owner authority is provisioned (its PUBLIC key is
    on disk at ``<base>/approval-authority.json`` — the offense side is KEYLESS) ⇒ return a callback that, on
    a destructive action, wires the EXISTING per-action approval machinery (it reimplements NO crypto):

      1. recover the EXACT ``(method, url, body_sha256)`` the executor is about to issue from the
         destructive-confirm question via :func:`agents.http_executor.parse_destructive_prompt` (the inverse
         of the one formatter that produced it, read from the binding FIRST line only — a byte-for-byte
         binding, never a guess); a parse failure ⇒ DENY;
      2. build ``ApprovalAction(tool_name="engage.http", target=url, action_digest=action_digest(
         "engage.http", url, {"method": method[, "body_sha256": …]}))`` — a body-carrying write
         (``gated_fetch`` → ``_capture`` sends ``content=body``) binds the sha256 of the EXACT transmitted
         bytes, so a token minted for body A can never authorize a different body B on the same (method, url);
         a no-body / query-param write binds ``{"method": …}`` (params ride in the URL = the target). Either
         way this binds the EXACT (tool, target, args);
      3. ``broker.bind(action)`` then ``broker.token_source()`` — publish a public-safe pending request the
         sovereign signer can see, and BLOCK up to the broker's own poll window (``_DEFAULT_WAIT_SECONDS``,
         or ``VIGIL_APPROVAL_WAIT_SECONDS``) for a matching owner-signed token;
      4. ``consume_token(token, action, authority=<pinned owner key>, now, ledger)`` — the SOLE authority:
         it verifies the owner signature, the pinned key-id, the action-binding (``ApprovalToken.matches``),
         the validity/dead-man's window, and ATOMICALLY burns the single-use nonce (O_EXCL check-and-burn);
      5. return ``decision.authorized`` — True only if every check passed.

    A CRUCIBLE deny / tripped kill-switch is refused by ``_run_gates`` BEFORE the destructive prompt, so this
    callback is never even invoked for one — a token can only ADD a gate to an otherwise-in-envelope write; it
    can never override a deny. Any error at any step (missing package, unparseable question, non-serialisable
    args, no/expired/replayed token, broker/burn error, timeout) returns False (DENY): fail-closed throughout.

    FATAL-2 / KEYLESS OFFENSE: the approval machinery is import-clean (``vigil_core`` + stdlib) and holds NO
    private key — only the owner's PUBLIC authority + owner-signed tokens cross the seam. Its imports are
    FUNCTION-LOCAL so the engage module never couples to ``vigil_integration`` at import time."""
    if not getattr(args, "approve_mutations", False):
        return None  # the flag is the explicit opt-in; without it the fail-closed default stands

    # FATAL-2: the per-action approval primitives are the import-clean, framework-free vigil_core+stdlib
    # modules (proven by integration/tests/test_two_env_boundary.py). Import them FUNCTION-LOCALLY — the
    # engage module must not couple framework → vigil_integration at import time. The offense side loads only
    # the PUBLIC authority + verifies/consumes owner-signed tokens; it imports/holds no private key material.
    try:
        import time as _time  # noqa: PLC0415
        from vigil_integration.live.approval_broker import (  # noqa: PLC0415 (FATAL-2: framework-free, keyless)
            ApprovalBroker,
            approvals_root,
            load_authority,
        )
        from vigil_integration.live.approval_token import (  # noqa: PLC0415 (FATAL-2: PUBLIC-key verify only)
            ApprovalAction,
            action_digest,
            consume_token,
        )
        from vigil_integration.live.nonce_ledger import NonceLedger  # noqa: PLC0415 (FATAL-2: stdlib-only)
    except Exception:  # noqa: BLE001 — the approval package unavailable ⇒ keep the fail-closed default (None)
        return None

    # The shared engagement base dir both planes agree on (``vigil up`` exports VIGIL_BASE_DIR for both);
    # matches apps/sigil offense_approvals._base_dir + the console. The authority is the owner's PUBLIC key
    # only (safe to load offense-side); absent/malformed ⇒ None ⇒ the fail-closed default (GET-only) stands.
    base_dir = os.environ.get("VIGIL_BASE_DIR") or ".vigil-live"
    authority = load_authority(base_dir)
    if authority is None:
        return None  # no owner authority provisioned ⇒ fail-closed default (destructive default-deny)

    # ONE single-use nonce ledger, shared with the engine's approval path (``<base>/approval-nonces``), so a
    # token's nonce burned by either path can never be replayed on the other. The broker's is_consumed lets
    # token_source PREFER a live, unspent token over an accumulated spent/expired shadow (consume_token stays
    # the SOLE burn authority). ``now=_time.time`` is the real clock the token dead-man's-switch is checked on.
    nonce_dir = os.environ.get("VIGIL_APPROVAL_NONCE_DIR") or str(Path(base_dir) / "approval-nonces")
    ledger = NonceLedger(nonce_dir)
    broker = ApprovalBroker(approvals_root(base_dir), now=_time.time, is_consumed=ledger.is_consumed)

    def _mutating_approval(question: str, _timeout: float) -> bool:
        # (1) recover the EXACT (method, url, body_sha256) the executor is about to issue — the inverse of the
        # one formatter that produced the question (binding read from the FIRST line only), so the binding is
        # byte-for-byte, never a guess. A body-carrying write carries its sha256; a no-body write carries None.
        parsed = parse_destructive_prompt(question)
        if parsed is None:
            return False  # cannot identify the exact action ⇒ fail-closed DENY (never authorize a guess)
        method, url, body_sha256 = parsed
        # (2) bind the EXACT (tool, target, args-digest). The args-digest carries the method AND — when the
        # write has a body — its sha256, so a token minted for body A can never authorize a DIFFERENT body B
        # on the same (method, url). No body (GET / query-param write) ⇒ {"method": …} ⇒ byte-identical digest.
        try:
            if body_sha256 is None:
                args_for_digest: dict = {"method": method}
                preview: object = {"method": method, "url": url}
            else:
                args_for_digest = {"method": method, "body_sha256": body_sha256}
                # INFORMED CONSENT: the sovereign signer's pending preview is the FULL question — it carries
                # the method, the URL, the bound body-sha256 AND the redacted human body preview, so the owner
                # sees exactly the payload they are authorizing before they sign.
                preview = question
            digest = action_digest("engage.http", url, args_for_digest)
            action = ApprovalAction(tool_name="engage.http", target=url, action_digest=digest)
        except Exception:  # noqa: BLE001 — a non-serialisable/malformed action ⇒ fail-closed DENY
            return False
        # (3) publish the public-safe pending request + BLOCK up to the broker's own poll window for a
        # matching owner-signed token. A broker error ⇒ no token ⇒ DENY.
        try:
            broker.bind(action, args_preview=preview)
            found = broker.token_source()
        except Exception:  # noqa: BLE001 — a broker/publish/poll error leaves the action DENIED (fail-closed)
            return False
        if not (isinstance(found, tuple) and len(found) == 2):
            return False  # no owner-signed token in the window ⇒ stays denied (never issued)
        token, tok_action = found
        # defense-in-depth: the token_source's returned action must be the exact one we bound (the broker
        # returns it, but a caller-supplied source could differ) — any mismatch never authorizes.
        if (getattr(tok_action, "tool_name", None) != "engage.http"
                or getattr(tok_action, "target", None) != url
                or getattr(tok_action, "action_digest", None) != digest):
            return False
        # (4) consume_token is the SOLE authority: signature + pinned key-id + action-binding + window +
        # ATOMIC single-use burn. Any verify/burn error ⇒ DENY (never fail-open on an infra error).
        try:
            decision = consume_token(token, action, authority=authority, now=_time.time(), ledger=ledger)
        except Exception:  # noqa: BLE001 — any verification/burn error ⇒ fail-closed DENY
            return False
        # (5) authorized only if EVERY check passed. This only satisfies the WARDEN human leg for a write the
        # CRUCIBLE gate already put in-envelope; the FACT is still adjudicated by the deterministic oracle.
        return bool(getattr(decision, "authorized", False))

    return _mutating_approval


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 engage",
        description="Authorized, fully-gated end-to-end web engagement (the Wave-1 "
                    "arsenal through the charter/scope/kill-switch/egress stack).",
    )
    parser.add_argument("slug", help="Engagement slug (directs charter, scope, evidence, log).")
    parser.add_argument("seed_url", nargs="?", default=None,
                        help="Absolute seed URL on an in-scope host. Omit ONLY with --fuse-only "
                             "(a seedless cloud/Kubernetes/infra posture run).")
    parser.add_argument("--request-budget", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-audit-requests", type=int, default=0)
    parser.add_argument(
        "--approve-mutations", action="store_true",
        help="Allow a state-changing (POST/PUT/DELETE/PATCH, or destructive-by-path) HTTP action to be "
             "authorized into the run by an OWNER-SIGNED, SINGLE-USE, ACTION-BOUND per-request approval "
             "token. The binding covers (tool, url, method AND the sha256 of the request body), so the owner "
             "sees a redacted preview of the body and a token for one payload can never authorize another. "
             "The owner signs on the sovereign/SIGIL side; the offense side stays keyless. Requires an "
             "approval authority to be provisioned (its PUBLIC key under $VIGIL_BASE_DIR). WITHOUT this flag "
             "(the default) a destructive action is fail-closed DENIED; a GET is never gated either way.")
    parser.add_argument("--bandit-file", default=None,
                        help="Persist/warm-start the self-learning check-ordering bandit.")
    parser.add_argument("--profile", choices=ENGAGEMENT_PROFILES, default="surface",
                        help="Engagement ROSTER profile (a PURE flag-expansion; no oracle, no relaxed "
                             "gate). 'surface' (default) = today's roster, unchanged. 'deep' = also the "
                             "opt-in browser passes (--domxss/--browser-xss) + --sso + --graphql-dos. "
                             "'full' = deep + the operator-spec-gated packs whose flags exist "
                             "(--access-control; still a no-op without --ac-ref, so no finding is "
                             "fabricated). It only turns EXISTING flags ON (an explicit --flag always "
                             "wins); plan-named packs with no flag yet are reported deferred. The "
                             "resolved profile + roster are recorded to <run_dir>/_engagement_profile.json.")
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
    parser.add_argument("--resume", action="store_true",
                        help="RESUME a prior run of this slug from its phase ledger "
                             "(targets/<slug>/<slug>.phases.jsonl): reload the prior run's "
                             "snapshotted SCAN report and skip re-crawling/re-auditing the target. "
                             "It is NOT a skip-everything shortcut: only the traffic-sending scan's "
                             "WORK is skipped (its report is reloaded). The veracity firewall and "
                             "every other pure-reasoning phase (finding-confidence, chaining, "
                             "grounding, fusion, defender) ALWAYS re-run over the reloaded report — "
                             "so a resumed report is re-verified (oracle contexts re-fire) and its "
                             "derived fields (fused leads/facts, defense) are recomputed, never a "
                             "stale snapshot. The re-run phases that also WRITE to the event spine "
                             "(fusion, defender; the reasoning pass is skipped outright) suppress "
                             "their spine RE-EMIT for any phase the original run already recorded "
                             "there, so their events are NOT double-counted on the append-only "
                             "stream. A scan that only started/failed (crashed before completing) is "
                             "retried; preflight authorization ALWAYS re-runs. Fail-open: a "
                             "missing/corrupt ledger just re-runs from scratch. Applies to the web "
                             "engage path (not --fuse-only).")
    parser.add_argument("--ephemeral", action="store_true",
                        help="EPHEMERAL / ZDR session (opt-in; persist-by-default). Re-root the "
                             "run's evidence archive + audit log onto an in-memory tmpfs dir that "
                             "is PURGED (and its absence verified) on exit; SUPPRESS every "
                             "persistent writer that can't be tmpfs-redirected (the on-disk "
                             "spine, the learned bandit, the outcome ledger); and FORCE the "
                             "sovereignty ZDR/local tier (consumer Anthropic + Claude Code refused; "
                             "anthropic-zdr / local preferred). Charter/scope reads are unaffected — "
                             "an ephemeral run still reads its real charter and stays in scope.")
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
                             "confirms it. Off by default (0 sensors) = byte-identical. AUTO-ENABLED "
                             "when a targets/<slug>/fusion.json manifest is present (NW-3).")
    parser.add_argument("--fuse-only", action="store_true",
                        help="SEEDLESS fusion-only engagement (slice C2b — cloud / Kubernetes / infra "
                             "POSTURE). Runs ONLY the operator's declared sensor fusion "
                             "(targets/<slug>/fusion.json: cloud_import / kube_bench / declared_service …) "
                             "and their deterministic promotion oracles (plus the C4 lateral-path pass), "
                             "with NO web seed and NO crawl / recon / scan. Takes NO seed_url. Still "
                             "requires a signed charter for <slug> (like a remote engage); every sensor "
                             "is still gated at run time (kill-switch/entitlement/scope/egress). Honest "
                             "empty when no fusion.json / the sensors no-op — nothing is fabricated.")
    parser.add_argument("--no-fuse-sensors", action="store_true",
                        help="Force sensor fusion OFF even when a targets/<slug>/fusion.json manifest "
                             "exists (the explicit opt-OUT that overrides NW-3's auto-enable-by-manifest-"
                             "presence). The default (manifest-absent) path is byte-identical either way.")
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
    parser.add_argument("--autonomous-reachability", action="store_true",
                        help="Let the --autonomous loop also drive a gated `declared_service` "
                             "reachability re-check of the engagement host (a SECOND gated tool "
                             "beyond reverify_finding). It runs through the FULL fail-closed chain "
                             "(kill-switch/entitlement/scope/destructive/egress) — an out-of-scope "
                             "host or a tripped kill-switch REFUSES it — and folds its output into "
                             "the world-model as intel-tier LEADS, never facts (only an oracle "
                             "promotes). Off by default (byte-identical).")
    parser.add_argument("--autonomous-discover", action="store_true",
                        help="DISCOVER (opt-in; requires --autonomous): the first honest step from a "
                             "re-verifying loop toward a DISCOVERING one. Seed LOW-prior probe-leaves "
                             "from world-model ENDPOINT nodes and drive the gated `probe_surface` tool "
                             "over them — it runs ONE existing scanner check (REFLECTED_XSS) through a "
                             "FRESH gated executor (full kill-switch/scope/egress/rate stack) and mints "
                             "a NEW oracle-confirmed finding ONLY when that check's oracle FIRES. "
                             "Localhost/authorized only; an out-of-scope endpoint or a tripped kill-"
                             "switch REFUSES the probe. Off by default (byte-identical); the "
                             "authoritative scan report is never mutated (discovered facts are "
                             "reported separately + on the spine).")
    parser.add_argument("--autonomous-crawl-expand", action="store_true",
                        help="EXPAND (opt-in; on top of --autonomous-discover): crawl each promoted/"
                             "discovered ROOT endpoint (bounded, scope-from-seed, over the same gated "
                             "send) and mint the discovered in-scope PARAM-BEARING surfaces as testable "
                             "endpoints — so a discovered host is not just reached but its real pages/"
                             "parameters are tested. Off by default (byte-identical).")
    parser.add_argument("--autonomous-multi-probe", action="store_true",
                        help="Probe each discovered surface with the CURATED near-zero-FP multi-class "
                             "check set (reflected-XSS + open-redirect + path-traversal + SSTI + "
                             "boolean-SQLi) instead of reflected-XSS only — one probe tests several bug "
                             "classes, each oracle-adjudicated. Off by default (byte-identical).")
    parser.add_argument("--autonomous-posture", choices=("discover-queue", "auto-test"),
                        default="discover-queue",
                        help="Whether an autonomously-discovered probe-leaf is TESTED now (`auto-test`) "
                             "or PARKED for operator approval (`discover-queue`, the SAFE DEFAULT — "
                             "enumeration/promotion/crawl run autonomously, but zero probe traffic is "
                             "issued until you approve a batch). Every probe is fully gated in BOTH "
                             "postures; discover-queue simply keeps a human on the ACT trigger.")
    parser.add_argument("--discover-autotest", action="store_true",
                        help="Shortcut for --autonomous-posture auto-test: actively test discovered "
                             "surfaces within charter scope (bounded, gated, oracle-adjudicated). "
                             "Explicit opt-in — the default parks discoveries for your approval.")
    parser.add_argument("--autonomous-lookahead", action="store_true",
                        help="Use bounded MULTI-STEP lookahead (depth-2) for --autonomous action "
                             "selection instead of one-step greedy (default off = byte-identical). "
                             "Lookahead picks the action that begins the best budget-feasible plan "
                             "toward a crown-jewel objective — committing a tight budget to COMPLETING "
                             "an affordable attack route rather than chasing the single highest-scoring "
                             "off-route leaf. Still gated, still deterministic; it only re-ranks which "
                             "open leaf runs next and never promotes a finding.")
    parser.add_argument("--learn", action="store_true",
                        help="LEARN (opt-in): persist this run's learning so the NEXT run warms up — the "
                             "Thompson effort-ranking bandit (targets/<slug>/bandit.json, warm-started + "
                             "saved across runs) AND, under --autonomous, the confirm/refute OutcomeLedger "
                             "(targets/<slug>/outcomes.json) the meta-monitor reads next run. Off by default "
                             "(it mutates the target dir). Non-circular: a single-oracle reverify is "
                             "DISPUTED never a fact, and the bandit only RE-RANKS effort — it never promotes "
                             "a finding or gates a surface out.")
    args = parser.parse_args(argv)

    # Slice 0.2 — expand the engagement PROFILE into existing enable_* flags (PURE: only turns flags ON;
    # an explicit --flag always survives; no oracle, no relaxed gate). Record what was flipped + which
    # plan-named packs have no flag yet, and tell the operator so the deferred roster is visible.
    args._profile_enabled_flags, args._profile_deferred = resolve_profile(args.profile, args)
    if args.profile != "surface":
        _flipped = ", ".join(f"--{d.replace('_', '-')}" for d in args._profile_enabled_flags) or "(none new)"
        print(f"profile: {args.profile} → enabled {_flipped} "
              "(flag-expansion only; no oracle added, no gate relaxed).")
    if args._profile_deferred:
        print(f"note: profile '{args.profile}' names packs with no enable flag yet (deferred to a later "
              f"wave): {', '.join(args._profile_deferred)}. The profile enabled only the flags that "
              "exist — it did not invent these packs.")

    # NW-3: auto-enable sensor fusion when the operator has authored a targets/<slug>/fusion.json
    # manifest (opt-in-by-presence), unless --no-fuse-sensors forces it off. Manifest-absent + no
    # flag ⇒ stays False ⇒ byte-identical default path (the benchmark/gate never reaches main()).
    args.fuse_sensors, args._fuse_sensors_auto = _resolve_fuse_sensors(
        args.slug, fuse_sensors=args.fuse_sensors, no_fuse_sensors=args.no_fuse_sensors)

    if args.access_control and not args.ac_ref:
        print("note: --access-control set but no --ac-ref supplied; the access-control pack "
              "needs operator victim references (bug_class:ref_param:victim_ref) and runs no "
              "checks without them.")

    # D2 EPHEMERAL / ZDR: persist-by-default; only under --ephemeral. Suppress every
    # persistent writer that CANNOT be tmpfs-redirected (the on-disk spine/blackboard, the
    # learned bandit, the outcome ledger) by forcing their flags off here — BEFORE the spine
    # is opened. The evidence archive + audit log are re-rooted onto the purged tmpfs write-
    # root by the ephemeral_session context in _engage_body; the ZDR tier is forced there too.
    if args.ephemeral:
        args.spine = False
        args.bandit_file = None
        args.learn = False

    spine = None
    if args.spine:
        try:
            from .agents.blackboard import open_blackboard
            spine = open_blackboard()
        except Exception:
            spine = None   # spine is opt-in telemetry; never block the engagement on it

    # Slice C2b — the SEEDLESS fusion-only branch: a cloud/Kubernetes/infra posture run has no web seed
    # and never enters the web-scan path below. It has its OWN fail-closed preflight (kill-switch +
    # signed charter, inside run_fusion_only). Placed BEFORE the seed-URL requirement so the URL is
    # genuinely optional here; honors --ephemeral exactly like the web path (tmpfs write-root + ZDR).
    if args.fuse_only:
        if args.ephemeral:
            from .common.ephemeral import ephemeral_session
            with ephemeral_session() as _sess:
                print(f"  ephemeral/ZDR     : ON (tier {_sess.forced_tier}; tmpfs write-root "
                      f"purged on exit; spine/bandit/outcomes suppressed)")
                return _run_fuse_only_cli(args, spine)
        return _run_fuse_only_cli(args, spine)
    if not args.seed_url:
        print("engage: seed_url is required (an absolute in-scope URL). For a seedless cloud / "
              "Kubernetes / infra posture run, pass --fuse-only instead.")
        return 2

    if args.ephemeral:
        from .common.ephemeral import ephemeral_session
        with ephemeral_session() as _sess:
            print(f"  ephemeral/ZDR     : ON (tier {_sess.forced_tier}; tmpfs write-root "
                  f"purged on exit; spine/bandit/outcomes suppressed)")
            return _engage_body(args, spine)
    return _engage_body(args, spine)


def _learn_bandit_path(slug: str) -> str:
    """P5 — the per-target persistent Thompson bandit under ``--learn``. WebScanCampaign warm-starts it at a
    run's start (``_resolve_bandit`` loads the file if present) and saves it at the end, so effort-ranking
    learns ACROSS engagements automatically. Non-circular: the bandit only re-ranks/defers effort — it never
    promotes a finding, gates a surface out, or feeds an oracle/SCE input."""
    from .common import paths
    return str(paths.target_dir(slug) / "bandit.json")


def _resolve_bandit_path(bandit_file: str | None, learn: bool, slug: str) -> str | None:
    """The bandit-persistence rule (P5): an explicit ``--bandit-file`` wins; else ``--learn`` auto-persists a
    per-target bandit (warm-start + save across runs); else None (no persistence — the --ephemeral / default
    path). Pure so the auto-loop rule is unit-testable without a full engagement."""
    if bandit_file:
        return bandit_file
    if learn:
        return _learn_bandit_path(slug)
    return None


def _engage_body(args: argparse.Namespace, spine: object) -> int:
    """Run the engagement and print its report. Split out of ``main`` so it can run either
    directly (persisting) or inside the ``ephemeral_session`` context (tmpfs + ZDR) without
    duplicating the ~120-line report renderer."""
    # P5 auto-loop: ``--learn`` auto-persists the Thompson bandit per target (warm-start + save across runs),
    # so cross-engagement effort-ranking learns WITHOUT the operator managing ``--bandit-file``. This closes
    # the bandit half of the loop (the OutcomeLedger→calibrator half already auto-closes under --learn). An
    # explicit ``--bandit-file`` still wins; ``--ephemeral`` already forced both off before this point.
    _bandit_path = _resolve_bandit_path(args.bandit_file, getattr(args, "learn", False), args.slug)
    try:
        result = run_engagement(
            args.slug, args.seed_url,
            spine=spine,
            # Per-action mutating-proof approval (opt-in via --approve-mutations). None (the default) ⇒
            # run_engagement falls back to its stdin default-deny, so a destructive action stays fail-closed;
            # a valid owner-signed single-use token authorizes exactly that one write. GET is never gated.
            prompt_callback=prompt_callback_from_args(args),
            request_budget=args.request_budget,
            max_pages=args.max_pages,
            max_audit_requests=args.max_audit_requests,
            bandit_path=_bandit_path,
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
            resume=getattr(args, "resume", False),
            profile=getattr(args, "profile", "surface"),
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
    from .scanner.report import coverage_line
    print(f"  {coverage_line(report)}")
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
        if getattr(args, "_fuse_sensors_auto", False):
            # NW-3: fusion was auto-enabled purely by the operator's manifest — say so, and how to opt out.
            print(f"  fusion active     : ({result.fused_leads} leads) — targets/{args.slug}/fusion.json "
                  f"(auto-enabled by manifest; --no-fuse-sensors to disable)")
        print(f"  fused sensors     : {result.fused_leads} lead(s) folded, "
              f"{result.fused_facts} oracle-promoted fact(s) "
              f"(from targets/{args.slug}/fusion.json; leads stay leads, oracles prove facts)")
    # Opt-in AUTONOMOUS OODA cycle (default OFF → this whole block is skipped and the engagement is
    # byte-identical). It runs AFTER the authoritative scan/report has already been PRINTED. Under
    # --autonomous-discover it folds newly-discovered oracle-confirmed findings into the IN-MEMORY
    # result.report.active_findings (deterministic + deduped, for downstream consumers / the spine);
    # the already-printed report and the byte-identical default/benchmark path are unaffected.
    if getattr(args, "autonomous", False):
        try:
            _run_autonomous(args, result, spine)
        except EngagementRefused as e:
            # W16-2 (LOW): the autonomous DISCOVERY leg refused because an EngagementAuthority is
            # provisioned but no governance trust root is discoverable to verify it. Surface it as a
            # clean fail-closed refusal (matching the scan-path handler) rather than let the resolver's
            # authorization refusal be swallowed into a silent discovery-skip. The already-printed
            # authoritative scan/report above is unaffected; the non-zero exit flags the refusal.
            print(f"engagement refused (autonomous discovery): {e}")
            return 2
    return 0
