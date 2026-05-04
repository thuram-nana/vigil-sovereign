"""
backends.fixtures — DryRun fixture providers per schema.

When the active backend is DryRun, URK calls a per-schema fixture
provider to produce a deterministic Pydantic instance from the
structured input. The output is *not* claimed to match what a live
LLM would produce; it is a plausible baseline derived from the v1
prose's own examples and a small static catalogue of canonical
patterns.

Bindings register providers via @register("SchemaName"). New schemas
without a registered provider get a generic minimal-valid synthesis
that is enough to keep tests green; bindings should always provide
their own fixture so the output is useful in addition to valid.

The catalogues below are extracted from the cognitive layer's own
worked examples (hypothesis-driven.md § 1, threat-modeling.md § 6,
pivot-protocols.md § 2-9, decision-frameworks.md § 1).
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel

from ..models import (
    Actor,
    Asset,
    AttackTreeNode,
    CritiqueResult,
    HypothesisSet,
    Hypothesis,
    LateralMove,
    Objection,
    OpsecGuidance,
    PivotProposal,
    SeverityDecision,
    StrideThreat,
    ThreatModel,
    TrustBoundary,
)


FixtureProvider = Callable[[type[BaseModel], dict[str, Any]], BaseModel]
_REGISTRY: dict[str, FixtureProvider] = {}


def register(name: str) -> Callable[[FixtureProvider], FixtureProvider]:
    def deco(fn: FixtureProvider) -> FixtureProvider:
        _REGISTRY[name] = fn
        return fn
    return deco


def get_provider(name: str) -> FixtureProvider:
    if name in _REGISTRY:
        return _REGISTRY[name]
    return _generic_provider


def _generic_provider(schema: type[BaseModel], _inp: dict[str, Any]) -> BaseModel:
    """Last-resort: build a minimal valid instance via Pydantic defaults.
    Most schemas in URK have required fields, so this rarely succeeds —
    the right fix is to register a binding-specific fixture."""
    return schema()  # raises ValidationError if required fields exist


# ---------------------------------------------------------------------------
# HypothesisSet — bug-class catalogue
# ---------------------------------------------------------------------------


_BUG_CLASS_CATALOGUE: list[dict[str, str]] = [
    {
        "bug_class": "IDOR",
        "given": "a low-priv authenticated session",
        "if": "GET {surface} with another user's identifier substituted in path or query",
        "then": "the response returns the other user's resource (200 + body)",
        "because": (
            "the controller likely authenticates the session but does not "
            "check that the authenticated user owns the requested resource"
        ),
        "refute_on": "response is 403/404 with no resource body leak",
        "cheap_test": "swap the resource id and replay; diff status and length against baseline",
    },
    {
        "bug_class": "mass-assignment",
        "given": "a low-priv authenticated session and a profile-like writable endpoint",
        "if": "PUT {surface} with extra fields role=admin, is_admin=true, balance=999999",
        "then": "the field is bound; subsequent GET shows the field changed or admin endpoints succeed",
        "because": (
            "the controller may bind request fields to the user model "
            "without an explicit allowlist (Laravel $fillable, Rails strong-params)"
        ),
        "refute_on": "fields silently dropped; subsequent GET shows fields unchanged",
        "cheap_test": "single PUT with payload, then GET to verify",
    },
    {
        "bug_class": "race",
        "given": "an action that checks-then-acts on a balance/refund/coupon",
        "if": "fire 20 concurrent requests against {surface} on a single HTTP/2 connection",
        "then": "two or more requests succeed; the post-condition violates the invariant",
        "because": "the check and the act are not atomic in DB or app code",
        "refute_on": "exactly one request succeeds; others 4xx/5xx; invariant holds",
        "cheap_test": "framework/scripts/race/race-balance.py with concurrency=20",
    },
    {
        "bug_class": "SSRF",
        "given": "an endpoint that accepts a URL field (avatar, webhook test, import)",
        "if": "submit {surface} pointing to 169.254.169.254/latest/meta-data/ or http://localhost:6379/",
        "then": "the response includes content from the internal target",
        "because": (
            "URL handling on the server may not validate the destination "
            "against a deny-list of internal/cloud-metadata addresses"
        ),
        "refute_on": "response is generic error; OAST callback never fires",
        "cheap_test": "framework/scripts/api/ssrf-probe.py with cloud + bypass payload sets",
    },
    {
        "bug_class": "auth-bypass",
        "given": "an admin or privileged endpoint exists at a guessable path",
        "if": "request {surface} with path normalisation tricks and header tricks (X-Original-URL, X-Forwarded-For)",
        "then": "endpoint returns content not normally accessible to this role",
        "because": (
            "auth check may be implemented at a proxy or middleware that "
            "does not normalise the URL/headers identically to the app"
        ),
        "refute_on": "every variant returns identical 401/403 to baseline",
        "cheap_test": "curl with X-Original-URL header rewrite of the admin path",
    },
    {
        "bug_class": "SQLi",
        "given": "a parameter that touches a query (search, sort, filter, id)",
        "if": "submit {surface} with a single-quote / boolean / time-based payload",
        "then": "response timing or body diverges from baseline measurably",
        "because": "the parameter may concatenate into SQL without parameterisation",
        "refute_on": "all payloads return identical response; no error leakage",
        "cheap_test": "boolean A vs A' diff, then time-based confirmation",
    },
    {
        "bug_class": "business-logic",
        "given": "an operation that takes numeric / state inputs",
        "if": "submit {surface} with negative quantity, zero, very large value, or skipped state transitions",
        "then": "the operation succeeds in a way that violates the intended invariant",
        "because": "the developer assumed clients send valid values; no server-side bounds check",
        "refute_on": "server rejects with 400 and no state change",
        "cheap_test": "single request with each boundary value; verify invariant after",
    },
]


@register("HypothesisSet")
def _hypothesis_set_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    surface = inp.get("surface") or "(unspecified surface)"
    observation = inp.get("observation") or "(no observation provided)"

    hypotheses: list[Hypothesis] = []
    for i, t in enumerate(_BUG_CLASS_CATALOGUE[:5]):
        hypotheses.append(
            Hypothesis.model_validate(
                {
                    "id": f"H-{i + 1:03d}",
                    "surface": surface,
                    "bug_class": t["bug_class"],
                    "given": t["given"],
                    "if": t["if"].replace("{surface}", surface),
                    "then": t["then"],
                    "because": t["because"],
                    "refute_on": t["refute_on"],
                    "cheap_test": t["cheap_test"].replace("{surface}", surface),
                    "confidence": 0.4,
                }
            )
        )
    return HypothesisSet(
        observation=observation,
        hypotheses=hypotheses,
        notes=(
            "DryRun fixture: hypotheses synthesised from a static bug-class "
            "catalogue, surface-substituted from the input. Reasoning "
            "quality bounded — see V2-LIMITATIONS.md."
        ),
    )


# ---------------------------------------------------------------------------
# CritiqueResult — heuristic decision based on claim shape
# ---------------------------------------------------------------------------


_CONFIRM_KEYWORDS = ("reproduced", "working poc", "confirmed", "evidence at", "twice")
_NEEDS_MORE = ("probably", "looks like", "i think", "seems", "might", "maybe")


@register("CritiqueResult")
def _critique_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    claim = inp.get("claim", "")
    cl = claim.lower()

    if any(k in cl for k in _CONFIRM_KEYWORDS) and len(claim) > 60:
        decision = "confirm"
        objections: list[Objection] = []
    elif any(k in cl for k in _NEEDS_MORE) or len(claim) < 40:
        decision = "more_evidence_needed"
        objections = [
            Objection(
                concern="Claim is hedged or under-specified.",
                severity="major",
                evidence_request="Reproduce twice; capture request/response; isolate the trigger.",
            )
        ]
    else:
        decision = "objections"
        objections = [
            Objection(
                concern="Reproducibility not demonstrated.",
                severity="major",
                evidence_request="Reproduce on a fresh session; confirm specificity.",
            ),
            Objection(
                concern="Impact not quantified.",
                severity="minor",
                evidence_request="State concrete data exposed / privilege gained / dollars moved.",
            ),
        ]

    return CritiqueResult(
        claim=claim,
        decision=decision,
        drift_detected=False,
        deception_check=(
            "Operator may be reading the response generously; verify by "
            "running the negative-control variant that should NOT trigger."
        ),
        coverage_gaps=[],
        objections=objections,
        one_more_thread=(
            "Try the same payload with one parameter set to the boundary "
            "value (empty / null / very long / unicode)."
        ),
    )


# ---------------------------------------------------------------------------
# PivotProposal — lateral moves
# ---------------------------------------------------------------------------


_LATERAL_MOVES: list[dict[str, Any]] = [
    {
        "kind": "surface",
        "suggestion": (
            "Walk adjacent surfaces of the same bug class — ticket subjects, "
            "profile names, CSV/Excel exports, search reflections, header echoes."
        ),
        "rationale": (
            "Hardening clusters around obvious surfaces (login, primary CRUD); "
            "adjacent surfaces are typically softer."
        ),
        "estimated_effort": "minutes",
        "confidence": 0.6,
    },
    {
        "kind": "class",
        "suggestion": (
            "Pivot to a different bug class on the same surface — auth-bypass "
            "even after SQLi failed; race after IDOR refuted; SSTI on apparent SQLi."
        ),
        "rationale": (
            "Surfaces hardened against one class are often soft against another; "
            "fewest preconditions cost the least to test."
        ),
        "estimated_effort": "minutes",
        "confidence": 0.55,
    },
    {
        "kind": "adversary",
        "suggestion": (
            "Switch to a financially-motivated criminal lens — exhaust money flow: "
            "balance, refund, coupon, deposit, withdrawal, payment-webhook surfaces."
        ),
        "rationale": (
            "On commerce platforms, money-flow chains pay off when info-leak chains stall."
        ),
        "estimated_effort": "hours",
        "confidence": 0.7,
    },
    {
        "kind": "layer",
        "suggestion": (
            "Drop a layer — TLS/HTTP smuggling, request interpretation, "
            "load-balancer behaviour, WAF-vs-app divergence."
        ),
        "rationale": (
            "Bugs operators fear most often live at a layer they did not consider."
        ),
        "estimated_effort": "hours",
        "confidence": 0.45,
    },
    {
        "kind": "operator",
        "suggestion": (
            "Ask the operator: feature you might have missed (admin tool, "
            "batch job, scheduled task, internal-only endpoint, third-party integration)."
        ),
        "rationale": (
            "Black-box can't infer features that aren't exposed in UI; the "
            "operator built the system."
        ),
        "estimated_effort": "minutes",
        "confidence": 0.65,
    },
]


@register("PivotProposal")
def _pivot_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    moves = [LateralMove(**m) for m in _LATERAL_MOVES]
    return PivotProposal(
        stuck_thread=inp.get("stuck_thread", "(unspecified thread)"),
        last_observation=inp.get("last_observation", ""),
        moves=moves,
        recommended=2,  # adversary pivot — empirically the highest-yield reset
    )


# ---------------------------------------------------------------------------
# SeverityDecision — heuristic CVSS-like scoring
# ---------------------------------------------------------------------------


_SEVERITY_KEYWORDS: list[tuple[str, str, float, str]] = [
    # (keyword,                severity,    cvss_base, rationale)
    ("rce",                    "Critical",  9.8, "remote code execution"),
    ("remote code execution",  "Critical",  9.8, "remote code execution"),
    ("account takeover",       "Critical",  9.1, "ATO at scale"),
    ("mass account",           "Critical",  9.1, "ATO at scale"),
    ("balance",                "High",      8.0, "money-flow integrity"),
    ("payment",                "High",      8.0, "money-flow integrity"),
    ("webhook",                "High",      7.5, "webhook forgery"),
    ("sql injection",          "High",      8.5, "SQLi"),
    ("sqli",                   "High",      8.5, "SQLi"),
    ("idor",                   "High",      6.5, "horizontal authz"),
    ("ssrf",                   "High",      8.0, "SSRF reaches metadata"),
    ("xss",                    "Medium",    6.1, "stored/reflected XSS"),
    ("csrf",                   "Medium",    6.5, "CSRF"),
    ("information disclosure", "Low",       3.7, "info disclosure"),
    ("verbose error",          "Low",       3.1, "error verbosity"),
    ("missing header",         "Low",       3.1, "header hardening"),
]


@register("SeverityDecision")
def _decide_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    summary = inp.get("finding_summary", "")
    s = summary.lower()
    sev: str = "Medium"
    base = 5.0
    rat = "default heuristic"
    for kw, label, score, why in _SEVERITY_KEYWORDS:
        if kw in s:
            sev, base, rat = label, score, why
            break

    likelihood = "high" if "no auth" in s or "unauthenticated" in s else "medium"
    impact = "high" if sev in ("Critical", "High") else "medium" if sev == "Medium" else "low"
    immediate = sev == "Critical" or "credential" in s or "key leaked" in s
    worth = "finding" if sev != "Info" else "engagement_log_only"

    return SeverityDecision(
        finding_summary=summary,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if sev == "Critical" else
                     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        cvss_base=base,
        severity=sev,  # type: ignore[arg-type]
        contextual_note=(
            f"DryRun fixture severity heuristic matched on {rat!r}. A live "
            "backend would weigh product-specific impact."
        ),
        likelihood=likelihood,  # type: ignore[arg-type]
        impact=impact,  # type: ignore[arg-type]
        worth_reporting=worth,  # type: ignore[arg-type]
        immediate_surface_to_operator=immediate,
        chain_candidates=[],
        regulator_paragraph=(
            f"Without this fix, an attacker could exploit '{summary}' "
            f"with low effort and no privilege.  Severity: {sev}.  "
            f"Estimated impact: {impact}."
        ),
    )


# ---------------------------------------------------------------------------
# OpsecGuidance — posture-aware boilerplate
# ---------------------------------------------------------------------------


@register("OpsecGuidance")
def _opsec_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    posture = inp.get("posture", "TEST").upper()
    if posture not in ("TEST", "AUDIT", "EMULATE"):
        posture = "TEST"
    action = inp.get("action_summary", "(unspecified action)")
    a = action.lower()

    # truly destructive operations — refused outright in any posture (§ 7).
    destructive = any(kw in a for kw in (
        "delete from", "drop table", "truncate", "shutdown",
        "rm -rf", "mkfs", "os-shell", "--os-pwn", "file-write", "rce",
        "webshell", "modify core", "wipe",
    ))
    # actions touching real users (§ 2.4 — never in any posture).
    real_user_contact = any(kw in a for kw in (
        "password reset to real", "email to real user", "sms to real",
        "notification to real", "real customer", "live payment",
    ))
    # heavy / state-change-at-scale — allowed but requires pre-approval (§ 2.3).
    heavy = any(kw in a for kw in (
        "brute-force", "brute force", "ffuf", "sqlmap",
        "mass account", "mass order", "100k", "10k", "high-rate",
        "force-browse",
    ))

    allowed = not destructive and not real_user_contact
    pre_approval = destructive or real_user_contact or heavy
    pre_reason = None
    if destructive:
        pre_reason = "destructive action; refused under § 7 absolutes"
    elif real_user_contact:
        pre_reason = "would contact real users; refused under § 2.4"
    elif heavy:
        pre_reason = "heavy / state-change-at-scale; needs pre-approval per § 2.3"

    if posture == "EMULATE":
        ua = "Mozilla/5.0 (per-actor signature; see opsec-discipline.md § 4.1)"
        rate = "spread over time; mimic real adversary cadence"
    elif posture == "AUDIT":
        ua = "OBSIDIAN/1.0 (audit-mode <date>)"
        rate = "concurrency 3-5; document every action with control reference"
    else:
        ua = "OBSIDIAN/1.0 (authorized owner-test <date>)"
        rate = "concurrency 5-10; respect 429; off-peak for heavy scans"

    return OpsecGuidance(
        action_summary=action,
        posture=posture,  # type: ignore[arg-type]
        allowed=allowed,
        pre_approval_required=pre_approval,
        pre_approval_reason=pre_reason,
        user_agent_recommendation=ua,
        rate_limit_recommendation=rate,
        cleanup_required=(
            ["track in notes/test-artifacts.md"] if posture == "TEST" else []
        ),
        log_to_command_log=True,
        notes=(
            f"DryRun fixture: posture-keyed boilerplate. Live backend would "
            f"weigh action-specific risk against the v1 § 7 absolutes."
        ),
    )


# ---------------------------------------------------------------------------
# ThreatModel — minimal-but-valid baseline derived from the input
# ---------------------------------------------------------------------------


@register("ThreatModel")
def _threat_model_fixture(schema: type[BaseModel], inp: dict[str, Any]) -> BaseModel:
    target = inp.get("target_name") or inp.get("target") or "(target)"
    archetype = inp.get("archetype", "")
    business_context = inp.get("business_context") or (
        f"Target {target}. Archetype: {archetype or 'unspecified'}. "
        "DryRun fixture; refine with live LLM or by hand."
    )

    assets = [
        Asset(
            id="A1", name="User account integrity",
            rationale="Direct user harm; the takeover surface lives here.",
            confidentiality="high", integrity="high", availability="low",
            priority="P0",
        ),
        Asset(
            id="A2", name="Underlying server / database",
            rationale="Catastrophic; web-shell, mass DB exfil possible if reached.",
            confidentiality="critical", integrity="critical", availability="medium",
            priority="P0",
        ),
        Asset(
            id="A3", name="Operator admin credentials",
            rationale="Final gate; if compromised the platform falls in one step.",
            confidentiality="critical", integrity="critical", availability="medium",
            priority="P0",
        ),
    ]
    actors = [
        Actor(id="T1", name="Credential-stuffer", goal="ATO via reused creds",
              skill="novice", motivation="opportunistic"),
        Actor(id="T2", name="Targeted ATO crew", goal="Specific user takeover",
              skill="journeyman", motivation="motivated"),
        Actor(id="T3", name="Drained-balance fraud", goal="Free balance via payment forgery",
              skill="journeyman", motivation="motivated"),
    ]
    boundaries = [
        TrustBoundary(
            name="Anonymous → web app",
            data_crossing="Unauthenticated requests",
            auth_check="Per-route auth middleware",
            failure_mode="Unauthorised access to authenticated functionality",
        ),
        TrustBoundary(
            name="User → admin",
            data_crossing="Privileged actions",
            auth_check="Role check in controller",
            failure_mode="Vertical privilege escalation",
        ),
    ]
    stride = [
        StrideThreat(
            boundary="Anonymous → web app", stride_class="S",
            threat="Spoofing via credential stuffing or reset token abuse",
            realistic=True,
        ),
        StrideThreat(
            boundary="User → admin", stride_class="E",
            threat="Mass-assignment of role on profile update",
            realistic=True,
        ),
    ]
    tree = AttackTreeNode(
        label="Take over a customer account",
        children=[
            AttackTreeNode(label="Credential stuffing", is_leaf=True),
            AttackTreeNode(label="Password reset abuse", is_leaf=True),
            AttackTreeNode(label="Session token weakness", is_leaf=True),
            AttackTreeNode(label="OAuth misuse (if integrated)", is_leaf=True),
            AttackTreeNode(label="MFA bypass (if enforced)", is_leaf=True),
        ],
    )
    return ThreatModel(
        business_context=business_context,
        assets=assets, actors=actors,
        trust_boundaries=boundaries,
        stride_threats=stride,
        attack_tree=tree,
        catastrophic_outcomes=[
            "Mass user account takeover with balance drain.",
            "Free balance creation via payment forgery.",
            "Operator account takeover leading to platform compromise.",
        ],
        not_in_model=[
            "Nation-state-grade adversary (not the realistic top threat).",
            "Physical access to operator's machine.",
        ],
    )
