"""oracle_families — H7: integrate discovery tools by SHARED ORACLE FAMILY, not per tool.

THE DEFECT this closes (Part II / H7 of the STRIX+HEXSTRIKE plan). FACT-capability and the
tool→verifier mapping were decided PER TOOL: ``brains/hexstrike_body._ORACLE_MAPPED_TOOLS`` was a flat
hand-maintained frozenset, and every new tool meant editing that set plus a bespoke ``_spec_for_kind``
branch. That is exactly the "many registries share no key" defect H4 fights, one level up: whether a tool
can mint a FACT is not a property of the TOOL, it is a property of the VIGIL VERIFIER FAMILY the tool feeds.
nmap, masscan, rustscan and naabu are not four independent integrations — they are four PROPOSERS for ONE
verifier (VIGIL's own gated ``capture_handshake`` → ``SERVICE_REACHABILITY``). Integrating "by family"
makes that explicit: a family owns the verifier and the fact-capability; a tool merely joins a family.

THE MODEL. Every discovery/assessment tool belongs to at most one :class:`OracleFamily`. A family names:

  * the ONE VIGIL-owned verifier that re-drives the family's proposals (service-reachability, the gated web
    re-drive, the bug-class verifier, the differential/control re-drive, TLS negotiation, source-to-sink,
    the artifact-scoped posture branches, controlled secret validation, DOM achieved-state);
  * whether that verifier is FACT-capable — i.e. VIGIL owns a re-drive that crosses ``verdict.admit()`` and
    mints a signed FACT (network-discovery, web-discovery and TLS today; the rest are LEAD-only);
  * the member tools that PROPOSE into it.

THE TWO LOAD-BEARING RULES (the authority ladder, unchanged):

  1. **Emit LEADs by default.** Routing a tool to its family verifier does NOT mint anything. A FACT is
     minted ONLY by VIGIL's own runner-owned re-drive (``live.external_tool.run_external_tool`` /
     ``live.web_redrive``) crossing ``verdict.admit()`` over its OWN gated capture — and even for a
     FACT-capable family that re-drive path is DEFAULT-OFF / flag-gated (``VIGIL_FAMILY_REDRIVE``), never a
     side effect of routing (see :func:`route` / :func:`redrive_flag_enabled`).

  2. **Agreement raises PRIORITY, never mints.** When several tools in the SAME family agree on the SAME
     observation, that agreement is a stronger reason to LOOK — it raises the resulting lead's priority — but
     it is NEVER evidence: N scanners agreeing is still N say-sos, and a say-so is a LEAD. :func:`fuse`
     returns :class:`FamilyVote`\\ s whose ``verdict`` is the LITERAL ``"LEAD"``, so no count of agreeing
     tools can ever compose into a FACT. This is the structural form of "scanner report → LEAD only".

vigil_core + stdlib ONLY — no framework import (FATAL-2 safe): this module is pure routing DATA + pure
functions, loadable in either env. It decides WHERE a tool routes and how agreement re-prioritises a lead;
it never runs a tool, never captures, never mints.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional


# The environment flag that gates whether a FACT-capable family's tool is ELIGIBLE for VIGIL's own
# runner-owned re-drive at all. DEFAULT-OFF per the checkpoint: absent/empty ⇒ routing emits LEADs only and
# marks nothing mint-eligible. The flag never mints by itself — it only lets the SEPARATE, gated runner path
# (run_external_tool → verdict.admit) become eligible; approval / entitlement / scope still apply there.
_REDRIVE_FLAG = "VIGIL_FAMILY_REDRIVE"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True)
class OracleFamily:
    """One shared VIGIL verifier family: the verifier, its fact-capability, and the tools that propose into
    it. ``verifier`` is the VIGIL-owned decision procedure the family routes to (an ``OracleKind`` member
    name for a single-oracle family, or an umbrella id like ``"bug_class"`` / ``"posture"`` for a family
    that dispatches over several posture/per-class oracles — documented in ``notes``). ``fact_capable`` is
    TRUE iff VIGIL owns a runner re-drive for this family that crosses ``verdict.admit()`` and mints a signed
    FACT; it is a property of the FAMILY, never of an individual tool. ``tools`` are the member PROPOSERS —
    joining a family is how a tool acquires (at most) its family's verifier, never a bespoke per-tool mint."""

    name: str
    verifier: str
    fact_capable: bool
    tools: tuple[str, ...]
    notes: str = ""


# ---------------------------------------------------------------------------
# THE FAMILY REGISTRY — the single source of truth for tool → verifier routing (H7).
#
# Membership rationale (kept honest, one line each):
#   * network_discovery — port / host / subdomain / SMB-service discovery. ONE verifier: VIGIL's own gated
#     TCP handshake (SERVICE_REACHABILITY). FACT-capable: the port scanners carry NO tool-supplied verdict —
#     the runner re-proves each proposed port with its own handshake (H5). Non-port members (subfinder /
#     amass / arp-scan / nbtscan / autorecon / enum4linux-ng / smbmap) are LEAD-only proposers in the SAME
#     family (no wired spec builder yet), which is exactly the point: fact-capability is the family's, and a
#     member gains it only when a runner-owned spec builder exists (see oracle_mapped_tools()).
#   * web_discovery — URL / content / parameter discovery over HTTP. ONE verifier: the gated web re-drive
#     (ACHIEVED_STATE, live.web_redrive). FACT-capable via the runner's OWN crafted, gated HTTP probe.
#   * scanners — template / signature scanners. Verifier: the bug-class verifier (dispatches the reported
#     class to VIGIL's per-class re-drive). NOT fact-capable from the tool: a scanner match is a LEAD; only a
#     VIGIL re-drive of the specific class mints.
#   * injection — injection / param-fuzz tools. Verifier: VIGIL's differential/control re-drive
#     (DIFFERENTIAL_RESPONSE). NOT fact-capable from the tool (sqlmap is EXCLUDED offense — never run; VIGIL
#     owns SQLi/XSS confirmation via its own differential probe).
#   * tls — TLS scanners. ONE verifier: VIGIL's gated TLS handshake (TLS_WEAKNESS). FACT-capable (slice 4).
#   * source — static / binary analysis. Verifier: source-to-sink. Local analysis; LEAD-only here.
#   * posture — cloud / IaC / K8s / SCA. Verifier: the EXISTING artifact-scoped posture branches (an umbrella
#     over CLOUD_POSTURE / K8S_POSTURE / VERSION_RANGE, dispatched by artifact type). LEAD-only from the tool.
#   * secrets — secret scanners. Verifier: VIGIL's controlled secret validation (SECRET_CREDENTIAL_VALIDITY).
#     LEAD-only from the tool.
#   * browser — headless browsers / DOM tools. Verifier: DOM achieved-state (DOM_EXECUTION). FACT-capable via
#     VIGIL's OWN egress-gated CDP re-drive (dom_execution / prototype_pollution), reached from the proof-sink
#     dispatch rail + engage re-drive — NOT via a tool spawn, so chromium/playwright are LEAD-only proposers
#     with no spec builder (excluded from oracle_mapped_tools), exactly like network_discovery's non-port
#     members.
#
# EXCLUDED pure-offense binaries (metasploit, pwntools, angr, hydra, john, …) belong to NO discovery family:
# family_for() returns None for them. They are not proposers of a verifiable observation, and the manifest's
# ``excluded`` flag (tool_manifest.py) — not this registry — keeps them out of any plan.
# ---------------------------------------------------------------------------
FAMILY_REGISTRY: tuple[OracleFamily, ...] = (
    OracleFamily(
        name="network_discovery",
        verifier="SERVICE_REACHABILITY",
        fact_capable=True,
        tools=("nmap", "masscan", "rustscan", "naabu", "zmap", "unicornscan", "arp-scan", "nbtscan",
               "subfinder", "amass", "autorecon", "enum4linux-ng", "smbmap"),
        notes="Proposers of open ports / live hosts / subdomains / SMB services; VIGIL re-proves each with "
              "its own gated TCP handshake (capture_handshake). FACT-capable via the runner's re-drive.",
    ),
    OracleFamily(
        name="web_discovery",
        verifier="ACHIEVED_STATE",
        fact_capable=True,
        tools=("httpx", "katana", "gau", "waybackurls", "gobuster", "ffuf",
               "feroxbuster", "dirsearch", "paramspider", "x8"),
        notes="Proposers of URLs / content / params; VIGIL re-drives its OWN crafted gated HTTP probe "
              "(live.web_redrive) and the ACHIEVED_STATE oracle judges the response. FACT-capable via re-drive.",
    ),
    OracleFamily(
        name="scanners",
        verifier="bug_class",
        fact_capable=False,
        tools=("nuclei", "nikto", "jaeles", "wpscan"),
        notes="Template / signature scanners. A match is a LEAD; the bug-class verifier dispatches the "
              "reported class to VIGIL's per-class re-drive, which is the only thing that can mint.",
    ),
    OracleFamily(
        name="injection",
        verifier="DIFFERENTIAL_RESPONSE",
        fact_capable=False,
        tools=("sqlmap", "dalfox", "arjun"),
        notes="Injection / param tools. sqlmap is EXCLUDED offense (never run). VIGIL confirms injection "
              "with its OWN differential/control re-drive — a tool's finding is a LEAD.",
    ),
    OracleFamily(
        name="tls",
        verifier="TLS_WEAKNESS",
        fact_capable=True,
        tools=("sslscan",),
        notes="TLS scanners. VIGIL negotiates its OWN bounded gated TLS handshake (capture_tls_handshake) "
              "and the weak-tls / weak-crypto oracles judge the negotiated params + presented cert.",
    ),
    OracleFamily(
        name="source",
        verifier="source_to_sink",
        fact_capable=False,
        tools=("gdb",),
        notes="Static / binary analysis (Semgrep / Joern / Bandit / gdb). Local-analysis proposals routed "
              "to the source-to-sink verifier; LEAD-only here.",
    ),
    OracleFamily(
        name="posture",
        verifier="posture",
        fact_capable=False,
        tools=("prowler", "scout-suite", "checkov", "terrascan", "trivy", "grype",
               "kube-bench", "kube-hunter"),
        notes="Cloud / IaC / K8s / SCA scanners. Routed to the EXISTING artifact-scoped posture branches "
              "(CLOUD_POSTURE / K8S_POSTURE / VERSION_RANGE by artifact type). LEAD-only from the tool.",
    ),
    OracleFamily(
        name="secrets",
        verifier="SECRET_CREDENTIAL_VALIDITY",
        fact_capable=False,
        tools=("trufflehog", "gitleaks"),
        notes="Secret scanners. A hit is a LEAD; VIGIL's controlled validation of the candidate credential "
              "against its provider is the FACT path (not covered by the current catalogue).",
    ),
    OracleFamily(
        name="browser",
        verifier="DOM_EXECUTION",
        fact_capable=True,
        tools=("chromium", "playwright"),
        notes="Headless browsers / DOM tools. FACT-capable via VIGIL's OWN egress-gated headless-Chromium/CDP "
              "re-drive (JS actually EXECUTED in a real DOM — the dom_execution / prototype_pollution "
              "achieved-state oracles), reached from the Strix proof-sink dispatch rail "
              "(proof/run.py:_dom_redrive_mint → live.dom_redrive) and the engage re-drive "
              "(wiring.py:_redrive_branch_for). chromium/playwright are LEAD-only PROPOSERS in this family: "
              "they carry NO runner-owned spec builder because VIGIL drives its OWN CDP harness, never the "
              "tool's argv — so they are excluded from oracle_mapped_tools (a builder is what makes a MEMBER "
              "mint-eligible, and the family's FACT path here is the CDP re-drive, not a tool spawn). Same "
              "shape as network_discovery's non-port proposers.",
    ),
)


# name -> OracleFamily, and tool -> OracleFamily, built once. A tool appearing in two families is a
# registry bug (routing must be unambiguous) — _build_index raises fail-closed if that ever happens.
def _build_index() -> tuple[dict[str, OracleFamily], dict[str, OracleFamily]]:
    by_family: dict[str, OracleFamily] = {}
    by_tool: dict[str, OracleFamily] = {}
    for fam in FAMILY_REGISTRY:
        if fam.name in by_family:
            raise ValueError(f"duplicate oracle family {fam.name!r} in FAMILY_REGISTRY")
        by_family[fam.name] = fam
        for t in fam.tools:
            if t in by_tool:
                raise ValueError(
                    f"tool {t!r} is claimed by two families ({by_tool[t].name!r} and {fam.name!r}) — "
                    f"routing must be unambiguous (a tool feeds exactly one shared verifier)")
            by_tool[t] = fam
    return by_family, by_tool


_BY_FAMILY, _BY_TOOL = _build_index()


# ---------------------------------------------------------------------------
# Routing — tool → family → verifier.
# ---------------------------------------------------------------------------
def families() -> tuple[OracleFamily, ...]:
    """The registered families (the routing SSOT)."""
    return FAMILY_REGISTRY


def family_for(tool: str) -> Optional[OracleFamily]:
    """The :class:`OracleFamily` this tool proposes into, or ``None`` for a tool in no discovery family
    (an EXCLUDED pure-offense binary, or a name the registry does not know)."""
    return _BY_TOOL.get((tool or "").strip())


def verifier_for(tool: str) -> str:
    """The VIGIL-owned verifier this tool routes to, or ``""`` when the tool is in no family."""
    fam = family_for(tool)
    return fam.verifier if fam else ""


def is_fact_capable_family(tool: str) -> bool:
    """True iff this tool's FAMILY is FACT-capable (VIGIL owns a re-drive that can mint for the family).
    NOTE: family fact-capability is necessary, not sufficient, for THIS tool to mint — see
    :func:`oracle_mapped_tools` (a member also needs a wired runner-owned spec builder)."""
    fam = family_for(tool)
    return bool(fam and fam.fact_capable)


def redrive_flag_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """Whether the DEFAULT-OFF ``VIGIL_FAMILY_REDRIVE`` flag is set truthy. Absent/empty ⇒ False, so family
    routing emits LEADs only and marks nothing mint-eligible unless an operator opts the re-drive path in."""
    e = os.environ if env is None else env
    return str(e.get(_REDRIVE_FLAG, "")).strip().lower() in _TRUTHY


@dataclass(frozen=True)
class RouteDecision:
    """The routing decision for one tool. ``verdict`` is ALWAYS ``"LEAD"``: routing never mints — a FACT is
    minted only by VIGIL's own runner-owned re-drive crossing ``verdict.admit()``. ``mint_via_redrive`` says
    whether this tool's family is FACT-capable AND the DEFAULT-OFF re-drive flag is enabled, i.e. whether the
    SEPARATE, gated runner re-drive is even ELIGIBLE to run for it — it is never itself a mint."""

    tool: str
    family: str
    verifier: str
    fact_capable_family: bool
    mint_via_redrive: bool
    verdict: str
    reason: str


def route(tool: str, *, redrive_enabled: Optional[bool] = None,
          env: Optional[Mapping[str, str]] = None) -> RouteDecision:
    """Route ``tool`` to its family verifier and decide its DEFAULT emission.

    Emit-LEADs-by-default (rule 1): ``verdict`` is always ``"LEAD"``. ``mint_via_redrive`` is True ONLY when
    the tool's family is FACT-capable AND the re-drive flag is enabled — and even then it merely marks the
    SEPARATE runner re-drive eligible; the FACT is minted there (over VIGIL's own gated capture, through
    admit()), never by this routing call. ``redrive_enabled`` overrides the flag for testing; otherwise the
    DEFAULT-OFF ``VIGIL_FAMILY_REDRIVE`` env flag decides (so the re-drive path stays off by default)."""
    fam = family_for(tool)
    if fam is None:
        return RouteDecision(tool=tool, family="", verifier="", fact_capable_family=False,
                             mint_via_redrive=False, verdict="LEAD",
                             reason="tool is in no discovery oracle family (excluded/unknown) — LEAD-only")
    re = redrive_flag_enabled(env) if redrive_enabled is None else bool(redrive_enabled)
    mint = fam.fact_capable and re
    if not fam.fact_capable:
        reason = f"family {fam.name!r} is LEAD-only (no VIGIL FACT re-drive for {fam.verifier!r})"
    elif not re:
        reason = (f"family {fam.name!r} is FACT-capable via {fam.verifier!r}, but the runner re-drive is "
                  f"DEFAULT-OFF ({_REDRIVE_FLAG} unset) — routing emits a LEAD")
    else:
        reason = (f"family {fam.name!r} FACT-capable via {fam.verifier!r}; runner re-drive ELIGIBLE "
                  f"({_REDRIVE_FLAG} set) — the FACT is still minted only by that gated re-drive, not here")
    return RouteDecision(tool=tool, family=fam.name, verifier=fam.verifier,
                         fact_capable_family=fam.fact_capable, mint_via_redrive=mint,
                         verdict="LEAD", reason=reason)


# ---------------------------------------------------------------------------
# Voting — agreement raises PRIORITY, never mints (rule 2).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ToolObservation:
    """One tool's say-so about one thing: which ``tool`` proposed it, the ``observation_key`` it is about
    (an insertion point / URL / port / bug-class — whatever makes "the same observation" identifiable), and
    the ``base_priority`` the planner assigned (lower = higher priority, the AttackStep convention)."""

    tool: str
    observation_key: str
    base_priority: int = 100


@dataclass(frozen=True)
class FamilyVote:
    """The fused lead for one (family, observation) that ≥1 tool proposed. ``verdict`` is the LITERAL
    ``"LEAD"`` — a vote can NEVER become a FACT no matter how many tools agree (rule 2). ``priority`` is
    raised (numerically lowered, bounded ≥1) by one step per ADDITIONAL agreeing distinct tool beyond the
    first; ``agreeing_tools`` is the sorted distinct set that voted."""

    family: str
    verifier: str
    observation_key: str
    agreeing_tools: tuple[str, ...]
    priority: int
    verdict: str = "LEAD"      # STRUCTURAL: never anything else — see fuse(). A vote is not evidence.

    @property
    def is_fact(self) -> bool:
        return False           # a vote is never a fact, by construction

    @property
    def agreement(self) -> int:
        """How many DISTINCT tools agreed (1 = a lone proposer, no priority raise)."""
        return len(self.agreeing_tools)


def raised_priority(base_priority: int, agreement: int) -> int:
    """Priority after agreement: one step higher (numerically lower) per additional agreeing tool beyond the
    first, floored at 1. ``agreement<=1`` ⇒ the base is unchanged. Pure and deterministic (no wallclock)."""
    return max(1, int(base_priority) - max(0, int(agreement) - 1))


def fuse(observations: Iterable[ToolObservation]) -> list[FamilyVote]:
    """Fuse per-tool observations into per-(family, observation) LEADs, raising priority on agreement.

    Grouping is by (family, observation_key): observations from tools in the SAME family about the SAME thing
    are one lead whose priority is raised by the number of DISTINCT agreeing tools. Observations from tools
    in DIFFERENT families never fuse (they route to different verifiers), and a tool in NO family is dropped
    from voting (it has no verifier to raise priority toward — it stays a plain LEAD elsewhere).

    Determinism: the base priority for a group is the MINIMUM base over its observations (the most urgent
    proposer wins the base), then :func:`raised_priority` lowers it by the distinct-tool count. Output is
    sorted by (priority asc, family, observation_key) — total and stable, no wallclock / RNG.

    THE INVARIANT (rule 2): every returned :class:`FamilyVote` has ``verdict == "LEAD"``. Agreement — even
    unanimous agreement across a FACT-CAPABLE family — raises priority and NEVER mints. Minting is the
    runner-owned re-drive's job alone (over VIGIL's own gated capture, through admit())."""
    groups: dict[tuple[str, str], dict] = {}
    for obs in observations:
        fam = family_for(obs.tool)
        if fam is None:
            continue  # no family ⇒ no shared verifier to vote toward
        key = (fam.name, obs.observation_key)
        g = groups.get(key)
        if g is None:
            g = {"family": fam, "tools": set(), "base": int(obs.base_priority)}
            groups[key] = g
        g["tools"].add(obs.tool)
        g["base"] = min(g["base"], int(obs.base_priority))

    votes: list[FamilyVote] = []
    for (fam_name, obs_key), g in groups.items():
        fam: OracleFamily = g["family"]
        tools = tuple(sorted(g["tools"]))
        votes.append(FamilyVote(
            family=fam_name, verifier=fam.verifier, observation_key=obs_key,
            agreeing_tools=tools, priority=raised_priority(g["base"], len(tools)),
            verdict="LEAD"))
    votes.sort(key=lambda v: (v.priority, v.family, v.observation_key))
    return votes


# ---------------------------------------------------------------------------
# The runner-owned ToolSpec builders — the SINGLE source of truth for "VIGIL can build + drive this
# tool's argv itself", shared by every registry that needs it.
# ---------------------------------------------------------------------------
# These are the tools with a wired runner-owned ToolSpec builder in ``live.external_tool`` (reached via
# ``brains.hexstrike_body._spec_for_kind``): VIGIL constructs their argv SERVER-SIDE, pins the host to the
# scope-authorised target, validates the ports schema, gates the spawn, and re-proves each proposal with its
# OWN oracle re-drive. That is a real, validated, gated argv builder — the STRONG "control via CLI" proof —
# exactly like the live executor's typed ``_BUILDERS``, only via the R4 runner path instead of the governed
# executor. Defined HERE (framework-free, FATAL-2-safe, importable in either env) so the two consumers can
# never drift apart from a duplicated literal:
#   * ``brains.hexstrike_body`` — derives ``_ORACLE_MAPPED_TOOLS = oracle_mapped_tools(SPEC_BUILDER_TOOLS)``
#     (a builder + a FACT-capable family ⇒ FACT-capable; the builder alone never mints).
#   * ``live.capability_join.resolve`` — folds this set into its builder source, so a port scanner that IS
#     spawnable + FACT-capable via the R4 runner is no longer mis-reported "no typed argv builder / can never
#     run" merely because it is absent from the governed executor's ``_BUILDERS``.
# Kept in lock-step with ``hexstrike_body._spec_for_kind`` by
# ``test_oracle_mapped_tools_all_have_a_spec_builder_no_drift`` (every mapped tool must build a spec).
# W2 DOWNGRADE: httpx and ffuf are deliberately ABSENT. They DO have runner-owned ToolSpec builders
# (``external_tool.httpx_url_scan`` / ``ffuf_content_scan``) and the web re-drive still runs for them as a
# LEAD ENRICHER (dispatched by ``hexstrike_body._LEAD_ENRICHER_TOOLS``), but after five adversarial rounds
# the ``achieved_state.endpoint_liveness`` branch is LEAD-only PERMANENTLY. ``oracle_mapped_tools`` derives
# "can mint a FACT" from this set, so membership here would assert the opposite of what the branch registry
# now declares. A builder is not a mint.
SPEC_BUILDER_TOOLS: "frozenset[str]" = frozenset({"nmap", "sslscan", "masscan", "rustscan", "naabu",
                                                  "zmap", "unicornscan"})


# ---------------------------------------------------------------------------
# Derivation — the body's FACT-capable set is a FAMILY property, not a hand-kept list.
# ---------------------------------------------------------------------------
def oracle_mapped_tools(spec_builder_tools: Iterable[str]) -> "frozenset[str]":
    """The tools that can mint a FACT: those with a runner-owned spec builder AND whose FAMILY is
    FACT-capable. This is what ``brains/hexstrike_body._ORACLE_MAPPED_TOOLS`` derives from — so
    FACT-capability is a FAMILY property (a member of a FACT-capable family that acquires a spec builder is
    automatically FACT-capable), not a flat set edited per tool.

    A spec-builder tool whose family is NOT fact-capable, or which is in no family, is deliberately EXCLUDED
    here: a builder alone does not make a FACT — the family must own a re-drive that crosses admit().

    The CONVERSE also holds and is load-bearing: a member of a FACT-capable family that has NO spec builder is
    EXCLUDED (it is not in ``spec_builder_tools``). This keeps the invariant honest for the ``browser`` family
    — FACT-capable via VIGIL's OWN CDP re-drive (dom_execution / prototype_pollution), NOT via a tool spawn —
    whose members (chromium / playwright) carry no runner-owned argv builder: they never enter this derived
    set, so a fact_capable MATRIX tool is still only ever one that BOTH has a wired spec builder AND belongs
    to a fact_capable family. The browser family's FACT path is the proof-sink / engage CDP re-drive, reached
    without any tool argv — the same "the family owns the verifier, a member joins it" split as
    network_discovery's non-port proposers."""
    return frozenset(
        t for t in {str(x) for x in spec_builder_tools}
        if is_fact_capable_family(t)
    )


# ---------------------------------------------------------------------------
# Cross-check — the family registry must not contradict the capability matrix (H4 join, one level up).
# ---------------------------------------------------------------------------
def validate_family_routing(manifests: Iterable) -> list[str]:
    """Return violations (empty ⇒ sound) between the family registry and the capability matrix rows
    (``tool_manifest.ToolManifest``). Pure structure; no framework import.

    Rules:
      * Every NON-EXCLUDED, catalogued tool must route to a family — a discovery tool with no shared
        verifier is exactly the per-tool scatter H7 removes (excluded offense tools are exempt: they route
        nowhere by design).
      * Every ``fact_capable`` matrix tool must belong to a ``fact_capable`` family whose verifier matches
        the row's ``oracle_family`` (case-insensitive) — the matrix may not claim a FACT the family cannot
        mint, and the two registries must agree on WHICH verifier mints it.
    """
    errs: list[str] = []
    for m in manifests:
        name = getattr(m, "name", "")
        excluded = bool(getattr(m, "excluded", False))
        fam = family_for(name)
        if fam is None:
            if not excluded:
                errs.append(
                    f"{name}: catalogued and NOT excluded but routes to NO oracle family — every discovery "
                    f"tool must feed a shared verifier (add it to a family in FAMILY_REGISTRY)")
            continue
        if bool(getattr(m, "fact_capable", False)):
            if not fam.fact_capable:
                errs.append(
                    f"{name}: matrix marks it fact_capable but its family {fam.name!r} is LEAD-only — the "
                    f"matrix outruns the family registry")
            declared = str(getattr(m, "oracle_family", "") or "").lower()
            if declared and declared != fam.verifier.lower():
                errs.append(
                    f"{name}: matrix oracle_family {declared!r} != family {fam.name!r} verifier "
                    f"{fam.verifier.lower()!r} — the registries disagree on which verifier mints its FACT")
    return errs
