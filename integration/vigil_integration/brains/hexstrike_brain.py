"""hexstrike_brain — a clean-room, DRIFT-FREE reimplementation of hexstrike-ai's deterministic decision
model, as a PROPOSE-ONLY VIGIL brain.

Design credit: hexstrike-ai (c) 2026 Muhammad Osama / 0x4m4, MIT — vendored (non-runnable) under
``vendor/hexstrike-ai/`` with the upstream line ranges this adapts:
``IntelligentDecisionEngine`` (hexstrike_server.py:572), ``_initialize_tool_effectiveness`` (:581),
``_initialize_attack_patterns`` (:698), ``TargetProfile`` (:473), ``select_optimal_tools`` (:971),
``create_attack_chain`` (:1462). This is a REIMPLEMENTATION of the design, not a copy of the upstream
module (which hard-imports flask/selenium/mitmproxy at module scope and cannot be imported here), and it
is CURATED for VIGIL's invariants — the upstream's evasion/stealth, credential-poisoning (responder
LLMNR/WPAD), WAF-tamper, and live-exploit/persistence stages are REMOVED by construction, not stripped
after the fact.

WHAT THIS IS: given a ``TargetProfile`` (assembled from VIGIL's own gated sensors/oracle observations —
NOT from network calls or URL-string guesses), it PROPOSES which recon/assessment tools to run, with what
parameters, in what order — each as a LEAD. It has:
  * ZERO network side effects (no DNS/socket/requests — the upstream's analyze_target->gethostbyname is
    removed; IPs are passed in from charter/sensors).
  * ZERO evasion (no stealth/proxy/VPN/IP-rotation/WAF-tamper knobs — a runtime guard rejects any that
    ever appear in a proposed parameter set).
  * ZERO fact authority (it proposes; the oracle confirms; the gate authorizes).
  * only stdlib imports.

The AgentBody that wires this to the conjunctive gate + gated runner + oracle is ``hexstrike_body``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class TargetType(str, Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"


class TechnologyStack(str, Enum):
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"


class ToolDanger(str, Enum):
    """VIGIL danger class for a proposed tool — drives WARDEN tiering. RECON is read/scan-oriented
    (auto-eligible only in STAGING/TWIN); ACTIVE mutates/probes offensively (always QUEUE for owner
    approval on a live target). The brain NEVER proposes an EXPLOIT/POISONING tool."""
    RECON = "recon"
    ACTIVE = "active"


# Curated tool -> danger class. Upstream tools that VIGIL forbids a brain from proposing — responder
# (LLMNR/NBT-NS/WPAD credential poisoning), the pwntools/angr/ropper live-exploit chains, pacu
# (cloud exploitation), netexec/hydra credential attacks by default — are simply ABSENT from this map,
# so the brain cannot select them. (VIGIL owns any such capability elsewhere, behind its own gate+oracle.)
_TOOL_DANGER: dict[str, ToolDanger] = {
    # recon / passive-ish scan
    "nmap": ToolDanger.RECON, "httpx": ToolDanger.RECON, "katana": ToolDanger.RECON,
    "gau": ToolDanger.RECON, "waybackurls": ToolDanger.RECON, "subfinder": ToolDanger.RECON,
    "amass": ToolDanger.RECON, "arp-scan": ToolDanger.RECON, "nbtscan": ToolDanger.RECON,
    "rustscan": ToolDanger.RECON, "masscan": ToolDanger.RECON, "naabu": ToolDanger.RECON,
    "autorecon": ToolDanger.RECON, "paramspider": ToolDanger.RECON,
    # TLS posture (read-only assessment): the runner re-drives its OWN gated handshake and judges a weak
    # protocol/cipher (weak_tls) or a broken-hash cert (weak_crypto_artifact) — never sslscan's rows.
    "sslscan": ToolDanger.RECON,
    # active assessment (mutating/probing — QUEUE on live)
    "nuclei": ToolDanger.ACTIVE, "gobuster": ToolDanger.ACTIVE, "ffuf": ToolDanger.ACTIVE,
    "feroxbuster": ToolDanger.ACTIVE, "dirsearch": ToolDanger.ACTIVE, "nikto": ToolDanger.ACTIVE,
    "sqlmap": ToolDanger.ACTIVE, "dalfox": ToolDanger.ACTIVE, "arjun": ToolDanger.ACTIVE,
    "wpscan": ToolDanger.ACTIVE, "jaeles": ToolDanger.ACTIVE, "x8": ToolDanger.ACTIVE,
    "enum4linux-ng": ToolDanger.ACTIVE, "smbmap": ToolDanger.ACTIVE,
    # cloud/container/iac posture scanners (read-only assessment)
    "prowler": ToolDanger.RECON, "scout-suite": ToolDanger.RECON, "trivy": ToolDanger.RECON,
    "checkov": ToolDanger.RECON, "terrascan": ToolDanger.RECON, "kube-bench": ToolDanger.RECON,
    "kube-hunter": ToolDanger.ACTIVE,
}

# Any proposed parameter carrying one of these tokens is an EVASION/OFFENSE-DRIFT knob VIGIL forbids.
# This is a fail-closed runtime guard (defence in depth): the curated tables below never set these, and
# this regex ensures a future edit cannot reintroduce one without a test catching it.
_EVASION_TOKENS = re.compile(
    r"(?i)(stealth|tamper|--proxy|\bproxy\b|\bvpn\b|rotate|evade|evasion|obfuscat|space2comment|"
    r"randomiz|decoy|spoof|frag|nse_scripts.*exploit)"
)


class Objective(str, Enum):
    """What the planner is being asked to do — a CLOSED set, because the label must equal the behaviour.

    Only the objectives the planner ACTUALLY implements are members. ``create_attack_chain`` branches on
    exactly one distinction — whether the vulnerability-assessment playbook is appended to the target-type
    playbook — so there are exactly two. Adding ``cloud``/``source``/``api``/``network`` members that all
    fall through to the same plan would re-create, in a new form, the very defect this enum fixes: a chain
    labelled one thing and built as another. Those objectives are planner work, not enum work.

    (Target TYPE already selects the cloud/api/network playbook — see ``create_attack_chain``'s
    ``pattern_key``. The objective is orthogonal: it says how thorough to be, not what kind of target.)
    """

    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"


DEFAULT_OBJECTIVE = Objective.COMPREHENSIVE


def parse_objective(value: "str | Objective | None", *,
                    default: Objective = DEFAULT_OBJECTIVE) -> Objective:
    """Normalise an objective, and REFUSE an unknown one rather than silently planning something else.

    The defect this exists to kill: ``--objective`` defaulted to ``""``; ``create_attack_chain`` tested
    ``objective == "comprehensive"``; so the shipped default silently produced the SHORT plan while the
    chain, the docs and the persisted proposal all called it "comprehensive". Anything unrecognised now
    raises instead of quietly degrading, and an empty value resolves to the documented default.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    if isinstance(value, Objective):
        return value
    try:
        return Objective(str(value).strip().lower())
    except ValueError:
        accepted = ", ".join(o.value for o in Objective)
        raise ValueError(
            f"unknown brain objective {value!r} — accepted: {accepted}. "
            "(The free-text ENGAGEMENT goal is a different flag: --objective. The planner objective is "
            "--brain-objective.)"
        ) from None


class DriftError(Exception):
    """A proposed action carried an evasion/offense-drift knob — fail-closed."""


@dataclass
class TargetProfile:
    """A profile of the target, assembled from VIGIL's gated observations (never from network calls here).
    Adapts hexstrike_server.py:473 TargetProfile, minus any field the upstream populated by probing."""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    technologies: list[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target, "target_type": self.target_type.value,
            "ip_addresses": list(self.ip_addresses), "open_ports": list(self.open_ports),
            "services": {str(k): v for k, v in self.services.items()},
            "technologies": [t.value for t in self.technologies],
            "cms_type": self.cms_type, "cloud_provider": self.cloud_provider,
            "attack_surface_score": self.attack_surface_score, "risk_level": self.risk_level,
            "confidence_score": self.confidence_score,
        }


@dataclass
class AttackStep:
    """One proposed step — a tool + parameters + priority. Carries no authority (adapts :512)."""
    tool: str
    priority: int
    params: dict[str, Any] = field(default_factory=dict)
    danger: ToolDanger = ToolDanger.ACTIVE
    effectiveness: float = 0.0

    def to_dict(self) -> dict:
        return {"tool": self.tool, "priority": self.priority, "params": dict(self.params),
                "danger": self.danger.value, "effectiveness": self.effectiveness}


@dataclass
class AttackChain:
    """An ordered proposal of steps (adapts AttackChain :522). success_probability is the compound
    product of per-step effectiveness*confidence — a PRIOR for ranking, never a fact."""
    target: str
    objective: str
    steps: list[AttackStep] = field(default_factory=list)
    success_probability: float = 0.0

    def calculate_success_probability(self, confidence: float) -> float:
        p = 1.0
        for s in self.steps:
            p *= max(0.0, min(1.0, s.effectiveness * confidence)) if s.effectiveness else 1.0
        self.success_probability = round(p, 4)
        return self.success_probability

    def to_dict(self) -> dict:
        return {"target": self.target, "objective": self.objective,
                "steps": [s.to_dict() for s in self.steps],
                "success_probability": self.success_probability}


def proposal_document(profile: "TargetProfile", steps: "list[AttackStep]", *,
                      objective: str = "comprehensive", posture: str = "live",
                      capabilities: "Mapping[str, Mapping[str, Any]] | None" = None) -> dict:
    """Serialise a REAL brain proposal to the exact ``brain-proposal.json`` shape the console reads
    (``framework.v2.console.api.brain_decision``): ``{target, objective, posture, profile, steps}``, with
    the per-step ``{tool, priority, params, danger, effectiveness}`` and the profile ``.to_dict()`` fields
    the Brain-screen decision panel renders. ONE serialiser, used by the producer that persists a proposal
    (``engine_think.BrainThink``), so the persisted proposal is BYTE-for-byte what the brain proposed — the
    panel can never show a chain that differs from the one the engine drove. Pure: it invents nothing,
    computes no facts, and reflects only the profile + steps handed to it (both carry no authority).

    ``capabilities`` — OPTIONAL capability annotation, a ``{tool -> {status, reason}}`` map (as produced by
    ``live.capability_join`` and folded to ``{r.name: {"status": r.status, "reason": r.reason}}``). When
    provided, EVERY serialised step gains a ``capability`` field ``{"status": …, "reason": …}`` looked up by
    the step's ``tool``, so the panel can render WHY a proposed tool is executable / blocked / unavailable
    rather than the plan quietly listing a step that can never run. A tool ABSENT from the map is annotated
    ``{"status": "UNAVAILABLE", "reason": "capability unknown"}`` — never silently un-annotated. This stays
    PURE: the annotation is a straight lookup over the caller's own data; nothing here probes a host or
    computes a status. DEFAULT ``None`` ⇒ NO step carries a ``capability`` key, so the output is
    BYTE-IDENTICAL to before this parameter existed."""
    step_dicts: list[dict] = []
    for s in steps:
        d = s.to_dict()
        if capabilities is not None:
            cap = capabilities.get(d["tool"])
            if cap is None:
                d["capability"] = {"status": "UNAVAILABLE", "reason": "capability unknown"}
            else:
                d["capability"] = {"status": cap.get("status"), "reason": cap.get("reason")}
        step_dicts.append(d)
    return {
        "target": profile.target,
        "objective": objective,
        "posture": posture,
        "profile": profile.to_dict(),
        "steps": step_dicts,
    }


class HexstrikeBrain:
    """Deterministic, propose-only decision brain. No network, no evasion, no fact authority."""

    def __init__(self) -> None:
        self.tool_effectiveness = self._tool_effectiveness()
        self.attack_patterns = self._attack_patterns()

    # ---- data tables (adapted + curated from hexstrike_server.py:581 / :698) --------------------
    def _tool_effectiveness(self) -> dict[str, dict[str, float]]:
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8, "httpx": 0.85, "katana": 0.88, "nuclei": 0.95, "gobuster": 0.9,
                "ffuf": 0.9, "feroxbuster": 0.85, "dirsearch": 0.87, "nikto": 0.85, "sqlmap": 0.9,
                "dalfox": 0.93, "arjun": 0.9, "paramspider": 0.85, "x8": 0.88, "jaeles": 0.92,
                "wpscan": 0.95, "gau": 0.82, "waybackurls": 0.8, "sslscan": 0.78,
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95, "rustscan": 0.9, "masscan": 0.92, "naabu": 0.9, "autorecon": 0.95,
                "enum4linux-ng": 0.88, "smbmap": 0.85, "nbtscan": 0.75, "arp-scan": 0.85, "amass": 0.7,
                "sslscan": 0.72,
            },
            TargetType.API_ENDPOINT.value: {
                "httpx": 0.9, "nuclei": 0.9, "arjun": 0.95, "x8": 0.92, "paramspider": 0.88,
                "katana": 0.85, "ffuf": 0.85, "jaeles": 0.88, "sslscan": 0.75,
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95, "scout-suite": 0.92, "trivy": 0.9, "checkov": 0.9, "terrascan": 0.88,
                "kube-bench": 0.88, "kube-hunter": 0.9,
            },
            TargetType.UNKNOWN.value: {"nmap": 0.8, "httpx": 0.7, "nuclei": 0.7},
        }

    def _attack_patterns(self) -> dict[str, list[dict[str, Any]]]:
        """Curated, recon/assessment-only playbooks (adapts :698). The upstream's
        comprehensive_network_pentest (responder poisoning + nse vuln/exploit), binary_exploitation /
        ctf_pwn (pwntools/angr exploit chains), and bug_bounty_high_impact (WAF-tamper, blind custom
        payloads) are DELIBERATELY OMITTED — a brain does not carry exploit/poisoning/evasion stages."""
        return {
            "web_reconnaissance": [
                {"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
                {"tool": "sslscan", "priority": 2, "params": {"port": 443}},
                {"tool": "httpx", "priority": 3, "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": True}},
                {"tool": "nuclei", "priority": 5, "params": {"severity": "critical,high", "tags": "tech"}},
                {"tool": "gobuster", "priority": 6, "params": {"mode": "dir", "extensions": "php,html,js,txt"}},
            ],
            "api_testing": [
                {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True}},
                {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True}},
                {"tool": "paramspider", "priority": 3, "params": {"level": 2}},
                {"tool": "nuclei", "priority": 4, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}},
            ],
            "network_discovery": [
                {"tool": "rustscan", "priority": 1, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "masscan", "priority": 2, "params": {}},
                {"tool": "naabu", "priority": 3, "params": {}},
                {"tool": "nmap", "priority": 4, "params": {"scan_type": "-sV -sC", "os_detection": True}},
                {"tool": "sslscan", "priority": 5, "params": {"port": 443}},
                {"tool": "enum4linux-ng", "priority": 6, "params": {"shares": True, "users": True}},
                {"tool": "smbmap", "priority": 7, "params": {"recursive": True}},
            ],
            "vulnerability_assessment": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high,medium"}},
                {"tool": "jaeles", "priority": 2, "params": {"threads": 20, "timeout": 20}},
                {"tool": "dalfox", "priority": 3, "params": {"mining_dom": True}},
                {"tool": "nikto", "priority": 4, "params": {"comprehensive": True}},
                {"tool": "sqlmap", "priority": 5, "params": {"crawl": 2, "batch": True, "level": 1, "risk": 1}},
            ],
            "cloud_assessment": [
                {"tool": "prowler", "priority": 1, "params": {"output_format": "json"}},
                {"tool": "scout-suite", "priority": 2, "params": {}},
                {"tool": "checkov", "priority": 3, "params": {"output_format": "json"}},
                {"tool": "trivy", "priority": 4, "params": {"scan_type": "config", "severity": "HIGH,CRITICAL"}},
            ],
        }

    # ---- profiling (NO network — adapts analyze_target :811 minus the DNS side effect) ----------
    def analyze_target(self, target: str, *, target_type: Optional[TargetType] = None,
                       ip_addresses: Optional[list[str]] = None, open_ports: Optional[list[int]] = None,
                       services: Optional[dict[int, str]] = None,
                       technologies: Optional[list[TechnologyStack]] = None,
                       cms_type: Optional[str] = None, cloud_provider: Optional[str] = None) -> TargetProfile:
        """Build a profile from OBSERVATIONS PASSED IN (from VIGIL's gated sensors/oracle context). Unlike
        the upstream, it performs NO DNS resolution and NO requests — a hostname is never resolved here."""
        p = TargetProfile(
            target=target, target_type=target_type or self._infer_type(target, open_ports, cloud_provider),
            ip_addresses=list(ip_addresses or []), open_ports=list(open_ports or []),
            services=dict(services or {}), technologies=list(technologies or []),
            cms_type=cms_type, cloud_provider=cloud_provider)
        p.attack_surface_score = self._attack_surface(p)
        p.risk_level = self._risk_level(p)
        p.confidence_score = self._confidence(p)
        return p

    @staticmethod
    def _infer_type(target: str, open_ports: Optional[list[int]], cloud_provider: Optional[str]) -> TargetType:
        if cloud_provider:
            return TargetType.CLOUD_SERVICE
        if target.startswith(("http://", "https://")):
            return TargetType.API_ENDPOINT if "/api" in target or target.rstrip("/").endswith("/api") \
                else TargetType.WEB_APPLICATION
        if open_ports:
            return TargetType.NETWORK_HOST
        return TargetType.UNKNOWN

    def _attack_surface(self, p: TargetProfile) -> float:
        score = 0.1 * len(p.open_ports) + 0.15 * len(p.technologies) + 0.2 * len(p.services)
        if p.cms_type:
            score += 0.2
        return round(min(1.0, score), 3)

    def _risk_level(self, p: TargetProfile) -> str:
        s = p.attack_surface_score
        # H3 — honest unknown: with NO observed surface (no ports/services/technologies/cms), we have
        # nothing to rate, so the risk is UNKNOWN — never a fabricated "low" for a target nobody observed.
        # A rated tier (low..critical) is reported only once a real observation gives the surface substance.
        if s <= 0.0:
            return "unknown"
        return "critical" if s >= 0.8 else "high" if s >= 0.6 else "medium" if s >= 0.3 else "low"

    def _confidence(self, p: TargetProfile) -> float:
        signals = sum(bool(x) for x in (p.ip_addresses, p.open_ports, p.services, p.technologies))
        return round(min(1.0, 0.25 * signals), 3)

    # ---- selection + optimization (propose-only; NO stealth objective — adapts :971 / :1003) ----
    def select_optimal_tools(self, profile: TargetProfile,
                             objective: "str | Objective | None" = None) -> list[str]:
        obj = parse_objective(objective)
        table = self.tool_effectiveness.get(profile.target_type.value, self.tool_effectiveness[TargetType.UNKNOWN.value])
        ranked = sorted(table.items(), key=lambda kv: kv[1], reverse=True)
        if obj is Objective.QUICK:
            chosen = [t for t, _ in ranked[:3]]
        else:  # "comprehensive" — the only other objective; there is deliberately NO "stealth" objective
            chosen = [t for t, e in ranked if e >= 0.7]
        # CMS-specific add-on (adapts the upstream tech-specific append), recon/assessment only
        if (profile.cms_type or "").lower() == "wordpress" and "wpscan" not in chosen:
            chosen.append("wpscan")
        return [t for t in chosen if t in _TOOL_DANGER]

    def optimize_parameters(self, tool: str, profile: TargetProfile,
                            context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Curated, drift-free per-tool parameters (adapts the legacy _optimize_<tool>_params :1070-1461,
        with every stealth/tamper/evasion branch removed). Fail-closed: the result is scanned for evasion
        tokens and raises DriftError if any slipped in."""
        ctx = context or {}
        params: dict[str, Any] = {}
        first_port = (profile.open_ports[0] if profile.open_ports else None)
        if tool == "nmap":
            params = {"scan_type": "-sV -sC", "ports": ctx.get("ports", "80,443,8080,8443"), "timing": "T3"}
        elif tool in ("rustscan", "masscan", "naabu"):
            params = {"ports": ctx.get("ports", "1-65535"), "rate": 1000}
        elif tool == "httpx":
            params = {"probe": True, "tech_detect": True, "status_code": True}
        elif tool in ("gobuster", "ffuf", "feroxbuster", "dirsearch"):
            params = {"mode": "dir", "extensions": "php,html,js,txt", "threads": 30}
        elif tool == "nuclei":
            sev = "critical,high" if profile.risk_level in ("critical", "high") else "critical,high,medium"
            params = {"severity": sev}
        elif tool == "sqlmap":
            params = {"batch": True, "level": 1, "risk": 1}  # NO tamper/evasion; conservative by default
        elif tool == "dalfox":
            params = {"mining_dom": True}  # NO blind/custom_payload
        elif tool == "wpscan":
            params = {"enumerate": "vp,vt,u"}
        elif tool in ("arjun", "x8", "paramspider"):
            params = {"method": "GET,POST"}
        elif tool in ("prowler", "scout-suite", "checkov", "terrascan", "trivy", "kube-bench"):
            params = {"output_format": "json"}
        else:
            params = {}
        # Carry the playbook's OWN curated params (katana depth/js_crawl, sslscan port, gobuster mode...).
        # They were passed in as `context` and then dropped for every tool without a `ctx.get` branch, so a
        # step's declared parameters silently never reached the proposal. The per-tool block above still
        # WINS on a key collision (it is the drift-reviewed source of truth); ctx only fills the rest. Both
        # sources are in-repo and curated — never operator or model input — and the merged result is still
        # scanned by _assert_drift_free below, so this cannot smuggle an evasion knob.
        params = {**{k: v for k, v in ctx.items() if k != "ports"}, **params}
        if first_port and tool in ("nmap", "rustscan", "masscan", "naabu"):
            params.setdefault("ports", str(first_port))
        self._assert_drift_free(tool, params)
        return params

    def create_attack_chain(self, profile: TargetProfile,
                            objective: "str | Objective | None" = None) -> AttackChain:
        """Pick a curated playbook by target type + optimize each step's params (propose-only).

        The chain records the NORMALISED objective, so the label on the plan is always the objective the
        plan was actually built from — never a caller's unnormalised string.
        """
        obj = parse_objective(objective)
        pattern_key = {
            TargetType.WEB_APPLICATION: "web_reconnaissance",
            TargetType.API_ENDPOINT: "api_testing",
            TargetType.NETWORK_HOST: "network_discovery",
            TargetType.CLOUD_SERVICE: "cloud_assessment",
        }.get(profile.target_type, "web_reconnaissance")
        if obj is Objective.COMPREHENSIVE and profile.target_type in (TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT):
            steps_src = self.attack_patterns[pattern_key] + self.attack_patterns["vulnerability_assessment"]
        else:
            steps_src = self.attack_patterns[pattern_key]
        table = self.tool_effectiveness.get(profile.target_type.value, {})
        chain = AttackChain(target=profile.target, objective=obj.value)
        seen: set[str] = set()
        # Priority is the position in the EMITTED chain, not the index of the source row: a skipped row
        # (non-curated tool, or a duplicate across the two concatenated playbooks) must not leave a gap in
        # the 1..N ordering the proposal contract promises. Deriving it from len(chain.steps) keeps the
        # sequence contiguous no matter how many rows are skipped.
        for step in sorted(steps_src, key=lambda s: s["priority"]):
            tool = step["tool"]
            if tool not in _TOOL_DANGER:
                continue  # never carry a non-curated (exploit/poisoning) tool
            if tool in seen:
                # A comprehensive chain concatenates two playbooks, so a tool listed in BOTH (nuclei is in
                # web_reconnaissance AND vulnerability_assessment) was emitted twice with identical params —
                # the same scan proposed, gated and run twice. Keep the FIRST (higher-priority) occurrence.
                continue
            seen.add(tool)
            params = self.optimize_parameters(tool, profile, step.get("params"))
            chain.steps.append(AttackStep(tool=tool, priority=len(chain.steps) + 1, params=params,
                                          danger=_TOOL_DANGER[tool], effectiveness=table.get(tool, 0.5)))
        # CMS-specific add-on (recon/assessment only) — a WordPress target earns a wpscan step.
        if (profile.cms_type or "").lower() == "wordpress" and not any(s.tool == "wpscan" for s in chain.steps):
            chain.steps.append(AttackStep(
                tool="wpscan", priority=len(chain.steps) + 1,
                params=self.optimize_parameters("wpscan", profile),
                danger=_TOOL_DANGER["wpscan"], effectiveness=table.get("wpscan", 0.9)))
        chain.calculate_success_probability(profile.confidence_score or 0.5)
        return chain

    def propose(self, profile: TargetProfile,
                objective: "str | Objective | None" = None) -> list[dict]:
        """The propose-only output: an ordered list of {tool, params, priority, danger, effectiveness}
        LEADs. Nothing here is authorized or a fact — the AgentBody submits each to the gate + runner."""
        return [s.to_dict() for s in self.create_attack_chain(profile, objective).steps]

    # ---- the drift guard ------------------------------------------------------------------------
    def _assert_drift_free(self, tool: str, params: dict[str, Any]) -> None:
        blob = f"{tool} " + " ".join(f"{k}={v}" for k, v in params.items())
        m = _EVASION_TOKENS.search(blob)
        if m:
            raise DriftError(f"proposed params for {tool!r} carry a forbidden evasion knob: {m.group(0)!r}")
