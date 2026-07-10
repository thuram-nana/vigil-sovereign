"""
sensors.web_scanner — Nuclei / ZAP / Burp driven as gated WEB-SCANNER sensors (Wave 4a).

CRUCIBLE is a reasoning OS: an external web scanner is a gated SENSOR whose output enters the ONE
world-model as a provenance-tagged OBSERVATION — a LEAD (``GROUNDING_INTEL``), NEVER a fact. A
Nuclei template match, a ZAP alert, a Burp issue is a THIRD PARTY's heuristic say-so; CRUCIBLE's own
deterministic ORACLES re-verify it to a ``fact`` where they can, else it stays a labelled lead. This
module reuses, UNCHANGED, the battle-tested parsers in ``eval.adapters`` (``parse_nuclei`` /
``parse_zap`` / ``parse_burp``) and wraps them behind the Wave-2 sensor framework.

The seam is the W2.1 framework end to end::

    invoke_tool (kill-switch / entitlement / scope / destructive / egress)  ->  <Sensor>.run
    (bounded subprocess / REST pull, fixed argv, no shell)  ->  normalize (reuse eval.adapters parse_*)
    ->  web_lead_observations (the SHARED web-lead minter)  ->  IntelIngest  ->  the ONE world-model

Doctrine, by construction:
  * PROVE-DON'T-GUESS. Every finding is minted as an OBSERVATION tagged ``IntelSourceKind.WEB_SCANNER``
    at MODERATE reliability (Admiralty C3 — a template match is not proof), projecting as
    ``GROUNDING_INTEL``. A Sensor NEVER writes a Finding, NEVER promotes a lead, and a tool's OWN
    "confirmed"/"certain" flag is RECORDED but NOT trusted. Only a deterministic oracle
    (``verify.confirmation.confirm_finding`` over INDEPENDENT evidence — see ``confirm_web_lead``)
    turns a lead into a ``fact``.
  * ACTIVE, so GATED. Nuclei/ZAP send probe requests and the Nuclei-template runner runs the corpus,
    so they are Tier-2 (``capability = ACTIVE_RECON``) and the invoker scope-gates ``args['target']``
    against the charter — they can only ever scan an in-scope target. Burp is a REST PULL from the
    operator's Burp server, so it declares that server as ``egress_hosts`` (the egress gate refuses it
    unless the operator allowlisted it). Correlatable, never evasive.
  * SCOPE-TIGHT. The minter mints a lead ONLY for an endpoint whose host matches the scoped target
    (a redirect / a Burp issue on another host mints nothing), so a sensor can never inject an
    out-of-scope asset into the world-model.
  * DEGRADES CLEANLY. No binary / no ``CRUCIBLE_BURP_URL`` / an unreachable REST endpoint / a
    malformed report -> a failed ToolResult with a reason (never a crash, never a guess).
  * DETERMINISM. The scan OUTPUT reflects the live target, but ``parse -> web_lead_observations ->
    project`` is a PURE, replayable function of that output (caller ``seq``, no wallclock, no rng);
    claim-keyed ``obs_id`` makes re-ingest idempotent; a malformed report yields zero observations.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import urllib.error
import urllib.request

from pydantic import BaseModel, ConfigDict, Field

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability
from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Reliability,
    SourceReliability,
)
from ..intel.refs import EntityRef, canonicalize
from ..verify.verifier import canonical_bug_class, is_known_bug_class, normalize_bug_class
from ..worldmodel.models import NodeKind

# A third-party web scanner match: a source of MODERATE trust (the tool is generally reliable, C
# reliability) whose SPECIFIC datum is only possibly-true (C3 credibility) — a heuristic/template
# match, not an oracle proof. Deliberately BELOW the active first-party sensors (Nmap A2, tshark B2):
# the whole point is that this is a lead to re-verify, not evidence to trust. weight() ≈ 0.65, so it
# still enters the graph (reliability > 0) but moves belief only modestly.
_WEB_SCANNER_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)

_DEFAULT_TIMEOUT_S = 600
_TEMPLATE_TIMEOUT_S = 1200
_ZAP_BINARIES: tuple[str, ...] = ("zap.sh", "zap-cli", "zaproxy")


# ---------------------------------------------------------------------------
# target validation — the AUTHORIZATION-CRITICAL guard (mirrors nmap's single-host rule)
# ---------------------------------------------------------------------------


def _is_safe_url_target(target: str) -> bool:
    """True iff ``target`` is EXACTLY one http(s) URL with a hostname — nothing a scanner would
    reinterpret. The invoker's scope gate validates ``urlsplit(target).hostname``; the scanner
    receives the SAME string as the value of ``-u`` (one argv token, no shell), so this guard
    guarantees the host the scanner probes is the host the gate authorized. Rejects an option-like
    value (leading ``-`` -> parsed as a scanner FLAG), any whitespace (a smuggled second argument),
    and a non-http(s) / hostless URL."""
    t = (target or "").strip()
    if not t or t.startswith("-") or any(c.isspace() for c in t):
        return False
    parts = urlsplit(t)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _target_host(target: str) -> str:
    """The lowercased hostname of a target URL/host string ("" if none)."""
    s = (target or "").strip()
    host = urlsplit(s).hostname if "://" in s else s.split("/", 1)[0].split(":", 1)[0]
    return (host or "").lower()


def _location_host(location: str) -> str:
    """The lowercased hostname a finding's location sits on, or "" when the location is a RELATIVE
    reference (a path / query / fragment) that is in-scope by construction. A scheme-LESS authority
    (``host`` / ``host:port`` — the form nuclei emits for ssl/network/tcp/dns templates) IS resolved
    to its host, symmetric with ``common.ethics.require_in_scope`` (which prepends ``https://`` before
    reading the hostname). Without this, a scheme-less foreign ``host:port`` reads as a bare path and
    the off-host drop is skipped — planting an out-of-scope asset in the world-model."""
    s = (location or "").strip()
    if not s or s[0] in "?#":
        return ""                       # a query / fragment — in-scope by construction
    if s.startswith("//"):
        s = "https:" + s                # protocol-relative //host/path — a FOREIGN authority, resolve it
    elif "://" not in s:
        # scheme-less: an AUTHORITY has a host-like head (a dotted name / IP, or a ':port'); a leading-
        # slash path, a bare relative path segment, or a param token does not — those are in-scope.
        head = s.split("/", 1)[0]
        if s[0] == "/" or ("." not in head and ":" not in head):
            return ""                   # relative path / bare param token — in-scope by construction
        s = "https://" + s              # a bare host[:port] — resolve it the way the scope gate does
    return (urlsplit(s).hostname or "").lower()


# ---------------------------------------------------------------------------
# WebLead — the structured, replayable verification-worklist item
# ---------------------------------------------------------------------------


class WebLead(BaseModel):
    """One third-party web-scanner finding, normalized into a LEAD (never a fact).

    A ``WebLead`` is exactly what its name says: a place to LOOK and a class to SUSPECT, carried out
    of a tool's output so CRUCIBLE's own oracle-grade re-probe can target it. ``bug_class`` is the
    format-normalized class (via ``verify.verifier.normalize_bug_class``); ``bug_class_raw`` retains
    the tool's original string; ``oracle_provable`` says whether that class is one an oracle could
    EVER prove (in the vocabulary) — a class the tool named that maps to no oracle stays an honest,
    un-provable lead rather than being forced into the vocabulary. ``tool_confirmed`` records the
    tool's OWN verdict (Burp ``certain``, sqlmap) — RECORDED for transparency, NEVER trusted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(description="The scanner that produced the lead (nuclei/zap/burp).")
    bug_class: str = Field(description="Format-normalized bug class (normalize_bug_class).")
    bug_class_raw: str = Field(description="The tool's original class string (template-id/alert/name).")
    location: str = Field(description="URL / path+param / bare param the lead sits on.")
    target: str = Field(description="The base target the scan ran against.")
    severity: str = ""
    evidence: str = ""
    tool_confirmed: bool = Field(default=False, description="The tool's OWN verdict — recorded, not trusted.")
    oracle_provable: bool = Field(default=False, description="Is bug_class in the oracle vocabulary?")

    @property
    def canonical_bug_class(self) -> str | None:
        """The canonical oracle-provable class for this lead, or None (out of vocabulary)."""
        return canonical_bug_class(self.bug_class)


def web_lead_from_finding(finding: object, *, target: str) -> WebLead:
    """Map one ``eval.validation.NormalizedFinding`` (or any object exposing the same
    ``tool``/``bug_class``/``location``/``severity``/``evidence``/``confirmed`` attributes) into a
    ``WebLead``. Pure and total: missing/None attributes degrade to empty strings / False."""
    raw = str(getattr(finding, "bug_class", "") or "")
    norm = normalize_bug_class(raw)
    return WebLead(
        tool=str(getattr(finding, "tool", "") or ""),
        bug_class=norm,
        bug_class_raw=raw,
        location=str(getattr(finding, "location", "") or ""),
        target=str(target or ""),
        severity=str(getattr(finding, "severity", "") or ""),
        evidence=str(getattr(finding, "evidence", "") or ""),
        tool_confirmed=bool(getattr(finding, "confirmed", False)),
        oracle_provable=is_known_bug_class(norm),
    )


def web_leads_from_findings(findings: object, *, target: str) -> list[WebLead]:
    """Map an iterable of NormalizedFinding-shaped objects into ``WebLead``s, dropping any whose
    location host is NOT the scoped target's host (an out-of-scope redirect / cross-host Burp issue
    mints nothing — the same scope guard the minter applies)."""
    base_host = _target_host(target)
    out: list[WebLead] = []
    for f in findings or []:
        loc_host = _location_host(str(getattr(f, "location", "") or ""))
        if loc_host and base_host and loc_host != base_host:
            continue
        out.append(web_lead_from_finding(f, target=target))
    return out


# ---------------------------------------------------------------------------
# the SHARED web-lead minter — findings -> world-model observations (leads)
# ---------------------------------------------------------------------------


def web_lead_observations(
    target: str,
    findings: object,
    *,
    seq: int,
    source: str,
    source_kind: IntelSourceKind = IntelSourceKind.WEB_SCANNER,
    reliability: SourceReliability = _WEB_SCANNER_RELIABILITY,
    webapp_confidence: float = 0.8,
    lead_confidence: float = 0.6,
) -> list[Observation]:
    """Mint a WEBAPP node for the scanned ``target`` + one ENDPOINT node per in-scope finding, each
    carrying a third-party LEAD — the SHARED minter every web-scanner sensor here reuses, so the
    web-lead schema is produced ONE way.

    Each finding is any object exposing ``bug_class`` / ``location`` / ``severity`` (a
    ``NormalizedFinding``). The finding's tool bug_class is FORMAT-normalized onto our vocabulary via
    ``normalize_bug_class`` (never forced — an unmapped class stays itself); the lead lives on the
    ENDPOINT the finding sits on (or on the WEBAPP itself for a host-level finding). SCOPE-TIGHT: a
    finding whose location host differs from ``target``'s host is SKIPPED (never minted), so a
    redirect or a cross-host Burp issue cannot inject an out-of-scope asset.

    PURE and total: no wallclock, no rng, no positional counter — ``obs_id`` IS the ``(source, seq,
    subject, claim)`` key, so re-ingest / reordering / an intra-batch duplicate collapse to one
    observation (idempotent; belief never inflates from input ordering). The observations project as
    ``GROUNDING_INTEL`` (leads), never facts. NO in-scope finding -> ZERO observations: a scanner
    that reported nothing (a clean run, or a malformed report the parser dropped) mints nothing, so
    the sensor asserts only what it actually observed — leads."""
    base = (target or "").strip()
    if not base:
        return []
    base_host = _target_host(base)
    webapp = canonicalize(NodeKind.WEBAPP, base)

    def _mint(subject: EntityRef, *, claim: str, conf: float,
              attrs: dict | None = None, evidence: str = "") -> Observation:
        # obs_id IS the claim key at this (source, seq): a DISTINCT (subject, claim) gets a distinct
        # id; the SAME one — re-declared / reordered / duplicated within one batch — gets the SAME id,
        # so IntelIngest dedups it. No positional index, no clock, no rng: a PURE replayable function.
        return Observation(
            obs_id=f"{source}:{seq}:{subject.node_id}|{claim}",
            source=source, source_kind=source_kind, collector=source,
            subject=subject, relation=None, object=None, attrs=attrs or {},
            source_reliability=reliability, confidence=conf, seq=seq, evidence=evidence)

    leads: list[Observation] = []
    for f in findings or []:
        location = str(getattr(f, "location", "") or "").strip()
        loc_host = _location_host(location)
        if loc_host and base_host and loc_host != base_host:
            continue   # SCOPE-TIGHT: an off-target host never mints
        raw = str(getattr(f, "bug_class", "") or "")
        norm = normalize_bug_class(raw)
        sev = str(getattr(f, "severity", "") or "")
        ev = (f"{source} lead: {raw or norm} @ {location or base} "
              f"sev={sev or '?'} — third-party heuristic match, NOT oracle-proven")
        if location and location != base:
            subject = canonicalize(NodeKind.ENDPOINT, location)
            attrs = {"surface": location, "web_lead": True, "lead_source": source}
        else:                                   # a host-level finding attaches to the app itself
            subject = webapp
            attrs = {"web_lead": True, "lead_source": source}
        leads.append(_mint(subject, claim=f"lead:{norm}", conf=lead_confidence, attrs=attrs, evidence=ev))

    if not leads:
        return []
    # the app itself — anchored ONLY once the scan actually produced an in-scope lead (one obs per
    # run; dedups). A no-finding scan mints nothing at all.
    webapp_obs = _mint(webapp, claim="exists", conf=webapp_confidence, attrs={"base_url": base})
    return [webapp_obs, *leads]


# ---------------------------------------------------------------------------
# the LEAD -> FACT bridge (prove-don't-guess: an oracle re-verifies, never the tool)
# ---------------------------------------------------------------------------


def confirm_web_lead(lead: WebLead, context: object, *, verifier: object = None) -> object:
    """Promote a ``WebLead`` to a FACT iff an INDEPENDENTLY-collected oracle context fires.

    ``context`` is a ``verify.adapter.FindingContext`` (or the raw mapping ``OracleVerifier.confirm``
    reads) built from evidence CRUCIBLE gathered ITSELF via a gated re-probe (two real HTTP responses,
    an OOB hit, a captured handshake, ...), NEVER the sensor's parsed record. Laundering the tool's
    say-so straight into an oracle would defeat prove-don't-guess — exactly the trap
    ``FindingContext.from_handshake`` warns about — so the lead here only supplies WHERE to look and
    WHAT class to suspect; the deterministic oracle over the independent evidence is the sole
    authority. Delegates to ``verify.confirmation.confirm_finding``: returns a ``ConfirmedFinding``
    (the fact, carrying the firing oracle signals) or ``None`` (nothing fired — the lead stays a
    clearly-labelled third-party lead). A web sensor NEVER calls this itself; a lead is only ever
    promoted by a caller who supplies real, independent evidence."""
    from ..verify.confirmation import confirm_finding

    finding = {
        "bug_class": lead.bug_class,
        "title": f"{lead.tool} web-scanner lead: {lead.bug_class_raw} at {lead.location}",
        "severity": lead.severity,
        "surface": lead.location,
        "summary": (
            f"Third-party ({lead.tool}) web-scanner lead re-verified by an INDEPENDENT CRUCIBLE "
            f"oracle over first-party evidence (the tool's match was not trusted)."
        ),
    }
    return confirm_finding(finding, context, verifier=verifier)


# ---------------------------------------------------------------------------
# the sensors
# ---------------------------------------------------------------------------


def _parse_web_output(kind: str, text: str) -> list:
    """Reuse the tested ``eval.adapters`` parser for a tool's raw output, returning ``[]`` on
    malformed output rather than raising (a bad report degrades to no observations, like a bad Nmap
    XML). Imported lazily so the sensors package does not pull the eval/scanner import chain at load."""
    from ..eval.adapters import AdapterError, parse_burp, parse_nuclei, parse_zap

    parsers = {"nuclei": parse_nuclei, "zap": parse_zap, "burp": parse_burp}
    parser = parsers.get(kind)
    if parser is None:
        return []
    try:
        return parser(text)
    except AdapterError:
        return []


class NucleiWebSensor:
    """Drive ``nuclei`` (gated) against a single in-scope URL and mint its template matches as web
    leads. args: ``{"target": "https://app.example.com"}``. Active (Tier-2): requires ``ACTIVE_RECON``
    and is charter-scope-gated on ``args['target']`` by the invoker; ``run`` additionally enforces
    that ``target`` is a single http(s) URL (no flag / whitespace), so the host nuclei probes is
    exactly the host the gate authorized."""

    name = "nuclei_web"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts: tuple = ()   # the concrete target is scope-gated via args['target'] (not a fixed host)

    def __init__(self, *, binary: str = "nuclei", extra_args: tuple[str, ...] = (),
                 timeout_s: int = _DEFAULT_TIMEOUT_S) -> None:
        self._binary = binary
        self._extra_args = tuple(extra_args)
        self._timeout_s = timeout_s

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str):
            return ToolResult(ok=False, note="nuclei_web requires args['target'] (a single in-scope http(s) URL)")
        if not _is_safe_url_target(target):
            return ToolResult(ok=False, note=(
                "nuclei_web target must be a single http(s) URL — an option-like value, whitespace, "
                "or a non-http(s)/hostless URL is refused (it could probe beyond the scoped host)"))
        binary = shutil.which(self._binary)
        if binary is None:
            return ToolResult(ok=False, note="nuclei not on PATH (install to enable web template scanning)")
        argv = [binary, "-u", target, "-jsonl", "-silent", *self._extra_args]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; target is -u's value, guarded above
                argv, capture_output=True, text=True, timeout=self._timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, note=f"nuclei timed out after {self._timeout_s}s")
        except OSError as e:
            return ToolResult(ok=False, note=f"nuclei failed to launch: {e}")
        return ToolResult(ok=True, summary=f"nuclei scanned {target}",
                          output={"jsonl": proc.stdout or "", "target": target})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        jsonl, target = out.get("jsonl"), out.get("target")
        if not isinstance(jsonl, str) or not isinstance(target, str) or not target:
            return []
        return web_lead_observations(target, _parse_web_output("nuclei", jsonl), seq=seq, source="nuclei")


class NucleiTemplateSensor:
    """Run an operator-supplied Nuclei TEMPLATE CORPUS (gated) against a single in-scope URL — the
    "run the template corpus as a sensor" importer. args: ``{"target": "https://app.example.com",
    "templates": "/path/to/templates"}``. Active (Tier-2, ``ACTIVE_RECON``), scope-gated on
    ``args['target']``; the templates path must exist and is passed as ``-t``'s value (never a flag)."""

    name = "nuclei_templates"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self, *, binary: str = "nuclei", timeout_s: int = _TEMPLATE_TIMEOUT_S) -> None:
        self._binary = binary
        self._timeout_s = timeout_s

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str):
            return ToolResult(ok=False, note="nuclei_templates requires args['target'] (a single in-scope http(s) URL)")
        if not _is_safe_url_target(target):
            return ToolResult(ok=False, note=(
                "nuclei_templates target must be a single http(s) URL (an option-like/whitespace/"
                "hostless value is refused)"))
        templates = args.get("templates") if isinstance(args, dict) else None
        if not templates or not isinstance(templates, str) or templates.startswith("-"):
            return ToolResult(ok=False, note="nuclei_templates requires args['templates'] (a template dir/file path)")
        tpl = Path(templates)
        if not tpl.exists():
            return ToolResult(ok=False, note=f"nuclei_templates: templates path not found: {templates}")
        binary = shutil.which(self._binary)
        if binary is None:
            return ToolResult(ok=False, note="nuclei not on PATH (install to run the template corpus)")
        argv = [binary, "-u", target, "-t", str(tpl), "-jsonl", "-silent"]
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; target/templates are flag values, guarded
                argv, capture_output=True, text=True, timeout=self._timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, note=f"nuclei timed out after {self._timeout_s}s")
        except OSError as e:
            return ToolResult(ok=False, note=f"nuclei failed to launch: {e}")
        return ToolResult(ok=True, summary=f"nuclei ran {tpl.name} against {target}",
                          output={"jsonl": proc.stdout or "", "target": target, "templates": str(tpl)})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        jsonl, target = out.get("jsonl"), out.get("target")
        if not isinstance(jsonl, str) or not isinstance(target, str) or not target:
            return []
        return web_lead_observations(target, _parse_web_output("nuclei", jsonl), seq=seq, source="nuclei")


class NucleiResultsImportSensor:
    """Import an operator-provided Nuclei ``-jsonl`` RESULTS FILE (offline, no network) as leads —
    the deterministic replay path. args: ``{"target": "https://app.example.com",
    "results_file": "/path/to/nuclei.jsonl"}``. Passive (Tier-1: reads a local file), yet still
    scope-gated on ``args['target']`` so only in-scope results ever enter the world-model."""

    name = "nuclei_import"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str) or not _is_safe_url_target(target):
            return ToolResult(ok=False, note="nuclei_import requires args['target'] (a single in-scope http(s) URL)")
        results_file = args.get("results_file") if isinstance(args, dict) else None
        if not results_file or not isinstance(results_file, str):
            return ToolResult(ok=False, note="nuclei_import requires args['results_file'] (a nuclei -jsonl file)")
        if not os.path.isfile(results_file):
            return ToolResult(ok=False, note=f"nuclei_import: results file not found: {results_file}")
        try:
            jsonl = Path(results_file).read_text(encoding="utf-8")
        except OSError as e:
            return ToolResult(ok=False, note=f"nuclei_import: cannot read {results_file}: {e}")
        return ToolResult(ok=True, summary=f"imported {os.path.basename(results_file)}",
                          output={"jsonl": jsonl, "target": target})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        jsonl, target = out.get("jsonl"), out.get("target")
        if not isinstance(jsonl, str) or not isinstance(target, str) or not target:
            return []
        return web_lead_observations(target, _parse_web_output("nuclei", jsonl), seq=seq, source="nuclei")


class ZapWebSensor:
    """Drive OWASP ZAP (gated) against a single in-scope URL and mint its alerts as web leads. args:
    ``{"target": "https://app.example.com"}``. Active (Tier-2, ``ACTIVE_RECON``), scope-gated on
    ``args['target']``. ZAP writes a JSON report to a temp file (``-quickout``); a missing report ->
    a failed ToolResult."""

    name = "zap_web"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False
    egress_hosts: tuple = ()

    def __init__(self, *, binaries: tuple[str, ...] = _ZAP_BINARIES, timeout_s: int = _DEFAULT_TIMEOUT_S) -> None:
        self._binaries = tuple(binaries)
        self._timeout_s = timeout_s

    def _resolve(self) -> str | None:
        for binary in self._binaries:
            if shutil.which(binary):
                return binary
        return None

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str):
            return ToolResult(ok=False, note="zap_web requires args['target'] (a single in-scope http(s) URL)")
        if not _is_safe_url_target(target):
            return ToolResult(ok=False, note=(
                "zap_web target must be a single http(s) URL (an option-like/whitespace/hostless value is refused)"))
        binary = self._resolve()
        if binary is None:
            return ToolResult(ok=False, note="ZAP not on PATH (install zap.sh/zaproxy to enable DAST scanning)")
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "zap-report.json"
            argv = [binary, "-cmd", "-quickurl", target, "-quickout", str(report)]
            try:
                subprocess.run(  # noqa: S603 - fixed argv, no shell; target is -quickurl's value, guarded above
                    argv, capture_output=True, text=True, timeout=self._timeout_s, check=False)
            except subprocess.TimeoutExpired:
                return ToolResult(ok=False, note=f"zap timed out after {self._timeout_s}s")
            except OSError as e:
                return ToolResult(ok=False, note=f"zap failed to launch: {e}")
            try:
                output = report.read_text(encoding="utf-8")
            except OSError as e:
                return ToolResult(ok=False, note=f"zap produced no JSON report at {report}: {e}")
        return ToolResult(ok=True, summary=f"zap scanned {target}", output={"json": output, "target": target})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        report, target = out.get("json"), out.get("target")
        if not isinstance(report, str) or not isinstance(target, str) or not target:
            return []
        return web_lead_observations(target, _parse_web_output("zap", report), seq=seq, source="zap")


class BurpWebSensor:
    """Pull scan issues from an operator-run Burp Suite REST API (gated) and mint them as web leads.
    args: ``{"target": "https://app.example.com"}`` — the in-scope target the issues pertain to
    (scope-gated). Burp is a SERVICE, not a probe: the sensor reaches the operator's Burp server
    (``CRUCIBLE_BURP_URL`` or an explicit ``api_url``), so it declares that server as ``egress_hosts``
    — the egress gate REFUSES it unless the operator allowlisted the Burp host in the charter. No
    configured URL / an unreachable endpoint -> a failed ToolResult. SCOPE-TIGHT: only issues on the
    target's host are minted (Burp may hold issues for other targets)."""

    name = "burp_web"
    tier = "T2"
    capability = Capability.ACTIVE_RECON
    destructive = False

    def __init__(self, *, api_url: str | None = None, issues_path: str = "/issues", timeout_s: int = 60) -> None:
        # None -> read the env; an explicit "" disables the sensor deterministically (like BurpAdapter).
        self._api_url = api_url if api_url is not None else os.environ.get("CRUCIBLE_BURP_URL", "")
        self._issues_path = issues_path
        self._timeout_s = timeout_s
        host = (urlsplit(self._api_url).hostname or "") if self._api_url else ""
        # Declared so the egress gate governs the pull from the operator's Burp server. Empty when no
        # URL is configured (run() then fails with a reason before any egress).
        self.egress_hosts: tuple = (host,) if host else ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        target = args.get("target") if isinstance(args, dict) else None
        if not target or not isinstance(target, str) or not _is_safe_url_target(target):
            return ToolResult(ok=False, note="burp_web requires args['target'] (a single in-scope http(s) URL)")
        if not self._api_url:
            return ToolResult(ok=False, note="burp_web: no Burp REST URL configured (set CRUCIBLE_BURP_URL or api_url)")
        url = self._api_url.rstrip("/") + self._issues_path
        try:
            with urllib.request.urlopen(url, timeout=self._timeout_s) as resp:  # noqa: S310 (operator-configured REST endpoint)
                body = resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            return ToolResult(ok=False, note=f"burp_web: Burp REST API unreachable at {url}: {e}")
        return ToolResult(ok=True, summary=f"burp issues for {target}", output={"json": body, "target": target})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int) -> list[Observation]:
        out = result.output or {}
        report, target = out.get("json"), out.get("target")
        if not isinstance(report, str) or not isinstance(target, str) or not target:
            return []
        return web_lead_observations(target, _parse_web_output("burp", report), seq=seq, source="burp")
