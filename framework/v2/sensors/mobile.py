"""sensors.mobile — ingest an operator-supplied MobSF static-analysis report into mobile posture LEADS.

The honest first slice for the mobile coverage gap (there was NO mobile code anywhere). Mirrors
``sensors.sbom.SbomVulnSensor`` method-for-method: Tier-1, reads a LOCAL operator-supplied MobSF ``--json``
export, no network, kill-switch-gated via ``sensors.pipeline.run_sensor``. It mints, as GROUNDING_INTEL
LEADS (never facts — a third-party tool's say-so is never a CRUCIBLE fact):

  * one ``APPLICATION`` node for the app (reusing the existing non-web-app node kind — no new NodeKind);
  * one ``CONTROL`` lead per posture finding, keyed ``mobile:<check_id>`` (exactly how the kube-bench
    sensor reuses CONTROL keyed ``cis-k8s:<id>``) — exported components, cleartext-traffic, missing pin,
    a possible hardcoded secret, etc.;
  * one ``ENDPOINT`` lead per embedded back-end URL (carrying a ``url`` attr so the discoverer can test
    it — the per-request charter scope gate refuses anything out of scope).

MOSTLY LEADS: nearly every mobile signal is resolved by an Android precedence/gating chain (manifest-attr
vs network_security_config; min vs target vs device SDK; explicit vs default export) a MobSF descriptor
routinely omits, so promoting them to FACTs would false-fire — they STAY honest leads. The ONE offline-
re-derivable exception this slice retains structured evidence for is an embedded PRIVATE-KEY PEM block:
the ``verify.mobile_posture`` oracle re-derives it by actually LOADING the key material (never a label-
match), and the ``engage_fusion`` feed promotes it to a FACT. Other sound slices (debuggable + non-debug
signing cert; unguarded exported content provider) are later work. Pure + total: a malformed report is a
non-ingestion, never a crash.
"""

from __future__ import annotations

import json
import os
import re

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind

# An operator-supplied static-analyser export: Admiralty B2 (usually reliable / probably true), like SBOM.
_MOBILE_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)

# Severity strings MobSF uses for a NON-defect (a passing/secure check) — never a lead.
_SECURE_SEV = frozenset({"secure", "good", "pass", "ok", "info", "none", ""})
_MAX_ITEMS = 400   # bound per report (a huge report is still bounded, deterministic)
_PEM_MAX = 20000   # a private key never approaches this; the bound just caps a pathological blob

# A PEM private-key block (PKCS#1 / PKCS#8 / SEC1 / encrypted). Retained VERBATIM (newlines intact) so the
# mobile-posture oracle can RE-DERIVE it by actually loading the key material offline — never a label-match.
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL)


def _extract_private_key_pem(value: str) -> str | None:
    """Return the FIRST embedded PEM private-key block VERBATIM (``\\n``-escapes normalised to real
    newlines so the block re-parses), or ``None``. Pure; bounded by ``_PEM_MAX``."""
    if not isinstance(value, str) or "PRIVATE KEY-----" not in value:
        return None
    text = value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    m = _PEM_PRIVATE_KEY_RE.search(text)
    if m is None:
        return None
    return m.group(0)[:_PEM_MAX]


def _findings_from(section: object, category: str) -> list[dict]:
    """Extract posture findings from one MobSF section (a dict of ``*_findings`` lists / a rule map, or a
    bare list). Tolerant across MobSF versions; returns ``[]`` for anything unrecognised."""
    items: list = []
    if isinstance(section, dict):
        for k in ("manifest_findings", "network_findings", "findings"):
            if isinstance(section.get(k), list):
                items = section[k]
                break
        else:
            items = [v for v in section.values() if isinstance(v, dict)]
    elif isinstance(section, list):
        items = section
    out: list[dict] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            continue
        title = str(it.get("title") or it.get("name") or it.get("rule") or it.get("description") or "").strip()
        if not title:
            continue
        sev = str(it.get("severity") or it.get("stat") or it.get("status") or "info").strip().lower()
        if sev in _SECURE_SEV:
            continue
        rule = str(it.get("rule") or it.get("name") or i)
        out.append({"check_id": f"{category}:{rule}"[:120], "category": category, "title": title[:200],
                    "severity": sev, "evidence": str(it.get("description") or it.get("desc") or "")[:300]})
    return out


def _embedded_urls(report: dict) -> list[str]:
    """The http(s) back-end URLs MobSF extracted (tolerant of the list-of-str / list-of-dict shapes)."""
    urls: set[str] = set()
    u = report.get("urls")
    if isinstance(u, list):
        for item in u:
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                urls.add(item.strip())
            elif isinstance(item, dict):
                for v in (item.get("url") or []):
                    if isinstance(v, str) and v.startswith(("http://", "https://")):
                        urls.add(v.strip())
    return sorted(urls)[:_MAX_ITEMS]


def parse_mobsf(text: str) -> dict:
    """Parse a MobSF static-analysis JSON export into ``{app, controls, urls}``. PURE + total — invalid
    JSON / an unknown shape yields ``{}``, never an exception."""
    try:
        report = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(report, dict):
        return {}
    app = {"package": str(report.get("package_name") or "").strip(),
           "name": str(report.get("app_name") or report.get("file_name") or "").strip(),
           "version": str(report.get("version_name") or "").strip()}
    controls: list[dict] = []
    for section, cat in (("manifest_analysis", "manifest"), ("network_security", "network"),
                         ("code_analysis", "code"), ("binary_analysis", "binary"),
                         ("security_analysis", "security"), ("niap_analysis", "niap")):
        controls.extend(_findings_from(report.get(section), cat))
    secrets = report.get("secrets") or report.get("possible_secrets")
    if isinstance(secrets, list):
        for i, s in enumerate(secrets):
            if isinstance(s, str):
                sv = s
            elif isinstance(s, (list, tuple)):
                sv = "\n".join(str(x) for x in s)   # MobSF sometimes splits a secret into per-line pieces
            else:
                sv = str(s)
            ctrl = {"check_id": f"secret:{i}", "category": "secret",
                    "title": "possible hardcoded secret", "severity": "warning",
                    "evidence": sv[:200]}
            pem = _extract_private_key_pem(sv)
            if pem is not None:
                # a structured, machine-checkable value the posture oracle RE-DERIVES by loading the key —
                # NOT the free-text a naive oracle would string-trust. Mirrors k8s `actual_value` / cicd `uses`.
                ctrl["rule"] = "private_key_material"
                ctrl["pem"] = pem
                ctrl["title"] = "embedded private key material"
                ctrl["severity"] = "high"
            controls.append(ctrl)
    return {"app": app, "controls": controls[:_MAX_ITEMS], "urls": _embedded_urls(report)}


def mobsf_observations(parsed: dict, *, seq: int, source: str = "mobsf") -> list[Observation]:
    """Mint the APPLICATION + CONTROL-lead + ENDPOINT-lead observations for a parsed MobSF report. All are
    GROUNDING_INTEL LEADS (``unverified``), never facts. Claim-keyed obs_ids → re-ingest is idempotent;
    pure (no wallclock / rng)."""
    app = parsed.get("app") or {}
    app_key = (app.get("package") or app.get("name") or "").strip().lower()
    if not app_key:
        return []
    out: list[Observation] = []

    def _obs(ref: EntityRef, attrs: dict, conf: float) -> None:
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None,
            attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            source_reliability=_MOBILE_RELIABILITY, confidence=conf, seq=seq))

    _obs(EntityRef(kind=NodeKind.APPLICATION, key=app_key),
         {"name": app.get("name"), "package": app.get("package"), "version": app.get("version"),
          "platform": "mobile"}, 0.85)

    seen: set[str] = set()
    for c in parsed.get("controls") or []:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        _obs(EntityRef(kind=NodeKind.CONTROL, key=f"mobile:{cid}"),
             {"lead": True, "unverified": True, "check_id": cid, "category": c.get("category"),
              "rule": c.get("rule"), "title": c.get("title"), "severity": c.get("severity"),
              "evidence": c.get("evidence"), "app": app_key}, 0.7)

    for url in parsed.get("urls") or []:
        _obs(EntityRef(kind=NodeKind.ENDPOINT, key=url),
             {"lead": True, "unverified": True, "url": url, "source": "mobile_embedded", "app": app_key}, 0.6)
    return out


class MobsfSensor:
    """Ingest an operator-provided MobSF static-analysis JSON report and mint mobile posture LEADS.
    args: ``{"report": "/path/to/mobsf.json"}``. Passive (Tier-1): reads a local file, no network, no
    entitlement — kill-switch-gated via ``sensors.pipeline.run_sensor``. Leads only; a mobile-posture
    ORACLE (promoting the offline-provable signals to FACTs) is a later slice."""

    name = "mobsf_static"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        report = args.get("report") if isinstance(args, dict) else None
        if not report or not isinstance(report, str):
            return ToolResult(ok=False, note="mobsf_static requires args['report'] (a MobSF JSON path)")
        if not os.path.isfile(report):
            return ToolResult(ok=False, note=f"mobsf_static: report not found: {report}")
        try:
            text = open(report, "r", encoding="utf-8", errors="replace").read()
        except OSError as e:
            return ToolResult(ok=False, note=f"mobsf_static: could not read report: {e}")
        parsed = parse_mobsf(text)
        n = len(parsed.get("controls") or []) + len(parsed.get("urls") or [])
        return ToolResult(ok=True, summary=f"mobsf: {n} mobile posture lead(s)", output={"parsed": parsed})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        parsed = out.get("parsed")
        if not isinstance(parsed, dict):
            return []
        return mobsf_observations(parsed, seq=seq, source="mobsf")
