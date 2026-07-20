"""sensors.cicd — ingest operator-supplied GitHub-Actions workflow(s) into CI/CD posture LEADS.

The capture feed that makes the CI/CD-posture oracle reachable in a real ``engage --fuse-sensors`` run
(a ``fusion.json`` task ``{sensor: "cicd_workflows", args: {workflow: ".github/workflows"}}``). Mirrors
``sensors.k8s_runtime.KubeBenchSensor`` method-for-method: Tier-1, reads a LOCAL file OR a directory of
``*.yml``/``*.yaml`` workflows (no network, no repo clone), parses each OFFLINE via
``verify.cicd_posture.ingest_workflow``, and mints one ``NodeKind.CONTROL`` LEAD per candidate construct,
keyed ``cicd:<workflow>:<job>:<rule>:<i>``. The leads STOP here; the CI/CD-posture oracle
(``verify.cicd_posture``) re-verifies a lead to a FACT only when it re-derives a concrete dangerous
construct (an unpinned third-party action / pwn-request / script-injection sink). Pure + total (a
malformed workflow is a non-ingestion, never a crash).
"""

from __future__ import annotations

import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..verify.cicd_posture import ingest_workflow
from ..worldmodel.models import NodeKind

_CICD_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)
_MAX_CONTROLS = 1000


def _read_workflows(path: str) -> list[tuple[str, str]]:
    """(workflow-name, text) for a single workflow file, or every ``*.yml``/``*.yaml`` under a directory
    (sorted → deterministic). Best-effort: an unreadable file is skipped, never raises."""
    out: list[tuple[str, str]] = []
    try:
        if os.path.isdir(path):
            names = sorted(n for n in os.listdir(path) if n.endswith((".yml", ".yaml")))
            paths = [(n, os.path.join(path, n)) for n in names]
        elif os.path.isfile(path):
            paths = [(os.path.basename(path), path)]
        else:
            return []
        for name, fp in paths:
            try:
                out.append((name, open(fp, "r", encoding="utf-8", errors="replace").read()))
            except OSError:
                continue
    except OSError:
        return []
    return out


def parse_workflows(path: str) -> list[dict]:
    """Parse a workflow file/dir into CI/CD control descriptors, each tagged with a stable ``check_id``
    (``<workflow>:<job>:<rule>:<i>``) so the lead and its later oracle-promoted FACT land on the SAME
    CONTROL node. Deterministic; ``[]`` when nothing parses."""
    controls: list[dict] = []
    for name, text in _read_workflows(path):
        for i, c in enumerate(ingest_workflow(text, name=name)):
            c = dict(c)
            c["check_id"] = f"{c.get('workflow', name)}:{c.get('job', '')}:{c.get('rule', '')}:{i}"
            controls.append(c)
            if len(controls) >= _MAX_CONTROLS:
                return controls
    return controls


def cicd_control_observations(controls: list[dict], *, seq: int, source: str = "cicd_workflows") -> list[Observation]:
    """Mint one ``NodeKind.CONTROL`` LEAD per workflow control, keyed ``cicd:<check_id>``. The control's
    full evidence (rule + uses/run/checkout_ref) rides in ``attrs`` so the CI/CD-posture oracle can
    re-derive the danger. GROUNDING_INTEL, claim-keyed obs_ids (idempotent), pure."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        cid = str(c.get("check_id") or "").strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ref = EntityRef(kind=NodeKind.CONTROL, key=f"cicd:{cid}".lower())
        attrs = {"lead": True, "unverified": True, "check_id": cid, "rule": c.get("rule"),
                 "workflow": c.get("workflow"), "job": c.get("job")}
        for k in ("uses", "run", "trigger", "checkout_ref"):
            if c.get(k):
                attrs[k] = c[k]
        out.append(Observation(
            obs_id=f"{source}:{seq}:{ref.node_id}||", source=source,
            source_kind=IntelSourceKind.OPERATOR_INGEST, collector=source, subject=ref,
            relation=None, object=None, attrs={k: v for k, v in attrs.items() if v not in (None, "")},
            source_reliability=_CICD_RELIABILITY, confidence=0.7, seq=seq))
    return out


class WorkflowScanSensor:
    """Ingest operator-provided GitHub-Actions workflow(s) and mint CI/CD posture LEADS. args:
    ``{"workflow": "/path/to/.github/workflows"}`` (a file or a directory). Passive (Tier-1): reads local
    files, no network, no repo clone, no entitlement. The leads STOP here; the CI/CD-posture oracle
    re-verifies a lead to a FACT. Mirrors ``KubeBenchSensor``."""

    name = "cicd_workflows"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = args.get("workflow") if isinstance(args, dict) else None
        if not path or not isinstance(path, str):
            return ToolResult(ok=False, note="cicd_workflows requires args['workflow'] (a file or dir path)")
        if not (os.path.isfile(path) or os.path.isdir(path)):
            return ToolResult(ok=False, note=f"cicd_workflows: no workflow file/dir at: {path}")
        controls = parse_workflows(path)
        return ToolResult(ok=True, summary=f"cicd: {len(controls)} workflow control(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return cicd_control_observations(controls, seq=seq, source="cicd_workflows")

    def controls(self, result: ToolResult) -> list[dict]:
        """The retained workflow controls for the CI/CD-posture oracle (``confirm_cicd_posture``)."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
