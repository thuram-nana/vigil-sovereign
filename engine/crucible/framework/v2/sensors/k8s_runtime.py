"""
sensors.k8s_runtime — Kubernetes-runtime posture sensor (Workstream C, first slice): a kube-bench
``--json`` report ingested OFFLINE as a gated producer of CIS-control-failure LEADS a future k8s-posture
oracle re-verifies to FACTS.

CRUCIBLE is a reasoning OS: kube-bench is a third-party CIS benchmark tool, so "kube-bench says control
1.2.1 (anonymous-auth) FAILED" is a LEAD (``GROUNDING_INTEL``), NEVER a fact — exactly like grype's
"package X @ V is affected by CVE-Y" in ``sensors.sbom``. This sensor mirrors ``SbomVulnSensor``
method-for-method: it ingests an operator-supplied JSON report (OFFLINE — Tier-1, no egress, no cluster
control) and mints one CONTROL observation per failed/warned check, carrying JSON-safe evidence
({check_id, description, status, section, remediation}) so a later oracle can re-derive the weakness.

The SENSOR STOPS at LEADs — it mints OBSERVATIONS, never facts, and confirms NOTHING itself. The
PROMOTION now exists as a deterministic oracle: ``verify.k8s_posture.confirm_k8s_posture`` re-derives a
CONCRETE insecure setting over the RETAINED control (a hard FAIL whose observed ``actual_value`` literally
carries a dangerous flag) and only then a lead becomes a FACT — mirroring how
``verify.version.confirm_vulnerable_dependency`` promotes SBOM leads. A passing/benign control never
confirms. (The opt-in ``engage --fuse-sensors`` path folds these leads + the oracle promotions into the
run world-model; the sensor is never trusted, the oracle proves.)

Doctrine, by construction:
  * PROVE-DON'T-GUESS. The scanner's FAIL/WARN is a LEAD; the observation is ``GROUNDING_INTEL``, never a
    fact. No Finding, no oracle here.
  * OFFLINE / GATED. Reads a local report the operator supplies — Tier-1, no network, no entitlement, no
    device/cluster egress; still kill-switch-gated via ``run_sensor``.
  * DEGRADES CLEANLY. No report / malformed JSON / an unknown shape -> a failed ToolResult (``run``) or
    ``[]`` (``parse_kube_bench``), never a crash.
  * DETERMINISM. ``parse -> observation`` is a PURE, replayable function (caller-supplied ``seq``, no
    wallclock, no rng). ``obs_id`` IS the ``(source, seq, subject-claim)`` key, so re-ingest is idempotent
    and an intra-batch duplicate check_id collapses to one observation (belief never inflates).
"""

from __future__ import annotations

import json
import os

from ..agents.tools import ToolContext, ToolResult
from ..intel.models import Credibility, IntelSourceKind, Observation, Reliability, SourceReliability
from ..intel.refs import EntityRef
from ..worldmodel.models import NodeKind

# A CIS benchmark tool: reliable, but a config-CHECK claim that is not proof of an exploitable weakness
# until an oracle re-verifies it against the live cluster. Admiralty B2 — a lead, never an auto-fact
# (mirrors ``sensors.sbom._SCA_RELIABILITY``).
_KUBE_BENCH_RELIABILITY = SourceReliability(reliability=Reliability.B, credibility=Credibility.C2)

# kube-bench only FAIL / WARN carry an actionable posture lead: PASS is a satisfied control and INFO is
# a note — neither is a weakness lead, so both are skipped at parse time.
_LEAD_STATUSES = frozenset({"FAIL", "WARN"})

# A hard FAIL is a stronger lead than a WARN (WARN is a "manual review needed" advisory). Deterministic:
# the confidence is a pure function of the status, never a clock/rng. Both stay < 1.0 (a lead, not a fact).
_STATUS_CONFIDENCE = {"FAIL": 0.85, "WARN": 0.6}


def _iter_control_docs(report: object):
    """Yield each ``{"Controls": [...]}`` document, handling BOTH kube-bench shapes defensively: the
    top-level object (one target) AND the newer top-level LIST (master/node/etcd/policies concatenated)."""
    if isinstance(report, dict):
        yield report
    elif isinstance(report, list):
        for doc in report:
            if isinstance(doc, dict):
                yield doc


def parse_kube_bench(text: str) -> list[dict]:
    """Parse a kube-bench ``--json`` report into failed/warned CIS-control lead dicts. PURE and total —
    invalid JSON / an unknown shape / a missing key yields ``[]``, never an exception.

    Handles both top-level shapes ``{"Controls": [...]}`` and ``[{"Controls": [...]}, ...]``. Walks
    ``Controls[].tests[].results[]`` and returns each result whose status is FAIL or WARN as
    ``{"check_id", "description", "status", "section"?, "remediation"?}`` (PASS/INFO skipped)."""
    try:
        report = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    out: list[dict] = []
    for doc in _iter_control_docs(report):
        for control in doc.get("Controls", []) or []:
            if not isinstance(control, dict):
                continue
            for test in control.get("tests", []) or []:
                if not isinstance(test, dict):
                    continue
                # The CIS section (e.g. "1.1") lives on the test GROUP, not the individual result; fall
                # back to its human description so the lead is never section-less when a number is absent.
                section = str(test.get("section") or test.get("desc") or "").strip()
                for res in test.get("results", []) or []:
                    if not isinstance(res, dict):
                        continue
                    status = str(res.get("status") or "").strip().upper()
                    if status not in _LEAD_STATUSES:
                        continue
                    check_id = str(res.get("test_number") or "").strip()
                    if not check_id:
                        continue
                    lead = {
                        "check_id": check_id,
                        "description": str(res.get("test_desc") or "").strip(),
                        "status": status,
                    }
                    if section:
                        lead["section"] = section
                    remediation = str(res.get("remediation") or "").strip()
                    if remediation:
                        lead["remediation"] = remediation
                    # The CONCRETE observed value kube-bench recorded (e.g. the actual apiserver/kubelet
                    # command line or config value). Retained so the k8s-posture oracle
                    # (verify.k8s_posture) can re-derive a proven insecure setting from it — the sensor
                    # still STOPS at a lead; the oracle promotes it. Absent value => the lead has no
                    # concrete proof and stays a lead (the oracle will not fire on it).
                    actual_value = str(res.get("actual_value") or "").strip()
                    if actual_value:
                        lead["actual_value"] = actual_value
                    out.append(lead)
    return out


def kube_bench_observations(controls: list[dict], *, seq: int, source: str = "kube_bench") -> list[Observation]:
    """Mint a CONTROL observation per failed/warned CIS control — a LEAD (``GROUNDING_INTEL``), never a
    confirmed weakness. The control's evidence (status/section/remediation) rides in ``attrs`` so a future
    k8s-posture oracle can re-derive the weakness, exactly as ``sca_observations`` carries advisory
    evidence for the version-range oracle.

    A failed CIS control IS a (missing/misconfigured) defensive control, so ``NodeKind.CONTROL`` is the
    faithful existing subject kind — one distinct node per check_id, keyed ``cis-k8s:<check_id>``, so N
    checks mint N distinct, collision-free leads. Claim-keyed obs_ids => re-ingest / reorder / an
    intra-batch duplicate check_id collapse to one observation; PURE (no wallclock/rng)."""
    out: list[Observation] = []
    seen: set[str] = set()
    for c in controls:
        if not isinstance(c, dict):
            continue
        check_id = str(c.get("check_id") or "").strip()
        if not check_id:
            continue
        key = f"cis-k8s:{check_id}".lower()
        if key in seen:
            continue
        seen.add(key)
        status = str(c.get("status") or "").strip().upper()
        ref = EntityRef(kind=NodeKind.CONTROL, key=key)
        out.append(Observation(
            # obs_id IS the (source, seq, subject) claim key — no positional index, no clock, no rng —
            # so a re-ingest or a duplicate check_id dedups and the Beta belief never double-counts.
            obs_id=f"{source}:{seq}:{ref.node_id}||",
            source=source, source_kind=IntelSourceKind.CLOUD_POSTURE, collector=source,
            subject=ref, relation=None, object=None,
            attrs={k: v for k, v in {
                "check_id": check_id,
                "status": status or None,
                "description": c.get("description") or None,
                "section": c.get("section") or None,
                "remediation": c.get("remediation") or None,
                # the concrete observed value the k8s-posture oracle re-derives a weakness from
                "actual_value": c.get("actual_value") or None,
                "benchmark": "cis-kubernetes",
            }.items() if v},
            source_reliability=_KUBE_BENCH_RELIABILITY,
            confidence=_STATUS_CONFIDENCE.get(status, 0.6), seq=seq))
    return out


class KubeBenchSensor:
    """Ingest an operator-provided kube-bench ``--json`` report and mint CIS-control-failure LEADS. args:
    ``{"report": "/path/to/kube-bench.json"}``. Passive (Tier-1): reads a local file, no network, no
    device/cluster control, no entitlement. The leads STOP here; the k8s-posture oracle
    (``verify.k8s_posture``) re-verifies a lead to a FACT only when the retained control proves a
    concrete insecure setting. Mirrors ``SbomVulnSensor``."""

    name = "kube_bench"
    tier = "T1"
    capability = None
    destructive = False
    egress_hosts: tuple = ()

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        report = args.get("report") if isinstance(args, dict) else None
        if not report or not isinstance(report, str):
            return ToolResult(ok=False, note="kube_bench requires args['report'] (a kube-bench --json path)")
        if not os.path.isfile(report):
            return ToolResult(ok=False, note=f"kube_bench: report not found: {report}")
        try:
            text = open(report, "r", encoding="utf-8", errors="replace").read()
        except OSError as e:
            return ToolResult(ok=False, note=f"kube_bench: could not read report: {e}")
        controls = parse_kube_bench(text)
        return ToolResult(ok=True, summary=f"kube-bench: {len(controls)} failed/warned control(s)",
                          output={"controls": controls})

    def normalize(self, result: ToolResult, ctx: ToolContext, *, seq: int):
        out = result.output or {}
        controls = out.get("controls")
        if not isinstance(controls, list):
            return []
        return kube_bench_observations(controls, seq=seq, source="kube_bench")

    def controls(self, result: ToolResult) -> list[dict]:
        """The failed/warned CIS-control evidence the k8s-posture oracle (verify.k8s_posture) re-verifies."""
        out = result.output or {}
        c = out.get("controls")
        return c if isinstance(c, list) else []
