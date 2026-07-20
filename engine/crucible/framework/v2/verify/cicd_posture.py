"""verify.cicd_posture — the confirmation seam + minimal offline ingest for the CI/CD-posture oracle.

A GitHub-Actions workflow is a config artifact (Phase-2 coverage). No CI/CD parser existed in the tree,
so — exactly like ``verify.mesh_posture.ingest_mesh_config`` — this module also carries a MINIMAL,
OFFLINE, READ-ONLY ingest: it parses a workflow (safe YAML / JSON, never executing code, never cloning a
repo) into per-control LEADS, then routes each through ``cicd_posture_oracle``, which RE-DERIVES the
danger over the RETAINED control (never trusting the parse's label). No benchmark/scan/engage finding
carries ``cicd_control``, so the gate stays byte-identical. Never raises: a malformed workflow is a
non-ingestion, not a crash.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier

try:  # optional dep — absent => YAML workflows don't ingest (JSON still does), never a crash
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None

# The ingest's (permissive) detection of an untrusted PR-head checkout — the oracle RE-CHECKS it strictly.
_UNTRUSTED_PR_CHECKOUT_RE = re.compile(
    r"(?i)(github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/)")


def _load_yaml(workflow: Any) -> Mapping[str, Any] | None:
    """Parse a workflow into a mapping (a dict as-is; JSON first, then SAFE YAML). ``None`` on anything
    unrecognised/malformed. NEVER raises, NEVER executes code (YAML uses safe_load; JSON is inert)."""
    if isinstance(workflow, Mapping):
        return workflow
    if not isinstance(workflow, str) or not workflow.strip():
        return None
    try:
        parsed = json.loads(workflow)
        return parsed if isinstance(parsed, Mapping) else None
    except Exception:
        pass
    if _yaml is None:
        return None
    try:
        doc = _yaml.safe_load(workflow)
    except Exception:
        return None
    return doc if isinstance(doc, Mapping) else None


def _trigger_names(wf: Mapping[str, Any]) -> set[str]:
    """The set of workflow trigger names. Handles the classic gotcha that YAML 1.1 parses the ``on:`` key
    as the boolean ``True``, and that ``on`` may be a string / list / mapping."""
    on = wf.get("on")
    if on is None:
        on = wf.get(True)   # `on:` parsed as boolean True by a YAML 1.1 loader
    names: set[str] = set()
    if isinstance(on, str):
        names.add(on)
    elif isinstance(on, (list, tuple)):
        names.update(str(x) for x in on)
    elif isinstance(on, Mapping):
        names.update(str(k) for k in on.keys())
    return {n.strip().lower() for n in names}


def ingest_workflow(workflow: Any, *, name: str = "workflow") -> list[dict[str, Any]]:
    """Parse a GitHub-Actions workflow (YAML/JSON text or a dict) into CI/CD control descriptors — the
    LEADS the oracle re-verifies. Permissive (emits a control per candidate construct); the oracle is the
    near-zero-FP gate (a SHA-pinned/first-party action, a plain ``pull_request``, a ``run`` with no
    untrusted interpolation all fail re-derivation). Deterministic order; ``[]`` on malformed input."""
    wf = _load_yaml(workflow)
    if not isinstance(wf, Mapping):
        return []
    controls: list[dict[str, Any]] = []
    has_ppt = "pull_request_target" in _trigger_names(wf)
    jobs = wf.get("jobs")
    if not isinstance(jobs, Mapping):
        return []
    for job_name in sorted(jobs.keys(), key=str):
        job = jobs.get(job_name)
        if not isinstance(job, Mapping):
            continue
        steps = job.get("steps")
        if not isinstance(steps, (list, tuple)):
            continue
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                controls.append({"rule": "unpinned_action", "workflow": name,
                                 "job": str(job_name), "uses": uses.strip()})
                if has_ppt and "checkout" in uses.lower():
                    with_ = step.get("with")
                    ref = str(with_.get("ref") or "") if isinstance(with_, Mapping) else ""
                    if _UNTRUSTED_PR_CHECKOUT_RE.search(ref):
                        controls.append({"rule": "pwn_request", "workflow": name, "job": str(job_name),
                                         "trigger": "pull_request_target", "checkout_ref": ref})
            run = step.get("run")
            if isinstance(run, str) and "${{" in run:
                controls.append({"rule": "script_injection", "workflow": name,
                                 "job": str(job_name), "run": run})
    return controls


def cicd_posture_context(control: Mapping[str, Any]) -> dict:
    """The verifier context for a retained workflow control — routes to the CI/CD-posture oracle."""
    return FindingContext.from_cicd_control(dict(control or {})).to_verifier_context()


def confirm_cicd_posture(control: Mapping[str, Any], *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge one retained workflow control: ``confirmed`` iff the oracle re-derives a concrete dangerous
    construct over it. Re-verifies offline from the finding's certificate."""
    return (verifier or OracleVerifier()).confirm(cicd_posture_context(control))


def confirm_workflow(workflow: Any, *, name: str = "workflow",
                     verifier: OracleVerifier | None = None) -> list[dict[str, Any]]:
    """Ingest a workflow + return the controls the oracle CONFIRMED as FACTs (each with its rule/evidence).
    Convenience over ``ingest_workflow`` + ``confirm_cicd_posture``; deterministic."""
    v = verifier or OracleVerifier()
    return [ctl for ctl in ingest_workflow(workflow, name=name) if confirm_cicd_posture(ctl, verifier=v).confirmed]
