"""observation — the ONE normalized record every external-tool run emits (integration criterion 4).

Before this, a tool run's parsed output was a bare ``list[ProposedService]`` and the "what the tool actually
said" bytes were unbound. The canonical :class:`Observation` normalizes every run into a single shape —
tool identity + version, the target, a sha256 of the RAW tool output (so an audit can see exactly what the
tool emitted, and a tampered tool row is detectable), the normalized proposals, and the outcome class — so
adding a new tool means emitting THIS record, not a bespoke dict per oracle.

Load-bearing honesty: the Observation is an OBSERVATION, never a fact. The tool output (and its digest) is a
PROPOSAL of where to look; a FACT is still minted only by the runner's own oracle re-drive over its own
gated capture (the ``raw_output_sha256`` binds the tool's SAY-SO, not a verdict). vigil_core + stdlib only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Observation:
    """The normalized result of ONE external-tool run. Deterministic (no wallclock — the spine's ``seq``
    is the monotonic order, exactly as the certificate does); JSON-safe."""

    tool: str
    target: str
    outcome_class: str                 # "ran" | "errored" | "refused"
    tool_version: str = ""             # producer's ASSERTED version (not a proof of the binary — see cert)
    raw_output_sha256: str = ""        # sha256 of the tool's raw stdout+stderr (binds the tool's say-so)
    proposals: tuple = ()              # normalized (host, port, protocol) tuples the runner will re-drive
    truncated: bool = False            # the tool output was capped
    backend: str = ""                  # the exec backend the tool ran through

    def to_dict(self) -> dict:
        return {
            "schema": "vigil-observation/1",
            "tool": self.tool, "target": self.target, "outcome_class": self.outcome_class,
            "tool_version": self.tool_version, "raw_output_sha256": self.raw_output_sha256,
            "proposals": [list(p) for p in self.proposals],
            "truncated": self.truncated, "backend": self.backend,
        }


def _raw_output_sha256(outcome: Any) -> str:
    """sha256 over the tool's raw stdout+stderr — a stable digest of exactly what the tool emitted (its
    proposal material). Binds the tool's say-so for the audit trail; NEVER a verdict."""
    raw = ((getattr(outcome, "stdout", "") or "") + "\x00" + (getattr(outcome, "stderr", "") or "")).encode(
        "utf-8", "replace")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def observe(spec: Any, target: str, outcome: Any, proposals: Any, *, tool_version: str = "",
            outcome_class: str = "ran") -> Observation:
    """Build the canonical Observation from a completed tool run (the runner calls this). Total — never
    raises; a missing field degrades to its default."""
    props = tuple(
        (getattr(p, "host", ""), getattr(p, "port", 0), getattr(p, "protocol", "tcp"))
        for p in (proposals or [])
    )
    return Observation(
        tool=str(getattr(spec, "name", "") or ""),
        target=str(target or ""),
        outcome_class=outcome_class,
        tool_version=str(tool_version or ""),
        raw_output_sha256=_raw_output_sha256(outcome) if outcome is not None else "",
        proposals=props,
        truncated=bool(getattr(outcome, "truncated", False)),
        backend=str(getattr(outcome, "backend", "") or ""),
    )


def refused_observation(spec: Any, target: str, *, reason: str = "") -> Observation:
    """The Observation for a run REFUSED before any traffic (scope/gate) — outcome_class 'refused', no
    output digest, no proposals. Records that the tool was NOT run."""
    return Observation(tool=str(getattr(spec, "name", "") or ""), target=str(target or ""),
                       outcome_class="refused")
