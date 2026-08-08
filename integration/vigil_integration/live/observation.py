"""observation — the ONE normalized record every external-tool run emits (integration criterion 4).

Before this, a tool run's parsed output was a bare ``list[ProposedService]`` and the "what the tool actually
said" bytes were unbound. The canonical :class:`Observation` normalizes every run into a single shape —
tool identity + version, the target, a sha256 of the RAW tool output (so an audit can see exactly what the
tool emitted, and a tampered tool row is detectable), the normalized proposals, and the outcome class — so
adding a new tool means emitting THIS record, not a bespoke dict per oracle.

Load-bearing honesty: the Observation is an OBSERVATION, never a fact. The tool output (and its digest) is a
PROPOSAL of where to look; a FACT is still minted only by the runner's own oracle re-drive over its own
gated capture (the ``raw_output_sha256`` binds the tool's SAY-SO, not a verdict). stdlib only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
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
    proposal material). Binds the tool's say-so for the audit trail; NEVER a verdict.

    The two streams are LENGTH-PREFIXED (``len(stdout)\\n stdout \\n stderr``) so the framing is INJECTIVE:
    a plain ``\\x00`` delimiter is not, because ``\\x00`` can occur in the data (stdout='a\\x00',stderr='b'
    would collide with stdout='a',stderr='\\x00b'). With the byte-length prefix, two distinct (stdout,stderr)
    pairs can never share a digest — so the bind is genuinely tamper-evident (over the audit trail)."""
    so = ((getattr(outcome, "stdout", "") or "")).encode("utf-8", "replace")
    se = ((getattr(outcome, "stderr", "") or "")).encode("utf-8", "replace")
    raw = f"{len(so)}\n".encode("ascii") + so + b"\n" + se
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def observe(spec: Any, target: str, outcome: Any, proposals: Any, *, tool_version: str = "",
            outcome_class: str = "ran") -> Observation:
    """Build the canonical Observation from a completed tool run (the runner calls this). A missing/None
    field degrades to its default (the runner always supplies well-typed inputs — spec.propose returns a
    list, ToolOutcome.stdout/stderr are str); wrong-typed fields are the caller's contract, not handled."""
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
