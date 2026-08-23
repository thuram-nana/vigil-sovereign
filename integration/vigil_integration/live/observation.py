"""observation — the ONE normalized record every external-tool EXECUTION emits (integration criterion 4).

Before this, a tool run's parsed output was a bare ``list[ProposedService]`` and the "what the tool actually
said" bytes were unbound. The canonical :class:`Observation` normalizes every run into a single shape so
adding a new tool means emitting THIS record, not a bespoke dict per oracle. Every field it carries:

  * ``tool`` / ``tool_version`` — the tool IDENTITY and its ASSERTED version (a producer say-so, NOT a proof
    of which binary ran — see ``binary_sha256`` and the certificate).
  * ``binary_sha256`` — the TRUSTED digest of the bytes that actually ran, attested by the exec backend (the
    host executable's file digest for a host backend; the digest-pinned image ref for a container backend).
    ``""`` when the backend cannot attest it — never fabricated.
  * ``target`` — the already-scope-authorised target the tool was pointed at.
  * ``args_sha256`` — a deterministic digest over the EXACT argv the tool was invoked with (injective
    length-prefixed framing), so an audit can bind WHAT was run without retaining the argv verbatim.
  * ``backend`` — the exec backend (topology seam) the tool ran through.
  * ``outcome_class`` — ``"ran"`` | ``"errored"`` | ``"refused"`` (never ``"fact"``: see below).
  * ``raw_output_sha256`` — sha256 of the tool's RAW stdout+stderr (binds the tool's say-so; tamper-evident).
  * ``artifact_refs`` — pointers to the artifacts THIS run produced (the ``finding_ref`` of each lead/fact the
    runner minted from it). Pointers, never a verdict.
  * ``proposals`` — the normalized ``(host, port, protocol)`` tuples the runner will independently re-drive.
  * ``truncated`` — the tool output was capped.
  * ``error_reason`` — why the run ERRORED (timeout/spawn) or was REFUSED (scope/gate/kill-switch), ``""`` on
    a clean run. Records the negative honestly.

Load-bearing honesty: the Observation is an OBSERVATION, never a FACT. Everything it carries is PROPOSAL /
provenance material (where to look, what ran, what the tool said) — it has NO field that can hold a verdict,
a signature, or a confirmed finding, and ``outcome_class`` is structurally one of ran/errored/refused. A FACT
is minted ONLY by the runner's own oracle re-drive over its OWN gated capture, crossing ``verdict.admit()``.
This record is the parser/normalizer output; the parser/normalizer may emit proposals and LEADs and it may
NEVER emit a FACT. stdlib only (no framework import — this record is sovereign-loaded, FATAL-2).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Observation:
    """The normalized result of ONE external-tool execution. Deterministic (no wallclock — the spine's
    ``seq`` is the monotonic order, exactly as the certificate does); JSON-safe. It carries proposals and
    provenance ONLY — there is no field that can hold a FACT, a verdict, or a signature."""

    tool: str
    target: str
    outcome_class: str                 # "ran" | "errored" | "refused"  (never "fact")
    tool_version: str = ""             # producer's ASSERTED version (not a proof of the binary — see below)
    binary_sha256: str = ""            # TRUSTED digest of the bytes that RAN, attested by the backend (host
    #                                    executable file digest, or the digest-pinned image ref). "" ⇒ the
    #                                    backend could not attest it — never fabricated.
    args_sha256: str = ""              # deterministic digest of the exact argv the tool was invoked with
    raw_output_sha256: str = ""        # sha256 of the tool's raw stdout+stderr (binds the tool's say-so)
    proposals: tuple = ()              # normalized (host, port, protocol) tuples the runner will re-drive
    artifact_refs: tuple = ()          # finding_refs of the leads/facts this run produced (pointers only)
    truncated: bool = False            # the tool output was capped
    backend: str = ""                  # the exec backend the tool ran through
    error_reason: str = ""             # why the run errored / was refused ("" on a clean run)

    def to_dict(self) -> dict:
        return {
            "schema": "vigil-observation/2",
            "tool": self.tool, "target": self.target, "outcome_class": self.outcome_class,
            "tool_version": self.tool_version, "binary_sha256": self.binary_sha256,
            "args_sha256": self.args_sha256, "raw_output_sha256": self.raw_output_sha256,
            "proposals": [list(p) for p in self.proposals],
            "artifact_refs": list(self.artifact_refs),
            "truncated": self.truncated, "backend": self.backend,
            "error_reason": self.error_reason,
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


def _args_sha256(argv: Any) -> str:
    """Deterministic digest over the exact argv the tool was invoked with. Each argument is LENGTH-PREFIXED
    (``len(arg)\\n arg``) so the framing is INJECTIVE — two distinct argv lists can never share a digest and
    an argument containing a newline cannot forge a boundary. Empty/absent argv ⇒ "" (no args recorded)."""
    items = list(argv or [])
    if not items:
        return ""
    raw = b"".join(
        f"{len(b)}\n".encode("ascii") + b
        for b in (str(a).encode("utf-8", "replace") for a in items)
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def observe(spec: Any, target: str, outcome: Any, proposals: Any, *, tool_version: str = "",
            outcome_class: str = "ran", artifact_refs: Any = (), error_reason: str = "") -> Observation:
    """Build the canonical Observation from a completed tool run (the runner calls this). A missing/None
    field degrades to its default (the runner always supplies well-typed inputs — spec.propose returns a
    list, ToolOutcome.stdout/stderr are str); wrong-typed fields are the caller's contract, not handled.

    ``binary_sha256`` and ``args_sha256`` are read/derived from the ``outcome`` the backend produced —
    the backend is the ONLY layer that knows which bytes actually ran (esp. a container backend), so the
    trusted binary digest is attested there and threaded through the outcome, never guessed here."""
    props = tuple(
        (getattr(p, "host", ""), getattr(p, "port", 0), getattr(p, "protocol", "tcp"))
        for p in (proposals or [])
    )
    return Observation(
        tool=str(getattr(spec, "name", "") or ""),
        target=str(target or ""),
        outcome_class=outcome_class,
        tool_version=str(tool_version or ""),
        binary_sha256=str(getattr(outcome, "binary_sha256", "") or "") if outcome is not None else "",
        args_sha256=_args_sha256(getattr(outcome, "argv", ())) if outcome is not None else "",
        raw_output_sha256=_raw_output_sha256(outcome) if outcome is not None else "",
        proposals=props,
        artifact_refs=tuple(str(r) for r in (artifact_refs or ())),
        truncated=bool(getattr(outcome, "truncated", False)),
        backend=str(getattr(outcome, "backend", "") or ""),
        error_reason=str(error_reason or ""),
    )


def refused_observation(spec: Any, target: str, *, reason: str = "") -> Observation:
    """The Observation for a run REFUSED before any traffic (scope/gate/kill-switch) — outcome_class
    'refused', no output digest, no proposals, no artifacts. Records that the tool was NOT run, and WHY
    (``error_reason``) so an audit sees the negative honestly."""
    return Observation(tool=str(getattr(spec, "name", "") or ""), target=str(target or ""),
                       outcome_class="refused", error_reason=str(reason or ""))
