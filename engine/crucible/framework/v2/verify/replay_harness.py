"""
verify.replay_harness — re-drive a stored PoC and prove it still reproduces (Proof Studio B4).

Given a stored :class:`evidence.poc.PoCArtifact`, this re-runs the proof over its captured exchanges and
returns pass/fail. The DEFAULT mode is a pure CONTENT replay (like :mod:`verify.confirmation`, which judges
on response content — status/length/lexical — never wallclock): reconstruct the ``FindingContext`` from the
artifact's captured bytes via :func:`verify.poc_translate.context_from_exchanges` and re-fire the pure
oracle through :func:`verify.reverify.reverify_context`. Because the oracle is pure and the retained bytes
are fixed, this is deterministic and needs no target — it is exactly "does the stored proof still prove
itself?".

A LIVE re-drive (re-sending the payload to a scope-gated target and capturing fresh bytes) is a strict
superset that runs under the SAME gate chain as any offense action (WARDEN ∧ CRUCIBLE scope ∧ kill-switch ∧
egress deny-default); it is out of scope for this pure harness and is the offense-worker's job. This module
only re-fires over RETAINED evidence.

DETERMINISM GAPS still to close before a LIVE re-drive can claim byte-identical reproduction (documented
here so the follow-up is explicit, per B4):
  * pin the sandbox by ``env.image_digest`` (content digest, not a tag) before re-running;
  * pin + hash the seccomp profile (``env.seccomp_profile_sha256``) and refuse a mismatch;
  * set the cgroup cpu/mem bound (``env.cgroup_limits``) so a replay cannot exhaust the host;
  * time-box each replay so a hang is a fail, not a wedge;
  * re-seed from ``env.seed`` / ``env.nonce`` so any injected non-determinism is reproduced, not re-rolled.
This CONTENT replay is unaffected by those gaps (it never re-executes anything); they matter only when the
harness is later extended to re-drive a live capture.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict

from .poc_translate import context_from_exchanges
from .reverify import reverify_context
from .verifier import OracleVerifier

ResolveFn = Callable[[str], "bytes | None"]


class ReplayResult(BaseModel):
    """The verdict of re-driving one stored PoC over its retained evidence."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    passed: bool                          # the stored proof still reproduces (oracle re-fired + matched)
    reproduced: bool = False              # the pure oracle re-fired over the retained context
    confirmed_by: str | None = None
    confidence: float = 0.0
    note: str = ""


def replay_poc(
    artifact: Any,
    *,
    resolve: ResolveFn,
    verifier: OracleVerifier | None = None,
) -> ReplayResult:
    """Re-drive ``artifact`` (a :class:`evidence.poc.PoCArtifact`, duck-typed: ``.finding_ref``,
    ``.bug_class``, ``.exchanges``) over its retained captured bytes and return whether it still
    reproduces. ``resolve`` maps a byte-ref to the stored raw bytes. Fail-closed: an artifact whose
    exchanges no longer carry a translatable context, or whose evidence no longer re-confirms, is a
    ``passed=False`` — never a spurious pass."""
    ref = str(getattr(artifact, "finding_ref", "") or "finding")
    bug_class = str(getattr(artifact, "bug_class", "") or "")
    exchanges = list(getattr(artifact, "exchanges", []) or [])

    ctx = context_from_exchanges(exchanges, bug_class=bug_class, resolve=resolve)
    if ctx is None:
        return ReplayResult(
            finding_ref=ref, passed=False, reproduced=False,
            note="stored exchanges no longer translate to an oracle context (missing/unreadable bytes)",
        )

    rr = reverify_context(ctx.model_dump(mode="json"), bug_class=bug_class, ref=ref, verifier=verifier)
    return ReplayResult(
        finding_ref=ref, passed=rr.reproduced, reproduced=rr.reproduced,
        confirmed_by=rr.confirmed_by, confidence=rr.confidence, note=rr.note,
    )
