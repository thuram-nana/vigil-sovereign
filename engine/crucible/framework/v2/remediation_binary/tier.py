"""remediation_binary.tier — a binary / memory-safety auto-patch tier scaffold (X2).

Parallel to the web auto-patch tier, but for native crashes (ASAN/UBSAN/MSAN/TSAN, glibc aborts,
Rust/Go panics, signals, Python tracebacks). Two parts:

  * [BUILT] ONE genuinely working narrow path — ``SanitizerSilenceTier``. It drives the EXISTING
    ``verify.oracles.sanitizer_signal_oracle`` (it does NOT reimplement crash detection) to (a) confirm a
    captured crash's signature and (b) decide remediation the A6a way: a fix is EARNED BY ORACLE SILENCE,
    never asserted. ``remediated_if_silent(before, after)`` is True ONLY when the sanitizer oracle FIRES
    on the pre-fix output and goes SILENT on the post-fix output.

  * [research-gated] the actual patch SYNTHESIS (symbolic execution / a cyber-reasoning system that
    localises the faulting instruction and emits a source/binary patch) is a ``NotImplementedError`` stub
    behind the same interface — ``synthesize_patch``. See docs/DEFERRED-INFRA.md (X2).

ORACLE AUTHORITY (load-bearing)
-------------------------------
This module NEVER asserts a crash is fixed. It only *observes* the sanitizer oracle: fired-then-silent.
If the crash never reproduced before the fix (oracle silent on ``before``), there is nothing to prove
remediated, so ``remediated_if_silent`` returns False — you cannot earn silence you never broke. The
oracle is the sole authority; this tier mints no fact and promotes nothing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..verify.models import OracleSignal
from ..verify.oracles import sanitizer_signal_oracle


@dataclass(frozen=True)
class CapturedCrash:
    """A crash captured from a target run — the raw sanitizer/panic/traceback output plus optional
    context. ``output`` is the ONLY thing the oracle reads; the rest is provenance for the audit trail."""

    output: str
    label: str = ""            # operator note (e.g. 'heap-uaf in parse_header'); NOT trusted by the oracle
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BinaryPatch:
    """A proposed native patch. A placeholder record for the interface — producing a real one is the
    research-gated CRS work below; this tier never fabricates a patch body."""

    description: str
    diff: str = ""
    provenance: str = ""


class BinaryPatchTier(ABC):
    """The interface a binary/memory-safety auto-patch tier satisfies — parallel to the web tier.

    ``confirm_crash`` + ``remediated_if_silent`` are the oracle-driven confirmation/verification surface
    (implementable today). ``synthesize_patch`` is the generative step (research-gated). A concrete tier
    may implement the confirmation surface and leave synthesis as a stub — that is the honest state today.
    """

    @abstractmethod
    def confirm_crash(self, crash: CapturedCrash) -> OracleSignal:
        """Confirm a captured crash's signature via the sanitizer oracle (returns the OracleSignal)."""

    @abstractmethod
    def synthesize_patch(self, crash: CapturedCrash) -> BinaryPatch:
        """Localise the fault and emit a patch. [research-gated] — the CRS/symbolic engine."""

    @abstractmethod
    def remediated_if_silent(self, before_crash: Any, after_crash: Any) -> bool:
        """True ONLY when the oracle fired on ``before`` and is silent on ``after`` (fix earned by silence)."""


class SanitizerSilenceTier(BinaryPatchTier):
    """[BUILT for confirm/verify · research-gated for synthesis] The one working narrow path.

    Confirmation and remediation-by-silence are real and run today over the existing sanitizer oracle.
    Patch *synthesis* raises ``NotImplementedError`` — this tier proves a fix is real (the oracle went
    silent) but does not itself generate the fix; a human or an external tool supplies the after-fix run.
    """

    def confirm_crash(self, crash: CapturedCrash) -> OracleSignal:
        """Drive the shared sanitizer oracle over the captured output. No reimplementation — the oracle
        is the single source of the crash-signature verdict."""
        return sanitizer_signal_oracle(crash.output)

    def remediated_if_silent(self, before_crash: Any, after_crash: Any) -> bool:
        """A6a 'earned by oracle silence': proven remediated iff the oracle FIRED on the pre-fix output
        AND does NOT fire on the post-fix output. A crash that never fired before the fix returns False
        (nothing to earn); a crash still firing after the fix returns False (not remediated)."""
        before = sanitizer_signal_oracle(_output_of(before_crash))
        after = sanitizer_signal_oracle(_output_of(after_crash))
        return bool(before.fired) and not bool(after.fired)

    def synthesize_patch(self, crash: CapturedCrash) -> BinaryPatch:  # pragma: no cover - stub
        raise NotImplementedError(
            "research-gated: automated native patch synthesis (symbolic execution / cyber-reasoning "
            "system) is not built. This tier PROVES a fix by oracle silence but does not generate it — "
            "supply the after-fix run to remediated_if_silent(). See docs/DEFERRED-INFRA.md (X2)."
        )


class SymbolicCrashRepairTier(BinaryPatchTier):
    """[research-gated] The full cyber-reasoning system behind the SAME interface — every method is a
    stub. This is the ROADMAP target: taproot the faulting input, drive symbolic execution to localise
    the memory-safety violation, synthesise + validate a patch, then confirm the fix by oracle silence.

    ACTIVATION RUNBOOK (docs/DEFERRED-INFRA.md → X2):
      1. Integrate a symbolic/concolic engine (e.g. angr) + a fuzzer harness for the target binary.
      2. Implement ``synthesize_patch`` to localise the fault and emit a candidate diff.
      3. Re-run the target under sanitizers on the candidate; gate acceptance on
         ``SanitizerSilenceTier().remediated_if_silent(before, after)`` — silence, never assertion.
    """

    def confirm_crash(self, crash: CapturedCrash) -> OracleSignal:  # pragma: no cover - stub
        raise NotImplementedError("research-gated: see docs/DEFERRED-INFRA.md (X2)")

    def synthesize_patch(self, crash: CapturedCrash) -> BinaryPatch:  # pragma: no cover - stub
        raise NotImplementedError("research-gated: see docs/DEFERRED-INFRA.md (X2)")

    def remediated_if_silent(self, before_crash: Any, after_crash: Any) -> bool:  # pragma: no cover - stub
        raise NotImplementedError("research-gated: see docs/DEFERRED-INFRA.md (X2)")


def _output_of(crash: Any) -> Any:
    """Accept a ``CapturedCrash`` or a raw string/bytes — extract the output the oracle reads."""
    if isinstance(crash, CapturedCrash):
        return crash.output
    return crash
