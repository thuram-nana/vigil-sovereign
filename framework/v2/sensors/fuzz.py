"""
sensors.fuzz — a gated, opt-in fuzz/ASan PRODUCER for the memory bug classes (Workstream D.1).

The verify layer already ships the ``sanitizer_signal_oracle`` (``verify.oracles``) and routes the
four memory classes — ``memory_corruption`` / ``buffer_overflow`` / ``use_after_free`` / ``crash`` —
to ``OracleKind.SANITIZER_SIGNAL`` (``verify.verifier.BUG_CLASS_ORACLES``). What was missing is the
PRODUCER of the ``process_output`` that oracle judges. This module is that producer: it drives a
bounded fuzz against a LOCALHOST / operator-authorized binary, captures its stdout+stderr, and hands
that captured output to the oracle so a real ASAN/UBSAN/panic/abort marker becomes a FACT.

This is ROBUSTNESS testing (does the operator's own binary crash on hostile input?), NOT
weaponization — there is no exploit synthesis, no payload delivery to a remote party, no persistence.
It is GATED to the hilt and OFF by default:

  * OPT-IN LATCH. ``run`` refuses unless ``args['authorized'] is True`` — the harness never fires on
    an implicit default.
  * AUTHORIZATION-CRITICAL binary allowlist. The binary must resolve (``realpath``, following
    symlinks) to a regular executable file INSIDE an operator-declared ``allowed_root`` directory.
    ``allowed_root`` defaults to None, so a freshly-registered harness refuses EVERYTHING until an
    operator wires a root — the same fail-closed spirit as nmap's single-host guard.
  * FULL GATE CHAIN. As a W1.4 tool it declares ``capability = EXPLOIT_EXECUTION`` (the entitlement
    gate refuses it without that grant), ``destructive = True`` (crashing a process needs the
    operator's destructive-confirm), and ``tier = 'T3'`` — so ``invoke_tool`` / ``run_sensor``
    enforce kill-switch -> entitlement -> destructive-confirm before ``run`` is ever reached.
  * DEGRADES CLEANLY. No binary / not authorized / a path that escapes the root -> a failed
    ToolResult with a reason, never a crash, never a guess.

PROVE-DON'T-GUESS. The harness's own "did it look like it crashed" flag is a LEAD only. The FACT is
minted solely by ``confirm_crash``, which re-runs the deterministic SANITIZER_SIGNAL oracle over the
captured output — the oracle is the sole authority, exactly as everywhere else in CRUCIBLE.

DETERMINISM. The subprocess OUTPUT reflects the live process, but the case corpus
(``default_fuzz_cases``) and the confirmation (``confirm_crash``) are PURE, replayable functions of
their inputs — no wallclock, no rng. Two runs over the same captured output confirm identically.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

from ..agents.tools import ToolContext, ToolResult
from ..entitlement.models import Capability

# The bug classes this producer can feed to the SANITIZER_SIGNAL oracle. Kept in sync with the
# BUG_CLASS_ORACLES rows that route to that oracle; a class outside this set defaults to "crash".
MEMORY_BUG_CLASSES: frozenset[str] = frozenset(
    {"memory_corruption", "buffer_overflow", "use_after_free", "crash"}
)

_DEFAULT_MAX_CASES = 64
_DEFAULT_TIMEOUT_S = 5
# Cap the captured text kept per case so a chatty binary cannot balloon the ToolResult.
_MAX_CAPTURED_CHARS = 8192


# ---------------------------------------------------------------------------
# case corpus — deterministic, no rng
# ---------------------------------------------------------------------------

# A small fixed set of classic memory-stressing inputs (length, format-string, integer-edge). These
# are ROBUSTNESS probes, not exploits: they carry no shellcode and no target-specific gadget — they
# just try to make a fragile parser mishandle its input so a sanitizer fires.
_KNOWN_STRESSORS: tuple[str, ...] = (
    "A" * 256,
    "A" * 1024,
    "A" * 4096,
    "%s%s%s%s%s%s%s%s",
    "%n%n%n%n",
    "%x" * 64,
    "-1",
    "2147483648",           # INT_MAX + 1
    "9999999999999999999",  # > INT64_MAX
    "../" * 64,
)


def default_fuzz_cases(
    seed_inputs: Any = None, *, max_cases: int = _DEFAULT_MAX_CASES
) -> list[str]:
    """A DETERMINISTIC, bounded case corpus: the operator's ``seed_inputs`` first (verbatim), then a
    fixed stressor set, then growing blocks of ``A`` (length/buffer probing via
    ``intruder.generators.char_blocks``). De-duplicated, order-preserving, capped at ``max_cases``.
    No rng, no clock — the same arguments always yield the same list, so a fuzz run is replayable."""
    from ..intruder.generators import char_blocks  # local import: avoid pulling intruder at module load

    if max_cases <= 0:
        return []
    ordered: list[str] = []
    if isinstance(seed_inputs, (list, tuple)):
        ordered.extend(str(s) for s in seed_inputs)
    ordered.extend(_KNOWN_STRESSORS)
    # deterministic length ladder: 8, 16, 32, ... doubling up to 8192
    length = 8
    while length <= 8192:
        ordered.append("A" * length)
        length *= 2
    # a fine-grained early ladder for small off-by-one boundaries
    ordered.extend(char_blocks("A", 1, 16))
    seen: set[str] = set()
    out: list[str] = []
    for c in ordered:
        if c not in seen:
            seen.add(c)
            out.append(c)
        if len(out) >= max_cases:
            break
    return out


# ---------------------------------------------------------------------------
# the LEAD -> FACT bridge (prove-don't-guess: the oracle re-fires, never the harness)
# ---------------------------------------------------------------------------


def _has_sanitizer_marker(captured: Any) -> bool:
    """Cheap LEAD check: does the captured output carry ANY sanitizer/crash marker? Used only to flag
    a case as interesting for the operator — NEVER to confirm. Confirmation is ``confirm_crash``."""
    from ..verify.oracles import sanitizer_signal_oracle

    return bool(sanitizer_signal_oracle(captured).fired)


def confirm_crash(captured: Any, *, bug_class: str = "crash", verifier: Any = None) -> Any:
    """Promote captured process output to a FACT iff the deterministic SANITIZER_SIGNAL oracle fires.

    ``captured`` is a binary's stdout+stderr. ``bug_class`` is normalised and, if it is not one of the
    four memory classes, defaults to ``crash`` (the generic sanitizer class) so a caller cannot smuggle
    an off-vocabulary class in. Delegates to ``verify.confirmation.confirm_finding`` over a
    ``FindingContext.from_process_output`` — returns a ``ConfirmedFinding`` (the FACT, carrying the
    firing oracle signal) or ``None`` (no marker fired -> the "crash" stays an un-promoted lead). There
    is NO assertion-only path to a fact: the harness's own verdict never confirms anything."""
    from ..verify.adapter import FindingContext
    from ..verify.confirmation import confirm_finding
    from ..verify.verifier import normalize_bug_class

    norm = normalize_bug_class(bug_class)
    if norm not in MEMORY_BUG_CLASSES:
        norm = "crash"
    ctx = FindingContext.from_process_output(captured, bug_class=norm)
    finding = {
        "bug_class": norm,
        "title": f"{norm} confirmed by a sanitizer signal in a fuzz run",
        "severity": "High",
        "surface": "fuzz-harness",
        "summary": (
            "A bounded fuzz of an authorized local binary produced output carrying a sanitizer/crash "
            "marker; the SANITIZER_SIGNAL oracle re-fired over it (prove-don't-guess)."
        ),
    }
    return confirm_finding(finding, ctx, verifier=verifier)


# ---------------------------------------------------------------------------
# authorization guard — the AUTHORIZATION-CRITICAL binary allowlist
# ---------------------------------------------------------------------------


def _authorized_binary(binary: str, allowed_root: str | None) -> str | None:
    """The realpath of ``binary`` iff it is a regular, executable file INSIDE ``allowed_root``
    (symlinks followed BEFORE the containment check, so a symlink cannot point out of the root), else
    None. Fail-closed: a None ``allowed_root``, a non-existent path, a non-file, a non-executable, or
    any path that escapes the root all return None. This guarantees the binary the harness executes is
    exactly one the operator placed under the authorized root — the local-binary analogue of nmap's
    single-host guard."""
    if not allowed_root or not isinstance(binary, str) or not binary.strip():
        return None
    try:
        root = os.path.realpath(allowed_root)
        real = os.path.realpath(binary)
    except (OSError, ValueError):
        return None
    if not os.path.isdir(root):
        return None
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        return None
    try:
        # commonpath raises on differing drives / mixed abs-rel; realpath makes both absolute.
        if os.path.commonpath([root, real]) != root:
            return None
    except ValueError:
        return None
    return real


# ---------------------------------------------------------------------------
# the harness
# ---------------------------------------------------------------------------


class FuzzHarnessSensor:
    """Drive a bounded fuzz against an operator-authorized LOCAL binary and capture its output for the
    SANITIZER_SIGNAL oracle. args: ``{"authorized": true, "binary": "/authorized/root/target",
    "mode": "stdin"|"argv"?, "seed_inputs": ["..."]?, "bug_class": "buffer_overflow"?}``.

    Gated (T3, ``EXPLOIT_EXECUTION``, destructive): ``invoke_tool`` enforces kill-switch -> entitlement
    -> destructive-confirm before ``run``. ``run`` itself enforces the opt-in latch and the
    ``allowed_root`` binary allowlist. OFF by default: ``allowed_root=None`` refuses everything.

    It produces ``process_output`` (a LEAD); ``confirm_crash`` is the sole FACT path. It intentionally
    exposes no ``normalize`` — it feeds the oracle bridge, not the world-model — so a run mints nothing
    on its own."""

    name = "fuzz_harness"
    tier = "T3"
    capability = Capability.EXPLOIT_EXECUTION
    destructive = True
    egress_hosts: tuple = ()   # a LOCAL binary: no network egress

    def __init__(
        self,
        *,
        allowed_root: str | None = None,
        max_cases: int = _DEFAULT_MAX_CASES,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
        fixed_args: tuple[str, ...] = (),
        default_bug_class: str = "crash",
    ) -> None:
        self._allowed_root = allowed_root
        self._max_cases = max(0, int(max_cases))
        self._timeout_s = max(1, int(timeout_s))
        self._fixed_args = tuple(str(a) for a in fixed_args)
        self._default_bug_class = default_bug_class

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, dict):
            return ToolResult(ok=False, note="fuzz_harness requires an args dict")
        # 1. OPT-IN LATCH — never fire on an implicit default.
        if args.get("authorized") is not True:
            return ToolResult(ok=False, note=(
                "fuzz_harness refused: pass args['authorized']=true to opt in "
                "(off by default — this executes an authorized local binary against fuzz input)"))
        binary = args.get("binary")
        if not binary or not isinstance(binary, str):
            return ToolResult(ok=False, note="fuzz_harness requires args['binary'] (a path to an authorized local binary)")
        # 2. AUTHORIZATION-CRITICAL allowlist — the binary must live under the operator-declared root.
        resolved = _authorized_binary(binary, self._allowed_root)
        if resolved is None:
            return ToolResult(ok=False, note=(
                "fuzz_harness refused: binary is not an executable file inside the operator-authorized "
                "allowed_root (or no allowed_root is configured — off by default)"))
        mode = args.get("mode", "stdin")
        if mode not in ("stdin", "argv"):
            return ToolResult(ok=False, note="fuzz_harness args['mode'] must be 'stdin' or 'argv'")
        bug_class = args.get("bug_class") or self._default_bug_class
        cases = default_fuzz_cases(args.get("seed_inputs"), max_cases=self._max_cases)
        if not cases:
            return ToolResult(ok=False, note="fuzz_harness produced no cases (max_cases=0?)")

        records: list[dict] = []
        crash_captured = ""
        for case in cases:
            captured, note = self._run_one(resolved, case, mode)
            if captured is None:
                # a launch error (OSError) is a clean stop, not a crash signal — degrade cleanly.
                return ToolResult(ok=False, note=f"fuzz_harness could not launch the binary: {note}")
            records.append({"input_repr": _repr_case(case), "captured": captured, "note": note})
            if not crash_captured and _has_sanitizer_marker(captured):
                crash_captured = captured   # first interesting case — a LEAD, confirmed only via confirm_crash

        return ToolResult(
            ok=True,
            summary=(f"fuzzed {os.path.basename(resolved)}: {len(records)} case(s), "
                     f"{'a sanitizer marker appeared' if crash_captured else 'no marker'}"),
            output={
                "binary": resolved,
                "mode": mode,
                "bug_class": bug_class,
                "cases": records,
                "crash_captured": crash_captured,
            },
        )

    def _run_one(self, binary: str, case: str, mode: str) -> tuple[str | None, str]:
        """Run the binary once with ``case``. Returns ``(captured, note)`` where captured is the
        combined stdout+stderr (truncated), or ``(None, reason)`` on a launch failure (OSError). A
        timeout is NOT a launch failure — a hang yields whatever was captured plus a note."""
        argv = [binary, *self._fixed_args]
        stdin_data: str | None = None
        if mode == "argv":
            argv += ["--", case]   # end-of-options guard: the case can never be read as a flag
        else:
            stdin_data = case
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell; binary is allowlist-guarded, case is stdin/argv value
                argv, input=stdin_data, capture_output=True, text=True,
                timeout=self._timeout_s, check=False,
            )
        except subprocess.TimeoutExpired as e:
            captured = _combine(e.stdout, e.stderr)
            return captured, f"timeout after {self._timeout_s}s"
        except OSError as e:
            return None, str(e)
        return _combine(proc.stdout, proc.stderr), f"exit {proc.returncode}"


def _combine(stdout: Any, stderr: Any) -> str:
    """Combine + truncate a case's stdout and stderr into one captured blob for the oracle."""
    def _s(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, bytes):
            return v.decode("utf-8", "replace")
        return str(v)
    text = (_s(stdout) + ("\n" if stdout and stderr else "") + _s(stderr))
    return text[:_MAX_CAPTURED_CHARS]


def _repr_case(case: str) -> str:
    """A short, non-exploding repr of a fuzz case for the audit record."""
    if len(case) <= 32:
        return case
    return f"{case[:16]}...<{len(case)} chars>"
