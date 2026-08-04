"""remediation_binary.asan_repair — a REAL, narrow ASan-grounded crash-confirm + patch-synthesis + fix-by-silence
path (TRUTHENOVATION R3, PR1).

Where :mod:`remediation_binary.tier` is the oracle-driven confirm/verify *interface* (with ``synthesize_patch`` a
``NotImplementedError`` stub), this module wires an ACTUAL end-to-end loop over the tooling that is present
(``gcc -fsanitize=address``): it COMPILES a C source under AddressSanitizer, RUNS it on a crashing input, confirms
the memory-safety crash via the EXISTING ``sanitizer_signal_oracle`` (through :class:`SanitizerSilenceTier`,
oracle authority — this module reimplements no crash detection), SYNTHESISES a patch, recompiles, and accepts the
fix ONLY when the sanitizer goes SILENT on the same crashing input AND the benign functionality is preserved (so a
``return 0`` / stub "fix" is rejected, not silence-gamed).

WHAT IS REAL vs the HONEST RESIDUAL (TRUTHENOVATION Rule 1/2/3)
--------------------------------------------------------------
REAL (BUILT + tested): the ASan-grounded crash-confirm and the fix-by-silence verification over a genuinely
compiled+run binary; and a **pattern-based** patch synthesiser for ONE narrow, well-defined memory-safety class —
an unbounded ``strcpy(dst, src)`` into a fixed-size stack buffer ``char dst[N]`` → a bounded
``strncpy(dst, src, N-1); dst[N-1]='\\0'``. It emits a real diff that compiles, silences ASan, and keeps the
function working.

RESIDUAL (marked, DEFERRED — tooling-bounded): GENERAL patch synthesis — localising an arbitrary memory-safety
fault by symbolic/concolic execution (angr / a cyber-reasoning system) and emitting a targeted patch — is NOT
built here because that engine is **absent from this environment** (no angr/claripy/z3). This module handles a
recognised pattern and returns ``SYNTHESIS_UNAVAILABLE`` for anything else — it NEVER fabricates a patch, and it
never asserts a fix the sanitizer did not confirm silent. The symbolic path stays the roadmap
(:class:`~remediation_binary.tier.SymbolicCrashRepairTier`, docs/DEFERRED-INFRA.md X2).

ORACLE AUTHORITY: acceptance is `SanitizerSilenceTier().remediated_if_silent(before, after)` — the sanitizer
oracle FIRED on the pre-fix crashing run and went SILENT on the post-fix one — plus an independent functional
check. This module mints no fact and promotes nothing; the oracle is the sole authority on "crash / no crash".
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..verify.oracles import sanitizer_signal_oracle
from .tier import BinaryPatch, CapturedCrash, SanitizerSilenceTier

_CC = "gcc"
_ASAN_FLAGS = ("-fsanitize=address", "-g", "-O0", "-fno-omit-frame-pointer")


# ---- verdict ---------------------------------------------------------------------------------------------
class BinRemState:
    REMEDIATED = "REMEDIATED"                       # crash-confirmed, patch silences ASan, functionality preserved
    NOT_REMEDIATED = "NOT_REMEDIATED"               # the synthesised patch did not silence the crash, or broke it
    SYNTHESIS_UNAVAILABLE = "SYNTHESIS_UNAVAILABLE"  # no recognised safe rewrite for this crash class (→ symbolic)
    INCONCLUSIVE = "INCONCLUSIVE"                   # no toolchain / no crash reproduced / did not compile


@dataclass(frozen=True)
class BinRemResult:
    state: str
    reason: str
    crash_signature: str = ""          # the ASan SUMMARY line of the confirmed pre-fix crash (provenance)
    patch: Optional[BinaryPatch] = None
    before_fired: bool = False         # the sanitizer oracle fired on the pre-fix crashing run (crash-confirmed)
    after_fired: bool = False          # the sanitizer oracle fired on the post-fix crashing run (should be False)
    functional_preserved: bool = False  # the patched build still produced the expected benign output


# ---- toolchain -------------------------------------------------------------------------------------------
def asan_available() -> bool:
    """True iff ``gcc`` with ``-fsanitize=address`` can compile+link a trivial program on this host. Probes for
    real (a missing ``libasan`` links fine at ``-c`` but fails at link) so a runner without ASan yields
    INCONCLUSIVE rather than a spurious verdict."""
    try:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "t.c"
            src.write_text("int main(void){return 0;}\n", encoding="utf-8")
            out = Path(td) / "t"
            r = subprocess.run([_CC, *_ASAN_FLAGS, "-o", str(out), str(src)],
                               capture_output=True, text=True, timeout=60)
            return r.returncode == 0 and out.exists()
    except (OSError, subprocess.SubprocessError):
        return False


def _compile_asan(source: str, out_path: Path, workdir: Path) -> "tuple[bool, str]":
    src = workdir / (out_path.name + ".c")
    src.write_text(source, encoding="utf-8")
    try:
        r = subprocess.run([_CC, *_ASAN_FLAGS, "-o", str(out_path), str(src)],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"compile failed: {e}"
    return (r.returncode == 0 and out_path.exists()), (r.stderr or r.stdout)


def _run_capture(binary: Path, argv: "list[str]", *, stdin: str = "", timeout: int = 10) -> str:
    """Run the binary and capture stdout+stderr (ASan reports go to stderr). ASAN_OPTIONS pins deterministic,
    non-interactive behaviour. A timeout / crash still returns the captured output (the oracle reads it).

    SECURITY (red-pen BLOCK): the env pin FORCES the report onto the captured stream — ``log_path=stderr`` +
    ``log_to_stderr=1`` OVERRIDE a source-level ``__asan_default_options(){return "log_path=<file>";}`` that
    would otherwise DIVERT the overflow report off stdout/stderr and fake "silence" while the bug still fires.
    Env ASAN_OPTIONS takes precedence over the source default-options for the flags it sets, so pinning the
    output flags closes the report-diversion silence-gaming vector."""
    env = {"ASAN_OPTIONS": "log_path=stderr:log_to_stderr=1:detect_leaks=0:abort_on_error=0:exitcode=1",
           "PATH": "/usr/bin:/bin"}
    try:
        r = subprocess.run([str(binary), *argv], input=stdin, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + (e.stderr or "") if isinstance(e.stdout, str) else "TIMEOUT"
    except (OSError, subprocess.SubprocessError) as e:
        return f"run failed: {e}"


def _summary_line(asan_output: str) -> str:
    for line in asan_output.splitlines():
        if "SUMMARY: AddressSanitizer" in line:
            return line.strip()
    return ""


# ---- pattern-based patch synthesis (narrow, REAL) --------------------------------------------------------
_CHAR_DECL = re.compile(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]")
_STRCPY = re.compile(r"\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*([^;)]+?)\s*\)")

# Sanitizer-tampering constructs a patch must NEVER introduce — they DISABLE/DIVERT the very oracle whose
# SILENCE the gate trusts (red-pen BLOCK: a report-diverting/suppressing patch fakes "silence" while the bug
# still fires). A defense-in-depth denylist for the REUSABLE gate (the shipped strcpy synthesiser emits none of
# these, but the gate is designed for reuse by the deferred symbolic tier). A fix that turns off the detector is
# not a fix.
_SANITIZER_TAMPER = (
    "__asan_default_options", "__asan_on_error", "__lsan_default_options", "__ubsan_default_options",
    "__msan_default_options", "__tsan_default_options", "__sanitizer_", "no_sanitize", "log_path",
    "ASAN_OPTIONS", "halt_on_error", "detect_stack_use", "signal(", "sigaction(",
)


def _patch_introduces_sanitizer_tampering(original: str, patched: str) -> str:
    """Return the first sanitizer-tampering token the PATCH introduced (present in ``patched``, absent from
    ``original``), or "" if none. A patch that disables/diverts/handles the sanitizer or catches the crash
    signal is rejected — silence over a disabled detector is not a remediation."""
    for tok in _SANITIZER_TAMPER:
        if tok in patched and tok not in original:
            return tok
    return ""


def synthesize_bounded_copy_patch(source: str) -> "tuple[Optional[str], Optional[BinaryPatch]]":
    """The one narrow, REAL synthesiser: rewrite an unbounded ``strcpy(dst, src)`` where ``dst`` is a fixed-size
    stack buffer ``char dst[N]`` into a bounded ``strncpy(dst, src, N-1); dst[N-1] = '\\0'``. Returns the patched
    source + a :class:`BinaryPatch` diff, or ``(None, None)`` if no such pattern is present (→ the caller reports
    SYNTHESIS_UNAVAILABLE; the general/symbolic case is the deferred angr path). NEVER fabricates a patch for a
    class it does not recognise."""
    sizes = {name: int(n) for name, n in _CHAR_DECL.findall(source)}
    if not sizes:
        return None, None
    changed: list[tuple[str, str]] = []      # (before-call, after-code) for each rewritten strcpy

    def _repl(m: "re.Match[str]") -> str:
        dst, src = m.group(1), m.group(2).strip()
        n = sizes.get(dst)
        if n is None:                      # unknown-size destination → cannot bound it safely → leave untouched
            return m.group(0)
        after = f"strncpy({dst}, {src}, {n} - 1); {dst}[{n} - 1] = '\\0'"
        changed.append((f"strcpy({dst}, {src})", after))
        return after

    patched = _STRCPY.sub(_repl, source)
    if not changed or patched == source:
        return None, None
    diff = ("\n".join(f"- {before}   /* unbounded */" for before, _ in changed)
            + "\n" + "\n".join(f"+ {after}" for _, after in changed))
    return patched, BinaryPatch(
        description="bounded-copy rewrite of an unbounded strcpy into a fixed stack buffer ("
                    + "; ".join(b for b, _ in changed) + ")",
        diff=diff, provenance="pattern-based (strcpy→strncpy); NOT symbolic — general synthesis is the deferred angr path")


# ---- the end-to-end proof --------------------------------------------------------------------------------
def prove_asan_remediation(source: str, *, crash_argv: "list[str]", benign_argv: "list[str]",
                           expected_benign: str, timeout: int = 10) -> BinRemResult:
    """Crash-confirm → synthesise → fix-by-silence, over a REAL ASan build. Steps:

    1. Compile ``source`` under ASan; run on ``crash_argv``; the sanitizer oracle MUST fire (crash-confirmed) —
       else INCONCLUSIVE (nothing to remediate; you cannot earn silence you never broke).
    2. Synthesise a patch (pattern-based). If the class is unrecognised → SYNTHESIS_UNAVAILABLE (never fabricate).
    3. Compile the patched source; run the SAME ``crash_argv``; accept ONLY if the oracle goes SILENT
       (``SanitizerSilenceTier.remediated_if_silent`` — fired-then-silent) AND the patched build reproduces
       ``expected_benign`` on ``benign_argv`` with no sanitizer fire (functionality preserved — a stub "fix" that
       breaks the program is rejected). Otherwise NOT_REMEDIATED.
    """
    if not asan_available():
        return BinRemResult(BinRemState.INCONCLUSIVE, "gcc/AddressSanitizer toolchain unavailable on this host")
    tier = SanitizerSilenceTier()
    with tempfile.TemporaryDirectory(prefix="asan-rem-") as td:
        work = Path(td)
        vuln = work / "vuln"
        ok, cerr = _compile_asan(source, vuln, work)
        if not ok:
            return BinRemResult(BinRemState.INCONCLUSIVE, f"original source does not compile under ASan: {cerr[:200]}")
        before_out = _run_capture(vuln, crash_argv, timeout=timeout)
        before = tier.confirm_crash(CapturedCrash(output=before_out))
        if not before.fired:
            return BinRemResult(BinRemState.INCONCLUSIVE,
                                "no AddressSanitizer crash reproduced on the crashing input — nothing to remediate")
        crash_sig = _summary_line(before_out)

        patched_source, patch = synthesize_bounded_copy_patch(source)
        if patched_source is None:
            return BinRemResult(
                BinRemState.SYNTHESIS_UNAVAILABLE,
                "no recognised safe rewrite for this crash class — general synthesis needs symbolic/concolic "
                "execution (angr), which is not available; the crash is confirmed but no patch is fabricated",
                crash_signature=crash_sig, before_fired=True)

        # REJECT a patch that DISABLES/DIVERTS the sanitizer or catches the crash signal — silence over a
        # disabled detector is not a fix (red-pen BLOCK: a report-diverting patch fakes silence). Defense in
        # depth for the reusable gate, on top of the log_path=stderr env pin in _run_capture.
        tamper = _patch_introduces_sanitizer_tampering(source, patched_source)
        if tamper:
            return BinRemResult(
                BinRemState.NOT_REMEDIATED,
                f"the synthesised patch introduces a sanitizer-tampering construct ({tamper!r}) — silence over a "
                "disabled/diverted detector is NOT a fix; rejected",
                crash_signature=crash_sig, patch=patch, before_fired=True)

        fixed = work / "fixed"
        ok, ferr = _compile_asan(patched_source, fixed, work)
        if not ok:
            return BinRemResult(BinRemState.NOT_REMEDIATED,
                                f"the synthesised patch did not compile: {ferr[:200]}",
                                crash_signature=crash_sig, patch=patch, before_fired=True)

        after_out = _run_capture(fixed, crash_argv, timeout=timeout)
        after_fired = bool(sanitizer_signal_oracle(after_out).fired)
        if not tier.remediated_if_silent(before_out, after_out):
            return BinRemResult(BinRemState.NOT_REMEDIATED,
                                "the synthesised patch did NOT silence the sanitizer on the crashing input "
                                "(oracle still fires) — not a fix",
                                crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=after_fired)

        benign_out = _run_capture(fixed, benign_argv, timeout=timeout)
        functional = (expected_benign in benign_out) and not bool(sanitizer_signal_oracle(benign_out).fired)
        if not functional:
            return BinRemResult(BinRemState.NOT_REMEDIATED,
                                "the patch silenced the crash but did NOT preserve the benign functionality "
                                f"(expected {expected_benign!r} in the output) — a silence-gaming stub is rejected",
                                crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=False)

        return BinRemResult(
            BinRemState.REMEDIATED,
            "crash-confirmed by AddressSanitizer; a pattern-synthesised bounded-copy patch made the oracle go "
            "SILENT on the same crashing input AND preserved the benign functionality (fix earned by silence, not "
            "asserted). RESIDUAL: pattern-based for the unbounded-strcpy class — general symbolic synthesis (angr) "
            "is deferred.",
            crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=False, functional_preserved=True)
