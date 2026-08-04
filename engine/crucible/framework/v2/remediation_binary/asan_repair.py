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


def _run_capture(binary: Path, argv: "list[str]", *, stdin: str = "", timeout: int = 10) -> "tuple[str, int | None]":
    """Run the binary; return ``(captured_text, returncode)``. The verdict is derived from BOTH — the sanitizer
    report AND whether the process died by a fatal signal (:func:`_died_by_fatal_signal`), an OUT-OF-BAND signal
    the child cannot hide.

    SECURITY (red-pen BLOCK + two re-checks): the child controls its OWN output streams, so capturing the report
    from stderr is spoofable — a patch can DIVERT it (``__asan_default_options(log_path=…)``), MANIPULATE the fd
    (``close(2)``/``dup2``/``fclose(stderr)``), or RE-EXEC itself with a child-chosen ``ASAN_OPTIONS`` to fake
    "silence" while the overflow still fires. Two robust defenses beyond the denylist:
      * ``log_path`` is pinned to a FILE in a dir WE own (env overrides a single-process source override); the
        report is read from THAT file, which fd games cannot suppress.
      * ``abort_on_error=1`` makes ASan ABORT (SIGABRT) at the faulting access — so a still-firing overflow KILLS
        the process by a fatal signal, observed by the PARENT via the exit status, which the child cannot forge
        or divert (short of catching the signal — denylisted — or re-execing to reconfigure — denylisted). The
        report first, then the abort, so the log file is written even when the process dies."""
    with tempfile.TemporaryDirectory(prefix="asan-log-") as logdir:
        log_base = Path(logdir) / "asan"
        env = {"ASAN_OPTIONS": f"log_path={log_base}:log_exe_name=0:detect_leaks=0:abort_on_error=1",
               "PATH": "/usr/bin:/bin"}
        rc: "int | None" = None
        std = ""
        try:
            r = subprocess.run([str(binary), *argv], input=stdin, capture_output=True, text=True,
                               timeout=timeout, env=env)
            std, rc = (r.stdout or "") + (r.stderr or ""), r.returncode
        except subprocess.TimeoutExpired as e:
            std = ((e.stdout or "") + (e.stderr or "")) if isinstance(e.stdout, str) else "TIMEOUT"
        except (OSError, subprocess.SubprocessError) as e:
            return f"run failed: {e}", None
        report = ""
        for f in sorted(Path(logdir).glob("asan*")):
            try:
                report += f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return report + "\n" + std, rc


def _completeness_fuzz(crash_argv: "list[str]") -> "list[list[str]]":
    """A length-sweep of the crash vector (the longest arg) — the CLASS-completeness check (red-pen BLOCK: a
    single-input silence over-claims). A partial fix leaves inputs that still overflow: buffer ENLARGEMENT
    (``char[16]``→``char[128]``) is defeated by a LONGER input; a NARROW length guard (``if strlen>20 return``
    with the buffer still ``[16]``) is defeated by a SHORT-but-over-buffer input. A genuine BOUNDED copy (the
    shipped synthesiser's ``strncpy``) survives EVERY length. Sweeping small→large catches both partial classes
    without knowing the buffer size. NOT exhaustive over input SHAPE — see the REMEDIATED residual."""
    if not crash_argv:
        return []
    idx = max(range(len(crash_argv)), key=lambda i: len(crash_argv[i]))
    fill = (crash_argv[idx] or "A")[0]
    lengths = (1, 4, 8, 12, 16, 17, 18, 20, 24, 31, 32, 48, 63, 64, 96, 127, 128, 192, 255, 256, 384, 512,
               1024, 2048, 4096)
    out = []
    for length in lengths:
        v = list(crash_argv)
        v[idx] = fill * length
        out.append(v)
    return out


def _died_by_fatal_signal(rc: "int | None") -> bool:
    """True if the process was killed by a fatal signal (subprocess reports a negative returncode). ASan with
    ``abort_on_error=1`` raises SIGABRT at the overflow; a SEGV from a smashed return address is also fatal. This
    out-of-band signal is not forgeable by the child's own output streams."""
    return rc is not None and rc < 0


def _crashed(text: str, rc: "int | None") -> bool:
    """A run 'crashed' if the sanitizer oracle fires on the captured report OR the process died by a fatal
    signal. Either is sufficient; a patch that hides the report still cannot avoid the SIGABRT."""
    return bool(sanitizer_signal_oracle(text).fired) or _died_by_fatal_signal(rc)


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
    # sanitizer reconfiguration / suppression
    "__asan_default_options", "__asan_on_error", "__lsan_default_options", "__ubsan_default_options",
    "__msan_default_options", "__tsan_default_options", "__sanitizer_", "no_sanitize", "log_path",
    "ASAN_OPTIONS", "halt_on_error", "detect_stack_use",
    # crash-signal handling (abort() still terminates, but a handler that _exit(0)s would dodge it)
    "signal(", "sigaction(", "sigprocmask", "bsd_signal", "sysv_signal",
    # RE-EXEC / env-mutation / raw syscall / inline asm — the family that lets a child RE-READ ASAN_OPTIONS with
    # child-chosen values (re-check BLOCK). These are IDENTIFIERS — C cannot split them across string literals
    # (unlike the split string ARGS the attack used), so a substring scan over the source catches them soundly.
    "execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle", "execveat", "fexecve",
    "setenv", "putenv", "clearenv", "unsetenv", "system(", "popen(", "posix_spawn",
    "syscall", "__asm", "asm ", "asm(", "asm\t", "asm\n",
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
        before_out, before_rc = _run_capture(vuln, crash_argv, timeout=timeout)
        # confirm_crash keeps the oracle as the crash-signature authority; _crashed additionally counts a fatal
        # signal (abort_on_error=1 → SIGABRT) as a crash, so the confirm is out-of-band-robust too.
        if not _crashed(before_out, before_rc):
            return BinRemResult(BinRemState.INCONCLUSIVE,
                                "no AddressSanitizer crash reproduced on the crashing input — nothing to remediate")
        crash_sig = _summary_line(before_out) or tier.confirm_crash(CapturedCrash(output=before_out)).evidence[:120]

        patched_source, patch = synthesize_bounded_copy_patch(source)
        if patched_source is None:
            return BinRemResult(
                BinRemState.SYNTHESIS_UNAVAILABLE,
                "no recognised safe rewrite for this crash class — general synthesis needs symbolic/concolic "
                "execution (angr), which is not available; the crash is confirmed but no patch is fabricated",
                crash_signature=crash_sig, before_fired=True)

        # REJECT a patch that DISABLES/DIVERTS the sanitizer, catches the crash signal, or RE-EXECS to reconfigure
        # it — silence over a defeated detector is not a fix (red-pen BLOCKs: report-diversion, fd games, and
        # re-exec with a child-chosen ASAN_OPTIONS all fake silence). Defense in depth alongside the out-of-band
        # abort_on_error=1 signal-death check + the driver-owned log file in _run_capture.
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

        after_out, after_rc = _run_capture(fixed, crash_argv, timeout=timeout)
        after_crashed = _crashed(after_out, after_rc)
        # REMEDIATED requires the SAME crashing input to no longer crash: the oracle SILENT on the captured report
        # AND the process did NOT die by a fatal signal (a diverted/hidden report cannot escape the SIGABRT).
        if after_crashed:
            return BinRemResult(BinRemState.NOT_REMEDIATED,
                                "the synthesised patch did NOT stop the crash on the crashing input (the sanitizer "
                                "still fires or the process still dies by a fatal signal) — not a fix",
                                crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=True)

        # COMPLETENESS (red-pen BLOCK — single-input silence over-claims): the confirmed input is silenced, but a
        # PARTIAL fix (buffer enlargement / narrow length guard) leaves the CLASS exploitable. Fuzz a length-sweep
        # of the crash vector; a bounded-copy fix survives every length, a partial fix crashes on one → the class
        # is NOT remediated.
        for fz in _completeness_fuzz(crash_argv):
            fz_out, fz_rc = _run_capture(fixed, fz, timeout=timeout)
            if _crashed(fz_out, fz_rc):
                fz_len = len(fz[max(range(len(fz)), key=lambda i: len(fz[i]))])
                return BinRemResult(
                    BinRemState.NOT_REMEDIATED,
                    "the patch stopped the confirmed crash input but a length-swept fuzz of the crash vector STILL "
                    f"crashes (input length {fz_len}) — a partial fix (buffer enlargement / narrow guard), NOT a "
                    "class-level remediation",
                    crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=True)

        benign_out, benign_rc = _run_capture(fixed, benign_argv, timeout=timeout)
        functional = ((expected_benign in benign_out) and not _crashed(benign_out, benign_rc))
        if not functional:
            return BinRemResult(BinRemState.NOT_REMEDIATED,
                                "the patch silenced the crash but did NOT preserve the benign functionality "
                                f"(expected {expected_benign!r} in the output) — a silence-gaming stub is rejected",
                                crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=False)

        return BinRemResult(
            BinRemState.REMEDIATED,
            "crash-confirmed by AddressSanitizer; a pattern-synthesised bounded-copy patch stopped the crash on "
            "the confirmed input AND across a LENGTH-SWEPT fuzz of the crash vector (oracle SILENT + no fatal "
            "signal on every length — a partial fix like buffer enlargement or a narrow guard would crash on "
            "one), AND preserved the benign functionality (fix earned by silence, not asserted). RESIDUAL: (1) "
            "class-completeness is proven over the fuzzed LENGTH sweep, NOT exhaustively over input SHAPE — a bug "
            "reachable only by a different input structure is out of scope; (2) pattern-based for the "
            "unbounded-strcpy class — general symbolic synthesis (angr) is deferred; (3) the fix-by-silence gate "
            "hardens against report-diversion / fd-games / re-exec / signal-catching (denylist + out-of-band "
            "SIGABRT), but a maximally-hostile patch-producer would need an out-of-band sandbox (ptrace/seccomp), "
            "which the shipped strcpy synthesiser never needs.",
            crash_signature=crash_sig, patch=patch, before_fired=True, after_fired=False, functional_preserved=True)
