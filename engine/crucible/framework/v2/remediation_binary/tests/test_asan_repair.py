"""TRUTHENOVATION R3 (PR1) — the ASan-grounded crash-confirm + pattern patch-synthesis + fix-by-silence path.

Compiles + runs REAL binaries under AddressSanitizer through ``gcc -fsanitize=address``, so it is skipped where
that toolchain is absent (ubuntu-latest CI has it). The sanitizer VERDICT is the existing
``sanitizer_signal_oracle`` — this suite proves the end-to-end loop, not a reimplemented crash detector.
"""
from __future__ import annotations

import pytest

from framework.v2.remediation_binary import asan_repair as R
from framework.v2.remediation_binary.asan_repair import BinRemState, prove_asan_remediation

pytestmark = pytest.mark.skipif(not R.asan_available(),
                                reason="gcc/AddressSanitizer toolchain not available on this host")

# a classic unbounded strcpy into a fixed 16-byte stack buffer — the class the pattern synthesiser handles.
STRCPY_VULN = (
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "int process(const char *in){ char buf[16]; strcpy(buf, in); return (int)strlen(buf); }\n"
    "int main(int argc, char**argv){ if(argc<2){printf(\"usage\\n\");return 2;} "
    "printf(\"len=%d\\n\", process(argv[1])); return 0; }\n"
)

# a HEAP overflow (strcpy into malloc'd memory, no fixed-size `char[N]` decl) — crash-confirmed, but the pattern
# synthesiser cannot bound it (unknown size) → SYNTHESIS_UNAVAILABLE (the deferred symbolic case), never fabricated.
HEAP_VULN = (
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <stdlib.h>\n"
    "int main(int argc, char**argv){ if(argc<2) return 2; char *buf = malloc(8); strcpy(buf, argv[1]); "
    "printf(\"ok=%d\\n\", (int)strlen(buf)); free(buf); return 0; }\n"
)

LONG = ["A" * 64]        # overflows a 16-byte / 8-byte buffer
SHORT = ["hello"]        # benign — 5 chars, fits every buffer


def test_strcpy_overflow_is_crash_confirmed_and_pattern_patched_to_remediated():
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.REMEDIATED, out
    assert out.before_fired is True and out.after_fired is False        # fired then SILENT (earned by silence)
    assert out.functional_preserved is True                            # benign "len=5" still produced
    assert "stack-buffer-overflow" in out.crash_signature              # the confirmed crash signature
    assert out.patch is not None and "strncpy" in out.patch.diff       # a REAL bounded-copy diff, not a stub
    assert "symbolic" in out.patch.provenance.lower()                  # honest: NOT the general symbolic path


def test_unrecognised_crash_class_is_synthesis_unavailable_never_fabricated():
    # the heap overflow IS crash-confirmed, but there is no fixed-size decl to bound → no patch is invented.
    out = prove_asan_remediation(HEAP_VULN, crash_argv=LONG, benign_argv=["hi"], expected_benign="ok=2")
    assert out.state == BinRemState.SYNTHESIS_UNAVAILABLE, out
    assert out.before_fired is True and out.patch is None              # confirmed, but never fabricated
    assert "angr" in out.reason.lower() or "symbolic" in out.reason.lower()   # honestly names the deferred path


def test_no_crash_reproduced_is_inconclusive():
    # a benign input never overflows → the oracle is silent on `before` → nothing to earn (cannot fake a fix).
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=SHORT, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.INCONCLUSIVE, out
    assert out.before_fired is False


def test_silence_gaming_stub_patch_is_rejected(monkeypatch):
    # a patch that SILENCES ASan by breaking the program (return 0, no output) must be REJECTED — the functional
    # check catches a silence-gaming stub. Force the synthesiser to emit such a stub.
    stub = ("int main(int argc, char**argv){ (void)argc; (void)argv; return 0; }\n", R.BinaryPatch(
        description="stub", diff="+ return 0", provenance="test-stub"))
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch", lambda _s: stub)
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert "functionality" in out.reason.lower()                       # silenced but broke the benign output


def test_non_silencing_patch_is_not_remediated(monkeypatch):
    # a "patch" that does not change the source recompiles to the same vulnerable binary → still crashes → the
    # oracle is NOT silent → NOT_REMEDIATED (a fix is never asserted, only earned by silence).
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                        lambda s: (s, R.BinaryPatch(description="noop", diff="", provenance="test-noop")))
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert out.after_fired is True                                     # the sanitizer still fires post-"patch"


def test_sanitizer_report_diverting_patch_is_rejected(monkeypatch):
    # RED-PEN BLOCK — a patch that DIVERTS the ASan report off the captured stream via a source-level
    # __asan_default_options(log_path=...) fakes "silence" while the overflow still fires. It must be REJECTED
    # (the tamper denylist catches it; the log_path=stderr env pin is the second layer). NOT a false REMEDIATED.
    divert = STRCPY_VULN.replace(
        "#include <string.h>",
        "#include <string.h>\nconst char* __asan_default_options(void){ return \"log_path=/tmp/asan_divert\"; }")
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                        lambda _s: (divert, R.BinaryPatch(description="divert", diff="", provenance="test")))
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert "sanitizer-tampering" in out.reason.lower()


def test_signal_catching_patch_is_rejected(monkeypatch):
    # a patch that installs a SIGSEGV/SIGABRT handler to swallow the crash is sanitizer-tampering → rejected.
    catch = STRCPY_VULN.replace("#include <string.h>", "#include <string.h>\n#include <signal.h>").replace(
        "char buf[16];", "signal(SIGSEGV, (void(*)(int))0); char buf[16];")
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                        lambda _s: (catch, R.BinaryPatch(description="catch", diff="", provenance="test")))
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert "sanitizer-tampering" in out.reason.lower()


def test_fd_manipulation_patch_cannot_fake_silence(monkeypatch):
    # RED-PEN re-check — a patch that MANIPULATES fd 2 (close(2) / dup2(...,2) / fclose(stderr)) to drop the ASan
    # report off the child's stderr must NOT fake silence: the report is captured from a log FILE the driver owns
    # (env log_path), which the child cannot suppress by closing/redirecting its own stderr → the oracle re-fires
    # → NOT_REMEDIATED (the overflow still executed). The child controls its stderr; it does not control our file.
    for construct in ("close(2);", "dup2(2, 2); close(2);", "fclose(stderr);"):
        redirected = STRCPY_VULN.replace(
            "#include <string.h>", "#include <string.h>\n#include <unistd.h>").replace(
            "char buf[16];", f"{construct} char buf[16];")
        monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                            lambda _s, p=redirected: (p, R.BinaryPatch(description="fd", diff="", provenance="test")))
        out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
        assert out.state == BinRemState.NOT_REMEDIATED, (construct, out)   # the report survives the fd game


def test_reexec_reconfigure_patch_cannot_fake_silence(monkeypatch):
    # RED-PEN re-check #2 BLOCK — a patch that RE-EXECS itself with a child-chosen ASAN_OPTIONS (setenv + execv),
    # with the option names split across adjacent string literals to dodge a naive substring scan, would make the
    # re-read'd ASan divert its report. It must NOT fake silence: `setenv`/`execv` are IDENTIFIERS (C cannot split
    # them across string literals) → the denylist catches them; and `abort_on_error=1` means a live overflow kills
    # the process by SIGABRT, an out-of-band signal the child cannot hide. → NOT_REMEDIATED.
    reexec = STRCPY_VULN.replace(
        "#include <string.h>", "#include <string.h>\n#include <stdlib.h>\n#include <unistd.h>").replace(
        "int main(int argc, char**argv){",
        "int main(int argc, char**argv){ if(!getenv(\"REEX\")){ setenv(\"REEX\",\"1\",1); "
        "setenv(\"ASAN\" \"_OPTIONS\", \"log\" \"_path=/tmp/sink_rx\", 1); execv(argv[0], argv); }")
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                        lambda _s: (reexec, R.BinaryPatch(description="reexec", diff="", provenance="test")))
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert "sanitizer-tampering" in out.reason.lower()


def test_out_of_band_signal_catches_report_suppression():
    # unit: even if the captured report text is empty, a process that died by a fatal signal is 'crashed' — a
    # report-suppressing patch cannot escape the SIGABRT (abort_on_error=1). The genuine-fix direction (silent +
    # clean exit) stays not-crashed.
    assert R._crashed("", -6) is True                          # SIGABRT with no captured report → crashed
    assert R._crashed("some output", 0) is False               # clean exit, no report → not crashed
    assert R._crashed("==1==ERROR: AddressSanitizer: heap-buffer-overflow", 1) is True   # report fires


def test_tamper_check_flags_only_patch_introduced_constructs():
    # unit: a construct already in the ORIGINAL is not flagged (only what the PATCH adds); a genuine strncpy
    # patch introduces nothing on the denylist.
    assert R._patch_introduces_sanitizer_tampering("no_sanitize x;", "no_sanitize x; y;") == ""   # pre-existing
    assert R._patch_introduces_sanitizer_tampering("clean;", "clean; __asan_default_options") == "__asan_default_options"
    assert R._patch_introduces_sanitizer_tampering("strcpy(b,s);", "strncpy(b, s, 8 - 1); b[8 - 1] = '\\0';") == ""


def test_buffer_enlargement_partial_fix_is_not_class_remediated(monkeypatch):
    # RED-PEN BLOCK — a plausible good-faith PARTIAL fix (enlarge the buffer 16→128) silences the confirmed
    # 64-byte input but a longer input still overflows the bigger buffer. The length-sweep completeness fuzz
    # catches it → NOT_REMEDIATED (a partial fix is not a class-level remediation).
    # both a small ([128]) and a LARGE ([8192], beyond the fixed part of the sweep) enlargement are caught — the
    # sweep scales to the crash length + a 1 MiB upper probe, so any fixed buffer is exceeded by some fuzz length.
    for size in (128, 8192):
        enlarge = STRCPY_VULN.replace("char buf[16];", f"char buf[{size}];")
        monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                            lambda _s, e=enlarge: (e, R.BinaryPatch(description="enlarge", diff="", provenance="test")))
        out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
        assert out.state == BinRemState.NOT_REMEDIATED, (size, out)
        assert "length-swept" in out.reason.lower() and "partial fix" in out.reason.lower()


def test_narrow_length_guard_partial_fix_is_not_class_remediated(monkeypatch):
    # a narrow guard (reject inputs >20) with the buffer STILL [16] silences the confirmed 64-byte input but a
    # 17–20 byte input passes the guard and overflows [16]. The short end of the length sweep catches it.
    guard = STRCPY_VULN.replace("char buf[16]; strcpy", "char buf[16]; if(strlen(in) > 20) return -1; strcpy")
    monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                        lambda _s: (guard, R.BinaryPatch(description="guard", diff="", provenance="test")))
    out = prove_asan_remediation(STRCPY_VULN, crash_argv=LONG, benign_argv=SHORT, expected_benign="len=5")
    assert out.state == BinRemState.NOT_REMEDIATED, out
    assert "partial fix" in out.reason.lower()


def test_narrow_guard_on_a_gap_sized_buffer_is_structurally_rejected(monkeypatch):
    # RED-PEN BLOCK — the length-sweep fuzz is a sparse point-set; a narrow guard on a GAP-sized buffer (e.g.
    # char[100] guarded >100, whose overflow length 100 is not a swept value) slips the fuzz. The STRUCTURAL
    # check (`_has_unbounded_strcpy_into_fixed_buffer`) catches it on ANY buffer size: an unbounded strcpy into a
    # fixed char[N] REMAINS → not bounded to capacity → NOT_REMEDIATED.
    for buf, guard in ((100, 100), (80, 90), (150, 150), (200, 200)):
        vuln = ("#include <stdio.h>\n#include <string.h>\n"
                f"int process(const char *in){{ char buf[{buf}]; strcpy(buf, in); return (int)strlen(buf); }}\n"
                "int main(int argc, char**argv){ if(argc<2){printf(\"usage\\n\");return 2;} "
                "printf(\"len=%d\\n\", process(argv[1])); return 0; }\n")
        partial = vuln.replace(f"char buf[{buf}]; strcpy", f"char buf[{buf}]; if(strlen(in) > {guard}) return -1; strcpy")
        monkeypatch.setattr(R, "synthesize_bounded_copy_patch",
                            lambda _s, p=partial: (p, R.BinaryPatch(description="guard", diff="", provenance="test")))
        out = prove_asan_remediation(vuln, crash_argv=["A" * (buf * 3)], benign_argv=["hi"], expected_benign="len=2")
        assert out.state == BinRemState.NOT_REMEDIATED, (buf, guard, out)
        assert "bounded" in out.reason.lower()


def test_structural_check_flags_a_remaining_unbounded_strcpy():
    # unit: the structural completeness check — an unbounded strcpy into a fixed char[N] remains → True (not a
    # bounded fix), on any size incl. enlargement; a bounded strncpy rewrite → False; strcpy into a non-fixed
    # (malloc'd) dst → False (out of the fixed-buffer class).
    assert R._has_unbounded_strcpy_into_fixed_buffer("char b[16]; strcpy(b, s);") is True
    assert R._has_unbounded_strcpy_into_fixed_buffer("char b[9999]; strcpy(b, s);") is True     # enlargement
    assert R._has_unbounded_strcpy_into_fixed_buffer("char b[16]; strncpy(b, s, 16 - 1); b[15]=0;") is False
    assert R._has_unbounded_strcpy_into_fixed_buffer("char *b = malloc(8); strcpy(b, s);") is False


def test_synthesiser_never_fabricates_without_a_fixed_size_declaration():
    # unit: the synthesiser returns (None, None) when there is no `char dst[N]` to bound — no fabricated patch.
    patched, patch = R.synthesize_bounded_copy_patch("char *p; strcpy(p, q);")
    assert patched is None and patch is None
    # and it DOES rewrite a real fixed-size strcpy.
    patched2, patch2 = R.synthesize_bounded_copy_patch("char b[8]; strcpy(b, src);")
    assert patched2 is not None and "strncpy(b, src, 8 - 1)" in patched2 and patch2 is not None
