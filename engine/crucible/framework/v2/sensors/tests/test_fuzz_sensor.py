"""
Tests for Workstream D.1 — the gated, opt-in fuzz/ASan producer.

The producer drives a bounded fuzz against an operator-authorized LOCAL binary and feeds the captured
stdout/stderr to the EXISTING SANITIZER_SIGNAL oracle. Coverage:

  * confirm_crash is the sole FACT path — it fires ONLY on a real sanitizer/crash marker (per bug
    class), and never on clean output (prove-don't-guess); it is deterministic.
  * the harness is OFF by default (opt-in latch + allowed_root allowlist) and refuses out-of-root /
    unauthorized / missing binaries — no subprocess ever runs for those.
  * as a T3/EXPLOIT_EXECUTION tool it is refused at the entitlement gate by run_sensor, before run().
  * the full loop works end to end against a tiny python fixture binary (no C toolchain needed).

No test fuzzes a real system binary; the only executed binary is a fixture script under tmp_path.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.entitlement.models import Capability
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import (
    FuzzHarnessSensor,
    confirm_crash,
    default_fuzz_cases,
    default_registry,
    run_sensor,
)
from framework.v2.sensors.fuzz import MEMORY_BUG_CLASSES, _authorized_binary
from framework.v2.verify.models import OracleKind
from framework.v2.worldmodel.graph import WorldModel


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Same isolation the nmap sensor test uses: redirect the killswitch/charter/target paths into
    # tmp_path so the gate chain reads a clean, test-local state.
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


# --- fixtures: sanitizer/crash markers straight from oracles._SANITIZER_PATTERNS ------------------

# (bug_class the caller asserts, captured output carrying a real marker)
_MARKERS: dict[str, str] = {
    "buffer_overflow": (
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        "READ of size 4 at 0xdead thread T0\n"
    ),
    "use_after_free": (
        "==999==ERROR: AddressSanitizer: heap-use-after-free on address 0xbeef\n"
    ),
    "memory_corruption": "*** stack smashing detected ***: terminated\n",
    "crash": "Segmentation fault (core dumped)\n",
}

_CLEAN = "usage: target [options]\nparsed 3 tokens ok\ndone.\n"


def test_all_four_memory_classes_confirm_on_a_real_marker() -> None:
    for bug_class, captured in _MARKERS.items():
        assert bug_class in MEMORY_BUG_CLASSES
        cf = confirm_crash(captured, bug_class=bug_class)
        assert cf is not None, f"{bug_class} should confirm on its marker"
        assert cf.confirmed_by == OracleKind.SANITIZER_SIGNAL
        assert cf.bug_class == bug_class


def test_clean_output_is_never_a_fact() -> None:
    # No sanitizer/crash/panic marker -> the oracle does not fire -> no fact (prove-don't-guess).
    for bug_class in MEMORY_BUG_CLASSES:
        assert confirm_crash(_CLEAN, bug_class=bug_class) is None


def test_off_vocabulary_bug_class_defaults_to_crash() -> None:
    # A caller cannot smuggle an off-vocabulary class in; it falls back to the generic sanitizer class.
    cf = confirm_crash(_MARKERS["crash"], bug_class="totally_made_up")
    assert cf is not None and cf.bug_class == "crash"


def test_ubsan_and_rust_panic_markers_confirm() -> None:
    assert confirm_crash("runtime error: signed integer overflow: 2147483647 + 1", bug_class="crash") is not None
    assert confirm_crash("thread 'main' panicked at src/lib.rs:10:5", bug_class="crash") is not None


def test_confirm_crash_is_deterministic() -> None:
    a = confirm_crash(_MARKERS["use_after_free"], bug_class="use_after_free")
    b = confirm_crash(_MARKERS["use_after_free"], bug_class="use_after_free")
    assert a is not None and b is not None
    assert a.model_dump() == b.model_dump()


# --- the deterministic case corpus ---------------------------------------------------------------


def test_default_fuzz_cases_deterministic_bounded_and_seed_first() -> None:
    a = default_fuzz_cases(["seed-1", "seed-2"], max_cases=20)
    b = default_fuzz_cases(["seed-1", "seed-2"], max_cases=20)
    assert a == b                      # replayable
    assert len(a) <= 20                # bounded
    assert a[0] == "seed-1" and a[1] == "seed-2"   # operator seeds come first, verbatim
    assert len(set(a)) == len(a)       # de-duplicated
    assert default_fuzz_cases(None, max_cases=0) == []


# --- the allowlist guard (AUTHORIZATION-CRITICAL) -------------------------------------------------


def _make_exec(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)
    return path


def test_authorized_binary_requires_a_root_and_containment(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = _make_exec(root / "target", "#!/bin/sh\ntrue\n")
    outside = _make_exec(tmp_path / "elsewhere", "#!/bin/sh\ntrue\n")

    assert _authorized_binary(str(inside), str(root)) == os.path.realpath(str(inside))
    assert _authorized_binary(str(inside), None) is None          # no root -> off by default
    assert _authorized_binary(str(outside), str(root)) is None    # escapes the root
    assert _authorized_binary(str(root / "nope"), str(root)) is None  # missing
    # a non-executable file inside the root is refused
    plain = root / "data.txt"
    plain.write_text("x", encoding="utf-8")
    assert _authorized_binary(str(plain), str(root)) is None


def test_symlink_escaping_the_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = _make_exec(tmp_path / "outside_bin", "#!/bin/sh\ntrue\n")
    link = root / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unsupported here")
    # realpath follows the symlink BEFORE the containment check, so a link that escapes is refused.
    assert _authorized_binary(str(link), str(root)) is None


# --- run() in-process guards (no subprocess for a refusal) ----------------------------------------


def test_run_refuses_without_the_opt_in_latch(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    binary = _make_exec(root / "target", "#!/bin/sh\ntrue\n")
    s = FuzzHarnessSensor(allowed_root=str(root))
    res = s.run({"binary": str(binary)}, ToolContext(slug="alpha"))   # authorized not set
    assert not res.ok and "authorized" in (res.note or "")


def test_run_refuses_binary_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = _make_exec(tmp_path / "outside", "#!/bin/sh\ntrue\n")
    s = FuzzHarnessSensor(allowed_root=str(root))
    res = s.run({"authorized": True, "binary": str(outside)}, ToolContext(slug="alpha"))
    assert not res.ok and "allowed_root" in (res.note or "")


def test_run_with_no_allowed_root_refuses_everything(tmp_path: Path) -> None:
    binary = _make_exec(tmp_path / "target", "#!/bin/sh\ntrue\n")
    s = FuzzHarnessSensor()   # allowed_root=None (default) -> off
    res = s.run({"authorized": True, "binary": str(binary)}, ToolContext(slug="alpha"))
    assert not res.ok


def test_run_missing_binary_degrades_cleanly(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    s = FuzzHarnessSensor(allowed_root=str(root))
    res = s.run({"authorized": True, "binary": str(root / "nope")}, ToolContext(slug="alpha"))
    assert not res.ok   # a reason, never a crash


# --- gating via run_sensor (entitlement gate, before run()) ---------------------------------------


def test_fuzz_harness_is_registered_in_the_default_registry() -> None:
    assert "fuzz_harness" in default_registry()


def test_refused_without_the_exploit_execution_entitlement(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The harness declares capability=EXPLOIT_EXECUTION, so run_sensor refuses it at the entitlement
    # gate (before run(), before any subprocess) when the grant is absent — and mints nothing.
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "fuzz_harness",
                     {"authorized": True, "binary": "/bin/true"},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "entitlement"
    assert res.observations == [] and res.applied == 0


def test_capability_is_exploit_execution_and_destructive() -> None:
    s = FuzzHarnessSensor()
    assert s.capability == Capability.EXPLOIT_EXECUTION
    assert s.destructive is True and s.tier == "T3" and s.egress_hosts == ()


# --- end-to-end: a tiny python fixture binary, no C toolchain -------------------------------------

# A fixture "target" that reads stdin and prints a segfault-style marker to stderr when the input is
# long — standing in for a fragile parser. Executed ONLY out of tmp_path (the allowed_root).
_FIXTURE = (
    "import sys\n"
    "data = sys.stdin.read()\n"
    "if len(data) >= 1024:\n"
    "    sys.stderr.write('Segmentation fault (core dumped)\\n')\n"
    "else:\n"
    "    sys.stdout.write('ok\\n')\n"
)


def test_end_to_end_fuzz_captures_a_marker_and_confirm_crash_promotes_it(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "frag_target.py"
    # a shebang'd, executable python script — a real subprocess, but entirely under the operator root
    target.write_text("#!" + sys.executable + "\n" + _FIXTURE, encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)

    s = FuzzHarnessSensor(allowed_root=str(root), max_cases=16, timeout_s=15)
    res = s.run({"authorized": True, "binary": str(target), "bug_class": "crash"},
                ToolContext(slug="alpha"))
    assert res.ok, res.note
    crash_captured = res.output.get("crash_captured", "")
    assert "Segmentation fault" in crash_captured   # the long-input case tripped the fixture

    # prove-don't-guess: the LEAD (crash_captured) becomes a FACT only via the oracle re-firing.
    cf = confirm_crash(crash_captured, bug_class=res.output.get("bug_class", "crash"))
    assert cf is not None and cf.confirmed_by == OracleKind.SANITIZER_SIGNAL


def test_end_to_end_clean_binary_mints_no_fact(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "safe_target.py"
    target.write_text("#!" + sys.executable + "\nimport sys; sys.stdin.read(); print('ok')\n",
                       encoding="utf-8")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)

    s = FuzzHarnessSensor(allowed_root=str(root), max_cases=8, timeout_s=15)
    res = s.run({"authorized": True, "binary": str(target)}, ToolContext(slug="alpha"))
    assert res.ok, res.note
    assert res.output.get("crash_captured", "") == ""            # a robust binary trips nothing
    assert confirm_crash(res.output.get("crash_captured", "")) is None
