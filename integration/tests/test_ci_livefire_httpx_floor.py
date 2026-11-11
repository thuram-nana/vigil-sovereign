"""Guard: the nightly live-fire cannot be pinned to an httpx that cannot record a refused probe.

WHY THIS EXISTS. ``_build_httpx`` passes ``-json -probe`` so that a probe which did NOT connect is
RECORDED (``"failed":true``) rather than dropped, and the live-fire table's closed-port control reads
that record as its evidence that the tool ran and reached its conclusion. ProjectDiscovery httpx only
keeps that promise from v1.6.10: up to v1.6.9 every errored result was skipped before the JSON writer,
so the control leg returned exit 0 and zero bytes. The nightly was pinned at v1.6.9 and was red on
exactly that row on every scheduled run from 2026-10-29 to 2026-11-11 — a non-required job nobody was
reading.

So the pin is held at or above the floor from the committed workflow alone (pure file reads — this
guard is framework-free and runs in the SOVEREIGN leg), and the workflow must also carry the step that
proves the BEHAVIOUR on the installed binary, because a version is only a proxy for it.

NEGATIVE CONTROLS. The checkers take the workflow text as an ARGUMENT, so the perturbations (the old
pin, a floating ``@latest``, the proof step removed) are exercised in-process, not merely described.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LIVEFIRE = _REPO / ".github" / "workflows" / "livefire.yml"

# The first release whose `-json -probe` writes a record for a probe that did not connect.
HTTPX_FLOOR = (1, 6, 10)

_INSTALL = re.compile(r"go install\s+github\.com/projectdiscovery/httpx/cmd/httpx@(\S+)")
_VERSION = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
_PROOF_STEP = "the installed httpx records a refused probe"


def _code_lines(workflow: str) -> str:
    """The workflow without its comment lines, so prose that QUOTES a pin is never read as one."""
    return "\n".join(ln for ln in workflow.splitlines() if not ln.lstrip().startswith("#"))


def httpx_pin_problems(workflow: str) -> list[str]:
    """Why the workflow's httpx install lines do not hold the floor ([] when they do)."""
    refs = _INSTALL.findall(_code_lines(workflow))
    if not refs:
        return ["no `go install …/httpx/cmd/httpx@<version>` line found — the pin cannot be checked"]
    problems = []
    for ref in refs:
        m = _VERSION.fullmatch(ref)
        if not m:
            problems.append(f"httpx@{ref} is not an exact vX.Y.Z pin")
            continue
        version = tuple(int(g) for g in m.groups())
        if version < HTTPX_FLOOR:
            problems.append(f"httpx@{ref} is below v{'.'.join(map(str, HTTPX_FLOOR))}: it writes no "
                            f"record for a refused probe under -json -probe")
    return problems


def proof_step_problems(workflow: str) -> list[str]:
    """Why the workflow does not prove the failed-probe record on the installed binary ([] when it does)."""
    code = _code_lines(workflow)
    marker = f"- name: {_PROOF_STEP}"
    if marker not in code:
        return [f"the step {_PROOF_STEP!r} is missing"]
    after = code.split(marker, 1)[1]
    step = after.split("\n      - ", 1)[0]
    drive = code.split("- name: drive the table against the loopback range", 1)
    problems = []
    if len(drive) != 2 or marker not in drive[0]:
        problems.append("the proof step does not run BEFORE the table is driven")
    for needle in ("-json", "-probe", '"failed":true', "exit 1"):
        if needle not in step:
            problems.append(f"the proof step no longer contains {needle!r}")
    if "continue-on-error" in step:
        problems.append("the proof step is continue-on-error, so its failure would not be seen")
    return problems


def test_the_nightly_httpx_pin_can_record_a_refused_probe():
    assert httpx_pin_problems(_LIVEFIRE.read_text()) == []


def test_the_workflow_proves_the_failed_probe_record_before_driving_the_table():
    assert proof_step_problems(_LIVEFIRE.read_text()) == []


def test_negative_control_the_old_pin_is_reported():
    text = _LIVEFIRE.read_text()
    pinned = _INSTALL.search(_code_lines(text))
    assert pinned is not None
    old = text.replace(pinned.group(0), pinned.group(0).replace(pinned.group(1), "v1.6.9"))
    assert old != text
    assert any("below v1.6.10" in p for p in httpx_pin_problems(old))


def test_negative_control_a_floating_ref_is_reported():
    text = _LIVEFIRE.read_text()
    pinned = _INSTALL.search(_code_lines(text))
    assert pinned is not None
    floating = text.replace(pinned.group(0), pinned.group(0).replace(pinned.group(1), "latest"))
    assert any("not an exact" in p for p in httpx_pin_problems(floating))


def test_negative_control_a_pin_only_quoted_in_a_comment_is_not_a_pin():
    text = "# go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10\n"
    assert any("no `go install" in p for p in httpx_pin_problems(text))


def test_negative_control_a_removed_or_defanged_proof_step_is_reported():
    text = _LIVEFIRE.read_text()
    assert proof_step_problems(text.replace(f"- name: {_PROOF_STEP}", "- name: something else"))
    assert any("exit 1" in p for p in proof_step_problems(
        text.replace("the closed-port control cannot be read as evidence\"\n            exit 1",
                     "the closed-port control cannot be read as evidence\"")))
