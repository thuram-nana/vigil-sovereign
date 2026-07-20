"""
Nervous-System N7 — the AI skill doc must match the SHIPPED code.

A skill/architecture doc that references a subcommand or module that does not exist is an
overclaim — the same honesty rule the veracity layer enforces. This test keeps the loadable
SKILL.md and the long-form CRUCIBLE-AI.md honest: every CLI workflow they cite is a real
dispatch subcommand, and every module they point at exists.
"""

from __future__ import annotations

import re
from pathlib import Path

from framework.v2.__main__ import _DISPATCH

_REPO = Path(__file__).resolve().parents[3]        # framework/v2/tests/ -> repo root
_SKILL = _REPO / ".claude" / "skills" / "crucible" / "SKILL.md"
_LONG = _REPO / "framework" / "v2" / "docs" / "CRUCIBLE-AI.md"


def test_the_docs_exist() -> None:
    assert _SKILL.is_file() and _LONG.is_file()


def test_skill_frontmatter_is_valid() -> None:
    text = _SKILL.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    fm = text.split("---", 2)[1]
    assert re.search(r"^name:\s*crucible\s*$", fm, re.MULTILINE)
    assert "description:" in fm


def test_every_cited_subcommand_is_real() -> None:
    # every `python3 -m framework.v2 <sub>` the docs cite must be a real dispatch key.
    cited = set()
    for doc in (_SKILL, _LONG):
        cited |= set(re.findall(r"framework\.v2\s+([a-z]+)", doc.read_text(encoding="utf-8")))
    assert cited, "expected the docs to cite at least one subcommand"
    unknown = cited - set(_DISPATCH)
    assert not unknown, f"docs cite non-existent subcommand(s): {sorted(unknown)}"


def test_key_referenced_modules_exist() -> None:
    # spot-check the nervous-system + veracity modules the long-form doc points at.
    for rel in [
        "framework/v2/agents/blackboard.py", "framework/v2/agents/spine_sink.py",
        "framework/v2/agents/spine_chain.py", "framework/v2/agents/spine_credit.py",
        "framework/v2/agents/critics.py", "framework/v2/agents/reflection.py",
        "framework/v2/agents/cognitive_refusal.py", "framework/v2/calibration/reward_bus.py",
        "framework/v2/calibration/meta_monitor.py", "framework/v2/veracity/firewall.py",
        "framework/cognitive/metacognition.md",
    ]:
        assert (_REPO / rel).is_file(), f"CRUCIBLE-AI.md references a missing module: {rel}"


def test_engage_examples_do_not_cite_scan_only_flags() -> None:
    # regression (N7 review): --strict-evidence is a scan-only flag; an engage command line that
    # cites it fails with 'unrecognized arguments'. No engage example may carry it.
    for doc in (_SKILL, _LONG):
        for line in doc.read_text(encoding="utf-8").splitlines():
            if "framework.v2 engage " in line or "engage <slug>" in line:
                assert "--strict-evidence" not in line, (
                    f"{doc.name}: engage example cites the scan-only --strict-evidence flag")


def test_long_doc_states_wiring_status_honestly() -> None:
    # the doc must distinguish LIVE mechanisms from additive primitives (no overclaim of wiring).
    assert "Wiring status" in _LONG.read_text(encoding="utf-8")


def test_oracle_authority_invariant_is_stated() -> None:
    long = _LONG.read_text(encoding="utf-8")
    skill = _SKILL.read_text(encoding="utf-8")
    for needle in ("oracle", "advise", "never"):
        assert needle.lower() in long.lower() and needle.lower() in skill.lower()
