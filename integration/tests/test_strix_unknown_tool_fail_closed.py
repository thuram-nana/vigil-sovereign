"""S4 slice 1 — an unknown Strix tool must FAIL CLOSED (queue), never auto-run.

THE DEFECT (verified on origin/main). The Strix WARDEN hook is built with ``floor="A0"`` and its classifier
``_strix_shell_classifier`` returned::

    "A3" if name in _STRIX_GATED_TOOLS else "A0"

— i.e. A0 (auto-run) for EVERY name outside the four-tool gated set. ``decide_tool``'s fail-closed branch
(``base not in _ORD`` → A3) never fired, because "A0" is a *valid* tier; and the A0 floor could not raise
it. So a tool a Strix upgrade adds — or one an agent registers at runtime — AUTO-RUNS ungated. That violates
invariant 4: "no unknown tool executed through a generic shell."

THE FIX. The classifier now auto-runs ONLY the explicit allowlist ``_STRIX_AUTO_TOOLS`` (the current
sandbox-contained / read-only surface) and returns A3 for the gated set AND for every unrecognised name. The
two dangerous defaults trade places: the safe one (fail closed) wins.

THE DRIFT GUARD (offline, history-free). ``test_classification_is_total`` harvests the shipped Strix tool
names from the vendored TUI render manifest and asserts every one is classified (gated OR auto). If a Strix
upgrade adds a tool, this test goes RED until someone classifies it — which is exactly "a new upstream tool
must fail closed until classified", enforced in CI. It reads committed vendor files only (no git, no import
of the un-vendored ``agents`` SDK), so it runs in the sovereign-env P5 job.
"""
from __future__ import annotations

import re
from pathlib import Path

from vigil_integration.warden_gate import (
    _STRIX_AUTO_TOOLS,
    _STRIX_GATED_TOOLS,
    _strix_shell_classifier,
    decide_tool,
)

_REPO = Path(__file__).resolve().parents[2]
_RENDERER_DIR = _REPO / "vendor" / "strix" / "strix" / "interface" / "tui" / "renderers"

# ``tool_name: ClassVar[str] = "exec_command"`` — the literal each renderer declares. This is the authoritative
# offline inventory of what the operator actually sees a Strix run do.
_TOOL_NAME_RE = re.compile(r'tool_name:\s*ClassVar\[str\]\s*=\s*"([^"]*)"')


def _shipped_tool_names() -> set[str]:
    names: set[str] = set()
    for path in sorted(_RENDERER_DIR.glob("*.py")):
        for m in _TOOL_NAME_RE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            if m.group(1).strip():  # drop the empty-string default on the base renderer
                names.add(m.group(1))
    return names


# --------------------------------------------------------------------------------------------------------
# The classifier itself
# --------------------------------------------------------------------------------------------------------

def test_an_unknown_tool_classifies_a3_not_a0():
    for name in ("a_tool_nobody_registered", "rm_rf_slash", "curl", "nmap", "python3", "totally_new_tool"):
        assert _strix_shell_classifier(name) == "A3", f"unknown tool {name!r} did not fail closed"


def test_empty_and_whitespace_names_fail_closed():
    for name in ("", "   ", "\t\n", None):  # type: ignore[arg-type]
        assert _strix_shell_classifier(name) == "A3"


def test_every_gated_tool_classifies_a3():
    assert _STRIX_GATED_TOOLS, "the gated set is empty — nothing would ever queue"
    for name in _STRIX_GATED_TOOLS:
        assert _strix_shell_classifier(name) == "A3", f"gated tool {name!r} does not queue"


def test_every_auto_tool_classifies_a0():
    assert _STRIX_AUTO_TOOLS, "the auto allowlist is empty — the whole agent would queue"
    for name in _STRIX_AUTO_TOOLS:
        assert _strix_shell_classifier(name) == "A0", f"allowlisted tool {name!r} does not auto-run"


def test_gated_and_auto_are_disjoint():
    overlap = _STRIX_GATED_TOOLS & _STRIX_AUTO_TOOLS
    assert not overlap, f"a tool is BOTH gated and auto — ambiguous classification: {sorted(overlap)}"


# --------------------------------------------------------------------------------------------------------
# The full decision path (classifier + floor="A0" + ceiling="A1"), as the hook wires it
# --------------------------------------------------------------------------------------------------------

def test_end_to_end_unknown_tool_queues_under_the_a0_floor():
    """The regression was end-to-end: even with floor A0, an unknown tool must QUEUE, not auto."""
    d = decide_tool("some_upgrade_added_this", classify=_strix_shell_classifier, floor="A0", ceiling="A1")
    assert d.outcome == "queue", f"an unknown tool decided {d.outcome!r} at tier {d.tier!r} (expected queue)"
    assert d.tier == "A3"


def test_end_to_end_gated_tool_queues():
    for name in ("exec_command", "write_stdin", "repeat_request", "web_search"):
        d = decide_tool(name, classify=_strix_shell_classifier, floor="A0", ceiling="A1")
        assert d.outcome == "queue", f"{name} decided {d.outcome!r} (expected queue)"


def test_end_to_end_allowlisted_read_tool_still_autos():
    """The agent must stay functional: a known read/sandbox tool auto-runs."""
    for name in ("think", "list_requests", "view_request", "create_note", "apply_patch"):
        d = decide_tool(name, classify=_strix_shell_classifier, floor="A0", ceiling="A1")
        assert d.outcome == "auto", f"{name} decided {d.outcome!r} (expected auto)"


def test_negative_control_the_old_denylist_default_would_auto_run_an_unknown_tool():
    """Proves the probe is not vacuous: the PRE-FIX classifier (A0 for everything unknown) auto-runs a
    tool nobody registered. If someone reintroduces that shape, the end-to-end test above turns red."""
    def old_classifier(name: str) -> str:
        return "A3" if str(name or "").strip() in _STRIX_GATED_TOOLS else "A0"

    d = decide_tool("some_upgrade_added_this", classify=old_classifier, floor="A0", ceiling="A1")
    assert d.outcome == "auto" and d.tier == "A0", (
        "the old denylist default no longer auto-runs an unknown tool — the negative control is stale"
    )


# --------------------------------------------------------------------------------------------------------
# The offline drift guard — every shipped Strix tool is explicitly classified
# --------------------------------------------------------------------------------------------------------

def test_the_render_manifest_is_readable():
    """Guards the guard: if the vendored renderer layout moves, fail loudly rather than pass vacuously."""
    assert _RENDERER_DIR.is_dir(), f"Strix renderer dir not found at {_RENDERER_DIR}"
    shipped = _shipped_tool_names()
    assert len(shipped) >= 25, (
        f"only harvested {len(shipped)} tool names from the render manifest — the ClassVar shape changed; "
        "the drift guard would silently under-cover"
    )


def test_classification_is_total_every_shipped_tool_is_gated_or_auto():
    shipped = _shipped_tool_names()
    classified = _STRIX_GATED_TOOLS | _STRIX_AUTO_TOOLS
    unclassified = shipped - classified
    assert not unclassified, (
        f"shipped Strix tool(s) {sorted(unclassified)} are neither gated nor allowlisted — a Strix upgrade "
        "added a tool. Classify each explicitly in warden_gate.py (gated if it execs/reaches the network, "
        "auto only if genuinely sandbox-contained / read-only)."
    )


def test_no_stale_classified_name_that_no_longer_ships():
    shipped = _shipped_tool_names()
    classified = _STRIX_GATED_TOOLS | _STRIX_AUTO_TOOLS
    stale = classified - shipped
    assert not stale, (
        f"warden_gate classifies {sorted(stale)}, which the vendored Strix no longer ships as a tool — "
        "remove the stale name(s) so the sets track the real tool surface"
    )
