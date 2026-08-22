"""W17-10 (#544): a finished agentic run must render as COMPLETED, not "Still running" forever.

WHY THIS TEST EXISTS. The console→live-engine bridge (`framework/v2/console/actions.py`
`launch_assessment`) spawns an agentic `vigil engage` run with `capture_report=False` and marks its meta
`stream:"progress", engine:"integration"`. So /api/report stays `{pending:true}` forever — the run never
captures a re-checkable web report. The P3 report view decides whether to show the honest "runs in its own
sandbox / no report captured" empty state (rather than the false "Still running… no saved report YET"
pending state) with `p3RunCapturesNoReport(run)` in `packages/vigil-ui/app.js`.

Before the fix that predicate matched only `stream === "none"` (aegis) or `mode === "codebase"` (Strix). An
integration bridge run is NEITHER — it shares `stream:"progress"` with the loopback scan (which DOES capture
a report) and is told apart only by `engine:"integration"`. So a completed agentic run fell through to the
pending-empty state and read "Still running" forever. The fix adds `engine === "integration"` to the
predicate.

This test reads files only — imports nothing, runs no tool, sends no packet — so it is correct to run in the
docs-only CI job (`pytest docs/tests -q`, which installs only pytest). It:

  * ports the LIVE predicate expression out of app.js and evaluates it against every stream/mode/engine
    combination `launch_assessment` can emit, asserting each renders correctly — the completed agentic run
    (this fails on a tree WITHOUT the fix), and the NEGATIVE CONTROLS: a still-running loopback scan (which
    captures a report) and a bogus/empty run both stay in the running/pending state, proving the predicate is
    not simply always-complete;
  * DRIFT GUARD — cross-checks the set of `stream`/`engine` literals `launch_assessment` actually emits
    against the combination table below, so a NEW combination cannot be added to the bridge without either
    being covered here (and by the predicate) or failing this test.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

APPJS = REPO / "packages" / "vigil-ui" / "app.js"
ACTIONS = REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py"


# ---------------------------------------------------------------------------
# The combination table: every combo `launch_assessment` can emit for a run that a viewer opens in P3.
# Each row is (label, run-fields, captures_report, live_stream_branch, expect_no_report_empty).
#
#   captures_report        — the run WROTE report.json (capture_report=True in the spawn), so /api/report is
#                            NOT pending and the real report renders; the empty-state predicate must be False.
#   handled_by_blackboard  — the run's stream is 'blackboard', which p3NoReportEmpty resolves in its OWN
#                            branch BEFORE p3RunCapturesNoReport is reached; the predicate is not the arbiter.
#   expect_no_report       — what p3RunCapturesNoReport(run) MUST return.
#
# The invariant this table encodes: every combo that captures NO report and is NOT the blackboard-live case
# must be caught by the predicate — otherwise it falls through to the false "Still running" pending-empty.
# ---------------------------------------------------------------------------
BRIDGE_COMBINATIONS = [
    # label, run, captures_report, handled_by_blackboard, expect_no_report
    ("codebase / Strix",
     {"stream": "progress", "mode": "codebase"}, False, False, True),
    ("aegis (defensive)",
     {"stream": "none", "mode": "aegis"}, False, False, True),
    ("agentic vigil engage bridge (url)",
     {"stream": "progress", "mode": "url", "engine": "integration"}, False, False, True),
    ("agentic vigil engage bridge (suite)",
     {"stream": "progress", "mode": "suite", "engine": "integration"}, False, False, True),
    ("agentic vigil engage bridge (tool)",
     {"stream": "progress", "mode": "tool", "engine": "integration"}, False, False, True),
    # NEGATIVE CONTROL — a loopback scan shares stream 'progress' but DOES capture a report, so it must NOT be
    # swallowed by the empty-state predicate (a genuinely-running one shows real pending; a finished one shows
    # its real report). If this returned True the predicate would be always-complete and hide real reports.
    ("loopback scan (captures a report)",
     {"stream": "progress", "mode": "url"}, True, False, False),
    # remote engage streams onto the blackboard — resolved by p3NoReportEmpty's own branch first.
    ("remote engage (blackboard)",
     {"stream": "blackboard", "mode": "url"}, False, True, False),
]

# NEGATIVE CONTROL — a wholly unknown/empty run must NOT be classed as no-report-captured (the predicate is a
# specific allow-set, never a catch-all that would hide a real pending state).
NEGATIVE_CONTROLS = [
    ("empty run", {}),
    ("unknown mode, no stream/engine", {"mode": "url"}),
    ("bogus engine string", {"stream": "progress", "mode": "url", "engine": "not-integration"}),
]


def _predicate_expr() -> str:
    """Pull the LIVE body of `p3RunCapturesNoReport` out of app.js — the exact boolean expression the browser
    runs — so this test exercises the real source, not a copy that could drift."""
    src = APPJS.read_text(encoding="utf-8")
    m = re.search(r"function p3RunCapturesNoReport\(run\)\s*\{\s*return\s*(.+?);\s*\}", src)
    assert m, "could not locate p3RunCapturesNoReport(run) { return ...; } in app.js"
    return m.group(1)


def _eval_predicate(expr: str, run: dict) -> bool:
    """Evaluate the JS boolean expression against a run dict, faithfully to JS semantics: `run.X` is a
    missing-safe property read (undefined ≠ any string), `===` is strict equality, `||` is OR. No eval of
    arbitrary JS — only these three constructs appear, and any other token is rejected so a future rewrite of
    the predicate into a shape this porter does not understand fails loudly instead of silently passing."""
    result = False
    for term in expr.split("||"):
        term = term.strip()
        m = re.fullmatch(r'run\.(\w+)\s*===\s*"([^"]*)"', term)
        assert m, f"unsupported term in p3RunCapturesNoReport predicate: {term!r} — update this porter"
        prop, want = m.group(1), m.group(2)
        # a missing property is JS `undefined`, which is never === a string
        if run.get(prop, None) == want:
            result = True
    return result


def test_predicate_source_includes_the_integration_engine_axis() -> None:
    """Guard: the fix must be in the source. The predicate distinguishes the integration bridge run (which
    shares stream 'progress' with the report-capturing loopback scan) only by engine === 'integration'."""
    expr = _predicate_expr()
    assert 'run.engine === "integration"' in expr, (
        "p3RunCapturesNoReport must match the agentic bridge run by engine === \"integration\" — "
        "without it a completed agentic run reads 'Still running' forever"
    )
    # keep the pre-existing axes too (a fix must not drop the aegis / codebase cases)
    assert 'run.stream === "none"' in expr, "predicate dropped the aegis (stream 'none') case"
    assert 'run.mode === "codebase"' in expr, "predicate dropped the codebase (Strix) case"


def test_every_bridge_combination_renders_correctly() -> None:
    """The core acceptance: a completed agentic run renders as no-report-captured (fails without the fix),
    and the negative controls (a report-capturing loopback scan; a blackboard live run) do NOT — proving the
    predicate is a specific allow-set, not always-complete."""
    expr = _predicate_expr()
    for label, run, captures_report, handled_by_blackboard, expect_no_report in BRIDGE_COMBINATIONS:
        got = _eval_predicate(expr, run)
        assert got is expect_no_report, (
            f"{label}: p3RunCapturesNoReport returned {got}, expected {expect_no_report} for run={run}"
        )
        # the cannot-fall-through invariant: no-report + not-blackboard MUST be caught by the predicate
        if not captures_report and not handled_by_blackboard:
            assert got is True, (
                f"{label}: captures no report and is not the blackboard-live case, yet the predicate does not "
                f"catch it — it would fall through to the false 'Still running' pending-empty state"
            )
        if captures_report:
            assert got is False, f"{label}: a report-capturing run must not be hidden by the empty-state"


def test_negative_controls_are_not_classed_as_no_report() -> None:
    """The gate is not a no-op: unknown / empty / bogus runs are rejected by the predicate (return False), so
    a genuinely still-running or report-bearing run is never misclassified as 'no report coming'."""
    expr = _predicate_expr()
    for label, run in NEGATIVE_CONTROLS:
        assert _eval_predicate(expr, run) is False, (
            f"{label}: predicate must NOT class an unknown run as no-report-captured (run={run})"
        )


def _launch_assessment_src() -> str:
    """The source of `launch_assessment` only — the console→live-engine bridge that emits the stream/mode/
    engine meta the P3 predicate keys on. Bounded to the next top-level `def` so a literal from an unrelated
    launcher (e.g. launch_cloud) cannot leak into the drift set."""
    src = ACTIONS.read_text(encoding="utf-8")
    start = src.index("\ndef launch_assessment(")
    tail = src[start + 1:]
    nxt = re.search(r"\ndef \w+\(", tail)
    return tail[: nxt.start()] if nxt else tail


def test_no_new_bridge_combination_can_fall_through() -> None:
    """DRIFT GUARD. The set of `stream`/`engine` literals `launch_assessment` actually emits must equal the
    set the combination table covers. If someone adds a new bridge combination (a new stream or engine),
    this fails until the table AND the predicate are updated — so a new combination cannot silently fall
    through to the pending-empty state."""
    body = _launch_assessment_src()
    emitted_streams = set(re.findall(r'"stream":\s*"([^"]+)"', body))
    emitted_engines = set(re.findall(r'"engine":\s*"([^"]+)"', body))

    table_streams = {run.get("stream") for _, run, *_ in BRIDGE_COMBINATIONS if run.get("stream")}
    table_engines = {run.get("engine") for _, run, *_ in BRIDGE_COMBINATIONS if run.get("engine")}

    assert emitted_streams == table_streams, (
        f"launch_assessment emits stream values {sorted(emitted_streams)} but the combination table covers "
        f"{sorted(table_streams)} — add the new combination to BRIDGE_COMBINATIONS and to "
        f"p3RunCapturesNoReport (or the blackboard branch) so it cannot fall through"
    )
    assert emitted_engines == table_engines, (
        f"launch_assessment emits engine values {sorted(emitted_engines)} but the combination table covers "
        f"{sorted(table_engines)} — add the new combination to BRIDGE_COMBINATIONS and to "
        f"p3RunCapturesNoReport so it cannot fall through"
    )
    # and the engine axis the bug was about is really emitted by the bridge (not just asserted in the UI)
    assert "integration" in emitted_engines, (
        "launch_assessment no longer emits engine:'integration' — the P3 predicate's engine test would be dead"
    )


def test_empty_state_text_is_not_codebase_or_aegis_only() -> None:
    """Red-pen HIGH: once engine === 'integration' routes an agentic `vigil engage` run into the
    no-report-captured empty state, the empty-state COPY must be true for that run too — the pre-fix text
    ("A codebase (Strix) / AEGIS run reports inside its sandbox") mis-attributed an agentic engage run as a
    codebase/AEGIS run. The copy must name the engage/agentic case or be generic across all routed types."""
    import pathlib

    app = pathlib.Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js"
    src = app.read_text(encoding="utf-8")
    # the exact pre-fix mis-attributing sentence must be gone
    assert "A codebase (Strix) / AEGIS run reports inside its sandbox" not in src, (
        "the empty-state copy still describes the run as codebase/AEGIS-only — it mis-attributes an "
        "agentic engage run routed here by engine === 'integration'"
    )
    # and the replacement must cover the agentic engage case (named, or a generic 'streams its work' form)
    assert ("agentic engage run" in src or "streams its work" in src), (
        "the empty-state copy must be true for the agentic engage run too (name it, or be generic)"
    )
