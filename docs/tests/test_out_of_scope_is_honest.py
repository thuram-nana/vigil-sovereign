"""The deferred-work frontier must agree with the code, or the build fails.

WHY THIS TEST EXISTS. The record of which tools the engine cannot yet drive lived in exactly one place:
the body of a merged pull request. A merged PR body is unreachable from the working tree, cannot be
reviewed beside the code it describes, and cannot be wrong in a way anything notices. Measured against
the code it WAS wrong, in both directions at once — it said "twelve further tools" while naming eleven,
and the true number with no driver at all was fifteen (it never mentioned katana, naabu or subfinder).

An undercount is the worse error: it reports the system as nearer to complete than it is. Nothing could
catch it, because nothing had ever read the list.

So the list now lives in ADR 0003, and this test reads BOTH the ADR and the code and fails when they
disagree. Three ways it can fail, each a real drift:

  1. a tool the ADR calls DEFERRED has quietly gained a driver (the doc now understates the system);
  2. `ncat` has gained a driver (a decision was reversed without reversing the decision record);
  3. a tool the ADR says Wave 2 SHIPPED has no driver (the doc overstates the system).

It reads files and imports the two driver registries. No tool runs, no packet is sent.
"""

from __future__ import annotations

import importlib
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ADR = REPO / "knowledge" / "decisions" / "0003-tool-waves-and-ncat.md"

# THIS FILE NEEDS BOTH TRUST DOMAINS, WHICH IS WHY IT CANNOT LIVE ONLY IN THE DOCS JOB.
#
# It compares the ADR against the real driver registries, so it must import `vigil_integration` AND
# `framework`. The `briefing-completeness` job installs nothing but pytest — deliberately, because the
# briefing test reads files only — so here every check SKIPPED, silently, while the ADR claimed to be
# "enforced by a required check". A skipped guard and a passing guard are the same colour.
#
# The fix is two-sided: the REQUIRED integration job now runs this file with both paths present, and
# there it sets VIGIL_REQUIRE_FRONTIER_CHECK=1 — which turns an import failure into a FAILURE instead
# of a skip. In the docs-only job the skip is still correct and honest.
_REQUIRED_HERE = (os.environ.get("VIGIL_REQUIRE_FRONTIER_CHECK") or "").strip().lower() in {
    "1", "true", "yes", "on"}


def _need(module: str):
    """Import ``module``, or skip — unless this environment declares the check mandatory, in which case
    an unimportable module is a hard failure. Nothing may silently disable this guard where it counts."""
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        if _REQUIRED_HERE:
            raise AssertionError(
                f"VIGIL_REQUIRE_FRONTIER_CHECK is set but {module!r} could not be imported ({exc}). "
                f"This job is the one that ENFORCES the deferred-tool frontier; a skip here would make "
                f"ADR 0003's guarantee silently absent.") from exc
        pytest.skip(f"could not import {module!r}: {exc}")


def _adr_text() -> str:
    assert ADR.is_file(), f"ADR 0003 is missing at {ADR} — the frontier has no home again"
    return ADR.read_text(encoding="utf-8")


def _tools_in_section(heading_fragment: str) -> set[str]:
    """Every `backticked` tool name inside the ADR bullet whose text contains ``heading_fragment``.

    Parsing the document the reader actually reads (rather than a machine-readable list kept beside it)
    is deliberate: a second list would be one more thing that can drift, and the whole point here is
    that the prose a human reviews is the thing under test.

    THE WHOLE BULLET, not its first line. The first version of this read one line and immediately
    under-reported: the Wave 4 bullet wraps, so `interactsh-client` sat on the continuation line and was
    invisible — the same class of undercount this file exists to catch, reproduced inside the checker.
    A bullet runs until a blank line or the next bullet."""
    lines = _adr_text().splitlines()
    for i, line in enumerate(lines):
        # Anchor on the BULLET, not on a mention. Matching bare "Wave 2" also hit the prose in the
        # section above it, which explains the analyzer contract — and dragged `is_available` and
        # `analyze` in as if they were tool names. The bullet is the only thing that starts this way.
        if not line.lstrip().startswith(heading_fragment):
            continue
        bullet = [line]
        for nxt in lines[i + 1:]:
            if not nxt.strip() or nxt.lstrip().startswith(("- ", "* ", "#", "|")):
                break
            bullet.append(nxt)
        return set(re.findall(r"`([a-z0-9_.\-]+)`", "\n".join(bullet)))
    raise AssertionError(f"ADR 0003 has no line containing {heading_fragment!r} — its shape changed")


def _driven() -> dict[str, str]:
    """Every tool the code can actually drive, mapped to the surface that drives it."""
    ex = _need("vigil_integration.live.executor")
    pf = _need("framework.v2.tools.profile")
    out: dict[str, str] = {}
    for name in ex._BUILDERS:
        out[name] = "cli"
    for name in pf._SENSOR_DRIVEN_TOOLS:
        out.setdefault(name, "sensor")
    for name in pf._ANALYZER_DRIVEN_TOOLS:
        out.setdefault(name, "analyzer")
    for name in pf._BROWSER_DRIVEN_TOOLS:
        out.setdefault(name, "browser")
    return out


def test_the_adr_is_readable_and_names_the_waves():
    """MUTATION CONTROL. Every assertion below is vacuous if the parse silently yields nothing, so pin
    that the document still has the shape this test reads."""
    assert _tools_in_section("**Wave 3 —"), "no Wave 3 tools parsed out of ADR 0003"
    assert _tools_in_section("**Wave 4 —"), "no Wave 4 tools parsed out of ADR 0003"
    assert len(_driven()) >= 10, "the driver registries look empty — the import or the names changed"


def test_no_tool_the_adr_calls_deferred_has_quietly_gained_a_driver():
    """The doc must not UNDERSTATE the system. A tool that gained a driver but stayed on the deferred
    list means the frontier moved and nobody said so."""
    deferred = _tools_in_section("**Wave 3 —") | _tools_in_section("**Wave 4 —")
    driven = _driven()
    contradictions = sorted(t for t in deferred if t in driven)
    assert not contradictions, (
        "ADR 0003 lists these as DEFERRED, but the code drives them: "
        + ", ".join(f"{t} (as {driven[t]})" for t in contradictions)
        + "\nMove them out of the deferred waves in knowledge/decisions/0003-tool-waves-and-ncat.md."
    )


def test_ncat_is_still_refused():
    """A permanent refusal must not be reversed by accident. Reversing it means editing the ADR that
    argues for it — which is the point: the decision and the code change together or not at all."""
    driven = _driven()
    assert "ncat" not in driven, (
        "ncat has gained a driver, but ADR 0003 records it as refused by design. Either revert the "
        "driver, or change the ADR and its reasoning in the same pull request."
    )
    text = _adr_text()
    assert "refused by design" in text or "refused rather than driven" in text, (
        "ADR 0003 no longer records the ncat refusal — the decision lost its rationale")


def test_every_tool_the_adr_says_wave_2_shipped_really_is_driven():
    """The doc must not OVERSTATE the system either. This is the direction that turns a plan into a
    false claim of capability, and it is the one a reader is least able to check."""
    shipped = _tools_in_section("**Wave 2 —")
    driven = _driven()
    # `semgrep`/`joern` are named in that line as already-driven context; they must be driven too, so
    # requiring the whole line is correct and slightly stronger.
    missing = sorted(t for t in shipped if t not in driven)
    assert not missing, (
        "ADR 0003 says Wave 2 shipped these, but no driver registry contains them: "
        + ", ".join(missing)
        + "\nEither build the driver or move them back to a deferred wave — do not leave the "
          "document claiming a capability the code does not have."
    )


def test_the_deferred_list_covers_every_undriven_tool_in_the_catalogue():
    """The undercount that started this. Any tool in the catalogue with no driver must be NAMED in the
    ADR — as deferred work or as a refusal. Silence about one is exactly how 'twelve' came to mean
    fifteen."""
    reg = _need("framework.v2.tools.registry")
    catalogue = {s.name for s in (*reg.HOST_TOOLS, *reg.SANDBOX_TOOLS)}
    undriven = catalogue - set(_driven())
    named = _tools_in_section("**Wave 3 —") | _tools_in_section("**Wave 4 —") | {"ncat"}
    unnamed = sorted(undriven - named)
    assert not unnamed, (
        "these tools are in the catalogue, have NO driver, and are named nowhere in ADR 0003: "
        + ", ".join(unnamed)
        + "\nAdd each to a deferred wave (or record a refusal). An unnamed gap reads to a "
          "reader as covered ground."
    )
