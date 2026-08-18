"""framework/v2/sbom.json must be a REAL SBOM, and SECURITY.md must describe the REAL gate.

THE DEFECT THIS PINS (W16-15). For the repo's whole history ``framework/v2/sbom.json`` was a
hand-written *scaffold*: ``metadata.timestamp`` was ``"0000-00-00T00:00:00Z"``,
``metadata.tools[0].name`` was ``"scaffold (operator regenerates with cyclonedx-bom)"``, and
the component versions were the *ranges* from ``requirements.in`` (``pydantic>=2.10,<3``) rather
than the resolved pins from the lock. Meanwhile ``SECURITY.md`` § 2.3 claimed the CI verifier
"Re-generates the SBOM and compares the component set to ``sbom.json`` — drift fails the build."
It did not: ``bin/verify-supply-chain.sh`` cross-checks a per-run temp SBOM against the *lock*
and never reads the committed file. So a placeholder sat behind a false "it's checked" claim.

WHAT THE FIX IS. ``framework/v2/tools/gen_sbom.py`` regenerates ``sbom.json`` from the lock
(stdlib only), and the A14 workflow runs ``gen_sbom --check`` so the committed file is genuinely
gated. SECURITY.md now states truthfully what is and is not checked.

Every ``test_*`` below asserts the fix holds; the two ``*_detector_actually_fires`` tests are the
negative controls — they feed each detector a KNOWN-BAD document and assert it flags it, so a
future edit cannot make these tests pass by weakening the detector into one that flags nothing.

Pure stdlib + pytest; the generator it exercises imports only the standard library too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

gen_sbom = pytest.importorskip("framework.v2.tools.gen_sbom")

_HERE = Path(__file__).resolve()
V2_DIR = _HERE.parents[2]              # .../framework/v2
CRUCIBLE_ROOT = _HERE.parents[4]       # .../engine/crucible
SBOM = V2_DIR / "sbom.json"
LOCK = V2_DIR / "requirements.lock.txt"
SECURITY = CRUCIBLE_ROOT / "SECURITY.md"
# Repo-root workflow — present in the monorepo checkout, absent if engine/crucible is imported
# standalone as a subtree. The workflow assertion is guarded on its existence for that reason.
WORKFLOW = CRUCIBLE_ROOT.parent.parent / ".github" / "workflows" / "supply-chain.yml"

ZERO_TS = "0000-00-00T00:00:00Z"
# The exact false sentence SECURITY.md § 2.3 carried; its return is the regression to catch.
FALSE_DOC_CLAIM = "compares the component set to `sbom.json`"
# Characters that only appear in a version *range*, never in a resolved pin.
RANGE_CHARS = set("<>*, ")


def _scaffold_problems(doc: dict) -> list[str]:
    """Return every reason ``doc`` looks like the old scaffold (empty list == it's real)."""
    problems: list[str] = []
    md = doc.get("metadata", {})
    tool_names = " ".join(t.get("name", "") for t in md.get("tools", [])).lower()
    if "scaffold" in tool_names:
        problems.append("tool name carries the scaffold sentinel")
    ts = md.get("timestamp", "")
    if ts == ZERO_TS or ts.startswith("0000-"):
        problems.append("zero/sentinel timestamp")
    for p in md.get("properties", []):
        val = str(p.get("value", "")).lower()
        if "scaffold" in val and "regenerat" in val:
            problems.append("SCAFFOLD status property present")
    comps = doc.get("components", [])
    if len(comps) < 5:
        problems.append(f"only {len(comps)} components")
    for c in comps:
        v = str(c.get("version", ""))
        if not v or "=" in v or any(ch in RANGE_CHARS for ch in v):
            problems.append(f"{c.get('name')} has a non-pinned version {v!r}")
    return problems


def _lock_pins() -> set[tuple[str, str]]:
    pins: set[tuple[str, str]] = set()
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\;]+)", line)
        if m:
            pins.add((gen_sbom._norm(m.group(1)), m.group(2)))
    return pins


# ======================================================================================
# The committed SBOM is real (not the scaffold)
# ======================================================================================


def test_committed_sbom_is_real_not_scaffold() -> None:
    doc = json.loads(SBOM.read_text(encoding="utf-8"))
    problems = _scaffold_problems(doc)
    assert not problems, "framework/v2/sbom.json regressed to a scaffold:\n  " + "\n  ".join(problems)

    by_norm = {gen_sbom._norm(c["name"]): c for c in doc["components"]}
    # Real resolved pins, with scope derived from the lock's provenance.
    assert "pydantic" in by_norm and re.match(r"^\d", by_norm["pydantic"]["version"])
    assert by_norm["pydantic"]["scope"] == "required"
    # pytest-httpserver is the test-only direct dep; it and werkzeug (reached only through it)
    # are optional, everything else required.
    assert by_norm["pytest-httpserver"]["scope"] == "optional"
    assert by_norm["werkzeug"]["scope"] == "optional"

    ts = doc["metadata"]["timestamp"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts), f"not a real timestamp: {ts!r}"
    assert int(ts[:4]) >= 2020, f"implausible year in {ts!r}"


def test_committed_sbom_matches_what_gen_sbom_derives_from_the_lock() -> None:
    """Proves the committed file was genuinely generated from the lock, not hand-edited."""
    committed = json.loads(SBOM.read_text(encoding="utf-8"))
    fresh = gen_sbom.build_sbom(LOCK.read_text(encoding="utf-8"), timestamp=ZERO_TS)

    def triples(d: dict) -> set[tuple[str, str, str]]:
        return {(gen_sbom._norm(c["name"]), c["version"], c["scope"]) for c in d["components"]}

    assert triples(committed) == triples(fresh), (
        "framework/v2/sbom.json is not what gen_sbom.py derives from the current lock — "
        "regenerate with `python3 -m framework.v2.tools.gen_sbom`"
    )
    committed_pairs = {(gen_sbom._norm(c["name"]), c["version"]) for c in committed["components"]}
    assert committed_pairs == _lock_pins(), "the committed SBOM's component set != the lock's pins"


# ======================================================================================
# SECURITY.md states the truth (doc-truth), and the workflow backs the new claim
# ======================================================================================


def test_security_md_no_longer_claims_a_check_that_does_not_run() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert FALSE_DOC_CLAIM not in text, (
        "SECURITY.md again claims verify-supply-chain.sh compares the regenerated SBOM to the "
        "committed sbom.json — that check does not exist; the script cross-checks the LOCK."
    )
    # And it positively describes the real mechanism.
    assert "gen_sbom" in text, "SECURITY.md should point at framework/v2/tools/gen_sbom.py"
    assert "from the lock" in text, "SECURITY.md should say the CI SBOM check is derived from the lock"


def test_security_md_gensbom_check_claim_is_backed_by_the_workflow() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert "gen_sbom --check" in text, (
        "SECURITY.md should document the committed-SBOM gate (gen_sbom --check)"
    )
    if WORKFLOW.is_file():
        wf = WORKFLOW.read_text(encoding="utf-8")
        assert "framework.v2.tools.gen_sbom --check" in wf, (
            "SECURITY.md says the A14 workflow runs `gen_sbom --check`, but "
            "supply-chain.yml does not invoke it — the claim would be false again."
        )


# ======================================================================================
# Negative controls — prove each detector actually detects
# ======================================================================================


def test_scaffold_detector_actually_fires() -> None:
    scaffold = {
        "metadata": {
            "timestamp": ZERO_TS,
            "tools": [{"name": "scaffold (operator regenerates with cyclonedx-bom)"}],
            "properties": [
                {"name": "crucible:sbom-status",
                 "value": "SCAFFOLD — operator regenerates via cyclonedx-py"},
            ],
        },
        "components": [{"name": "pydantic", "version": ">=2.10,<3"}],
    }
    problems = _scaffold_problems(scaffold)
    assert problems, "the scaffold detector flagged nothing on a known scaffold — it proves nothing"
    joined = " ".join(problems)
    assert "scaffold sentinel" in joined
    assert "timestamp" in joined
    assert "non-pinned version" in joined


def test_docdrift_detector_actually_fires() -> None:
    known_false_sentence = (
        "3. Re-generates the SBOM and compares the component set to `sbom.json` "
        "— drift fails the build."
    )
    assert FALSE_DOC_CLAIM in known_false_sentence, (
        "the doc-truth needle no longer matches the sentence it must catch"
    )
