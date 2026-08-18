"""The two 'Read this FIRST' docs must not describe SHIPPED safety gates as MISSING.

WHY THIS TEST EXISTS (slice W16-17 / #523). Two resume docs are the first thing a stateless
cloud agent reads. Both had drifted a full roadmap behind the code and, read literally, told a
reviewer the platform's two FATAL-flagged safety gates were absent:

  * `docs/CONTINUATION.md` listed P5-P10 / I1-I5 under "what is NEXT (build in this order)",
    ordered the reader to "Do not run the fused offensive agent until both exist", and said the
    P6 host-side egress gate was still to-build ("do not run fused offense before it") — while
    `gateway/`, `envs/`, the WARDEN tool gate and the offense gate are all in-tree and default-ON.
  * `engine/crucible/SYSTEM-STATE.md` § 5 said "Producers don't populate `oracle_context` yet"
    and "the oracle authority only fires in tests" — while `http_executor` / `exploit_agent` and
    the whole scanner path build a `FindingContext` and fire the oracle in the live `engage` path.

An "understated" doc is the dangerous kind: it reports the system as further from safe than it
is, so a reviewer concludes a FATAL gate is missing and either re-builds it or refuses to run.

This test reads BOTH docs and the code they describe, and fails three ways, each a real drift:

  1. a FORBIDDEN false sentence has returned to a doc (the doc understates the shipped system);
  2. a corrected anchor sentence is gone (someone reverted the fix);
  3. a code fact the correction now CITES is not actually true in-tree (the fix over-claimed).

It reads files only. No module is imported, no tool runs, no packet is sent — so it is correct
to run in the docs-only CI job that installs nothing but pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONTINUATION = REPO / "docs" / "CONTINUATION.md"
SYSTEM_STATE = REPO / "engine" / "crucible" / "SYSTEM-STATE.md"


def _collapsed(path: Path) -> str:
    """File text with every run of whitespace collapsed to one space, so a claim that the source
    wraps across several indented lines still matches as a single phrase."""
    assert path.is_file(), f"doc missing: {path}"
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. The specific FALSE sentences must be GONE (collapsed-whitespace match).
# ---------------------------------------------------------------------------
FORBIDDEN = [
    # SYSTEM-STATE.md § 5 — the oracle-authority seam falsely reported open.
    (SYSTEM_STATE, "Producers don't populate `oracle_context` yet"),
    (SYSTEM_STATE, "oracle authority only fires in tests"),
    (SYSTEM_STATE, "the last mile (producer"),
    # CONTINUATION.md — the two FATAL gates falsely reported unbuilt.
    (CONTINUATION, "Do not run the fused offensive agent until both exist"),
    (CONTINUATION, "do not run fused offense before it"),
    (CONTINUATION, "what is NEXT (build in this order"),
]


def test_false_missing_gate_sentences_are_gone():
    collapsed = {SYSTEM_STATE: _collapsed(SYSTEM_STATE), CONTINUATION: _collapsed(CONTINUATION)}
    for path, phrase in FORBIDDEN:
        needle = re.sub(r"\s+", " ", phrase)
        assert needle not in collapsed[path], (
            f"{path.name} still contains the false 'gate is missing' sentence: {phrase!r}. "
            f"These gates are SHIPPED — do not let the resume doc understate the system.")


# ---------------------------------------------------------------------------
# 2. The corrected anchor sentences must be PRESENT (guards a silent revert).
# ---------------------------------------------------------------------------
REQUIRED_ANCHORS = [
    (SYSTEM_STATE, "Producers DO populate `oracle_context`"),
    (SYSTEM_STATE, "this seam is CLOSED"),
    (CONTINUATION, "The two FATAL gates are SHIPPED"),
    (CONTINUATION, "roadmap (SHIPPED"),
]


def test_corrected_anchors_present():
    collapsed = {SYSTEM_STATE: _collapsed(SYSTEM_STATE), CONTINUATION: _collapsed(CONTINUATION)}
    for path, phrase in REQUIRED_ANCHORS:
        needle = re.sub(r"\s+", " ", phrase)
        assert needle in collapsed[path], (
            f"{path.name} lost the corrected anchor {phrase!r} — the fix appears reverted.")


# ---------------------------------------------------------------------------
# 3. Every code fact the correction CITES must actually be true in-tree.
#    (Guards against replacing a false 'missing' claim with a false 'shipped' one.)
# ---------------------------------------------------------------------------
CITED_CODE_STRINGS = [
    # oracle_context IS populated by the live producers + the scanner.
    ("engine/crucible/framework/v2/agents/http_executor.py", "oracle_context=context.model_dump()"),
    ("engine/crucible/framework/v2/agents/exploit_agent.py",
     'update["oracle_context"] = outcome.oracle_context'),
    ("engine/crucible/framework/v2/scanner/engine.py", "oracle_context=_context_dump(ctx)"),
]

CITED_FILES = [
    # P5 two-env boundary.
    "envs/offense.txt", "envs/sovereign.txt",
    # P6 host egress gate.
    "gateway/vigil_gateway/nftables.py", "gateway/vigil_gateway/proxy.py",
    "gateway/vigil_gateway/denylist.py", "gateway/README.md",
    # P7 boundary + WARDEN tool gate.
    "apps/sigil/sigil/governor/offense_gate.py", "integration/vigil_integration/warden_gate.py",
    # P8 Claude runtime hardening (price table).
    "vendor/strix/strix/report/anthropic_pricing.py",
    # P9 / P10 oracle-confirmation + inert-data spine-sign.
    "integration/vigil_integration/oracle_adapter.py",
    "integration/vigil_integration/inert_finding.py",
    "apps/sigil/sigil/inbound/finding_receiver.py",
    # I1 / I2 / I4 moonshots the doc now calls SHIPPED.
    "integration/vigil_integration/challenge_oracle.py",
    "integration/vigil_integration/transparency.py",
    "integration/vigil_integration/destruction_gate.py",
]


def test_cited_code_actually_exists():
    for rel, needle in CITED_CODE_STRINGS:
        p = REPO / rel
        assert p.is_file(), f"cited producer source missing: {rel}"
        assert needle in p.read_text(encoding="utf-8"), (
            f"the docs now cite {needle!r} in {rel}, but the code does not contain it — "
            f"the correction would be a NEW overclaim.")
    for rel in CITED_FILES:
        assert (REPO / rel).exists(), (
            f"the docs now cite {rel} as SHIPPED, but it is absent — new overclaim.")


# ---------------------------------------------------------------------------
# 4. The honest RESIDUALS the correction keeps must still be code-true.
#    (Guards the other direction: the fix must not over-claim what is NOT built.)
# ---------------------------------------------------------------------------
def test_honest_residuals_stay_true():
    # realistic_executor is a TEST HARNESS and by design does NOT attach oracle_context —
    # the corrected SYSTEM-STATE bullet says so; keep it true.
    re_src = (REPO / "engine/crucible/framework/v2/agents/realistic_executor.py").read_text(encoding="utf-8")
    assert "oracle_context" not in re_src, (
        "realistic_executor.py now writes oracle_context — the SYSTEM-STATE 'honest residual' that "
        "calls it a test harness that does not attach one is no longer true; update the doc.")

    # I3 (the Claude-Agent-SDK-native agent body) is genuinely NOT built; CONTINUATION says so.
    # If a real claude-agent-sdk body module lands, the doc's 'still out of reach' line is stale.
    sdk_hits = list(REPO.glob("integration/**/claude_agent_sdk*.py")) + \
        list(REPO.glob("vendor/**/claude_agent_sdk*.py"))
    assert not sdk_hits, (
        f"a Claude-Agent-SDK body module appeared ({sdk_hits}); CONTINUATION.md still lists I3 as "
        "'out of reach' — update the doc rather than let it understate the system.")
