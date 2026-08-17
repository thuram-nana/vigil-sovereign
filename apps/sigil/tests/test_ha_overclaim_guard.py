"""Claim 6 Piece B (B-S5) — the HA OVER-CLAIM guard (risk #12).

Two invariants a future edit must not silently break:
  1. the sovereign k8s StatefulSet stays `replicas: 1` (raising it turns the spine into a multi-writer,
     i.e. a fork factory — a data-corruption bug, not scale);
  2. HA-PROFILE.md keeps the EXACT verbatim non-claim that VIGIL does not provide multi-writer HA of the
     sovereign spine.

Pure file checks (no sigil/offense imports) so this runs anywhere. Markdown normalization makes the
non-claim check robust to blockquote markers and line re-wrapping — it asserts the SENTENCE survives,
not a particular layout.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[3]
_STATEFULSET = _REPO / "infra" / "ha" / "k8s" / "sovereign-statefulset.yaml"
_HA_PROFILE = _REPO / "docs" / "architecture" / "HA-PROFILE.md"

# The load-bearing non-claim — MUST appear verbatim in HA-PROFILE.md. Do not soften it.
NONCLAIM = ("VIGIL does not provide, and this profile does not claim, multi-writer high availability of "
            "the sovereign spine. The spine is single-writer; the floor and witness quorum make a second "
            "concurrent writer a detectable fork.")


def _norm(text: str) -> str:
    """Drop Markdown blockquote/emphasis markers and collapse whitespace, so a re-wrapped or blockquoted
    sentence still matches its canonical one-line form."""
    return re.sub(r"\s+", " ", re.sub(r"[>*`]", "", text)).strip()


def test_sovereign_statefulset_is_replicas_1():
    assert _STATEFULSET.exists(), f"missing {_STATEFULSET}"
    text = _STATEFULSET.read_text(encoding="utf-8")
    # Strong check: parse the StatefulSet doc and assert its declared replicas is exactly 1.
    ss = next(d for d in yaml.safe_load_all(text)
              if isinstance(d, dict) and d.get("kind") == "StatefulSet")
    assert ss["spec"]["replicas"] == 1, (
        f"sovereign StatefulSet replicas={ss['spec']['replicas']} — MUST be 1. replicas>1 makes the "
        f"single-writer spine a multi-writer fork (data corruption, not scale).")
    # Belt-and-braces literal grep so a future edit cannot slip a different value past a lenient parser.
    assert re.search(r"^\s*replicas:\s*1\s*(#.*)?$", text, re.MULTILINE), \
        "sovereign-statefulset.yaml must contain a literal `replicas: 1` line"


def test_ha_profile_contains_the_verbatim_nonclaim():
    assert _HA_PROFILE.exists(), f"missing {_HA_PROFILE}"
    doc = _norm(_HA_PROFILE.read_text(encoding="utf-8"))
    assert _norm(NONCLAIM) in doc, (
        "HA-PROFILE.md is missing the verbatim multi-writer-HA non-claim — it must not be deleted or "
        "softened (claim-discipline: state the honest limit, do not remove it).")
