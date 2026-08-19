"""W16-3 (#508) — the two live cloud/K8s prerequisites must be documented in README and DEPLOY,
and the documented behaviour must be TRUE OF THE CODE.

The defect: a live cloud/K8s assessment needs two prerequisites — **ambient read-only credentials**
and a provisioned egress scope, **`targets/<slug>/collector-hosts.txt`** — that were named in build
docs but ZERO times in README or DEPLOY, so an operator who ran an assessment without them saw a
SILENT CLEAN (the worst failure mode for a sound-negative product).

This test reads files only (no import, no tool, no packet), so it is correct to run in the docs-only
CI job that installs nothing but pytest. It fails three ways, each a real drift:

  1. README.md or docs/DEPLOY.md stopped documenting a prerequisite (or the "INCONCLUSIVE, never
     CLEAN" behaviour) — the silent-clean caveat regressed out of the operator-facing docs;
  2. the docs' code-mirrored claim is no longer true in-tree — the sensor sources no longer emit a
     structured INCONCLUSIVE outcome, or `k8s_live` no longer names `collector-hosts.txt`, so the
     docs would over-claim a behaviour the code dropped;
  3. a required doc file is missing.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
DEPLOY = REPO / "docs" / "DEPLOY.md"
SENSORS = REPO / "engine" / "crucible" / "framework" / "v2" / "sensors"
LIVE_SENSORS = ("cloud_live", "gcp_live", "azure_live", "k8s_live")


def _collapsed(path: Path) -> str:
    """File text with every whitespace run collapsed to one space, so a claim wrapped across several
    lines still matches as one phrase. Lower-cased for case-insensitive substring checks."""
    assert path.is_file(), f"doc missing: {path}"
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).lower()


# ---------------------------------------------------------------------------
# 1. README and DEPLOY each document BOTH prerequisites + the INCONCLUSIVE-not-clean behaviour
# ---------------------------------------------------------------------------


def _assert_documents_both_prerequisites(path: Path) -> None:
    text = _collapsed(path)
    # (2) the provisioned egress-scope file — named ZERO times before this slice
    assert "collector-hosts.txt" in text, f"{path.name} must name targets/<slug>/collector-hosts.txt"
    # (1) the ambient read-only credential requirement
    assert "ambient" in text and "credential" in text, f"{path.name} must document ambient credentials"
    # the behaviour: a missing prerequisite is INCONCLUSIVE, NEVER a clean negative
    assert "inconclusive" in text, f"{path.name} must state the missing-prerequisite outcome is INCONCLUSIVE"
    assert re.search(r"never[^.]{0,40}clean", text), f"{path.name} must state it is NEVER a clean result"


def test_readme_documents_both_prerequisites():
    _assert_documents_both_prerequisites(README)


def test_deploy_documents_both_prerequisites():
    _assert_documents_both_prerequisites(DEPLOY)


# ---------------------------------------------------------------------------
# 2. the documented behaviour is TRUE OF THE CODE (derive the mirrored claim from the source, so it
#    cannot drift): the live sensors emit a structured INCONCLUSIVE outcome, and k8s_live names the
#    collector-hosts.txt prerequisite in that path
# ---------------------------------------------------------------------------


def test_live_sensors_emit_a_structured_inconclusive_outcome():
    for name in LIVE_SENSORS:
        src = (SENSORS / f"{name}.py")
        assert src.is_file(), f"live sensor source missing: {src}"
        body = src.read_text(encoding="utf-8")
        # the doc claim "a missing prerequisite is INCONCLUSIVE" is grounded in the actual return path
        assert "inconclusive_result(" in body, f"{name}.py must mint an inconclusive_result on a missing prerequisite"


def test_k8s_live_names_the_collector_hosts_prerequisite_in_code():
    body = (SENSORS / "k8s_live.py").read_text(encoding="utf-8")
    # the DEPLOY/README claim that k8s_live 'names collector-hosts.txt explicitly' must be true of code
    assert "collector-hosts.txt" in body
    # and it must be on an inconclusive path, not merely a stale comment — the marker helper is imported
    assert "from .base import inconclusive_result" in body


def test_inconclusive_primitive_exists_and_names_the_prerequisite():
    base = (SENSORS / "base.py").read_text(encoding="utf-8")
    # the shared primitive the docs' behaviour rests on: names the missing prerequisite, marks not-assessed
    assert "def inconclusive_result(" in base and "def is_inconclusive(" in base
    assert "missing_prerequisite" in base and '"assessed": False' in base
