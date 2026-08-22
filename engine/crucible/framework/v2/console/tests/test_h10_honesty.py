"""H10 honesty regressions — two claims the console makes about the offense engine must MATCH the code.

A. The ``arsenal`` capability pack label must describe what ``--arsenal`` actually does. ``--arsenal`` is
   the opt-in ADVANCED WEB arsenal (``engage.py enable_arsenal`` → ``scanner/campaign.py``: HTTP request
   smuggling, cross-site WebSocket hijacking, single-packet race). It runs NO host CLIs. The prior copy
   ("Run host CLIs (nmap/nuclei/…)") described a capability the flag does not have — a false claim the
   operator would act on. This test fails if the label regresses to a host-CLI claim, and it grounds the
   assertion in the REAL behaviour (campaign.py), not just in the new wording.

B. ``api.brain_decision``'s ``brain`` block must be DERIVED from the brain's own source, never frozen
   literals. The block is parsed (static ``ast``, no import — FATAL-2) out of the brain module, so a
   rename, an edited design-credit line, an added exploit/execute method, or a changed objective enum all
   flow through. The conclusive proof monkeypatches the source locator to a DIFFERENT file and shows the
   output tracks it — a frozen literal could not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import framework.v2 as fv2
from framework.v2.console import actions, api


# ---------------------------------------------------------------------------
# A. arsenal capability label matches the actual --arsenal behaviour
# ---------------------------------------------------------------------------

def _arsenal_cap() -> dict:
    caps = [c for c in actions.ENGAGE_CAPABILITIES if c["id"] == "arsenal"]
    assert caps, "the 'arsenal' capability pack must exist"
    return caps[0]


def test_arsenal_label_makes_no_host_cli_claim() -> None:
    cap = _arsenal_cap()
    blob = (cap["label"] + " " + cap["purpose"]).lower()
    # the false claim the old copy made — a host-CLI arsenal running nmap/nuclei
    assert "nmap" not in blob, "arsenal label must not claim to run nmap (it does not)"
    assert "nuclei" not in blob, "arsenal label must not claim to run nuclei (it does not)"
    assert "host cli" not in blob, "arsenal label must not claim to run host CLIs (it does not)"


def test_arsenal_label_describes_the_real_web_arsenal() -> None:
    cap = _arsenal_cap()
    blob = (cap["label"] + " " + cap["purpose"]).lower()
    assert "web" in blob, "arsenal is the advanced WEB arsenal — the label must say so"
    # at least one of the modules the flag actually drives
    assert any(k in blob for k in ("smuggl", "websocket", "cswsh", "race")), \
        "arsenal label must name a module --arsenal actually drives (smuggling/CSWSH/race)"


def test_arsenal_label_is_consistent_with_campaign_code() -> None:
    """Ground the label in the CODE that implements --arsenal, so the two cannot drift apart."""
    camp = (Path(fv2.__file__).parent / "scanner" / "campaign.py").read_text(encoding="utf-8").lower()
    # the real behaviour: an advanced WEB arsenal of smuggling / CSWSH / race
    assert "advanced web arsenal" in camp
    assert "smuggl" in camp and ("cswsh" in camp or "websocket" in camp) and "race" in camp
    # and it is NOT a host-CLI arsenal — campaign.py drives no nmap/nuclei
    assert "nmap" not in camp and "nuclei" not in camp
    # therefore the console label must also make no host-CLI claim
    blob = (_arsenal_cap()["label"] + " " + _arsenal_cap()["purpose"]).lower()
    assert "nmap" not in blob and "nuclei" not in blob and "host cli" not in blob


# ---------------------------------------------------------------------------
# B. brain_decision.brain is DERIVED from the brain source, not a frozen literal
# ---------------------------------------------------------------------------

def test_brain_block_derived_from_real_source() -> None:
    brain = api.brain_decision()["brain"]
    assert brain.get("derived") is True
    assert brain.get("available") is True, "the shipped brain source must be locatable + parseable"
    assert brain["name"] == "HexstrikeBrain"          # from the ClassDef, not a literal
    assert brain["propose_only"] is True              # from the class's method set
    assert brain["module"].endswith("hexstrike_brain.py")
    # design credit is PARSED from the module docstring — carries the real, source-only markers
    assert "0x4m4" in (brain["design_credit"] or "") and "MIT" in (brain["design_credit"] or "")
    # the objective vocabulary is derived from the brain's own closed Objective enum
    objs = {o["id"]: o["default"] for o in brain.get("objectives", [])}
    assert objs == {"quick": False, "comprehensive": True}


_FAKE_BRAIN_SRC = '''\
"""fake brain module for the H10 derivation test.

Design credit: FAKE-CREDIT-MARKER-QWERTY — a stand-in credit line for the test.
"""
from enum import Enum


class Objective(str, Enum):
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"


DEFAULT_OBJECTIVE = Objective.QUICK


class HexstrikeBrain:
    def propose(self):
        return []

    def execute(self):   # an offense/execution verb — must flip propose_only to False
        return None
'''


def test_brain_block_tracks_a_different_source(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Conclusive proof of derivation: point the locator at a DIFFERENT source and the block tracks it.

    A frozen literal would keep returning the real credit / propose_only=True / comprehensive-default no
    matter what the source says. Because the values change to match the fake file, the block is derived.
    """
    fake = tmp_path / "hexstrike_brain.py"
    fake.write_text(_FAKE_BRAIN_SRC, encoding="utf-8")
    monkeypatch.setattr(api, "_find_brain_source", lambda: fake)

    brain = api.brain_decision()["brain"]
    assert brain["derived"] is True
    # credit tracks the fake docstring — NOT the real "0x4m4 / MIT" literal
    assert "FAKE-CREDIT-MARKER-QWERTY" in (brain["design_credit"] or "")
    assert "0x4m4" not in (brain["design_credit"] or "")
    # propose_only is COMPUTED from the class methods: an `execute` method makes it False (not frozen True)
    assert brain["propose_only"] is False
    assert brain["propose_evidence"]["has_propose"] is True
    assert any("execute" in m for m in brain["propose_evidence"]["offending_methods"])
    # the default objective tracks the fake enum (QUICK here, COMPREHENSIVE in the real source)
    objs = {o["id"]: o["default"] for o in brain["objectives"]}
    assert objs == {"quick": True, "comprehensive": False}


def test_brain_block_fails_closed_when_source_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No stale literal when the source cannot be found — an honest unavailable, not a frozen claim."""
    monkeypatch.setattr(api, "_find_brain_source", lambda: None)
    brain = api.brain_decision()["brain"]
    assert brain["derived"] is True
    assert brain["available"] is False
    assert brain["name"] is None and brain["propose_only"] is None
    assert brain.get("design_credit") is None
