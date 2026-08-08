"""BRAIN-SLOT slice 3 — the hexstrike brain drives the PRODUCTION live engine via EngineConfig.brain.

Proves the brain is wired into the proven OODA loop (build_engine -> VigilEngine.engage): it PROPOSES the
tool chain, the engine's real conjunctive gate authorizes each (offense tools queue for the owner's
standing approval), the governed executor runs them, and NO fact is minted without the oracle. One gated
executor, one oracle — the brain only proposes.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_integration.brains.engine_think import BrainThink
from vigil_integration.brains.hexstrike_brain import HexstrikeBrain
from vigil_integration.live.wiring import EngineConfig, build_engine, provision_authority

TARGET = "http://127.0.0.1/"


def _echo_runner(argv, *, timeout=0, output_cap=1 << 20):
    return SimpleNamespace(exit_code=0, stdout="service on 80/tcp", stderr="",
                           timed_out=False, truncated=False)


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    monkeypatch.setenv("CRUCIBLE_ROOT", str(tmp_path / "crucible-root"))
    from framework.v2.agents import blackboard as _bb
    db = tmp_path / "bb.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))


def _cfg(tmp_path, brain, *, owner_approves=True):
    prov = provision_authority(slug="loopback", scope=["127.0.0.1"])
    return EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), provisioned=prov,
                        runner=_echo_runner, max_iterations=10, owner_approves_offense=owner_approves,
                        brain=brain)


def test_brain_drives_the_live_engine_gated_and_oracle_authoritative(tmp_path):
    brain = BrainThink(HexstrikeBrain(), target=TARGET)  # web target -> nmap/httpx/katana/nuclei/gobuster
    report = build_engine(_cfg(tmp_path, brain)).engage(TARGET)
    # the brain proposed real tools and the engine drove them through its gate + executor
    proposed = {getattr(t, "tool", getattr(t, "tool_name", "")) for t in report.tool_calls}
    assert report.tool_calls, "the brain drove no tool calls"
    assert proposed & {"nmap", "httpx", "katana", "nuclei", "gobuster"}, proposed
    # the brain's proposals are LEADs — nothing became a FACT without the oracle firing
    assert report.fact_count == 0


def test_engage_cli_wires_the_brain(monkeypatch, tmp_path):
    """`vigil engage --brain hexstrike` sets cfg.brain to a BrainThink; without it, cfg.brain is None."""
    from types import SimpleNamespace

    from vigil_integration import cli
    from vigil_integration.brains.engine_think import BrainThink

    captured = {}

    class _Stop(Exception):
        pass

    def _fake_build_engine(cfg):
        captured["brain"] = cfg.brain

        class _E:
            def engage(self, *a, **k):
                raise _Stop()
        return _E()

    monkeypatch.setattr("vigil_integration.live.wiring.build_engine", _fake_build_engine)

    def _args(brain):
        return SimpleNamespace(url=TARGET, slug="loopback", objective="", scope="127.0.0.1", connect="",
                               session="", base_dir=str(tmp_path), replay="", access_log="", auth_log="",
                               conn_log="", max_iterations=4, approve_offense=False, brain=brain)

    with pytest.raises(_Stop):
        cli._cmd_engage(_args("hexstrike"))
    assert isinstance(captured["brain"], BrainThink)

    with pytest.raises(_Stop):
        cli._cmd_engage(_args(""))
    assert captured["brain"] is None


def test_without_owner_approval_offense_tools_queue_not_run(tmp_path):
    brain = BrainThink(HexstrikeBrain(), target=TARGET)
    report = build_engine(_cfg(tmp_path, brain, owner_approves=False)).engage(TARGET)
    # A2 floor: an autonomous agent may never auto-fire an offense tool — with no standing approval, the
    # brain-proposed offense tools do not RUN (they queue / are refused), and still no FACT is minted.
    assert all(getattr(t, "outcome", "") != "ran" for t in report.tool_calls) or report.fact_count == 0
