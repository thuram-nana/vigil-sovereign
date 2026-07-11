"""
Tests for engage_fusion — fuse GATED sensors into a live engagement's world-model (Workstream B).

``fuse_sensors(world, slug, ctx)`` runs a small set of SAFE, OFFLINE sensors through the existing
gated pipeline (``run_sensor`` -> ``invoke_tool``'s fail-closed chain), folds their observations into
the passed world-model as ``GROUNDING_INTEL`` LEADS, and lets the existing oracles re-verify in-run:
the version-range oracle over SBOM advisories promotes a confirmed LEAD to an ``oracle:``-grounded
FACT. Doctrine under test: everything gated; nothing enters as a FACT without an oracle re-firing;
deterministic + idempotent (caller seq, no wallclock/rng).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.engage_fusion import fuse_sensors
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    GROUNDING_INTEL,
    EdgeKind,
)


# A signed charter listing the declared host in scope — a sensor acting on args['host'] is
# charter-scope-gated, so a minting run needs a real charter (mirrors sensors/tests/test_sensors.py).
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `10.0.0.5` | Declared host | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""

# grype JSON: log4j-core@2.14.1 matched by two CVEs whose ranges (<2.15.0, <2.16.0) BOTH contain
# 2.14.1 — so the version-range oracle CONFIRMS both (the scanner match is a lead; the oracle proves).
_GRYPE = """
{"matches": [
  {"vulnerability": {"id": "CVE-2021-44228"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.15.0 (unknown)"}}]},
  {"vulnerability": {"id": "CVE-2021-45046"},
   "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
   "matchDetails": [{"found": {"versionConstraint": ">=2.0.0,<2.16.0"}}]}
]}
"""

_DECL_ARGS = {"host": "10.0.0.5", "services": [
    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0"},
    {"port": 22, "protocol": "tcp", "state": "closed"},   # closed -> not minted
]}

_PKG_ID = "package:log4j-core@2.14.1"
_VULN_ID = "vulnerability:CVE-2021-44228"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate the per-slug paths to tmp_path and lay down a signed charter for 'alpha'."""
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    td = tmp_path / "alpha"
    td.mkdir(parents=True, exist_ok=True)
    (td / "charter.md").write_text(_CHARTER.format(slug="alpha"), encoding="utf-8")


def _grype_report(tmp_path: Path, text: str = _GRYPE) -> str:
    p = tmp_path / "grype.json"
    p.write_text(text, encoding="utf-8")
    return str(p)


def _ctx(*tasks) -> SimpleNamespace:
    """A minimal caller ctx carrying an explicit fusion plan (WS-A's path)."""
    return SimpleNamespace(fusion_tasks=list(tasks))


# ---- declared_service: LEADs fold into the world, nothing grounded ----------


def test_declared_service_fuses_leads_into_the_world() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "declared_service", "args": _DECL_ARGS}))
    assert minted, "declared_service should mint observations"
    # the HOST + SERVICE + HOSTS structure folded into the PASSED world-model
    assert world.has_node("host:10.0.0.5")
    assert world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    assert not world.has_node("service:10.0.0.5:22/tcp")   # the closed port minted nothing


def test_declared_service_output_is_a_lead_never_a_fact() -> None:
    # No live service-reachability handshake oracle runs offline, so a declared 'open' stays a LEAD:
    # every node fusion produced from this sensor is intel-grounded, none is oracle-grounded.
    world = WorldModel()
    fuse_sensors(world, "alpha", _ctx({"sensor": "declared_service", "args": _DECL_ARGS}))
    assert world.get_node("service:10.0.0.5:443/tcp").grounding == GROUNDING_INTEL
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- sbom: an oracle re-fires in-run and promotes a LEAD to a FACT ----------


def test_sbom_lead_is_promoted_to_a_fact_by_the_version_range_oracle(tmp_path: Path) -> None:
    world = WorldModel()
    report = _grype_report(tmp_path)
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "sbom_vuln", "args": {"report": report}}))
    # the sensor minted the PACKAGE as a LEAD (intel-grounded) — never a confirmed vuln by itself
    assert any(o.subject.node_id == _PKG_ID for o in minted)
    assert world.get_node(_PKG_ID).grounding == GROUNDING_INTEL
    # the version-range oracle re-fired in-run: the vulnerability + AFFECTS edge are oracle-GROUNDED
    vuln = world.get_node(_VULN_ID)
    assert vuln is not None and vuln.grounding == GROUNDING_GROUNDED
    assert vuln.provenance.startswith("oracle:")
    edge = world.get_edge(_VULN_ID, _PKG_ID, EdgeKind.AFFECTS)
    assert edge is not None and edge.grounding == GROUNDING_GROUNDED
    # the promoted FACT is written to the world, NOT returned as a minted observation
    assert all(o.subject.node_id != _VULN_ID for o in minted)


def test_sbom_patched_version_stays_a_lead_no_oracle_no_fact(tmp_path: Path) -> None:
    # A patched version is out of every affected range: the scanner still "matched" (a LEAD) but the
    # oracle REFUSES — so no vulnerability fact is minted. Nothing enters as a fact without an oracle.
    world = WorldModel()
    report = _grype_report(tmp_path, _GRYPE.replace("2.14.1", "2.17.1"))
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "sbom_vuln", "args": {"report": report}}))
    assert any(o.subject.node_id == "package:log4j-core@2.17.1" for o in minted)   # the LEAD
    assert not world.has_node(_VULN_ID)                                            # no fact
    assert all(n.grounding != GROUNDING_GROUNDED for n in world.all_nodes())


# ---- everything gated, fail-closed ------------------------------------------


def test_a_tripped_kill_switch_refuses_every_sensor_and_mints_nothing(tmp_path: Path) -> None:
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("test halt")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}}))
    assert minted == []
    assert world.all_nodes() == []           # gate ran BEFORE any minting or oracle re-verification


def test_an_out_of_scope_declared_host_is_refused_and_mints_nothing() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx(
        {"sensor": "declared_service", "args": {"host": "8.8.8.8", "services": [{"port": 53}]}}))
    assert minted == []
    assert not world.has_node("host:8.8.8.8")


def test_active_sensor_tasks_are_dropped_in_the_first_slice() -> None:
    # An active/live sensor (nmap) is NOT in the offline allowlist: it is dropped before invocation
    # (roadmap), so nothing is minted and no live binary is ever reached.
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", _ctx({"sensor": "nmap", "args": {"target": "10.0.0.5"}}))
    assert minted == []
    assert world.all_nodes() == []


# ---- plan resolution: ctx (attr + dict) and the operator manifest -----------


def test_empty_plan_returns_empty_no_manifest() -> None:
    world = WorldModel()
    assert fuse_sensors(world, "alpha", SimpleNamespace()) == []
    assert world.all_nodes() == []


def test_a_dict_ctx_carrying_a_plan_is_honoured() -> None:
    world = WorldModel()
    minted = fuse_sensors(world, "alpha",
                          {"fusion_tasks": [{"sensor": "declared_service", "args": _DECL_ARGS}]})
    assert minted and world.has_node("host:10.0.0.5")


def test_a_tool_context_ctx_is_accepted(tmp_path: Path) -> None:
    # WS-A may pass a plain ToolContext; fuse still resolves a plan from the manifest fallback.
    (tmp_path / "alpha" / "fusion.json").write_text(
        '[{"sensor": "declared_service", "args": '
        '{"host": "10.0.0.5", "services": [{"port": 443, "protocol": "tcp"}]}}]', encoding="utf-8")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", ToolContext(slug="alpha"))
    assert minted and world.has_node("service:10.0.0.5:443/tcp")


def test_operator_manifest_fallback_is_read(tmp_path: Path) -> None:
    (tmp_path / "alpha" / "fusion.json").write_text(
        '{"tasks": [{"sensor": "sbom_vuln", "args": {"report": "%s"}}]}' % _grype_report(tmp_path),
        encoding="utf-8")
    world = WorldModel()
    minted = fuse_sensors(world, "alpha", SimpleNamespace())   # no ctx plan -> manifest
    assert any(o.subject.node_id == _PKG_ID for o in minted)
    assert world.get_node(_VULN_ID).grounding == GROUNDING_GROUNDED


# ---- determinism + idempotence ----------------------------------------------


def test_fusion_is_deterministic_across_fresh_worlds(tmp_path: Path) -> None:
    plan = _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}})

    def _run():
        w = WorldModel()
        m = fuse_sensors(w, "alpha", plan)
        return [o.obs_id for o in m], sorted((n.id, n.grounding) for n in w.all_nodes())

    ids_a, nodes_a = _run()
    ids_b, nodes_b = _run()
    assert ids_a == ids_b            # identical obs_ids (pure function of caller seq + claim)
    assert nodes_a == nodes_b        # identical world state incl. grounding tiers


def test_re_running_fusion_on_the_same_world_is_idempotent(tmp_path: Path) -> None:
    plan = _ctx(
        {"sensor": "declared_service", "args": _DECL_ARGS},
        {"sensor": "sbom_vuln", "args": {"report": _grype_report(tmp_path)}})
    world = WorldModel()
    fuse_sensors(world, "alpha", plan)
    n_nodes = len(world.all_nodes())
    ids = {n.id for n in world.all_nodes()}
    # re-run: node ids are keyed by claim identity, so a second pass re-asserts the SAME nodes
    # (a legitimate corroboration) — it never spawns duplicate/phantom nodes. Graph shape is stable.
    fuse_sensors(world, "alpha", plan)
    assert len(world.all_nodes()) == n_nodes
    assert {n.id for n in world.all_nodes()} == ids
