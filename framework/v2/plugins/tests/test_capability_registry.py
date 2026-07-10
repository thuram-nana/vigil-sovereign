"""
Tests for the unified capability registry (Wave 6a).

The catalog must be:
  * a DISCOVERED (not hardcoded) view of the live sensor/tool/oracle/operator/CLI
    rosters — a sensor added to ``register_builtin_sensors`` auto-appears;
  * DETERMINISTIC — a pure, sorted, reproducible function of what is installed;
  * READ-ONLY — building it NEVER runs a capability (registration ≠ invocation);
  * EXTENSIBLE — a plugin can register a sensor/oracle/operator through the API
    and it appears, WITHOUT editing core files;
  * ADDITIVE to the CLI — the new subcommand prints the catalog; existing
    subcommands are unchanged.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.plugins import (
    CapabilityDescriptor,
    PluginError,
    PluginRegistry,
    capability_registry,
)
from framework.v2.plugins import cli as plugins_cli
from framework.v2.sensors.builtin import default_registry as sensor_default_registry
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES


# ---------------------------------------------------------------------------
# Discovery of the built-in rosters
# ---------------------------------------------------------------------------


def test_catalog_enumerates_every_installed_sensor_by_discovery() -> None:
    # The catalog is DISCOVERED from the live sensor registry, not a hardcoded list:
    # its sensor set is exactly the registry's names.
    reg = sensor_default_registry()
    cat = capability_registry(plugins=PluginRegistry())
    assert [d.name for d in cat.sensors] == reg.names()
    # the reference roster is present (sanity)
    names = {d.name for d in cat.sensors}
    assert {"declared_service", "nmap", "tshark_flow", "nuclei_web"} <= names
    assert all(d.kind == "sensor" and d.origin == "builtin" for d in cat.sensors)


def test_sensor_gating_metadata_mirrors_declared_attributes() -> None:
    cat = capability_registry(plugins=PluginRegistry())
    by = {d.name: d for d in cat.sensors}
    # a passive reference sensor: Tier 1, no entitlement, degrades cleanly
    ds = by["declared_service"]
    assert ds.tier == "T1"
    assert ds.entitlement is None
    assert ds.destructive is False
    assert ds.degrades_cleanly is True
    # an active sensor: Tier 2, requires the ACTIVE_RECON entitlement
    nmap = by["nmap"]
    assert nmap.tier == "T2"
    assert nmap.entitlement == "active_recon"


def test_internal_tools_group_discovered() -> None:
    cat = capability_registry(plugins=PluginRegistry())
    names = {d.name for d in cat.tools}
    assert "reverify_finding" in names
    assert all(d.kind == "tool" for d in cat.tools)


def test_oracle_catalog_inverts_bug_class_oracles() -> None:
    cat = capability_registry(plugins=PluginRegistry())
    oracles = {d.name: d for d in cat.oracles}
    # every OracleKind is represented as a descriptor
    assert set(oracles) == {k.value for k in OracleKind}
    # achieved_state confirms the access-control classes
    assert {"idor", "bola", "broken_access_control"} <= set(oracles["achieved_state"].produces)
    # every canonical bug_class in the source map appears under at least one oracle
    covered = {bc for d in cat.oracles for bc in d.produces}
    assert set(BUG_CLASS_ORACLES) <= covered
    # produces is sorted (determinism)
    for d in cat.oracles:
        assert list(d.produces) == sorted(d.produces)


def test_operator_catalog_reads_effects_and_intel() -> None:
    cat = capability_registry(plugins=PluginRegistry())
    ops = {d.name: d for d in cat.operators}
    assert "unauth-endpoint-read" in ops
    op = ops["unauth-endpoint-read"]
    assert op.provable_by == ("achieved_state",)
    assert "reachable_from" in op.produces          # from its ASSERT_EDGE effect
    assert "T1190" in op.intel_refs
    # a chained operator that also sets an attr surfaces the attr production
    host = ops["deserialization-to-code-exec"]
    assert any(p.startswith("attr:") for p in host.produces)


def test_commands_group_includes_existing_and_new_subcommands() -> None:
    cat = capability_registry()
    names = {d.name for d in cat.commands}
    # existing subcommands are enumerated ...
    assert {"scan", "engage", "benchmark", "verify", "status"} <= names
    # ... and the new one describes itself
    assert "capabilities" in names


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_catalog_is_deterministic() -> None:
    a = capability_registry(plugins=PluginRegistry()).to_dict()
    b = capability_registry(plugins=PluginRegistry()).to_dict()
    assert a == b
    # byte-stable under sorted JSON
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_every_group_is_name_sorted() -> None:
    cat = capability_registry(plugins=PluginRegistry())
    for _, group in cat.groups():
        assert [d.name for d in group] == sorted(d.name for d in group)


# ---------------------------------------------------------------------------
# Extensibility — a plugin registers and appears (without editing core files)
# ---------------------------------------------------------------------------


class _RecordingSensor:
    """A plugin sensor that FLAGS if its run/normalize is ever called — the probe
    that proves catalog-building is registration, never invocation."""

    name = "plugin_probe"
    tier = "T2"
    capability = None
    destructive = False
    egress_hosts: tuple = ()
    produces = ("HOST", "SERVICE")
    graceful_absent = True

    def __init__(self) -> None:
        self.ran = False

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:  # pragma: no cover - must NOT run
        self.ran = True
        return ToolResult(ok=True)

    def normalize(self, result, ctx, *, seq):  # pragma: no cover - must NOT run
        self.ran = True
        return []


def test_plugin_sensor_appears_in_catalog() -> None:
    plugins = PluginRegistry()
    plugins.register_sensor(_RecordingSensor())
    cat = capability_registry(plugins=plugins)
    d = cat.get("sensor", "plugin_probe")
    assert d is not None
    assert d.origin == "plugin"
    assert d.tier == "T2"
    assert d.produces == ("HOST", "SERVICE")


def test_registration_is_not_invocation() -> None:
    # Build the catalog many ways; the plugin sensor's run/normalize must never fire.
    sensor = _RecordingSensor()
    plugins = PluginRegistry()
    plugins.register_sensor(sensor)
    cat = capability_registry(plugins=plugins)
    _ = cat.to_dict()
    _ = cat.all()
    assert sensor.ran is False


def test_plugin_oracle_bug_class_appears_under_its_kind() -> None:
    plugins = PluginRegistry()
    plugins.register_oracle("cache_poisoning", [OracleKind.DIFFERENTIAL_RESPONSE])
    cat = capability_registry(plugins=plugins)
    diff = cat.get("oracle", "differential_response")
    assert diff is not None
    assert "cache_poisoning" in diff.produces


def test_plugin_operator_appears() -> None:
    from framework.v2.knowledge.catalog import UNAUTH_ENDPOINT_READ

    clone = UNAUTH_ENDPOINT_READ.model_copy(update={"id": "plugin-op-1"})
    plugins = PluginRegistry()
    plugins.register_operator(clone)
    cat = capability_registry(plugins=plugins)
    d = cat.get("operator", "plugin-op-1")
    assert d is not None
    assert d.origin == "plugin"


# ---------------------------------------------------------------------------
# Fail-loud registration contract (mirrors ToolRegistry.register)
# ---------------------------------------------------------------------------


def test_duplicate_plugin_sensor_name_fails_loud() -> None:
    plugins = PluginRegistry()
    plugins.register_sensor(_RecordingSensor())
    with pytest.raises(Exception):
        plugins.register_sensor(_RecordingSensor())


def test_plugin_sensor_shadowing_builtin_fails_loud() -> None:
    class _Shadow:
        name = "nmap"  # collides with the built-in sensor
        tier = "T1"
        capability = None

        def run(self, args, ctx):  # pragma: no cover
            return ToolResult(ok=True)

    plugins = PluginRegistry()
    plugins.register_sensor(_Shadow())
    with pytest.raises(PluginError):
        capability_registry(plugins=plugins)


def test_plugin_oracle_rejects_unknown_kind() -> None:
    plugins = PluginRegistry()
    with pytest.raises(PluginError):
        plugins.register_oracle("whatever", ["not_a_real_oracle_kind"])


def test_plugin_oracle_requires_a_kind() -> None:
    plugins = PluginRegistry()
    with pytest.raises(PluginError):
        plugins.register_oracle("whatever", [])


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_human_output(capsys) -> None:
    rc = plugins_cli.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CRUCIBLE capability catalog" in out
    assert "sensors" in out and "oracles" in out and "operators" in out


def test_cli_json_output_is_valid_and_sorted(capsys) -> None:
    rc = plugins_cli.main(["--json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert "sensors" in parsed and "oracles" in parsed and "counts" in parsed
    # deterministic: re-serialising with sort_keys reproduces the emitted bytes
    assert out.strip() == json.dumps(parsed, indent=2, sort_keys=True)


def test_cli_kind_filter(capsys) -> None:
    rc = plugins_cli.main(["--kind", "sensor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sensors" in out
    # other groups suppressed
    assert "oracles (" not in out


def test_cli_no_commands_flag(capsys) -> None:
    rc = plugins_cli.main(["--no-commands"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "commands (" not in out


# ---------------------------------------------------------------------------
# Additive to the CLI dispatch table
# ---------------------------------------------------------------------------


def test_dispatch_is_additive_and_wired() -> None:
    from framework.v2 import __main__ as m

    # every pre-existing subcommand still present
    expected = {
        "intake", "memory", "intel", "kernel", "entitlement", "eval", "improve",
        "defender", "analysis", "authority", "socialdefense", "scan", "engage",
        "verify", "evidence", "collaborator", "benchmark", "console", "status",
    }
    assert expected <= set(m._DISPATCH)
    # the new one is added, wired to a callable
    assert "capabilities" in m._DISPATCH
    assert callable(m._DISPATCH["capabilities"])


def test_dispatch_capabilities_runs_via_main(capsys) -> None:
    from framework.v2 import __main__ as m

    rc = m.main(["capabilities", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["counts"]["sensors"] >= 1


def test_descriptor_to_dict_shape() -> None:
    d = CapabilityDescriptor(kind="sensor", name="x", tier="T2", entitlement="active_recon")
    got = d.to_dict()
    assert got["kind"] == "sensor" and got["name"] == "x"
    assert got["tier"] == "T2" and got["entitlement"] == "active_recon"
    # entitlement is always present (None == ungated is meaningful)
    d2 = CapabilityDescriptor(kind="sensor", name="y")
    assert d2.to_dict()["entitlement"] is None
