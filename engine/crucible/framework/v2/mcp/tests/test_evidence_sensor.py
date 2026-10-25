"""
Tests for the external-MCP EVIDENCE connector GLUE — ``mcp.evidence_sensor`` (the slice over Modules
A/B/C): the gated, LEAD-ONLY :class:`MCPEvidenceSensor`, the :func:`build_evidence_sensors` provisioner,
and the :func:`fuse_evidence_sensors` pipeline entry.

The load-bearing invariants pinned here:
  * LEAD, NEVER A FACT. Every entry an external evidence server returns enters the ONE world-model as an
    ``IntelSourceKind.MCP_EVIDENCE`` GROUNDING_INTEL lead — the sensor writes no Finding, promotes
    nothing, and there is NO re-verification step on this axis (promotion is a downstream oracle's job).
  * SUBJECT FIXED BY THE INTEGRATOR. The untrusted remote supplies only ``(kind, name, detail)``; it can
    never plant or redirect to another node (the minter enforces this — re-pinned here through the glue).
  * DOUBLY-GATED, DISJOINT EGRESS. An http evidence sensor carries its host in ``egress_hosts`` so
    ``invoke_tool``'s egress gate refuses it unless the operator ALSO provisioned it in
    ``collector-hosts.txt`` (proven live, end to end), and a host overlapping the charter target scope is
    DROPPED at build time (the disjointness doctrine). A stdio server needs no egress.
  * FAIL-CLOSED / OFF BY DEFAULT. No provisioning ⇒ no sensors, nothing ingested; a remote error / a bad
    arg / a malformed payload mints nothing and never crashes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolRegistry
from framework.v2.agents.tools.base import ToolResult
from framework.v2.common import paths as _paths
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.project import observation_to_finding_payload
from framework.v2.intel.refs import canonicalize
from framework.v2.mcp.evidence_config import EvidenceServer
from framework.v2.mcp.evidence_sensor import (
    MCPEvidenceSensor,
    _safe_entries,
    build_evidence_sensors,
    fuse_evidence_sensors,
)
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import GROUNDING_INTEL, NodeKind, classify_provenance

_SUBJECT = canonicalize(NodeKind.DATASTORE, "orders-db")
_LEAD = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)


class _FakeClient:
    """A fake mcp.client.MCPClient — records each call_tool and returns a canned normalised view."""

    def __init__(self, *, structured=None, ok=True, error=None, raises=None) -> None:
        self._structured = structured if structured is not None else {}
        self._ok = ok
        self._error = error
        self._raises = raises
        self.calls: list[tuple] = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        if self._raises is not None:
            raise self._raises
        if not self._ok:
            return {"ok": False, "is_error": True, "structured": {}, "content": [],
                    "error": self._error or {"code": -1, "message": "boom"}}
        return {"ok": True, "is_error": False, "structured": self._structured, "content": [],
                "error": None}


class _RecSink:
    """A duck-typed spine sink that records refusals so a test can assert WHICH gate refused."""

    def __init__(self) -> None:
        self.refusals: list[tuple[str, str]] = []
        self._id = 0

    def tool_call(self, *a, **k):
        self._id += 1
        return self._id

    def tool_result(self, *a, **k):
        pass

    def refusal(self, gate, label, *, reason="", fatal=False):
        self.refusals.append((gate, reason))


def _sensor(client, remote_tool="dump_schema", **kw):
    return MCPEvidenceSensor("mcp_evidence:orders:dump_schema", client, remote_tool, _SUBJECT, **kw)


def _ctx():
    return ToolContext(slug="alpha")


# =============================================================================
# _safe_entries — the bounded extractor (one firewall is the minter; this only bounds)
# =============================================================================


def test_safe_entries_accepts_the_flat_entries_shape() -> None:
    s = {"entries": [{"kind": "schema_table", "name": "users"},
                     {"kind": "env_key", "name": "DB_PASSWORD", "detail": "sealed"}]}
    assert _safe_entries(s) == s["entries"]


def test_safe_entries_maps_the_convenience_arrays() -> None:
    s = {"tables": ["users", {"name": "orders", "detail": "fact table"}],
         "columns": [{"name": "users.ssn"}],
         "env_keys": ["AWS_SECRET_ACCESS_KEY"],
         "log_events": [{"name": "login_spike", "detail": "src=1.2.3.4"}]}
    out = _safe_entries(s)
    assert {"kind": "schema_table", "name": "users"} in out
    assert {"kind": "schema_table", "name": "orders", "detail": "fact table"} in out
    assert {"kind": "schema_column", "name": "users.ssn"} in out
    assert {"kind": "env_key", "name": "AWS_SECRET_ACCESS_KEY"} in out
    assert {"kind": "log_event", "name": "login_spike", "detail": "src=1.2.3.4"} in out


def test_safe_entries_is_bounded_and_degrades_to_empty() -> None:
    from framework.v2.sensors.base import _MAX_EVIDENCE_ENTRIES
    big = {"columns": [{"name": f"c{i}"} for i in range(_MAX_EVIDENCE_ENTRIES * 2 + 5)]}
    assert len(_safe_entries(big)) == _MAX_EVIDENCE_ENTRIES
    assert _safe_entries(None) == []
    assert _safe_entries({"nope": 1}) == []
    assert _safe_entries({"entries": "not-a-list"}) == []


# =============================================================================
# MCPEvidenceSensor.run / normalize
# =============================================================================


def test_run_then_normalize_mints_one_mcp_evidence_lead_per_entry() -> None:
    client = _FakeClient(structured={"entries": [
        {"kind": "schema_table", "name": "users"},
        {"kind": "schema_column", "name": "users.password_hash", "detail": "bcrypt"},
    ]})
    sensor = _sensor(client)
    res = sensor.run({}, _ctx())
    assert res.ok and res.output["remote_tool"] == "dump_schema"
    obs = sensor.normalize(res, _ctx(), seq=1)
    assert len(obs) == 2
    assert all(o.source_kind is IntelSourceKind.MCP_EVIDENCE for o in obs)
    assert all(o.subject == _SUBJECT for o in obs)
    by_name = {o.attrs["name"]: o for o in obs}
    assert by_name["users.password_hash"].attrs["evidence_kind"] == "schema_column"
    assert by_name["users.password_hash"].attrs["detail"] == "bcrypt"


def test_remote_payload_cannot_change_the_subject_or_forge_a_node() -> None:
    client = _FakeClient(structured={"entries": [
        {"kind": "schema_table", "name": "users", "subject": "host:8.8.8.8",
         "node_id": "domain:evil.example.com", "obs_id": "forged", "confidence": 1.0},
    ]})
    sensor = _sensor(client)
    obs = sensor.normalize(sensor.run({}, _ctx()), _ctx(), seq=1)
    assert len(obs) == 1
    assert obs[0].subject == _SUBJECT and obs[0].obs_id != "forged"
    assert "subject" not in obs[0].attrs and "node_id" not in obs[0].attrs
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(obs, seq=1)
    assert world.has_node(_SUBJECT.node_id)
    assert not world.has_node("host:8.8.8.8") and not world.has_node("domain:evil.example.com")


def test_ingested_output_is_a_lead_never_a_fact() -> None:
    client = _FakeClient(structured={"tables": ["users"]})
    sensor = _sensor(client)
    obs = sensor.normalize(sensor.run({}, _ctx()), _ctx(), seq=1)
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(obs, seq=1)
    node = world.get_node(_SUBJECT.node_id)
    assert node is not None and classify_provenance(node.provenance) == GROUNDING_INTEL
    payload = observation_to_finding_payload(obs[0])
    assert payload["verified_by_oracle"] is False
    assert payload["oracle_context"] is None and payload["oracle_kind"] is None


def test_dry_run_rehearses_without_calling_the_remote() -> None:
    client = _FakeClient(structured={"tables": ["users"]})
    sensor = _sensor(client)
    res = sensor.run({}, ToolContext(slug="alpha", dry_run=True))
    assert res.ok and res.output["entries"] == []
    assert client.calls == []           # no external call under dry-run
    assert sensor.normalize(res, _ctx(), seq=1) == []


def test_remote_args_forwarded_but_must_be_an_object() -> None:
    client = _FakeClient(structured={"tables": ["users"]})
    sensor = _sensor(client)
    sensor.run({"remote_args": {"schema": "public"}}, _ctx())
    assert client.calls[0] == ("dump_schema", {"schema": "public"})
    bad = sensor.run({"remote_args": ["not", "an", "object"]}, _ctx())
    assert bad.ok is False and "remote_args" in bad.note


def test_remote_error_or_exception_mints_nothing() -> None:
    err = _sensor(_FakeClient(ok=False, error={"code": -32001, "message": "db down"}))
    res = err.run({}, _ctx())
    assert res.ok is False and "db down" in res.note
    assert err.normalize(res, _ctx(), seq=1) == []

    boom = _sensor(_FakeClient(raises=RuntimeError("socket reset")))
    res2 = boom.run({}, _ctx())
    assert res2.ok is False and "RuntimeError" in res2.note


def test_normalize_handles_a_failed_result_without_entries() -> None:
    sensor = _sensor(_FakeClient(ok=False))
    assert sensor.normalize(ToolResult(ok=False, note="x"), _ctx(), seq=1) == []


def test_sensor_rejects_bad_construction() -> None:
    c = _FakeClient()
    with pytest.raises(ValueError):
        MCPEvidenceSensor("", c, "t", _SUBJECT)
    with pytest.raises(ValueError):
        MCPEvidenceSensor("n", c, "", _SUBJECT)
    with pytest.raises(ValueError):
        MCPEvidenceSensor("n", object(), "t", _SUBJECT)       # no call_tool
    with pytest.raises(ValueError):
        MCPEvidenceSensor("n", c, "t", "not-an-entityref")     # subject must be an EntityRef


def test_sensor_is_never_destructive() -> None:
    assert _sensor(_FakeClient()).destructive is False


# =============================================================================
# through the REAL gated pipeline (run_sensor -> invoke_tool -> normalize -> ingest)
# =============================================================================


def test_run_sensor_ingests_leads_through_the_full_gate_chain() -> None:
    from framework.v2.sensors.pipeline import run_sensor
    client = _FakeClient(structured={"tables": ["users", "orders"], "env_keys": ["DB_PASSWORD"]})
    sensor = _sensor(client)                       # stdio-style: no egress host, Tier-1 → gate passes
    reg = ToolRegistry()
    reg.register(sensor)
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(reg, sensor.name, {}, _ctx(), ingest=ingest, seq=1)
    assert res.ok and res.applied > 0
    node = world.get_node(_SUBJECT.node_id)
    assert classify_provenance(node.provenance) == GROUNDING_INTEL


# =============================================================================
# build_evidence_sensors — the provisioner
# =============================================================================


@pytest.fixture()
def targets_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A hermetic targets/ root (no global crucible-root cache mutation)."""
    root = tmp_path / "targets"
    (root / "alpha").mkdir(parents=True)
    monkeypatch.setattr(_paths, "target_dir", lambda s: root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: root / s / "charter.md")
    return root


_CHARTER = """\
# Engagement charter — `alpha`

## 1. Operator attestation
Signed: `tester`     Date: `2026-10-25`

## 2. In-scope systems

| Host | Notes | Auth |
|------|-------|------|
| `alpha.example` | Primary | Yes |
"""


def _write(root: Path, name: str, text: str) -> None:
    (root / "alpha" / name).write_text(text, encoding="utf-8")


def test_build_default_empty_when_nothing_provisioned(targets_root: Path) -> None:
    sensors, skipped = build_evidence_sensors("alpha", _SUBJECT)
    assert sensors == [] and skipped == []


def test_build_stdio_server_yields_one_sensor_per_tool_no_egress(targets_root: Path) -> None:
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"schemasrv","transport":"stdio","command":"schema-mcp",'
           '"allowed_tools":["dump_schema","list_env"]}]')
    sensors, skipped = build_evidence_sensors(
        "alpha", _SUBJECT, client_factory=lambda srv: _FakeClient())
    assert skipped == []
    assert {s.name for s in sensors} == {
        "mcp_evidence:schemasrv:dump_schema", "mcp_evidence:schemasrv:list_env"}
    assert all(s.egress_hosts == () and s.tier == "T1" for s in sensors)


def test_build_http_server_carries_its_host_in_egress_hosts(targets_root: Path) -> None:
    _write(targets_root, "charter.md", _CHARTER)
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"logsrv","transport":"http","url":"https://evidence-db.internal:8443/mcp",'
           '"allowed_tools":["query_logs"]}]')
    sensors, skipped = build_evidence_sensors(
        "alpha", _SUBJECT, client_factory=lambda srv: _FakeClient())
    assert skipped == [] and len(sensors) == 1
    assert sensors[0].egress_hosts == ("evidence-db.internal",)


def test_build_skips_a_server_that_declares_no_tools(targets_root: Path) -> None:
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"schemasrv","transport":"stdio","command":"schema-mcp"}]')
    sensors, skipped = build_evidence_sensors(
        "alpha", _SUBJECT, client_factory=lambda srv: _FakeClient())
    assert sensors == []
    assert len(skipped) == 1 and "allowed_tools" in skipped[0]


def test_build_drops_an_http_host_overlapping_the_charter_scope(targets_root: Path) -> None:
    _write(targets_root, "charter.md", _CHARTER)       # scope = alpha.example
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"bad","transport":"http","url":"https://alpha.example/mcp",'
           '"allowed_tools":["query_logs"]}]')
    sensors, skipped = build_evidence_sensors(
        "alpha", _SUBJECT, client_factory=lambda srv: _FakeClient())
    assert sensors == []
    assert len(skipped) == 1 and "disjoint" in skipped[0]


def test_build_drops_a_server_whose_transport_refuses_to_construct(targets_root: Path) -> None:
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"schemasrv","transport":"stdio","command":"schema-mcp","allowed_tools":["t"]}]')

    def _boom(_srv):
        raise ValueError("bad transport")

    sensors, skipped = build_evidence_sensors("alpha", _SUBJECT, client_factory=_boom)
    assert sensors == []
    assert len(skipped) == 1 and "transport could not be constructed" in skipped[0]


def test_default_client_factory_wires_floor_transport_and_out_of_band_token(targets_root: Path) -> None:
    """The PRODUCTION factory (no client_factory stub): an http server MUST get Module C's floor-pinned
    transport with the bearer resolved OUT-OF-BAND from auth_env and held in the Authorization path (the
    transport's _bearer), NEVER in the URL; a stdio server MUST get a subprocess transport with no egress.
    This is the only code wiring gate (b) of the doubly-gated egress + the secret handling — stubbed out
    by every other build/fuse test, so it needs its own coverage."""
    from framework.v2.mcp.client import StdioSubprocessTransport
    from framework.v2.mcp.evidence_transport import FloorPinnedHttpTransport
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"logsrv","transport":"http","url":"https://evidence-db.internal/mcp",'
           '"auth_env":"EV_TOKEN","allowed_tools":["query_logs"]},'
           '{"id":"schemasrv","transport":"stdio","command":"schema-mcp","allowed_tools":["dump"]}]')
    resolved: dict = {}

    def _resolver(name):
        resolved["name"] = name
        return "SECRET-BEARER-xyz"

    sensors, skipped = build_evidence_sensors("alpha", _SUBJECT, token_resolver=_resolver)  # REAL factory
    assert skipped == []
    by = {s.name.split(":")[1]: s for s in sensors}
    http_t = by["logsrv"]._client._transport
    assert isinstance(http_t, FloorPinnedHttpTransport)
    assert resolved["name"] == "EV_TOKEN"            # resolved out-of-band from the env-var NAME
    assert http_t._bearer == "SECRET-BEARER-xyz"     # held for the Authorization header
    assert "SECRET-BEARER-xyz" not in http_t._url    # NEVER in the URL
    assert isinstance(by["schemasrv"]._client._transport, StdioSubprocessTransport)
    assert by["schemasrv"].egress_hosts == ()        # stdio: no egress


# =============================================================================
# fuse_evidence_sensors — the pipeline entry (true-egress e2e, fail-closed)
# =============================================================================


def test_fuse_off_by_default_ingests_nothing(targets_root: Path) -> None:
    world = WorldModel()
    assert fuse_evidence_sensors(world, "alpha", _ctx(), subject=_SUBJECT, seq=1) == 0


def test_fuse_stdio_ingests_leads_lead_only(targets_root: Path) -> None:
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"schemasrv","transport":"stdio","command":"schema-mcp","allowed_tools":["dump"]}]')
    client = _FakeClient(structured={"tables": ["users", "orders"], "columns": [{"name": "users.ssn"}]})
    world = WorldModel()
    applied = fuse_evidence_sensors(
        world, "alpha", _ctx(), subject=_SUBJECT, seq=1, client_factory=lambda srv: client)
    assert applied > 0
    node = world.get_node(_SUBJECT.node_id)
    # LEAD-only: the subject lands as GROUNDING_INTEL, never an oracle-grounded fact, from this path
    assert node is not None and classify_provenance(node.provenance) == GROUNDING_INTEL


def test_fuse_http_passes_only_when_the_host_is_also_in_collector_hosts(targets_root: Path) -> None:
    """The live, end-to-end egress gate: an http evidence sensor runs through ``invoke_tool``, whose
    egress gate builds the engagement allowlist from ``collector-hosts.txt``. With the host provisioned
    there it runs; without it the gate REFUSES before any call — fail-closed."""
    _write(targets_root, "charter.md", _CHARTER)
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"logsrv","transport":"http","url":"https://evidence-db.internal/mcp",'
           '"allowed_tools":["query_logs"]}]')
    structured = {"log_events": [{"name": "failed_login_spike", "detail": "n=42"}]}

    # (a) host NOT provisioned in collector-hosts.txt → egress gate refuses → nothing ingested
    client_a = _FakeClient(structured=structured)
    world_a = WorldModel()
    sink_a = _RecSink()
    applied_a = fuse_evidence_sensors(
        world_a, "alpha", _ctx(), subject=_SUBJECT, seq=1, client_factory=lambda srv: client_a, sink=sink_a)
    assert applied_a == 0
    assert client_a.calls == []                     # the gate refused BEFORE any external call
    assert not world_a.has_node(_SUBJECT.node_id)
    # PROVE it is the EGRESS gate (gate 5) that refused — not an unrelated scope/build failure that would
    # pass the applied==0 check while the collector-hosts egress check was silently defeated.
    assert any(gate == "egress" and "not on charter allowlist" in reason
               for gate, reason in sink_a.refusals), sink_a.refusals

    # (b) same host now provisioned → the gate permits → the lead is ingested
    _write(targets_root, "collector-hosts.txt", "evidence-db.internal\n")
    client_b = _FakeClient(structured=structured)
    world_b = WorldModel()
    applied_b = fuse_evidence_sensors(
        world_b, "alpha", _ctx(), subject=_SUBJECT, seq=1, client_factory=lambda srv: client_b)
    assert applied_b > 0
    assert client_b.calls and client_b.calls[0][0] == "query_logs"
    node = world_b.get_node(_SUBJECT.node_id)
    assert classify_provenance(node.provenance) == GROUNDING_INTEL


def test_fuse_loopback_http_is_reachable_on_config_alone_the_documented_exemption(targets_root: Path) -> None:
    # The ONE documented exemption to the collector-hosts.txt second gate: a loopback evidence server (the
    # operator's own box, which the engine's egress baseline always permits) is reachable with NO
    # collector-hosts.txt entry. Pins the behaviour the docstring states so it cannot silently change.
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"localsrv","transport":"http","url":"http://127.0.0.1:9000/mcp","allowed_tools":["dump"]}]')
    client = _FakeClient(structured={"tables": ["users"]})
    world = WorldModel()
    applied = fuse_evidence_sensors(
        world, "alpha", _ctx(), subject=_SUBJECT, seq=1, client_factory=lambda srv: client)
    assert applied > 0 and client.calls            # reachable on config alone (loopback = the own box)
    assert world.get_node(_SUBJECT.node_id) is not None


def test_fuse_belief_is_order_invariant_across_fresh_worlds(targets_root: Path) -> None:
    # Purity, not mere repeatability: feed the SAME claim set in FORWARD vs REVERSED order across two fresh
    # worlds at the same seq and assert the subject's Beta belief is IDENTICAL — a clock/rng/positional
    # counter on the path would make the two diverge. (Intra-batch DUPLICATE-collapse is proven separately
    # by the minter's own suite, test_evidence_observations; node.attrs is order-sensitive BY DESIGN —
    # documented on the minter — so this asserts belief, the order-invariant quantity.)
    _write(targets_root, "mcp-evidence-servers.json",
           '[{"id":"schemasrv","transport":"stdio","command":"schema-mcp","allowed_tools":["dump"]}]')
    fwd = {"tables": ["users", "orders"], "columns": [{"name": "a"}, {"name": "b"}]}
    rev = {"columns": [{"name": "b"}, {"name": "a"}], "tables": ["orders", "users"]}
    w1 = WorldModel()
    a1 = fuse_evidence_sensors(w1, "alpha", _ctx(), subject=_SUBJECT, seq=5,
                               client_factory=lambda srv: _FakeClient(structured=fwd))
    w2 = WorldModel()
    a2 = fuse_evidence_sensors(w2, "alpha", _ctx(), subject=_SUBJECT, seq=5,
                               client_factory=lambda srv: _FakeClient(structured=rev))
    assert a1 > 0 and a1 == a2
    assert w1.get_node(_SUBJECT.node_id).belief_mean == w2.get_node(_SUBJECT.node_id).belief_mean
