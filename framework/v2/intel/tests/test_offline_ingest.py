"""
Offline asset-graph ingestion (P4): operator-provided cloud/IAM inventory and SBOM
projected onto the world-model. The cloud adapter mints the exact PRINCIPAL / resource
nodes + CAN_ASSUME / MEMBER_OF / HAS_GRANT edges the existing IAM chaining operators
consume; the SBOM adapter builds the PACKAGE / DEPENDS_ON dependency graph. Both are
total (malformed input never raises) and idempotent (deterministic obs_ids).
"""

from __future__ import annotations

from framework.v2.intel.from_cloud import observations_from_cloud
from framework.v2.intel.from_sbom import observations_from_sbom
from framework.v2.intel.ingest import IntelIngest
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind, NodeKind


# ---- cloud / IAM ------------------------------------------------------------


_CLOUD = {
    "principals": [
        {"id": "role/dev", "kind": "role", "can_assume": ["role/admin"], "member_of": ["group/eng"]},
        {"id": "role/admin", "kind": "role"},
    ],
    "resources": [
        {"id": "s3/customer-data", "kind": "datastore", "grants": [{"principal": "role/admin", "access": "read"}]},
    ],
}


def test_cloud_mints_iam_nodes_and_edges() -> None:
    obs = observations_from_cloud(_CLOUD, seq=1)
    edges = {(o.subject.node_id, o.relation, o.object.node_id) for o in obs if o.relation}
    assert (("principal:role/dev", EdgeKind.CAN_ASSUME, "principal:role/admin")) in edges
    assert (("principal:role/dev", EdgeKind.MEMBER_OF, "principal:group/eng")) in edges
    assert (("principal:role/admin", EdgeKind.HAS_GRANT, "datastore:s3/customer-data")) in edges


def test_cloud_projects_onto_worldmodel_for_iam_chaining() -> None:
    world = WorldModel()
    IntelIngest(world).ingest(observations_from_cloud(_CLOUD, seq=1))
    # the graph now carries the CAN_ASSUME / HAS_GRANT structure the operators chain over
    assert world.get_node("principal:role/dev") is not None
    assert world.get_edge("principal:role/dev", "principal:role/admin", EdgeKind.CAN_ASSUME) is not None
    assert world.get_edge("principal:role/admin", "datastore:s3/customer-data", EdgeKind.HAS_GRANT) is not None


# ---- supply-chain / SBOM ----------------------------------------------------


def test_sbom_normalized_builds_dependency_graph() -> None:
    sbom = {"application": "myapp", "packages": [
        {"name": "lodash", "version": "4.17.20", "depends_on": ["ms@2.1.2"]},
        {"name": "ms", "version": "2.1.2"}]}
    obs = observations_from_sbom(sbom, seq=1)
    ids = {o.subject.node_id for o in obs} | {o.object.node_id for o in obs if o.object}
    assert "package:lodash@4.17.20" in ids and "package:ms@2.1.2" in ids
    deps = {(o.subject.node_id, o.object.node_id) for o in obs if o.relation is EdgeKind.DEPENDS_ON}
    assert ("application:myapp", "package:lodash@4.17.20") in deps
    assert ("package:lodash@4.17.20", "package:ms@2.1.2") in deps


def test_sbom_cyclonedx_shape() -> None:
    cdx = {"components": [{"name": "left-pad", "version": "1.0.0", "bom-ref": "a"},
                          {"name": "core", "version": "2.0.0", "bom-ref": "b"}],
           "dependencies": [{"ref": "b", "dependsOn": ["a"]}]}
    obs = observations_from_sbom(cdx, seq=1)
    deps = {(o.subject.node_id, o.object.node_id) for o in obs if o.relation is EdgeKind.DEPENDS_ON}
    assert ("package:core@2.0.0", "package:left-pad@1.0.0") in deps


def test_adapters_are_total_on_garbage() -> None:
    for junk in (None, 42, "x", {}, {"principals": "bad"}, {"packages": [1, 2, {"noname": 1}]}):
        assert observations_from_cloud(junk) == [] or isinstance(observations_from_cloud(junk), list)
        assert isinstance(observations_from_sbom(junk), list)


def test_offline_ingest_is_idempotent() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    obs = observations_from_cloud(_CLOUD, seq=1)
    ing.ingest(obs)
    n1, e1 = world.node_count, world.edge_count
    ing.ingest(obs)   # same obs_ids → no-op
    assert (world.node_count, world.edge_count) == (n1, e1)
