"""B7 — a cracked credential is absent from EVERY durable artifact of the import path, end to end.

hydra's whole output is a real password for a real account. Two layers were already covered: the parser
masks it in the finding evidence (test_imports.py::test_hydra_password_is_masked_in_the_persisted_evidence),
and the live executor redacts it from the signed ExecRecord (test_live_executor.py). What was NOT covered
is the leg BETWEEN them: parse_hydra_export -> observations_from_imported -> project_observation ->
Node.attrs -> the serialized world-model. ``observations_from_imported`` copies finding fields (including
``evidence``) into a lead's attrs; a field added there later, or a parser edit that stopped masking, would
put the secret into the graph and its serialized record with nothing to catch it.

This walks the whole chain with a fixture that carries a real credential and asserts the secret string
appears in NONE of: the parsed finding, the minted Observations, the projected node/edge attrs, or the
serialized world-model (the durable record). A control asserts the secret IS in the raw input and the
finding IS still graded a real weak-credential — so the test proves masking, not mere dropping.

Offline: no hydra runs. The input is WRITTEN TO hydra 9.7's output shape, not captured from a live run —
a distinction this branch insists on elsewhere and must hold itself to. It is faithful to the format the
parser was built against (and to the captured fixtures in ``test_imports.py``), but an upstream change to
hydra's success line would break the real reader while this file stayed green.
"""

from __future__ import annotations

from framework.v2.imports import import_report
from framework.v2.imports.parsers import parse_hydra_export
from framework.v2.imports.to_observations import observations_from_imported
from framework.v2.intel.models import IntelSourceKind
from framework.v2.intel.project import project_observation
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.store import to_json

# A recorded hydra-9.7 success line. The password is the secret that must never survive into a record.
_SECRET = "hunter2secret"
_LOGIN = "admin"
HYDRA = (
    "Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak\n\n"
    "Hydra starting at 2026-08-14 09:00:00\n"
    "[DATA] max 4 tasks per 1 server, overall 4 tasks, 6 login tries (l:2/p:3), ~2 tries per task\n"
    "[DATA] attacking http-get://127.0.0.1:18821/private\n"
    f"[18821][http-get] host: 127.0.0.1   misc: /private   login: {_LOGIN}   password: {_SECRET}\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
    "Hydra finished at 2026-08-14 09:00:00\n"
)


def test_the_fixture_actually_carries_the_secret():
    """CONTROL. If the raw input did not contain the secret, every absence assertion below would pass
    vacuously — the test would prove nothing. Pin that the secret is really there to be leaked."""
    assert _SECRET in HYDRA


def test_the_finding_is_a_real_weak_credential_but_masks_the_password():
    """CONTROL for 'masking, not dropping'. The parser must still grade this a real weak-credential
    finding — the value it protects is real — while the password is masked out of the evidence."""
    findings = parse_hydra_export(HYDRA)
    assert findings, "the parser dropped the hydra hit entirely"
    hit = findings[0]
    assert hit.bug_class == "weak_credentials" and hit.severity.lower() == "high"
    assert _LOGIN in hit.evidence, "the login (not a secret) should be recorded for the operator"
    assert _SECRET not in hit.evidence, "the password leaked into the finding evidence"


def test_the_secret_is_absent_from_the_minted_observations():
    findings = parse_hydra_export(HYDRA)
    obs = observations_from_imported(findings, source_tool="hydra", source_kind=IntelSourceKind.SCAN, seq=1)
    assert obs, "no observations minted from the hydra finding"
    for o in obs:
        blob = o.model_dump_json()   # the whole observation, attrs and all
        assert _SECRET not in blob, f"the password leaked into an Observation: {o.obs_id}"


def test_the_secret_is_absent_from_the_projected_world_model_and_its_serialized_record():
    findings = parse_hydra_export(HYDRA)
    obs = observations_from_imported(findings, source_tool="hydra", source_kind=IntelSourceKind.SCAN, seq=1)
    world = WorldModel()
    for o in obs:
        project_observation(world, o)
    for n in world.all_nodes():
        assert _SECRET not in n.model_dump_json(), f"the password leaked into node attrs: {n.id}"
    for e in world.all_edges():
        assert _SECRET not in e.model_dump_json(), "the password leaked into an edge"
    # the DURABLE record: the serialized world-model (the spine's persisted graph) must not carry it.
    assert _SECRET not in to_json(world), "the password leaked into the serialized world-model record"


def test_the_secret_is_absent_through_the_wired_import_path():
    """The same guarantee through the high-level ``import_report`` that a real run uses — parse ->
    observations -> ingest into the world-model in one call — so a regression anywhere along the wired
    path (not just the pieces exercised above) is caught."""
    world = WorldModel()
    result = import_report("hydra", HYDRA, world=world)
    assert result.applied > 0, "the wired import applied nothing — the fixture stopped parsing"
    assert _SECRET not in to_json(world), "the password leaked into the world-model via import_report"
    assert _SECRET not in result.model_dump_json(), "the password leaked into the ImportResult"
