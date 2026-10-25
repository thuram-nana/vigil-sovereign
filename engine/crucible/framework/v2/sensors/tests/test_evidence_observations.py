"""
Tests for ``evidence_observations`` — the SHARED minter for external-MCP EVIDENCE leads
(Module A of the CONSUME-direction evidence connector).

An operator's EXTERNAL MCP server reports a subject's internals — DB schema (tables/columns), an env
keyset, a log stream. That is a THIRD PARTY's say-so, so every entry must enter the ONE world-model as
a provenance-labelled OBSERVATION tagged ``IntelSourceKind.MCP_EVIDENCE`` — a LEAD, NEVER a fact — with
a deterministic claim-keyed ``obs_id``, bounded against an untrusted payload, dropping anything
malformed instead of crashing. These tests pin exactly those invariants on the minter in isolation
(the gated sensor that drives it is a later slice).
"""

from __future__ import annotations

from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.project import observation_to_finding_payload
from framework.v2.intel.refs import EntityRef, canonicalize
from framework.v2.sensors.base import (
    _EVIDENCE_KINDS,
    _MAX_EVIDENCE_ENTRIES,
    _MAX_EVIDENCE_STR,
    evidence_observations,
)
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import GROUNDING_INTEL, NodeKind, classify_provenance

# An external MCP server is a MODERATE-trust source: generally reliable (C) but its specific datum is
# only possibly-true (C3) — a lead to RE-VERIFY, not an oracle proof. Exactly the consumed-tool rating.
_LEAD = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)
_SUBJECT = canonicalize(NodeKind.DATASTORE, "orders-db")


def _mint(entries, *, seq: int = 1, subject: EntityRef = _SUBJECT):
    return evidence_observations(
        subject, entries, seq=seq, source="mcp:evidence:orders",
        source_kind=IntelSourceKind.MCP_EVIDENCE, reliability=_LEAD)


# ---- one LEAD observation per entry, tagged MCP_EVIDENCE -------------------


def test_each_entry_mints_one_lead_observation_tagged_mcp_evidence() -> None:
    entries = [
        {"kind": "schema_table", "name": "users"},
        {"kind": "schema_column", "name": "users.password_hash", "detail": "bcrypt"},
        {"kind": "env_key", "name": "AWS_SECRET_ACCESS_KEY"},
        {"kind": "log_event", "name": "failed_login_spike", "detail": "src=1.2.3.4"},
    ]
    obs = _mint(entries)
    assert len(obs) == 4                                   # exactly one Observation per entry
    assert all(o.source_kind is IntelSourceKind.MCP_EVIDENCE for o in obs)
    # every lead is a NODE claim about the integrator-chosen subject — never an edge, never a new node
    assert all(o.relation is None and o.object is None for o in obs)
    assert all(o.subject == _SUBJECT for o in obs)
    # the per-entry facet is the structured, per-lead payload (what an oracle re-verifies one at a time)
    by_name = {o.attrs["name"]: o for o in obs}
    assert by_name["users"].attrs == {"evidence_kind": "schema_table", "name": "users"}
    assert by_name["users.password_hash"].attrs["detail"] == "bcrypt"
    assert by_name["users.password_hash"].attrs["evidence_kind"] == "schema_column"


def test_output_is_a_lead_never_a_fact() -> None:
    world = WorldModel()
    obs = _mint([{"kind": "schema_table", "name": "users"}])
    IntelIngest(world, engagement_slug="alpha").ingest(obs, seq=1)
    node = world.get_node(_SUBJECT.node_id)
    assert node is not None
    # GROUNDING_INTEL — a lead, never oracle-proof (mirrors every other sensor's observation)
    assert node.provenance.startswith("intel:")
    assert classify_provenance(node.provenance) == GROUNDING_INTEL
    # and it can NEVER be dressed as a fact: the lead → finding adapter carries no oracle grounding
    payload = observation_to_finding_payload(obs[0])
    assert payload["verified_by_oracle"] is False
    assert payload["oracle_context"] is None and payload["oracle_kind"] is None


def test_provenance_is_intel_only_no_oracle_or_cert_grounding() -> None:
    # The minter must set ONLY source_kind for provenance — never fabricate an oracle:/cert: grounding.
    obs = _mint([{"kind": "env_key", "name": "DB_PASSWORD"}])
    assert obs[0].source_kind is IntelSourceKind.MCP_EVIDENCE
    assert obs[0].reliability() == _LEAD.weight()          # C3 lead weight, not a 1.0 proof
    # the Observation model has no oracle/grounding field at all — a lead cannot carry a proof
    assert not hasattr(obs[0], "oracle") and not hasattr(obs[0], "grounding")


# ---- deterministic, claim-keyed obs_id -------------------------------------


def test_obs_ids_are_claim_keyed_so_reorder_and_duplicates_collapse() -> None:
    a = {"kind": "schema_table", "name": "users"}
    b = {"kind": "env_key", "name": "DB_PASSWORD", "detail": "sealed"}
    fwd = {o.obs_id for o in _mint([a, b])}
    rev = {o.obs_id for o in _mint([b, a])}               # reordering yields the SAME id set
    assert fwd == rev
    dup = {o.obs_id for o in _mint([a, a])}               # an intra-batch duplicate collapses
    single = {o.obs_id for o in _mint([a])}
    assert dup == single
    # identical inputs → byte-identical ids across calls (pure: no clock, no rng, no positional index)
    assert [o.obs_id for o in _mint([a, b])] == [o.obs_id for o in _mint([a, b])]


def test_obs_id_distinguishes_kind_and_name_under_the_fixed_subject() -> None:
    # Same name, different kind → distinct claims; same kind, different name → distinct claims.
    obs = _mint([
        {"kind": "schema_table", "name": "sessions"},
        {"kind": "log_event", "name": "sessions"},
        {"kind": "schema_table", "name": "tokens"},
    ])
    assert len({o.obs_id for o in obs}) == 3
    assert all(o.obs_id.startswith("mcp:evidence:orders:1:datastore:orders-db|") for o in obs)


def test_reingest_at_the_same_seq_is_idempotent_no_belief_inflation() -> None:
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    entries = [{"kind": "schema_table", "name": "users"},
               {"kind": "schema_column", "name": "users.email"}]
    r1 = ingest.ingest(_mint(entries, seq=1), seq=1)
    assert r1.applied > 0
    mean_before = world.get_node(_SUBJECT.node_id).belief_mean
    # re-declaring the SAME evidence at the SAME seq must not re-project (deterministic obs_id dedup)
    r2 = ingest.ingest(_mint(list(reversed(entries)), seq=1), seq=1)
    assert r2.applied == 0
    assert world.get_node(_SUBJECT.node_id).belief_mean == mean_before


# ---- untrusted-input firewall: bounded, sanitized, drop-malformed ----------


def test_only_the_four_known_evidence_kinds_survive() -> None:
    assert _EVIDENCE_KINDS == {"schema_table", "schema_column", "env_key", "log_event"}
    good = [{"kind": k, "name": f"n_{k}"} for k in sorted(_EVIDENCE_KINDS)]
    assert len(_mint(good)) == 4
    # an invented kind is not a claim the remote may make
    assert _mint([{"kind": "arbitrary_rce", "name": "pwn"}]) == []


def test_malformed_entries_are_dropped_never_crash() -> None:
    dirty = [
        {"kind": "schema_table", "name": "users"},        # the one good entry
        "not-a-dict",                                      # dropped: not a dict
        {"kind": "schema_table"},                          # dropped: no name
        {"kind": "schema_table", "name": ""},             # dropped: blank name
        {"kind": "schema_table", "name": "   "},          # dropped: whitespace-only name
        {"kind": "schema_table", "name": 1234},           # dropped: non-str name
        {"name": "orphan"},                                # dropped: no kind
        {"kind": "unknown", "name": "x"},                 # dropped: unknown kind
        {"kind": ["schema_table"], "name": "poison"},     # dropped: UNHASHABLE (list) kind — must NOT raise
        {"kind": {"x": 1}, "name": "poison2"},            # dropped: UNHASHABLE (dict) kind — must NOT raise
        None,                                              # dropped: not a dict
        12345,                                             # dropped: not a dict
    ]
    obs = _mint(dirty)
    assert len(obs) == 1 and obs[0].attrs["name"] == "users"
    # an unhashable kind must DROP, never raise (the frozenset membership test is guarded) — an operator's
    # possibly-compromised evidence server cannot void a whole batch with one crafted entry.
    assert _mint([{"kind": ["schema_table"], "name": "x"}, {"kind": "schema_table", "name": "ok"}]) \
        and len(_mint([{"kind": {}, "name": "y"}, {"kind": "env_key", "name": "K"}])) == 1
    # a wholly malformed batch degrades to zero leads — no crash, no guess
    assert _mint(["junk", None, {"kind": "nope"}, {}]) == []
    assert _mint([]) == []


def test_name_and_detail_are_length_bounded_and_stripped() -> None:
    obs = _mint([{"kind": "schema_column", "name": "  " + "n" * 5000 + "  ",
                  "detail": "d" * 5000}])
    assert len(obs) == 1
    assert len(obs[0].attrs["name"]) == _MAX_EVIDENCE_STR    # overlong name clipped
    assert len(obs[0].attrs["detail"]) == _MAX_EVIDENCE_STR  # overlong detail clipped


def test_detail_is_optional_and_only_a_nonblank_string_survives() -> None:
    # absent / non-str / blank detail → no 'detail' key; a real string → carried
    assert "detail" not in _mint([{"kind": "env_key", "name": "A"}])[0].attrs
    assert "detail" not in _mint([{"kind": "env_key", "name": "A", "detail": 99}])[0].attrs
    assert "detail" not in _mint([{"kind": "env_key", "name": "A", "detail": "   "}])[0].attrs
    assert _mint([{"kind": "env_key", "name": "A", "detail": "secret"}])[0].attrs["detail"] == "secret"


def test_entry_count_is_bounded_against_an_untrusted_flood() -> None:
    # A giant remote payload cannot flood intake: only the first _MAX_EVIDENCE_ENTRIES are examined.
    def _flood():
        for i in range(_MAX_EVIDENCE_ENTRIES * 2 + 17):
            yield {"kind": "schema_column", "name": f"col_{i}"}
    obs = _mint(_flood())                                 # also proves any Iterable works, not just list
    assert len(obs) == _MAX_EVIDENCE_ENTRIES
    assert len({o.obs_id for o in obs}) == _MAX_EVIDENCE_ENTRIES   # all distinct, none duplicated


def test_untrusted_entry_cannot_plant_a_node_id_or_off_subject_asset() -> None:
    # The remote supplies only (kind, name, detail); extra keys that look like node ids / subjects are
    # ignored, so an untrusted payload can NEVER redirect a lead off the integrator-chosen subject.
    world = WorldModel()
    obs = _mint([{"kind": "schema_table", "name": "users",
                  "subject": "host:8.8.8.8", "node_id": "domain:evil.example.com",
                  "obs_id": "forged", "source_kind": "scan", "confidence": 1.0}])
    assert len(obs) == 1
    assert obs[0].subject == _SUBJECT                     # bound to the integrator's subject
    assert obs[0].obs_id != "forged" and obs[0].confidence < 1.0
    assert "subject" not in obs[0].attrs and "node_id" not in obs[0].attrs
    IntelIngest(world, engagement_slug="alpha").ingest(obs, seq=1)
    assert not world.has_node("host:8.8.8.8")
    assert not world.has_node("domain:evil.example.com")
    assert world.has_node(_SUBJECT.node_id)
