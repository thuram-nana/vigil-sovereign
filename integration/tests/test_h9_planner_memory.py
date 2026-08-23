"""H9 — bounded adaptive re-planning: the planner-memory KNOWLEDGE layer.

These pin the durable-knowledge invariants of ``brains.planner_memory`` — the deterministic, propose-only
memory the hexstrike planner updates on new observations and re-plans from. The load-bearing property is the
ADMISSION GATE:

    **Unverified model prose NEVER enters durable knowledge as a FACT.**

The module is stdlib-only (no ``framework`` / ``strix`` / ``sigil`` / network), so this whole file runs in
BOTH CI legs — including the sovereign leg where the offense engine is not importable (FATAL-2). It uses the
real ``AgentState`` / ``Finding`` (pydantic, import-clean) so the state shape is exactly the engine's.
"""
from __future__ import annotations

import pytest

from vigil_integration.agent.state import AgentState, Finding
from vigil_integration.brains.hexstrike_brain import AttackStep
from vigil_integration.brains.planner_memory import (
    SCHEMA_VERSION,
    KnowledgeEntry,
    PlannerMemory,
    Verdict,
    observations_from_finding,
)

_PROV_FIELDS = {"source_engagement", "observation_digest", "verdict", "certificate_digest",
                "schema_version", "confidence", "asserted_seq", "stale_after_seq"}


def _fact_state() -> AgentState:
    """A state carrying ONE oracle-confirmed FACT (a signed evidence ref) and ONE unverified LEAD (model
    prose, no evidence). This is exactly the shape the live engine accumulates."""
    st = AgentState(objective="http://target/")
    st.record_lead(Finding(ref="llm:xss", bug_class="xss", title="possible reflected XSS (model prose)",
                           severity="medium", source="llm"))
    st.record_fact(Finding(ref="orc:svc", bug_class="service_reachable",
                           title="443/tcp open; WordPress", severity="info", source="nmap"),
                   evidence_ref="cert:deadbeef")
    return st


# ===================================================================================================
# ADMISSION GATE — the negative control: unverified prose never becomes a FACT
# ===================================================================================================
def test_unverified_prose_never_enters_durable_knowledge_as_a_fact():
    m = PlannerMemory(engagement_slug="eng-1")
    m.ingest_state(_fact_state())

    by_subject = {e.subject: e for e in m.ledger}
    lead_entry = by_subject["finding:llm:xss"]
    fact_entry = by_subject["finding:orc:svc"]

    # the LEAD (unverified prose) is recorded — but as a LEAD, with NO certificate digest, NEVER a fact
    assert lead_entry.verdict == Verdict.LEAD.value, lead_entry.to_dict()
    assert lead_entry.certificate_digest == "", "a lead must carry no certificate digest"

    # the oracle-confirmed finding IS a fact, and it carries the signed evidence ref as its certificate
    assert fact_entry.verdict == Verdict.FACT.value
    assert fact_entry.certificate_digest == "cert:deadbeef"

    # POSITIVE control (non-vacuous): the memory CAN mint a FACT, so the negative result above is real
    assert m.facts(), "the memory admitted no FACT at all — the negative control would be vacuous"
    # and NOTHING derived from the lead is a fact
    assert all(e.verdict != Verdict.FACT.value for e in m.ledger if e.subject == "finding:llm:xss")


def test_admission_gate_refuses_a_fact_with_no_certificate_digest():
    """The gate is enforced at the type, so no code path (ingest, supersede, a direct construction) can mint
    a fact without an oracle certificate."""
    with pytest.raises(ValueError):
        KnowledgeEntry(subject="s", predicate="p", obj="o", verdict=Verdict.FACT.value,
                       source_engagement="e", observation_digest="d", certificate_digest="   ",
                       schema_version=SCHEMA_VERSION, confidence=0.9, asserted_seq=1, stale_after_seq=0)
    # a LEAD with no certificate is fine (that is the whole point)
    KnowledgeEntry(subject="s", predicate="p", obj="o", verdict=Verdict.LEAD.value,
                   source_engagement="e", observation_digest="d", certificate_digest="",
                   schema_version=SCHEMA_VERSION, confidence=0.4, asserted_seq=1, stale_after_seq=5)


def test_a_duck_typed_fact_without_evidence_is_downgraded_to_lead_not_admitted_as_fact():
    """Belt-and-braces: even if a duck-typed 'fact' (status=='fact' but no evidence_ref) reaches ingest —
    a shape ``Finding``'s own validator forbids — it is recorded as a LEAD, never fabricated into a FACT."""
    from types import SimpleNamespace
    m = PlannerMemory(engagement_slug="eng-x")
    bogus = SimpleNamespace(ref="bogus:1", bug_class="rce", title="claims RCE", severity="critical",
                            status="fact", evidence_ref="", source="liar")
    m.ingest_state(SimpleNamespace(objective="x", facts=[bogus], leads=[], execution_trace=[]))
    entry = next(e for e in m.ledger if e.subject == "finding:bogus:1")
    assert entry.verdict == Verdict.LEAD.value, "a fact without a signed evidence ref must NOT be a FACT"
    assert not m.facts(), "no FACT should have been admitted from an evidence-less claim"


# ===================================================================================================
# PROVENANCE / VERDICT / STALENESS — every entry carries the full metadata
# ===================================================================================================
def test_every_knowledge_entry_carries_provenance_verdict_and_staleness():
    m = PlannerMemory(engagement_slug="eng-prov", lead_ttl=6)
    m.ingest_state(_fact_state())
    assert m.ledger
    for e in m.ledger:
        d = e.to_dict()
        assert _PROV_FIELDS <= set(d), (d, _PROV_FIELDS - set(d))
        assert d["entry_id"], "an entry must be content-addressed (entry_id)"
        assert d["source_engagement"] == "eng-prov"
        assert d["observation_digest"], "an entry must record the digest of the observation that minted it"
        assert d["schema_version"] == SCHEMA_VERSION
        assert d["verdict"] in {v.value for v in Verdict}
        assert 0.0 <= d["confidence"] <= 1.0
        assert isinstance(d["asserted_seq"], int) and d["asserted_seq"] >= 1
        assert isinstance(d["stale_after_seq"], int)
    # a FACT never staleness-expires by default; a LEAD carries a finite horizon
    fact = next(e for e in m.ledger if e.verdict == Verdict.FACT.value)
    lead = next(e for e in m.ledger if e.verdict == Verdict.LEAD.value)
    assert fact.stale_after_seq == 0, "a signed FACT must not expire on a timer (it is superseded, not aged)"
    assert lead.stale_after_seq == lead.asserted_seq + 6, "a lead's staleness horizon must be recorded"


def test_staleness_is_a_view_not_a_mutation():
    """A stale LEAD drops out of the live ``current()`` view but STAYS in the immutable ledger."""
    m = PlannerMemory(engagement_slug="eng-stale", lead_ttl=3)
    st = AgentState(objective="x")
    st.record_lead(Finding(ref="l:1", bug_class="info", title="a weak lead"))
    m.ingest_state(st)
    lead = m.ledger[0]
    horizon = lead.stale_after_seq
    assert lead in m.current(at_seq=horizon), "not yet stale at the horizon"
    assert lead not in m.current(at_seq=horizon + 1), "must be stale one step past the horizon"
    assert lead in m.ledger, "staleness must NOT remove the historical entry (immutability)"


# ===================================================================================================
# IMMUTABILITY + SUPERSESSION — historical evidence is append-only, never edited
# ===================================================================================================
def test_supersede_appends_and_never_edits_history():
    m = PlannerMemory(engagement_slug="eng-sup")
    old = m._admit(subject="surface:cms", predicate="is", obj="drupal", verdict=Verdict.LEAD,
                   observation_digest="obs1", certificate_digest="", confidence=0.4, seq=m._next_seq())
    frozen_old = old.to_dict()
    old_id = old.entry_id
    n = len(m.ledger)

    new = m.supersede(old, obj="wordpress")

    assert len(m.ledger) == n + 1, "supersede must APPEND, not edit in place"
    assert m.ledger[0].to_dict() == frozen_old, "the historical entry was mutated — immutability broken"
    assert new.supersedes == old_id, "the superseding entry must name what it replaced"
    live = m.current()
    assert old not in live and new in live, "current() must surface the survivor, not the superseded entry"
    # the whole supersession chain is still reconstructable from the immutable ledger
    assert any(e.entry_id == old_id for e in m.ledger), "the superseded entry must remain in the ledger"


def test_supersede_still_honours_the_admission_gate():
    m = PlannerMemory(engagement_slug="eng-sup2")
    lead = m._admit(subject="s", predicate="p", obj="v", verdict=Verdict.LEAD,
                    observation_digest="o", certificate_digest="", confidence=0.4, seq=m._next_seq())
    with pytest.raises(ValueError):
        m.supersede(lead, obj="v2", verdict=Verdict.FACT, certificate_digest="")  # fact w/o cert → refused


# ===================================================================================================
# FAILED-PATH MEMORY + TOOL-EFFECTIVENESS STATISTICS
# ===================================================================================================
def test_failed_path_is_remembered_and_deprioritized():
    m = PlannerMemory(engagement_slug="eng-fp")
    trace = [
        {"iteration": 1, "action": "use_tool", "tool": "nmap", "outcome": "ran", "facts": 0, "leads": 0},
        {"iteration": 2, "action": "use_tool", "tool": "httpx", "outcome": "ran", "facts": 0, "leads": 3},
        {"iteration": 3, "action": "use_tool", "tool": "gobuster", "outcome": "deny", "reason": "A2 floor"},
    ]
    m.ingest_state(AgentState(objective="x", execution_trace=trace))

    # nmap (ran, no progress) and gobuster (denied) are failed paths; httpx (made progress) is NOT
    assert "nmap" in m.failed_paths and "gobuster" in m.failed_paths
    assert "httpx" not in m.failed_paths

    # effectiveness statistics are accumulated
    assert m.tool_stats["nmap"].no_progress == 1
    assert m.tool_stats["httpx"].leads == 3 and m.tool_stats["httpx"].no_progress == 0
    assert m.tool_stats["gobuster"].denied == 1

    # re-plan DEPRIORITIZES failed paths to the end while preserving base order within each partition
    base = [AttackStep(tool=t, priority=i + 1)
            for i, t in enumerate(["nmap", "httpx", "gobuster", "nuclei"])]
    order = [s.tool for s in m.replan(base)]
    assert order == ["httpx", "nuclei", "nmap", "gobuster"], order


def test_progress_supersedes_an_earlier_failed_path_verdict():
    """A tool that fails once but later makes progress is no longer a failed path (re-rank, not a life
    sentence)."""
    m = PlannerMemory(engagement_slug="eng-fp2")
    m.ingest_state(AgentState(objective="x", execution_trace=[
        {"iteration": 1, "action": "use_tool", "tool": "ffuf", "outcome": "ran", "facts": 0, "leads": 0}]))
    assert "ffuf" in m.failed_paths
    m.ingest_state(AgentState(objective="x", execution_trace=[
        {"iteration": 1, "action": "use_tool", "tool": "ffuf", "outcome": "ran", "facts": 0, "leads": 0},
        {"iteration": 2, "action": "use_tool", "tool": "ffuf", "outcome": "ran", "facts": 0, "leads": 2}]))
    assert "ffuf" not in m.failed_paths, "progress should clear the failed-path verdict"


def test_ingest_is_idempotent_per_observation():
    """The engine calls ingest on every cycle with a GROWING state; a finding/trace row already consumed is
    never double-counted."""
    m = PlannerMemory(engagement_slug="eng-idem")
    st = _fact_state()
    st.execution_trace.append(
        {"iteration": 1, "action": "use_tool", "tool": "nmap", "outcome": "ran", "facts": 0, "leads": 0})
    m.ingest_state(st)
    m.ingest_state(st)  # same state again — nothing new
    assert len(m.ledger) == 2, "re-ingesting the same findings double-counted the ledger"
    assert m.tool_stats["nmap"].ran == 1, "re-ingesting the same trace row double-counted stats"


# ===================================================================================================
# DISCOVERED SURFACES — a new observation re-shapes the profile the next plan is built from
# ===================================================================================================
def test_discovered_surfaces_from_a_fact_augment_the_profile():
    m = PlannerMemory(engagement_slug="eng-surf")
    m.ingest_state(_fact_state())  # the fact's title mentions "443/tcp" and "WordPress"
    aug = m.augment({"target_type": "web_application"})
    assert aug.get("cms_type") == "wordpress", aug
    assert 443 in aug.get("open_ports", []), aug
    # the seed's own value is preserved (union, not overwrite)
    assert aug["target_type"] == "web_application"


def test_augment_is_a_no_op_without_discovered_surfaces():
    """With nothing discovered, augment returns the seed unchanged — so a run with no new observation
    re-plans to the identical chain (build-once preserved as a special case, not a hard-coded branch)."""
    m = PlannerMemory()
    seed = {"target_type": "network_host", "open_ports": [22]}
    assert m.augment(seed) == seed


def test_unrecognised_fingerprint_is_dropped_not_guessed():
    """The surface reducer is conservative: an unknown token yields no observation (honest unknown)."""
    from types import SimpleNamespace
    obs = observations_from_finding(
        SimpleNamespace(bug_class="", title="frobnicator 9000 detected", ref="x", source="s"),
        oracle_confirmed=True)
    assert obs == [], obs


# ===================================================================================================
# DETERMINISM — no wallclock / rng anywhere (the metacognition/RL determinism rule)
# ===================================================================================================
def test_two_identical_ingest_sequences_yield_identical_ledgers_and_digests():
    def build():
        m = PlannerMemory(engagement_slug="det")
        m.ingest_state(_fact_state())
        m.ingest_state(AgentState(objective="x", execution_trace=[
            {"iteration": 1, "action": "use_tool", "tool": "nmap", "outcome": "ran", "facts": 0, "leads": 0}]))
        return m

    a, b = build(), build()
    assert a.world_digest() == b.world_digest()
    assert [e.entry_id for e in a.ledger] == [e.entry_id for e in b.ledger]
    assert a.snapshot() == b.snapshot()


def test_world_digest_is_stable_when_no_new_observation_arrives():
    """The re-plan trigger: the world digest changes ONLY when a new observation materially updates the
    plan's inputs, and is invariant to re-ingesting the same static state (so a static run does not rebuild
    the plan on every idle cycle)."""
    m = PlannerMemory(engagement_slug="stab")
    empty = AgentState(objective="x")
    m.ingest_state(empty)
    d0 = m.world_digest()
    m.ingest_state(empty)
    assert m.world_digest() == d0, "re-ingesting an empty state must not change the world digest"
    m.ingest_state(_fact_state())
    assert m.world_digest() != d0, "a new observation MUST change the world digest (re-plan trigger)"
