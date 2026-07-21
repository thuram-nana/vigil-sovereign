"""F2 §5 C1 — spine-snapshot checkpointing of the ReAct ``AgentState``.

The through-line every test defends: the checkpointer is an APPEND-ONLY, SIGNED, DETERMINISTIC
serialisation of state that replaces redamon's mutable MemorySaver/Postgres — and it can never launder
an unproven claim into a fact. A ``Finding`` in ``AgentState.facts`` round-trips only WITH its signed
``evidence_ref``; a forged snapshot carrying an evidence-less "fact" is un-rebuildable (skipped by the
``Finding`` validator); rebuild is deterministic, total on garbage, and append-only (torn tail → last
good). No wallclock/RNG: the temporal coordinate is the injected ``seq``.
"""

from __future__ import annotations

import json

from vigil_integration.agent.checkpoint import (
    GENESIS_PREV,
    SnapshotRecord,
    head_hash,
    rebuild,
    rebuild_from,
    serialize,
    verify_chain,
    write_checkpoint,
)
from vigil_integration.agent.state import AgentState, Finding, Phase

# --- injected thunks (no live kernel) ---------------------------------------------------------------


def _signer(content_hash: str) -> str:
    """A deterministic stand-in for the SIGIL signed-head signer: a stable ref derived from the hash."""
    return f"sig:{content_hash[:16]}"


def _verifier(content_hash: str, signature_ref: str) -> bool:
    """The matching verifier: a signature is valid iff it is what ``_signer`` would have produced."""
    return signature_ref == f"sig:{content_hash[:16]}"


def _state_with_fact(*, slug="eng-a", evidence_ref="cert:evi-1", seq_phase=Phase.EXPLOITATION):
    """A realistic state: one oracle-confirmed FACT (with a signed evidence ref) + one LEAD + a trace."""
    st = AgentState(engagement_slug=slug, phase=seq_phase, iteration=3, objective="own the box")
    st.record_fact(Finding(ref="f-sqli", bug_class="sqli", title="auth bypass", severity="critical"),
                   evidence_ref=evidence_ref)
    st.record_lead(Finding(ref="l-xss", bug_class="xss", title="reflected xss?", severity="medium",
                           source="zap"))
    st.execution_trace.append({"tool": "sqlmap", "verdict": "new_info"})
    return st


# --- round-trip fidelity ----------------------------------------------------------------------------


def test_roundtrip_preserves_fact_with_its_evidence_ref():
    st = _state_with_fact()
    rec = serialize(st, seq=1, signer=_signer)
    back = rebuild([rec], verify=_verifier)
    assert back.engagement_slug == "eng-a"
    assert back.phase == Phase.EXPLOITATION
    assert back.iteration == 3
    # the FACT survived WITH its signed evidence ref, in the facts store (never the leads store)
    assert [f.ref for f in back.facts] == ["f-sqli"]
    assert back.facts[0].status == "fact"
    assert back.facts[0].evidence_ref == "cert:evi-1"
    assert all(f.ref != "f-sqli" for f in back.leads)


def test_lead_rebuilds_as_lead_never_upgraded():
    st = _state_with_fact()
    back = rebuild([serialize(st, seq=1, signer=_signer)], verify=_verifier)
    assert [ld.ref for ld in back.leads] == ["l-xss"]
    lead = back.leads[0]
    assert lead.status == "lead"
    assert lead.evidence_ref == ""          # a lead carries no evidence ref, before AND after rebuild
    assert all(f.ref != "l-xss" for f in back.facts)   # a lead never lands in facts


def test_full_state_roundtrips_byte_identical():
    st = _state_with_fact()
    back = rebuild([serialize(st, seq=7, signer=_signer)], verify=_verifier)
    assert back.model_dump(mode="json") == st.model_dump(mode="json")


# --- THE SOVEREIGN INVARIANT (the red-pen attacks exactly this) -------------------------------------


def test_SOVEREIGN_INVARIANT_forged_snapshot_cannot_rebuild_an_evidenceless_fact():
    """A fact can NEVER be reconstructed without its signed evidence_ref.

    Attack: an adversary who can write to the spine forges a snapshot whose ``state_json`` claims a
    ``status="fact"`` finding but STRIPS the evidence ref (empty string). To defeat the torn-record and
    signature checks, the forgery is made internally consistent — the content hash is recomputed over the
    tampered state and the record is (re-)signed with a valid signature. The ONLY thing standing between
    the attacker and a laundered fact is the ``Finding`` validator, re-run on rebuild. It must hold: the
    evidence-less fact is un-rebuildable, so it appears in NEITHER facts NOR leads."""
    st = _state_with_fact()
    good = serialize(st, seq=1, signer=_signer)

    # forge: strip the fact's evidence_ref inside the serialised state, keep status="fact"
    payload = json.loads(good.state_json)
    assert payload["facts"][0]["status"] == "fact"
    payload["facts"][0]["evidence_ref"] = ""            # <-- the laundering attempt
    forged_state_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    # recompute a MATCHING content hash + a VALID signature so ONLY the evidence invariant can catch it
    from vigil_integration.agent.checkpoint import _content_hash  # noqa: PLC0415 — white-box attack
    forged_hash = _content_hash(good.seq, good.engagement, good.prev_hash, forged_state_json)
    forged = SnapshotRecord(seq=good.seq, hash=forged_hash, engagement=good.engagement,
                            state_json=forged_state_json, prev_hash=good.prev_hash,
                            signature_ref=_signer(forged_hash))

    # the forged record is intact (hash matches) AND correctly signed (verifier passes) ...
    assert forged.hash == _content_hash(forged.seq, forged.engagement, forged.prev_hash,
                                        forged.state_json)
    assert _verifier(forged.hash, forged.signature_ref) is True
    # ... yet the evidence-less fact is UN-REBUILDABLE — the record is skipped entirely.
    back = rebuild([forged], verify=_verifier)
    assert back.facts == []                             # the laundered fact never materialises
    assert all(f.ref != "f-sqli" for f in back.leads)  # and it is NOT silently downgraded to a lead
    # crash-recovery: with the good record also present, rebuild falls back to it (fact intact)
    back2 = rebuild([good, forged], verify=_verifier)
    assert [f.ref for f in back2.facts] == ["f-sqli"] and back2.facts[0].evidence_ref == "cert:evi-1"


def test_whitespace_evidence_ref_fact_is_also_unrebuildable():
    """The invariant uses ``.strip()`` — a whitespace-only evidence ref is as empty as ``""``."""
    st = _state_with_fact()
    good = serialize(st, seq=1, signer=_signer)
    payload = json.loads(good.state_json)
    payload["facts"][0]["evidence_ref"] = "   \t "
    forged_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    from vigil_integration.agent.checkpoint import _content_hash  # noqa: PLC0415
    h = _content_hash(good.seq, good.engagement, good.prev_hash, forged_json)
    forged = SnapshotRecord(seq=1, hash=h, engagement=good.engagement, state_json=forged_json,
                            prev_hash=good.prev_hash, signature_ref=_signer(h))
    assert rebuild([forged], verify=_verifier).facts == []


def test_forged_fact_with_case_or_lead_status_is_unrebuildable():
    """Finding-1 root-cause regression (the whole class, not one spelling).

    The ``Finding`` validator's evidence guard fires only on the EXACT string ``status == "fact"``. A
    spine-writer who spells the status ``"Fact"``/``"FACT"``/``"fact "``/``" fact"`` — or uses a non-fact
    status ``"lead"``/``"confirmed"``/``"proven"`` — with an empty ``evidence_ref`` slips straight past
    that validator. ``_facts_store_is_sound`` re-checks facts-store MEMBERSHIP on rebuild, so none of these
    can launder an evidence-less finding into the facts store, nor is it silently downgraded to a lead.
    Each forgery is internally consistent (matching content hash + a valid signature) and carries a HIGHER
    seq than the genuine record, so ONLY the facts-store soundness re-check can catch it."""
    from vigil_integration.agent.checkpoint import _content_hash  # noqa: PLC0415 — white-box attack
    st = _state_with_fact()
    good = serialize(st, seq=1, signer=_signer)

    for bad_status in ("Fact", "FACT", "fact ", " fact", "lead", "confirmed", "proven"):
        payload = json.loads(good.state_json)
        payload["facts"] = [{"ref": "f-laundered", "status": bad_status, "evidence_ref": ""}]
        sj = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        h = _content_hash(2, good.engagement, good.hash, sj)   # a LATER, higher-seq forged snapshot
        forged = SnapshotRecord(seq=2, hash=h, engagement=good.engagement, state_json=sj,
                                prev_hash=good.hash, signature_ref=_signer(h))
        # the record is intact AND validly signed — only the soundness re-check stands between it and a fact
        assert _verifier(forged.hash, forged.signature_ref) is True
        back = rebuild([forged], verify=_verifier)
        assert back.facts == [], f"status={bad_status!r} laundered an evidence-less fact into facts"
        assert all(ld.ref != "f-laundered" for ld in back.leads), f"status={bad_status!r} downgraded to a lead"
        # crash-recovery: even though the forgery has the higher seq, rebuild falls back to the genuine fact
        back2 = rebuild([good, forged], verify=_verifier)
        assert [f.ref for f in back2.facts] == ["f-sqli"]
        assert back2.facts[0].evidence_ref == "cert:evi-1"


def test_forged_fact_with_valid_looking_but_case_variant_status_is_rejected():
    """A status variant with a NON-empty (still fabricated) evidence ref is also rejected: the facts store
    admits ONLY the canonical ``status="fact"`` spelling, so no case/whitespace variant is normalised in.
    A genuine round-tripped fact always serialises as exactly ``"fact"``, so this is a pure forgery filter."""
    from vigil_integration.agent.checkpoint import _content_hash  # noqa: PLC0415
    good = serialize(_state_with_fact(), seq=1, signer=_signer)
    payload = json.loads(good.state_json)
    payload["facts"] = [{"ref": "f-x", "status": "Fact", "evidence_ref": "cert:FABRICATED"}]
    sj = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    h = _content_hash(good.seq, good.engagement, good.prev_hash, sj)
    forged = SnapshotRecord(seq=good.seq, hash=h, engagement=good.engagement, state_json=sj,
                            prev_hash=good.prev_hash, signature_ref=_signer(h))
    assert rebuild([forged], verify=_verifier).facts == []


def test_rebuild_denies_by_default_without_verifier_or_optout():
    """Finding-2 root-cause regression: verification is non-optional on the read path.

    A perfectly valid, correctly-signed record is NOT rebuilt when the caller wires neither a verifier nor
    the explicit ``trust_unverified`` opt-out — deny-by-default, symmetric with serialize/write_checkpoint
    forcing ``signer``. A spine-writer can no longer SILENTLY rebuild forged facts off an unauthenticated
    read. State comes back ONLY when a verifier is wired, OR the caller explicitly opts in."""
    st = _state_with_fact()
    rec = serialize(st, seq=1, signer=_signer)

    # no verifier + no opt-out → deny-by-default: a fresh empty state, no facts materialise
    assert rebuild([rec]).model_dump() == AgentState().model_dump()
    assert rebuild_from(lambda: [rec]).model_dump() == AgentState().model_dump()

    # the only two ways to get state back: wire a verifier, or EXPLICITLY opt into trusting the spine
    assert rebuild([rec], verify=_verifier).facts[0].ref == "f-sqli"
    assert rebuild([rec], trust_unverified=True).facts[0].ref == "f-sqli"
    assert rebuild_from(lambda: [rec], verify=_verifier).facts[0].ref == "f-sqli"
    assert rebuild_from(lambda: [rec], trust_unverified=True).facts[0].ref == "f-sqli"


# --- determinism + no wallclock/RNG -----------------------------------------------------------------


def test_serialize_is_deterministic_for_same_seq_and_state():
    st = _state_with_fact()
    a = serialize(st, seq=5, signer=_signer)
    b = serialize(st, seq=5, signer=_signer)
    assert a.model_dump() == b.model_dump()      # byte-identical: no wallclock, no RNG, no uuid
    # a different seq changes the identity (the seq is the only temporal coordinate)
    c = serialize(st, seq=6, signer=_signer)
    assert c.hash != a.hash


def test_rebuild_is_order_independent():
    st1 = _state_with_fact(slug="eng-a")
    st2 = AgentState(engagement_slug="eng-a", phase=Phase.POST_EXPLOITATION, iteration=9)
    r1 = serialize(st1, seq=1, signer=_signer)
    r2 = serialize(st2, seq=2, signer=_signer, prev_hash=r1.hash)
    forward = rebuild([r1, r2], verify=_verifier)
    reverse = rebuild([r2, r1], verify=_verifier)
    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    assert forward.iteration == 9 and forward.phase == Phase.POST_EXPLOITATION   # latest (seq=2) wins


def test_latest_valid_snapshot_wins():
    a = serialize(AgentState(engagement_slug="e", iteration=1), seq=1, signer=_signer)
    b = serialize(AgentState(engagement_slug="e", iteration=2), seq=2, signer=_signer, prev_hash=a.hash)
    c = serialize(AgentState(engagement_slug="e", iteration=3), seq=3, signer=_signer, prev_hash=b.hash)
    assert rebuild([a, b, c], verify=_verifier).iteration == 3


# --- totality on garbage / torn input ---------------------------------------------------------------


def test_rebuild_is_total_on_garbage():
    for junk in (None, [], [None], ["torn", 123, {}, {"seq": "x"}], [{"not": "a snapshot"}]):
        out = rebuild(junk, trust_unverified=True)   # exercise the garbage-totality path, not deny-by-default
        assert isinstance(out, AgentState)
        assert out.facts == [] and out.leads == []      # no signal, fresh empty state, no crash


def test_torn_tail_falls_back_to_last_good_snapshot():
    good = serialize(AgentState(engagement_slug="e", iteration=1), seq=1, signer=_signer)
    # a torn record: its state_json was corrupted AFTER hashing → recomputed hash won't match
    torn = good.model_copy(update={"seq": 2, "state_json": good.state_json + "GARBAGE"})
    back = rebuild([good, torn], verify=_verifier)
    assert back.iteration == 1                           # the torn seq=2 is skipped, seq=1 survives


def test_torn_json_and_nonobject_state_are_skipped():
    from vigil_integration.agent.checkpoint import _content_hash  # noqa: PLC0415
    # a record whose state_json is not even valid JSON, but with a self-consistent hash
    bad_json = "{not json"
    h = _content_hash(1, "e", GENESIS_PREV, bad_json)
    rec = SnapshotRecord(seq=1, hash=h, engagement="e", state_json=bad_json, prev_hash=GENESIS_PREV,
                         signature_ref=_signer(h))
    assert rebuild([rec], verify=_verifier).model_dump() == AgentState().model_dump()


def test_rebuild_accepts_dict_rows_from_a_json_spine_reader():
    st = _state_with_fact()
    rec = serialize(st, seq=1, signer=_signer)
    as_dict = rec.model_dump()
    back = rebuild([as_dict], verify=_verifier)          # a JSON-spine loader hands back dicts
    assert [f.ref for f in back.facts] == ["f-sqli"]


# --- signature: fail-closed signer + verifier-gated rebuild -----------------------------------------


def test_missing_signer_yields_unsigned_record_never_crashes():
    st = _state_with_fact()
    rec = serialize(st, seq=1, signer=None)
    assert rec.signature_ref == ""                      # unsigned, but a well-formed record
    # still rebuildable when no verifier is wired — but ONLY with the explicit trust_unverified opt-out
    assert rebuild([rec], trust_unverified=True).facts[0].ref == "f-sqli"


def test_erroring_signer_is_fail_closed_to_unsigned():
    def boom(_h):
        raise RuntimeError("HSM offline")

    def empty(_h):
        return "   "

    st = _state_with_fact()
    assert serialize(st, seq=1, signer=boom).signature_ref == ""     # exception → unsigned, no crash
    assert serialize(st, seq=1, signer=empty).signature_ref == ""    # empty/whitespace return → unsigned


def test_verifier_rejects_unsigned_and_forged_records():
    st = _state_with_fact()
    unsigned = serialize(st, seq=1, signer=None)
    assert rebuild([unsigned], verify=_verifier).model_dump() == AgentState().model_dump()

    # a record signed with the WRONG signature is rejected when a verifier is wired
    wrong = serialize(st, seq=2, signer=lambda h: "sig:forged", prev_hash=unsigned.hash)
    assert rebuild([wrong], verify=_verifier).model_dump() == AgentState().model_dump()

    # the correctly-signed one passes the same verifier
    good = serialize(st, seq=3, signer=_signer)
    assert rebuild([good], verify=_verifier).facts[0].ref == "f-sqli"


def test_verifier_exception_is_fail_closed():
    st = _state_with_fact()
    good = serialize(st, seq=1, signer=_signer)

    def boom(_h, _s):
        raise RuntimeError("verifier down")

    assert rebuild([good], verify=boom).model_dump() == AgentState().model_dump()


# --- engagement isolation (no cross-store contamination) --------------------------------------------


def test_rebuild_filters_by_engagement():
    a = serialize(_state_with_fact(slug="engagement-a"), seq=5, signer=_signer)
    b = serialize(AgentState(engagement_slug="engagement-b", iteration=99), seq=9, signer=_signer)
    # without a filter, the globally-latest (seq=9, engagement-b) would win — proving the need to filter
    assert rebuild([a, b], verify=_verifier).engagement_slug == "engagement-b"
    # filtering to engagement-a ignores b entirely, even though b has a higher seq
    only_a = rebuild([a, b], engagement="engagement-a", verify=_verifier)
    assert only_a.engagement_slug == "engagement-a"
    assert [f.ref for f in only_a.facts] == ["f-sqli"]


# --- append-only chain: writer, head threading, verify_chain ----------------------------------------


def test_write_checkpoint_appends_via_injected_writer_and_threads_head():
    spine: list[SnapshotRecord] = []
    prev = GENESIS_PREV
    for i in range(1, 4):
        rec = write_checkpoint(AgentState(engagement_slug="e", iteration=i), seq=i, signer=_signer,
                               writer=spine.append, prev_hash=prev)
        prev = rec.hash
    assert len(spine) == 3
    assert verify_chain(spine) is True                  # a contiguous, append-only prev_hash chain
    assert head_hash(spine) == spine[-1].hash           # head = latest record's hash
    assert rebuild(spine, verify=_verifier).iteration == 3


def test_verify_chain_detects_a_broken_link():
    a = serialize(AgentState(engagement_slug="e", iteration=1), seq=1, signer=_signer)
    # seq=2 does NOT chain to a (wrong prev_hash) → the chain is inconsistent
    b = serialize(AgentState(engagement_slug="e", iteration=2), seq=2, signer=_signer,
                  prev_hash="deadbeef")
    assert verify_chain([a, b]) is False
    # but rebuild is TOLERANT of the gap and still returns the latest valid state
    assert rebuild([a, b], verify=_verifier).iteration == 2


def test_head_hash_of_empty_or_garbage_is_genesis():
    assert head_hash([]) == GENESIS_PREV
    assert head_hash(None) == GENESIS_PREV
    assert head_hash([None, "torn"]) == GENESIS_PREV


def test_write_checkpoint_without_writer_returns_record():
    rec = write_checkpoint(AgentState(engagement_slug="e"), seq=1, signer=_signer, writer=None)
    assert isinstance(rec, SnapshotRecord) and rec.seq == 1


# --- rebuild_from: injected reader, total on outage -------------------------------------------------


def test_rebuild_from_reader_reads_and_rebuilds():
    st = _state_with_fact()
    rec = serialize(st, seq=1, signer=_signer)
    back = rebuild_from(lambda: [rec], verify=_verifier)
    assert [f.ref for f in back.facts] == ["f-sqli"]


def test_rebuild_from_is_total_on_reader_outage():
    def boom():
        raise RuntimeError("spine unreachable")

    assert rebuild_from(None).model_dump() == AgentState().model_dump()
    assert rebuild_from(boom).model_dump() == AgentState().model_dump()
    assert rebuild_from(lambda: None).model_dump() == AgentState().model_dump()
    assert rebuild_from(lambda: 12345).model_dump() == AgentState().model_dump()   # non-iterable


# --- no wallclock / RNG anywhere in the module ------------------------------------------------------


def test_module_uses_no_wallclock_or_rng():
    """Spine-safety, checked on the AST (not prose): the module imports NO wallclock/RNG source and
    calls no ``time.``/``random.``/``datetime.``/``uuid.``/``secrets.`` API — the only temporal
    coordinate is the injected ``seq``."""
    import ast
    import inspect

    import vigil_integration.agent.checkpoint as cp

    banned = {"time", "random", "datetime", "uuid", "secrets"}
    tree = ast.parse(inspect.getsource(cp))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not (banned & {n.name.split(".")[0] for n in node.names}), "imports a wallclock/RNG"
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in banned, "imports from a wallclock/RNG module"
        # no attribute call into a banned module either (e.g. time.time(), datetime.now())
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id not in banned, f"calls into {node.value.id} (wallclock/RNG)"


def test_load_state_total_on_deeply_nested_json():
    # RE-CHECK MEDIUM: deeply-nested JSON raises RecursionError (a RuntimeError, not ValueError) — the
    # loader must SKIP the torn record (return None), never crash the whole rebuild.
    from vigil_integration.agent.checkpoint import _load_state
    deep = "[" * 20000 + "]" * 20000
    assert _load_state(deep) is None


def test_forged_fact_in_leads_is_normalized_to_a_lead():
    # RE-CHECK LOW: a forged status="fact" smuggled into leads[] must not masquerade as a fact on rebuild.
    from vigil_integration.agent.checkpoint import _load_state
    forged = json.dumps({"engagement_slug": "x", "facts": [],
                         "leads": [{"ref": "z", "status": "fact", "evidence_ref": "forged"}]})
    st = _load_state(forged)
    assert st is not None and len(st.leads) == 1
    assert st.leads[0].status == "lead" and st.leads[0].evidence_ref == ""
    assert st.facts == []   # the forged fact never entered the facts store


def test_rebuild_total_on_a_lazy_reader_that_raises_mid_iteration():
    # RE-CHECK MEDIUM (whole-class): a lazy generator reader hitting a torn tail (JSONDecodeError — a
    # ValueError, not a TypeError) mid-iteration must NOT crash rebuild/rebuild_from/head_hash/verify_chain.
    # The walk stops at the last good record (append-only torn-tail semantics); the good prefix survives.
    import json as _json

    good = serialize(AgentState(engagement_slug="e"), seq=0, prev_hash=GENESIS_PREV, signer=_signer)

    def torn():
        yield good
        raise _json.JSONDecodeError("torn tail", "partial", 0)

    assert rebuild(torn(), trust_unverified=True).engagement_slug == "e"          # good prefix recovered
    assert rebuild_from(reader=torn, trust_unverified=True).engagement_slug == "e"
    head_hash(torn())        # must not raise
    assert verify_chain(torn()) in (True, False)   # must not raise


def test_rebuild_total_on_a_reader_whose_iter_or_len_raises():
    # RE-CHECK MEDIUM (whole class): the raise can happen in the funnel PREAMBLE too — a re-iterable
    # file-backed reader that opens the spine in __iter__ and fails (OSError), or whose __bool__/__len__
    # raises. Every consumer must degrade to the empty state, never propagate.
    class IterRaises:            # a lazy reader that fails to open the spine at iter() time
        def __iter__(self):
            raise OSError(9, "Bad file descriptor")

    class LenRaises:             # __len__ raises at the `if not records` truthiness check
        def __len__(self):
            raise RuntimeError("boom")

        def __iter__(self):
            return iter([])

    for bad in (IterRaises(), LenRaises()):
        assert rebuild(bad, trust_unverified=True).engagement_slug == ""      # empty state, no crash
        assert rebuild_from(reader=lambda b=bad: b, trust_unverified=True).engagement_slug == ""
        head_hash(bad)                       # must not raise
        assert verify_chain(bad) in (True, False)
