"""F7 chainast — a typed, reversible AST over a reasoning/tool-call chain + append-only, signature-safe
compaction. The through-line every test defends (the sovereign invariant the red-pen attacks):

  * parse → render is BYTE-IDENTICAL (a re-executable projection; anyone re-derives the same bytes);
  * compaction is APPEND-ONLY (a new Summarization record cites the [start, end] Merkle range it covers;
    the originals are never mutated or deleted);
  * the most-recent body-pair (latest thinking+tool block) is NEVER summarized — even under an
    adversarial config (protects Claude extended-thinking signatures);
  * a summary node is NON-AUTHORITATIVE (veracity SUMMARY, never FACT), even if its records lie;
  * everything is TOTAL on malformed input and DETERMINISTIC (no wallclock/RNG in a spine artifact).
"""

from __future__ import annotations

import hashlib

import pytest

from vigil_integration.chainast import (
    SUMMARIZATION_TOOL_NAME,
    SUMMARIZED_CONTENT_PREFIX,
    BodyPairType,
    ChainRecord,
    MessageRole,
    SummarizerConfig,
    SummaryCitation,
    ToolCallSpec,
    Veracity,
    assemble_compacted,
    compact,
    from_canonical_bytes,
    is_summarized,
    merkle_root,
    normalize,
    parse,
    plan_compaction,
    record_bytes,
    render,
    repair,
    to_canonical_bytes,
    validate,
)

# --- builders -----------------------------------------------------------------------------------


def _rec(seq, role, **kw):
    return ChainRecord(seq=seq, role=role, **kw)


def _sys(seq, content="system-prompt"):
    return _rec(seq, MessageRole.SYSTEM, content=content)


def _human(seq, content="question"):
    return _rec(seq, MessageRole.HUMAN, content=content)


def _ai(seq, content="", thinking="", sig="", tool_calls=None, **kw):
    return _rec(seq, MessageRole.AI, content=content, thinking=thinking, thinking_signature=sig,
               tool_calls=tool_calls or [], **kw)


def _tool(seq, tcid, content="tool-output", name="scan", **kw):
    return _rec(seq, MessageRole.TOOL, tool_call_id=tcid, content=content, name=name, **kw)


def _tc(cid, name="scan", args=None):
    return ToolCallSpec(id=cid, name=name, args=args or {})


def _rich_chain():
    """A two-section chain: system+human header, a request/response pair with a Claude thinking
    signature, a completion, then a new human turn with another request/response pair."""
    return [
        _sys(0), _human(1),
        _ai(2, thinking="think-A", sig="sig-A", tool_calls=[_tc("c1", "nmap", {"target": "10.0.0.1"})]),
        _tool(3, "c1", "22/open 80/open"),
        _ai(4, content="the host exposes ssh + http"),
        _human(5, "escalate"),
        _ai(6, thinking="think-B", sig="sig-B", tool_calls=[_tc("c2", "curl")]),
        _tool(7, "c2", "200 OK"),
    ]


# --- 1. lossless byte-identical round-trip (the re-executable projection) ------------------------


def test_roundtrip_is_byte_identical():
    records = _rich_chain()
    ast = parse(records)
    rendered = render(ast)
    assert rendered == records                                    # order + every field preserved
    assert to_canonical_bytes(rendered) == to_canonical_bytes(records)


def test_roundtrip_reexecutes_from_raw_canonical_bytes():
    records = _rich_chain()
    data = to_canonical_bytes(records)
    # anyone holding the signed span re-derives the same bytes through the full pipeline
    recovered = from_canonical_bytes(data)
    assert to_canonical_bytes(render(parse(recovered))) == data


def test_roundtrip_preserves_unicode_and_nested_tool_args():
    records = [
        _sys(0, "sürvëy — 日本語"), _human(1, "q\nwith\nnewlines"),
        _ai(2, tool_calls=[_tc("c1", "x", {"z": 1, "a": {"nested": [3, 2, 1]}})]),
        _tool(3, "c1", "résultat ✓"),
    ]
    assert render(parse(records)) == records
    # canonical bytes are stable regardless of dict key insertion order
    reordered = [
        _sys(0, "sürvëy — 日本語"), _human(1, "q\nwith\nnewlines"),
        _ai(2, tool_calls=[_tc("c1", "x", {"a": {"nested": [3, 2, 1]}, "z": 1})]),
        _tool(3, "c1", "résultat ✓"),
    ]
    assert to_canonical_bytes(records) == to_canonical_bytes(reordered)
    assert record_bytes(records[0]) == record_bytes(_sys(0, "sürvëy — 日本語"))


def test_empty_chain_roundtrips():
    assert render(parse([])) == []
    assert to_canonical_bytes([]) == b""
    assert from_canonical_bytes(b"") == []


# --- 2. structure ------------------------------------------------------------------------------


def test_section_and_bodypair_structure():
    ast = parse(_rich_chain())
    assert len(ast.sections) == 2
    s0, s1 = ast.sections
    assert s0.header.system is not None and s0.header.human is not None
    assert [bp.pair_type for bp in s0.body_pairs] == [
        BodyPairType.REQUEST_RESPONSE, BodyPairType.COMPLETION]
    assert s1.header.system is None and s1.header.human is not None
    assert len(s1.body_pairs) == 1
    # the most-recent body-pair is the last section's last pair
    last = ast.last_body_pair()
    assert last is s1.body_pairs[-1]
    assert last.ai is not None and last.ai.thinking_signature == "sig-B"


# --- 3. totality on malformed / hostile chains (still lossless) ---------------------------------


def test_parse_is_total_and_lossless_on_malformed_chains():
    cases = [
        [_tool(0, "orphan")],                                   # orphan tool response, no AI/header
        [_human(0), _human(1), _ai(2)],                         # consecutive humans
        [_human(0), _ai(1), _sys(2, "mid"), _human(3), _ai(4)],  # mid-chain system
        [_ai(0), _ai(1), _tool(2, "c")],                        # AI with no header, then orphan-ish tool
    ]
    for records in cases:
        ast = parse(records)                                    # never raises
        assert render(ast) == records                           # lossless regardless of validity


def test_parse_and_normalize_are_total_on_garbage():
    junk = [None, 123, "a string", {"role": "not-a-role"}, {"no": "role"},
            _sys(0), {"seq": 1, "role": "human", "content": "ok"}]
    recs = normalize(junk)
    assert [r.role for r in recs] == [MessageRole.SYSTEM, MessageRole.HUMAN]  # only valid survive
    assert render(parse(junk)) == recs                          # no crash, drops garbage
    assert parse(None).sections == [] and parse("string").sections == []


def test_from_canonical_bytes_recovers_only_valid_lines():
    good = to_canonical_bytes([_sys(0), _human(1)])
    tampered = b"not json\n" + good + b"\n{bad json"
    recovered = from_canonical_bytes(tampered)
    assert [r.role for r in recovered] == [MessageRole.SYSTEM, MessageRole.HUMAN]


# --- 4. veracity tags (FACT / LEAD / SUMMARY) --------------------------------------------------


def test_confirmed_toolresponse_makes_a_fact_pair():
    records = [_sys(0), _human(1),
               _ai(2, tool_calls=[_tc("c1")]),
               _tool(3, "c1", status="fact", evidence_ref="cert:1", signature_ref="sig:1"),
               _ai(4, content="done")]
    ast = parse(records)
    fact_pair = ast.sections[0].body_pairs[0]
    assert fact_pair.veracity == Veracity.FACT and fact_pair.is_fact


def test_unconfirmed_pair_is_a_lead():
    records = [_sys(0), _human(1), _ai(2, tool_calls=[_tc("c1")]), _tool(3, "c1", status="lead")]
    pair = parse(records).sections[0].body_pairs[0]
    assert pair.veracity == Veracity.LEAD and not pair.is_fact


def test_claimed_fact_without_signed_evidence_is_a_lead():
    # a record can CLAIM status="fact" but with no signed evidence_ref/signature_ref it is NOT confirmed
    records = [_sys(0), _human(1), _ai(2, tool_calls=[_tc("c1")]),
               _tool(3, "c1", status="fact")]                    # no evidence_ref/signature_ref
    pair = parse(records).sections[0].body_pairs[0]
    assert pair.veracity == Veracity.LEAD and not pair.is_fact


# --- 5. validation + repair (pentagi invariants; total) ----------------------------------------


def test_validate_clean_chain_ok():
    assert validate(_rich_chain()).ok


def test_validate_flags_each_invariant_violation():
    assert not validate([_tool(0, "x")]).ok                     # must open with system/human
    assert not validate([_human(0), _human(1)]).ok              # consecutive humans
    assert not validate([_human(0), _ai(1), _sys(2)]).ok        # mid-chain system
    assert not validate([_sys(0), _human(1), _ai(2, tool_calls=[_tc("c1")])]).ok  # unanswered call
    assert not validate([_sys(0), _human(1), _tool(2, "ghost")]).ok  # response to unknown call


def test_validate_accepts_ast_or_records_and_never_raises():
    rep = validate(parse(_rich_chain()))
    assert rep.ok and rep.issues == []
    assert validate(None).ok and validate(12345).ok             # total on garbage


def test_repair_makes_a_malformed_chain_valid():
    broken = [_human(0, "a"), _human(1, "b"), _ai(2, tool_calls=[_tc("c1"), _tc("c2")])]
    repaired = repair(broken)
    assert validate(repaired).ok                                # merged humans + injected responses
    tool_responses = [r for r in repaired if r.role == MessageRole.TOOL]
    assert {r.tool_call_id for r in tool_responses} == {"c1", "c2"}
    assert repair([None, 123]) == []                            # total on garbage


# --- 6. Merkle range commitment ----------------------------------------------------------------


def test_merkle_root_is_deterministic_orderindependent_and_rederivable():
    recs = _rich_chain()
    root = merkle_root(recs)
    assert root == merkle_root(list(reversed(recs)))            # sorted internally → order-independent
    assert root == merkle_root([r.model_copy() for r in recs])  # value-equal set → same commitment
    assert merkle_root(recs + [_ai(99)]) != root               # a different set → a different root
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()   # RFC-6962 empty tree


# --- 7. compaction planning (preserve-last + idempotency + budget) -----------------------------


def test_plan_preserves_last_section_and_covers_older_ones():
    ast = parse(_rich_chain())                                  # 2 sections
    plan = plan_compaction(ast, SummarizerConfig(keep_last_sections=1))
    assert plan.eligible
    assert set(plan.covered_seqs) == {0, 1, 2, 3, 4}            # section 0 only
    assert plan.start_seq == 0 and plan.end_seq == 4
    # the most-recent body-pair (seqs 6,7) is never in the covered range
    assert 6 not in plan.covered_seqs and 7 not in plan.covered_seqs


def test_plan_no_op_when_everything_preserved():
    ast = parse(_rich_chain())
    assert not plan_compaction(ast, SummarizerConfig(keep_last_sections=5)).eligible


def test_plan_below_trigger_bytes_is_no_op():
    ast = parse(_rich_chain())
    huge = SummarizerConfig(keep_last_sections=1, trigger_bytes=10_000_000)
    assert not plan_compaction(ast, huge).eligible


# --- 8. compaction is append-only, deterministic, secret-free ----------------------------------


def _fixed_handler(_prompt):
    return "prior recon found ssh+http on the host"


def test_compact_is_append_only_and_cites_the_merkle_range():
    records = _rich_chain()
    ast = parse(records)
    before = to_canonical_bytes(render(ast))
    result = compact(ast, SummarizerConfig(keep_last_sections=1), handler=_fixed_handler, seq=100)
    assert result.summarized
    # APPEND-ONLY: the AST and its rendered bytes are untouched by compaction
    assert to_canonical_bytes(render(ast)) == before
    # the citation cites the exact covered range + a re-derivable Merkle root over the ORIGINALS
    cit = result.citation
    assert (cit.covered_start_seq, cit.covered_end_seq, cit.covered_count) == (0, 4, 5)
    originals = [r for r in records if r.seq in set(result.covered_seqs)]
    assert cit.merkle_root == merkle_root(originals)            # anyone re-derives it from signed source
    # the new records are a Summarization pair beyond the covered range
    assert [r.seq for r in result.summary_records] == [100, 101]
    assert all(r.kind == "Summarization" for r in result.summary_records)


def test_compact_summary_is_non_authoritative_summary_never_fact():
    ast = parse(_rich_chain())
    result = compact(ast, SummarizerConfig(keep_last_sections=1), handler=_fixed_handler, seq=100)
    # re-parse the emitted Summarization pair; it must tag SUMMARY, never FACT
    summ_ast = parse(result.summary_records)
    pair = summ_ast.sections[0].body_pairs[0]
    assert pair.pair_type == BodyPairType.SUMMARIZATION
    assert pair.veracity == Veracity.SUMMARY and not pair.is_fact
    assert is_summarized(pair)


def test_compact_redacts_secrets_from_the_summary_text():
    def leaky_handler(_prompt):
        return "creds were Authorization: Bearer SECRETTOKEN123456 and api_key=SUPERSECRETVALUE"
    ast = parse(_rich_chain())
    result = compact(ast, SummarizerConfig(keep_last_sections=1), handler=leaky_handler, seq=100)
    body = next(r for r in result.summary_records if r.role == MessageRole.TOOL).content
    assert body.startswith(SUMMARIZED_CONTENT_PREFIX)
    assert "SECRETTOKEN123456" not in body and "SUPERSECRETVALUE" not in body
    assert "••••" in body                                       # scrubbed via the single F3 path


def test_compact_is_deterministic():
    ast = parse(_rich_chain())
    cfg = SummarizerConfig(keep_last_sections=1)
    r1 = compact(ast, cfg, handler=_fixed_handler, seq=100)
    r2 = compact(ast, cfg, handler=_fixed_handler, seq=100)
    assert to_canonical_bytes(r1.summary_records) == to_canonical_bytes(r2.summary_records)
    assert r1.citation == r2.citation and r1.covered_seqs == r2.covered_seqs


def test_compact_fail_closed_paths_mint_nothing():
    ast = parse(_rich_chain())
    cfg = SummarizerConfig(keep_last_sections=1)

    def raising(_p):
        raise RuntimeError("summarizer down")

    assert not compact(ast, cfg, handler=None, seq=100).summarized          # no handler wired
    assert not compact(ast, cfg, handler=raising, seq=100).summarized       # handler raises
    assert not compact(ast, cfg, handler=lambda _p: 123, seq=100).summarized  # non-str return
    assert not compact(ast, cfg, handler=lambda _p: "   ", seq=100).summarized  # empty/whitespace
    # append-only: seq must be a FRESH index strictly beyond the covered range (end_seq == 4)
    assert not compact(ast, cfg, handler=_fixed_handler, seq=4).summarized
    assert not compact(ast, cfg, handler=_fixed_handler, seq=True).summarized  # bool is not a seq


def test_compacted_context_replaces_covered_and_keeps_the_tail_verbatim():
    records = _rich_chain()
    ast = parse(records)
    result = compact(ast, SummarizerConfig(keep_last_sections=1), handler=_fixed_handler, seq=100)
    view = assemble_compacted(ast, result)
    seqs = [r.seq for r in view]
    assert seqs == [100, 101, 5, 6, 7]                          # summary + preserved tail
    covered = set(result.covered_seqs)
    assert not (covered & set(seqs))                            # no covered original leaks into context
    # the most-recent body-pair survives verbatim, thinking signature intact
    tail = {r.seq: r for r in view}
    assert tail[6].thinking_signature == "sig-B" and tail[7].content == "200 OK"


def test_compaction_is_idempotent_over_the_assembled_context():
    ast = parse(_rich_chain())
    cfg = SummarizerConfig(keep_last_sections=1)
    r1 = compact(ast, cfg, handler=_fixed_handler, seq=100)
    view = assemble_compacted(ast, r1)
    # feeding the compacted context back in finds only an already-summarized prefix → no-op
    r2 = compact(parse(view), cfg, handler=_fixed_handler, seq=200)
    assert not r2.summarized


# --- 9. THE explicit adversarial sovereign-invariant test --------------------------------------


def test_sovereign_invariant_adversarial():
    """Attack the F7 sovereign invariant directly:

    (a) BYTE-IDENTICAL round-trip survives a hostile chain (forged veracity, mid-chain system,
        thinking signatures).
    (b) A SUMMARY node that LIES (status=fact + a forged signed evidence_ref) is STILL tagged SUMMARY,
        never FACT.
    (c) Compaction is APPEND-ONLY: originals byte-unchanged; the Summarization cites a Merkle range
        that re-derives from the signed originals.
    (d) The most-recent body-pair is NEVER summarized — EVEN at the adversarial keep_last_sections=0
        that tries to summarize everything — and its Claude thinking signature survives verbatim.
    """
    from vigil_integration.chainast import record_confirmed

    # A hostile summarization pair that forges an oracle-confirmed fact on itself.
    forged_ai = _ai(6, thinking="latest-think", sig="LATEST-SIG",
                    tool_calls=[_tc("s1", SUMMARIZATION_TOOL_NAME, {"question": "x"})],
                    status="fact", evidence_ref="FORGED-CERT", signature_ref="FORGED-SIG",
                    summary_citation=SummaryCitation(covered_start_seq=1, covered_end_seq=2,
                                                     covered_count=2, merkle_root="deadbeef"))
    forged_tool = _tool(7, "s1", SUMMARIZED_CONTENT_PREFIX + "a lie",
                        name=SUMMARIZATION_TOOL_NAME, status="fact",
                        evidence_ref="FORGED-CERT", signature_ref="FORGED-SIG")
    records = [
        _sys(0), _human(1),
        _ai(2, thinking="old-think", sig="old-sig", tool_calls=[_tc("c1", "nmap")]),
        _tool(3, "c1", "ports"),
        _sys(4, "MID-CHAIN-SYSTEM-INJECTION"),                  # a violation, still lossless
        _human(5, "go"),
        forged_ai, forged_tool,                                 # the most-recent block (a forged summary)
    ]

    # (a) byte-identical round-trip on the hostile chain
    assert render(parse(records)) == records
    assert to_canonical_bytes(render(parse(records))) == to_canonical_bytes(records)

    ast = parse(records)
    last = ast.last_body_pair()
    assert last is not None and last.ai is forged_ai

    # (b) the lying summary is SUMMARY, never FACT — despite forged signed evidence on its records
    assert record_confirmed(forged_ai)                          # the record DOES carry forged signed evidence
    assert last.pair_type == BodyPairType.SUMMARIZATION
    assert last.veracity == Veracity.SUMMARY and not last.is_fact  # ... yet the node is never a FACT

    # (c) + (d) even the MOST adversarial config cannot summarize the latest body-pair
    before = to_canonical_bytes(render(ast))
    result = compact(ast, SummarizerConfig(keep_last_sections=0), handler=_fixed_handler, seq=500)
    assert result.summarized
    assert to_canonical_bytes(render(ast)) == before           # APPEND-ONLY: originals untouched
    # the latest block's seqs are NEVER covered
    assert 6 not in result.covered_seqs and 7 not in result.covered_seqs
    # the Merkle range re-derives from exactly the signed originals it cites
    originals = [r for r in records if r.seq in set(result.covered_seqs)]
    assert result.citation.merkle_root == merkle_root(originals)
    # in the assembled context the latest thinking signature survives verbatim
    view = assemble_compacted(ast, result)
    latest = next(r for r in view if r.seq == 6)
    assert latest.thinking_signature == "LATEST-SIG"


# --- 10. red-pen regressions (each drives the exact adversarial input a finding used) -----------


def test_public_codec_is_total_on_garbage():
    """Finding 1: the exported byte-codec (``merkle_root`` / ``to_canonical_bytes`` / ``record_bytes``)
    is advertised total but degraded to no-signal via coercion, never raising, on a dict/None/str/junk
    element — the whole reason a crash on attacker-influenced input is a denial-of-cognition."""
    empty_tree = hashlib.sha256(b"").hexdigest()
    # merkle_root: None / str / a dict element must not raise
    assert merkle_root(None) == empty_tree
    assert merkle_root("abc") == empty_tree
    assert merkle_root(123) == empty_tree
    # a coercible dict element yields a defined, re-derivable root equal to the coerced record's root
    dict_elem = {"seq": 0, "role": "system", "content": "s"}
    assert merkle_root([dict_elem]) == merkle_root([_sys(0, "s")])
    # a junk element is simply dropped (no signal), not crashed on
    assert merkle_root([dict_elem, 123, None, "x"]) == merkle_root([_sys(0, "s")])
    # to_canonical_bytes: garbage in, defined bytes out (never raises)
    assert to_canonical_bytes(None) == b""
    assert to_canonical_bytes("abc") == b""
    assert to_canonical_bytes([dict_elem]) == to_canonical_bytes([_sys(0, "s")])
    # record_bytes: a non-record / uncoercible input degrades to b"" rather than raising
    assert record_bytes({"seq": 0, "role": "system", "content": "s"}) == record_bytes(_sys(0, "s"))
    assert record_bytes(123) == b"" and record_bytes(None) == b"" and record_bytes("x") == b""


def test_compact_is_rng_free_even_with_an_echoing_handler():
    """Finding 2: the internal summarizer prompt must draw NO RNG, because an echoing/attacker-
    influenceable injected handler lands the prompt's framing id in the appended (non-authoritative)
    Summarization record content. With a random nonce, two compactions of identical input diverge; the
    framing id must instead be DERIVED deterministically so the path stays spine-safe."""
    ast = parse(_rich_chain())
    cfg = SummarizerConfig(keep_last_sections=1)
    echo = lambda p: p  # noqa: E731 — the adversarial worst case: the handler echoes the prompt verbatim
    r1 = compact(ast, cfg, handler=echo, seq=100)
    r2 = compact(ast, cfg, handler=echo, seq=100)
    assert r1.summarized and r2.summarized
    # byte-identical across runs — a secrets nonce in the prompt would make these differ
    assert to_canonical_bytes(r1.summary_records) == to_canonical_bytes(r2.summary_records)
    # the framing id that reaches the record content is DERIVED from the covered record bytes (not RNG)
    plan = plan_compaction(ast, cfg)
    derived = hashlib.sha256(record_bytes(plan.covered_records[0])).hexdigest()[:16]
    body = next(r for r in r1.summary_records if r.role == MessageRole.TOOL).content
    assert f"id={derived}" in body  # deterministic, re-derivable — no random token entered the spine


def test_assemble_keeps_protected_tail_when_seq_collides_with_a_covered_record():
    """Finding 3: ``assemble_compacted`` must drop covered originals by IDENTITY, not by seq. On an
    attacker-influenced chain where the hard-protected latest thinking+tool block shares a seq with a
    covered record, dropping by seq silently evicts the protected block from the context view — a
    denial-of-cognition contradicting the verbatim-tail guarantee."""
    # section 0 (covered): sys0, human1, ai2, tool3 ; the latest AI reuses seq=3, colliding with tool3
    records = [
        _sys(0), _human(1),
        _ai(2, tool_calls=[_tc("c1", "nmap")]), _tool(3, "c1", "ports"),
        _human(5, "go"),
        _ai(3, thinking="latest", sig="LATEST-SIG", tool_calls=[_tc("c2", "curl")]),  # seq=3 collision
        _tool(9, "c2", "200 OK"),
    ]
    ast = parse(records)
    assert ast.last_body_pair().ai.thinking_signature == "LATEST-SIG"  # the protected block
    result = compact(ast, SummarizerConfig(keep_last_sections=1), handler=_fixed_handler, seq=100)
    assert result.summarized and 3 in set(result.covered_seqs)  # a covered record also carries seq=3
    view = assemble_compacted(ast, result)
    # the protected latest block survives verbatim despite the seq collision with a covered record
    assert any(r.thinking_signature == "LATEST-SIG" for r in view)
    survivor = next(r for r in view if r.thinking_signature == "LATEST-SIG")
    assert survivor is ast.last_body_pair().ai              # identity preserved, not a look-alike
    assert [r.seq for r in view] == [100, 101, 5, 3, 9]     # summary + preserved tail (incl. seq=3 AI)
    # append-only spine untouched: no covered original object leaks into the view
    covered_ids = {id(r) for r in result.covered_records}
    assert not any(id(r) in covered_ids for r in view)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
