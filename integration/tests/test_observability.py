"""
F11 slice — observability: an OTel-style span/trace model + a Langfuse-style observation taxonomy
BOUND TO SPINE IDENTITY. The through-line every test defends: observability is EMIT-ONLY (it records,
it never gates or mints a fact), every recorded attribute is SECRET-FREE (F3-redacted), identity
binding is DETERMINISTIC (ids from the injected spine hash/seq, no wallclock/RNG), a Guardrail fires on
a WARDEN block and an Evaluator on an oracle confirm/refute, and every builder is TOTAL on malformed
attacker-influenceable input (never raises — a telemetry crash is a denial-of-cognition).
"""

from __future__ import annotations

import pathlib

import pytest

from vigil_integration.agent.react import EdgeVerdict
from vigil_integration.observability import (
    CollectingExporter,
    Observation,
    ObservationLevel,
    ObservationType,
    Span,
    SpanKind,
    SpanStatus,
    SpineTracer,
    complete_span,
    derive_observation_id,
    derive_span_id,
    derive_trace_id,
    evaluator_observation,
    guardrail_observation,
    is_warden_block,
    new_observation,
    new_span,
    redact_attributes,
    span_id_matches,
    warden_outcome,
)
from vigil_integration.tools.governance import ToolCallVerdict
from vigil_integration.warden_gate import ToolDecision

# Fields/methods that would mean observability can authorize — NONE of these may appear on a record.
_AUTHORITY_SURFACE = ("allowed", "allow", "deny", "denied", "authorize", "authorized",
                      "tier", "outcome", "verdict", "grant", "permit")


# --- identity: deterministic, spine-bound, no wallclock/RNG -----------------------------------------

def test_ids_derive_deterministically_from_spine_identity():
    # same spine hash/seq → byte-identical ids, every time (a trace rebuilds identically from the spine).
    assert derive_span_id("h-abc", 7) == derive_span_id("h-abc", 7)
    assert derive_trace_id("root-1") == derive_trace_id("root-1")
    assert derive_observation_id("h-abc", 7, kind="guardrail", name="n") == \
        derive_observation_id("h-abc", 7, kind="guardrail", name="n")
    # OTel wire widths preserved (128-bit trace, 64-bit span) and hex.
    assert len(derive_trace_id("root-1")) == 32
    assert len(derive_span_id("h-abc", 7)) == 16
    int(derive_trace_id("root-1"), 16)   # valid hex
    int(derive_span_id("h-abc", 7), 16)


def test_distinct_spine_identity_yields_distinct_ids():
    assert derive_span_id("h1", 1) != derive_span_id("h2", 1)
    assert derive_span_id("h1", 1) != derive_span_id("h1", 2)
    # a guardrail and an evaluator projected off ONE spine record get distinct ids (kind disambiguates).
    assert derive_observation_id("h1", 1, kind="guardrail") != \
        derive_observation_id("h1", 1, kind="evaluator")


def test_span_id_offline_verifiable_against_spine_hash():
    sid = derive_span_id("spine-hash-9", 3)
    assert span_id_matches(sid, "spine-hash-9", 3) is True
    assert span_id_matches(sid, "spine-hash-OTHER", 3) is False
    assert span_id_matches("", "spine-hash-9", 3) is False   # total on garbage


def test_span_carries_the_spine_hash_as_shared_identity():
    s = new_span("recon.scan", spine_hash="rec:abc123", seq=12)
    assert s is not None
    assert s.spine_hash == "rec:abc123"           # traces + spine records SHARE the identity
    assert s.span_id == derive_span_id("rec:abc123", 12)   # derived, verifiable


# --- span model: OTel shape, injected timestamps, append-only completion ----------------------------

def test_new_span_shape_and_injected_timestamp():
    s = new_span("http.get", kind=SpanKind.CLIENT, spine_hash="h", seq=4, ts=1000,
                 attributes={"http.method": "GET"})
    assert isinstance(s, Span)
    assert s.kind == SpanKind.CLIENT
    assert s.start_ts == 1000 and s.end_ts is None     # timestamp is INJECTED, span is still open
    assert s.status == SpanStatus.UNSET
    assert s.attributes == {"http.method": "GET"}


def test_complete_span_is_append_only_never_mutates_original():
    s = new_span("op", spine_hash="h", seq=1, ts=10, attributes={"a": "1"})
    done = complete_span(s, ts=20, status=SpanStatus.OK, attributes={"b": "2"})
    assert done is not None
    assert done.end_ts == 20 and done.status == SpanStatus.OK
    assert done.attributes == {"a": "1", "b": "2"}     # merged
    # the ORIGINAL is untouched (frozen record; completion produced a NEW span) — spine-safe.
    assert s.end_ts is None and s.status == SpanStatus.UNSET and s.attributes == {"a": "1"}
    assert done.span_id == s.span_id                   # same identity, new record


def test_span_is_frozen():
    s = new_span("op", spine_hash="h", seq=1)
    assert s is not None
    with pytest.raises(Exception):
        s.status = SpanStatus.OK   # frozen: cannot be mutated into a different outcome


# --- observation taxonomy ---------------------------------------------------------------------------

def test_observation_taxonomy_covers_the_langfuse_types():
    names = {t.value for t in ObservationType}
    assert {"generation", "agent", "tool", "chain", "retriever",
            "evaluator", "embedding", "guardrail"} <= names


def test_new_observation_unknown_type_degrades_to_none():
    assert new_observation("not-a-real-type", "x") is None      # no signal, not a mislabel
    ok = new_observation("tool", "nmap", spine_hash="h", seq=2)
    assert isinstance(ok, Observation) and ok.type == ObservationType.TOOL


# --- Guardrail on a WARDEN block --------------------------------------------------------------------

def test_guardrail_fires_on_a_warden_block_across_verdict_shapes():
    # warden_gate.ToolDecision (outcome="queue"/"deny")
    d1 = ToolDecision(tool="sqlmap", tier="A3", outcome="queue", reason="A3 requires owner approval")
    assert is_warden_block(d1) is True
    obs = guardrail_observation("sqlmap", d1, spine_hash="h", seq=5)
    assert isinstance(obs, Observation) and obs.type == ObservationType.GUARDRAIL
    assert obs.attributes["warden.outcome"] == "queue"
    assert obs.attributes["warden.tier"] == "A3"
    assert obs.attributes["warden.tool"] == "sqlmap"
    assert obs.level == ObservationLevel.WARNING

    # governance.ToolCallVerdict (allowed=False, outcome="deny")
    d2 = ToolCallVerdict(allowed=False, outcome="deny", tier="A2", destructive=False,
                         requires_quorum=False, reason="out-of-phase")
    assert is_warden_block(d2) is True

    # react.EdgeVerdict allow → NOT a block
    d3 = EdgeVerdict(allowed=True, outcome="allow", reason="ok", tier="A1")
    assert is_warden_block(d3) is False

    # warden_outcome duck-types across shapes and NEVER decides — it only echoes the gate's own outcome.
    assert warden_outcome(d1) == "queue"
    assert warden_outcome(d2) == "deny"
    assert warden_outcome(d3) == "allow"
    assert warden_outcome(None) == "unknown"          # undecipherable → unknown (a block, fail-closed)
    assert is_warden_block(None) is True


def test_tracer_guardrail_fires_only_on_block_by_default():
    exp = CollectingExporter()
    tr = SpineTracer(sink=exp, root_hash="engagement-1")
    allow = EdgeVerdict(allowed=True, outcome="allow", reason="ok", tier="A1")
    deny = EdgeVerdict(allowed=False, outcome="deny", reason="no gate", tier="A2")
    assert tr.on_warden_decision("http.get", allow, spine_hash="h1", seq=1) is None   # no block → nothing
    fired = tr.on_warden_decision("metasploit", deny, spine_hash="h2", seq=2)
    assert isinstance(fired, Observation) and fired.type == ObservationType.GUARDRAIL
    assert exp.observations() == [fired]                       # exactly one guardrail emitted
    # always=True records even an allow (for full-fidelity traces).
    forced = tr.on_warden_decision("http.get", allow, spine_hash="h1", seq=1, always=True)
    assert isinstance(forced, Observation)


# --- Evaluator on an oracle confirm/refute ----------------------------------------------------------

def test_evaluator_records_confirm_and_refute():
    conf = evaluator_observation(confirmed=True, evidence_ref="cert:spine:9", spine_hash="h", seq=3)
    assert isinstance(conf, Observation) and conf.type == ObservationType.EVALUATOR
    assert conf.attributes["oracle.verdict"] == "confirm"
    assert conf.attributes["oracle.evidence_ref"] == "cert:spine:9"
    assert conf.attributes["oracle.evidence_present"] is True

    ref = evaluator_observation(confirmed=False, spine_hash="h", seq=4)
    assert ref.attributes["oracle.verdict"] == "refute"
    assert ref.attributes["oracle.evidence_present"] is False


def test_evaluator_confirm_requires_explicit_true_fails_closed():
    # a non-bool "confirmed" NEVER records a confirm — telemetry must not over-claim a confirmation.
    for junk in (None, "true", 1, "confirm", [], {}):
        o = evaluator_observation(confirmed=junk, evidence_ref="x", spine_hash="h", seq=1)
        assert o.attributes["oracle.verdict"] == "refute"


# --- SECRET-FREE: every attribute is F3-redacted ----------------------------------------------------

def test_span_attributes_are_redacted():
    s = new_span("llm.call", spine_hash="h", seq=1, attributes={
        "authorization": "Bearer sk-SUPERSECRET-TOKEN-1234567890",
        "api_key": "AKIA-DEADBEEF-SECRET",
        "note": "curl -H 'Authorization: Bearer sk-LEAK-98765' https://t",
        "url": "https://user:hunter2@target.example/path",
        "safe": "kept",
    })
    assert s is not None
    blob = repr(s.attributes)
    for secret in ("SUPERSECRET", "DEADBEEF", "sk-LEAK-98765", "hunter2"):
        assert secret not in blob, f"secret {secret!r} leaked into span attributes"
    assert s.attributes["safe"] == "kept"           # non-secret structure preserved


def test_guardrail_reason_is_redacted():
    d = ToolDecision(tool="x", tier="A2", outcome="deny",
                     reason="blocked call carrying token=SECRETVALUE12345 in args")
    obs = guardrail_observation("x", d, spine_hash="h", seq=1)
    assert "SECRETVALUE12345" not in repr(obs.attributes)


def test_secret_smuggled_into_an_attribute_KEY_is_scrubbed_not_just_the_value():
    # NEGATIVE CONTROL for the key-leak class (finding 1): a JSON object can carry ANY string key, so a
    # secret smuggled into a dict KEY is reachable from attacker-influenceable parsed tool/LLM output. It
    # must be scrubbed by the SAME F3 vocabulary the VALUES use, and must not survive into the record OR
    # into model_dump_json() — the exact wire form destined for the deferred OTel/Langfuse collector.
    s = new_span("t", spine_hash="h", seq=1, attributes={
        "aws_secret_access_key=AKIA-LEAKED-9999": "x",          # inline secret in the KEY
        "authorization=Bearer sk-KEY-LEAK-2222": "y",           # bearer smuggled into the KEY
        "x-api-key=SECRET-KEY-3333": "z",                       # hyphenated secret KEY
        "note": "curl -H 'Authorization: Bearer sk-VAL-LEAK-4444' https://t",  # value path still covered
        "safe": "kept",
    })
    assert s is not None
    wire = s.model_dump_json()                                  # the exact form headed to the collector
    for secret in ("AKIA-LEAKED-9999", "sk-KEY-LEAK-2222", "SECRET-KEY-3333", "sk-VAL-LEAK-4444"):
        assert secret not in wire, f"secret {secret!r} leaked into the span wire form via a KEY/value"
        assert secret not in repr(s.attributes)
    # a plain non-secret key/value survives structurally (key-scrubbing is targeted, not scorched-earth).
    assert s.attributes.get("safe") == "kept"
    # observations route through the SAME redactor — the key path is closed there too.
    o = new_observation("tool", "nmap", spine_hash="h", seq=2,
                        attributes={"client_secret=SECRET-OBS-5555": "v"})
    assert o is not None and "SECRET-OBS-5555" not in o.model_dump_json()


def test_object_value_repr_residual_is_documented_and_stays_deterministic():
    # DOCUMENTED RESIDUAL (finding 2, LOW), the sibling of redact_tool_args's positional-secret residual:
    # a secret reachable ONLY through a NON-str value's __repr__ is a foreign object — UNREACHABLE from
    # JSON-native untrusted input (tool/LLM output parses to str/int/float/bool/None/dict/list). It is
    # left un-stringified BY DESIGN: str(obj) would inject a non-deterministic memory address and break
    # the spine-identity determinism this package guarantees. This test pins the boundary — the residual
    # is acknowledged, not silently claimed away.
    class S:
        def __repr__(self) -> str:
            return "Bearer DEADBEEF-obj"

    # the REACHABLE class (a JSON-native str value under a recognized secret key, and a recognized secret
    # smuggled into a key) IS fully scrubbed on both sides...
    covered = new_span("t", spine_hash="h", seq=1, attributes={"token": "sk-REACHABLE-6666",
                                                               "api_key=SECRET-7777": "w"})
    assert covered is not None
    for secret in ("sk-REACHABLE-6666", "SECRET-7777"):
        assert secret not in covered.model_dump_json()
    # ...the foreign-object value is passed through verbatim (the residual), NOT coerced to a
    # non-deterministic str — determinism is the higher invariant here, and record construction is total.
    span = new_span("t", spine_hash="h", seq=1, attributes={"x": S()})
    assert span is not None
    assert span.attributes["x"].__class__ is S              # preserved as-is, not stringified
    # determinism holds: identical injected identity → byte-identical id regardless of the foreign value.
    again = new_span("t", spine_hash="h", seq=1, attributes={"x": S()})
    assert again is not None and again.span_id == span.span_id


def test_redact_attributes_total_on_nondict():
    assert redact_attributes(None) == {}
    assert redact_attributes("not-a-dict") == {}
    assert redact_attributes(["list"]) == {}


# --- TOTAL on malformed attacker-influenceable input ------------------------------------------------

def test_builders_never_raise_on_malformed_input():
    # names, hashes, seqs, kinds, attributes all hostile — none may raise.
    assert new_span(None, spine_hash=None, seq="not-int", ts=object(), kind="garbage",
                    attributes="not-a-dict") is not None
    assert new_span(12345, spine_hash=b"bytes", seq=True, attributes={"k": object()}) is not None
    assert complete_span("not-a-span") is None
    assert complete_span(None) is None
    assert new_observation(None, None) is None                  # unknown type → no signal
    # guardrail/evaluator with a garbage decision / inputs still produce a well-formed record.
    assert isinstance(guardrail_observation(None, None, spine_hash=None, seq=None), Observation)
    assert isinstance(evaluator_observation(confirmed=object(), evidence_ref=object()), Observation)


def test_bool_and_bad_seq_do_not_become_a_timestamp():
    # bool is an int subclass but is never a valid injected time coordinate → degrades to 0.
    s = new_span("op", spine_hash="h", seq=True, ts=False)
    assert s.seq == 0 and s.start_ts == 0


def test_a_failing_sink_never_breaks_the_recorder():
    def boom(_record):
        raise RuntimeError("collector down")

    tr = SpineTracer(sink=boom, root_hash="r")
    s = tr.start_span("op", spine_hash="h", seq=1)     # sink raises internally...
    assert isinstance(s, Span)                          # ...but the record is still returned
    assert tr.dropped == 1                              # failure tracked, cognition not denied
    o = tr.on_oracle_verdict(True, evidence_ref="c", spine_hash="h", seq=2)
    assert isinstance(o, Observation) and tr.dropped == 2


# --- exporter/sink contract -------------------------------------------------------------------------

def test_tracer_emits_records_to_the_injected_sink():
    exp = CollectingExporter()
    tr = SpineTracer(sink=exp, root_hash="eng")
    s = tr.start_span("op", spine_hash="h1", seq=1)
    tr.end_span(s, ts=5)
    tr.observe(ObservationType.TOOL, "nmap", spine_hash="h2", seq=2)
    assert len(exp.spans()) == 2 and len(exp.observations()) == 1
    # all records share the tracer's one trace identity (offline-verifiable AND debuggable).
    assert {r.trace_id for r in exp.records} == {tr.trace_id}


def test_tracer_with_no_sink_still_builds_records():
    tr = SpineTracer()                                  # no exporter wired
    s = tr.start_span("op", spine_hash="h", seq=1)
    assert isinstance(s, Span) and tr.dropped == 0


# ====================================================================================================
# THE SOVEREIGN INVARIANT — observability is EMIT-ONLY and never gates/authorizes anything.
# This is the adversarial test the red-pen attacks; it asserts every clause of the invariant at once.
# ====================================================================================================

def test_sovereign_invariant_observability_is_emit_only_and_authorizes_nothing():
    exp = CollectingExporter()
    tr = SpineTracer(sink=exp, root_hash="engagement-X")

    # A WARDEN DENY and an oracle CONFIRM both flow through observability. Neither must yield anything
    # an actor could read as an authorization.
    deny = ToolCallVerdict(allowed=False, outcome="deny", tier="A3", destructive=True,
                           requires_quorum=True, reason="unauthorized destructive tool")
    guard = tr.on_warden_decision("mimikatz", deny, spine_hash="s1", seq=1, ts=100)
    evalu = tr.on_oracle_verdict(True, evidence_ref="cert:signed:1", spine_hash="s2", seq=2, ts=101)
    span = tr.start_span("exploit", kind=SpanKind.CLIENT, spine_hash="s3", seq=3, ts=102)
    span_done = tr.end_span(span, ts=103, status=SpanStatus.ERROR)

    records = [guard, evalu, span, span_done]

    # (1) EMIT-ONLY: no record exposes an authorization surface (no allowed/deny/tier/outcome/verdict…
    #     field OR method). The WARDEN tier/outcome and oracle verdict live ONLY as inert redacted
    #     strings inside `attributes`, never as a typed decision on the record.
    for rec in records:
        for attr in _AUTHORITY_SURFACE:
            assert not hasattr(rec, attr), f"{type(rec).__name__} exposes an authorization surface .{attr}"
    # the descriptive echoes ARE present as inert telemetry strings (proving we recorded the block),
    # but they are data, not a decision the observability layer made.
    assert guard.attributes["warden.outcome"] == "deny"
    assert guard.attributes["warden.tier"] == "A3"
    assert evalu.attributes["oracle.verdict"] == "confirm"

    # (2) recording an oracle "confirm" MINTS NO FACT: the Evaluator is an Observation, not a Finding,
    #     and carries no fact-minting/authorizing method. The signed FACT is the oracle path's job.
    assert isinstance(evalu, Observation)
    for method in ("record_fact", "confirm", "authorize", "promote", "sign"):
        assert not hasattr(evalu, method)
    # a "confirm" with an EMPTY evidence_ref still only DESCRIBES — observability does not adjudicate it.
    empty = evaluator_observation(confirmed=True, evidence_ref="", spine_hash="s", seq=9)
    assert empty.attributes["oracle.verdict"] == "confirm"
    assert empty.attributes["oracle.evidence_present"] is False   # surfaced, never "fixed" into a fact

    # (3) the return values are records (or None), never a verdict an actor could branch on to proceed.
    for rec in records:
        assert isinstance(rec, (Span, Observation))

    # (4) SECRET-FREE across the whole emitted corpus.
    leaky = tr.observe(ObservationType.GENERATION, "llm",
                       spine_hash="s4", seq=4, attributes={"prompt": "auth: Bearer sk-INVARIANT-LEAK-1"})
    assert "sk-INVARIANT-LEAK-1" not in repr(leaky.attributes)

    # (5) DETERMINISTIC identity: every emitted id is a pure function of injected spine identity — no
    #     wallclock, no RNG. Re-deriving matches, and a byte-identical replay reproduces the ids.
    assert span.span_id == derive_span_id("s3", 3)
    assert span_id_matches(guard.id, "s1", 1) is False   # obs id keyed on kind/name, not a bare hash
    exp2 = CollectingExporter()
    tr2 = SpineTracer(sink=exp2, root_hash="engagement-X")
    guard2 = tr2.on_warden_decision("mimikatz", deny, spine_hash="s1", seq=1, ts=100)
    assert guard2.id == guard.id and guard2.trace_id == guard.trace_id   # reproducible

    # (6) TOTAL: even fully hostile input to the emit path returns records/None and never raises.
    assert isinstance(tr.on_warden_decision(object(), object(), spine_hash=object(), seq=object()),
                      Observation)


def test_no_wallclock_or_rng_in_observability_source():
    """Structural guard the red-pen loves: the whole package must contain NO wallclock/RNG import so
    identity binding can never become non-deterministic. (prompt_safety uses `secrets` for its nonce —
    that layer is fine; the SPINE-IDENTITY layer here must not.)"""
    pkg = pathlib.Path(__file__).resolve().parents[1] / "vigil_integration" / "observability"
    forbidden = ("import time", "import random", "import datetime", "import uuid", "import secrets",
                 "time.time", "datetime.now", "utcnow", "random.", "uuid.", "secrets.")
    for py in pkg.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{py.name} contains forbidden non-determinism source {token!r}"
