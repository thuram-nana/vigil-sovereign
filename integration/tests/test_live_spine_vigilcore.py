"""VIGIL-LIVE §12 WS-1f — the REAL signed-spine binder for ReAct checkpointing.

The through-line every test defends: :class:`VigilCoreSpine` binds the F2 checkpoint seams
(signer/verify_record/writer/reader) to a real Ed25519 keypair and a real append-only spine FILE,
hash-chained with ``vigil_core.chain`` — and going to a real file changes NOTHING about the sovereign
contract. A ``Finding`` in ``facts`` round-trips off disk ONLY with its signed ``evidence_ref``; an
adversary who can write the file AND holds the key still cannot launder an evidence-less fact; a torn tail
is dropped (good prefix survives); a tampered record / broken chain / forged entry is detected and never
silently trusted; rebuild is deterministic + total; the private key never touches disk.
"""

from __future__ import annotations

import ast
import inspect
import json
import os

import pytest

from vigil_core import generate_keypair
from vigil_integration.agent.checkpoint import (
    GENESIS_PREV,
    SnapshotRecord,
    rebuild_from,
    serialize,
    verify_chain,
    write_checkpoint,
)
from vigil_integration.agent.checkpoint import _content_hash  # white-box forging helper
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.live import spine_vigilcore as sv
from vigil_integration.live.spine_vigilcore import SpineLine, SpineWriteError, VigilCoreSpine

# --- fixtures / helpers -----------------------------------------------------------------------------


def _kp():
    return generate_keypair()


def _spine(tmp_path, kp, name="eng.spine"):
    return VigilCoreSpine(kp, str(tmp_path / name))


def _state_with_fact(*, slug="eng-a", evidence_ref="cert:evi-1", phase=Phase.EXPLOITATION):
    """A realistic state: one oracle-confirmed FACT (signed evidence ref) + one LEAD + a trace."""
    st = AgentState(engagement_slug=slug, phase=phase, iteration=3, objective="own the box")
    st.record_fact(Finding(ref="f-sqli", bug_class="sqli", title="auth bypass", severity="critical"),
                   evidence_ref=evidence_ref)
    st.record_lead(Finding(ref="l-xss", bug_class="xss", title="reflected xss?", severity="medium",
                           source="zap"))
    st.execution_trace.append({"tool": "sqlmap", "verdict": "new_info"})
    return st


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _raw_lines(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [ln for ln in fh.read().split("\n") if ln]


def _rewrite(path, lines):
    with open(path, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")


# --- round-trip off a real file ---------------------------------------------------------------------


def test_write_then_rebuild_from_real_file_preserves_fact_with_evidence(tmp_path):
    kp = _kp()
    spine = _spine(tmp_path, kp)
    spine.write_state(_state_with_fact(), seq=1)

    # rebuild from a FRESH spine object on the same file — nothing cached in memory, pure disk read
    back = _spine(tmp_path, kp).rebuild()
    assert back.engagement_slug == "eng-a"
    assert back.phase == Phase.EXPLOITATION
    assert back.iteration == 3
    assert [f.ref for f in back.facts] == ["f-sqli"]
    assert back.facts[0].status == "fact"
    assert back.facts[0].evidence_ref == "cert:evi-1"      # the signed evidence ref survived the round-trip
    assert [ld.ref for ld in back.leads] == ["l-xss"]      # the lead rebuilt as a lead
    assert back.leads[0].status == "lead" and back.leads[0].evidence_ref == ""
    assert all(f.ref == "f-sqli" for f in back.facts)      # the lead never landed in facts


def test_documented_wiring_serialize_signer_writer_rebuild_from(tmp_path):
    """The exact wiring the mission specifies: serialize(signer=spine.signer) → spine.writer →
    rebuild_from(reader=spine.reader, verify=spine.verify_record)."""
    kp = _kp()
    spine = _spine(tmp_path, kp)
    rec = serialize(_state_with_fact(), seq=1, signer=spine.signer)
    assert rec.signature_ref                                # the record was signed by the real key
    spine.writer(rec)

    back = rebuild_from(reader=spine.reader, verify=spine.verify_record)
    assert [f.ref for f in back.facts] == ["f-sqli"]
    assert back.facts[0].evidence_ref == "cert:evi-1"


def test_write_checkpoint_flow_via_injected_writer(tmp_path):
    kp = _kp()
    spine = _spine(tmp_path, kp)
    prev = GENESIS_PREV
    for i in range(1, 4):
        rec = write_checkpoint(AgentState(engagement_slug="e", iteration=i), seq=i,
                               signer=spine.signer, writer=spine.writer, prev_hash=prev)
        prev = rec.hash
    assert rebuild_from(reader=spine.reader, verify=spine.verify_record).iteration == 3
    assert spine.verify() is True


# --- append-only, hash-chained, signed FILE + restart continuity ------------------------------------


def test_append_only_chain_verifies_and_survives_restart(tmp_path):
    kp = _kp()
    s1 = _spine(tmp_path, kp)
    for i in range(1, 4):
        s1.write_state(AgentState(engagement_slug="e", iteration=i), seq=i)
    assert s1.verify() is True

    # a RESTART: a new binder recovers the append point from disk and continues the SAME chain (no fork)
    s2 = _spine(tmp_path, kp)
    s2.write_state(AgentState(engagement_slug="e", iteration=4), seq=4)
    assert s2.verify() is True                              # the whole file is still one clean signed chain
    assert s2.rebuild().iteration == 4
    assert s2.head_hash() != GENESIS_PREV

    # the checkpoint record chain is also contiguous (prev_hash threaded across the restart)
    assert verify_chain(list(s2.reader())) is True


def test_signer_verify_record_are_a_matched_pair(tmp_path):
    kp = _kp()
    spine = _spine(tmp_path, kp)
    h = _content_hash(1, "e", GENESIS_PREV, "{}")
    sig = spine.signer(h)
    assert sig and spine.verify_record(h, sig) is True     # our own signature verifies
    assert spine.signer(h) == sig                          # Ed25519 is deterministic (no RNG in the seam)
    assert spine.verify_record(h, sig[:-2] + ("AA" if not sig.endswith("AA") else "BB")) is False

    # a DIFFERENT key's verifier must reject our signature (authentication, not just integrity)
    other = VigilCoreSpine(_kp(), str(tmp_path / "other.spine"))
    assert other.verify_record(h, sig) is False


def test_head_hash_and_verify_on_missing_file_are_total(tmp_path):
    spine = _spine(tmp_path, _kp(), name="does-not-exist.spine")
    assert list(spine.reader()) == []                      # no file → no records, no crash
    assert spine.rebuild().model_dump() == AgentState().model_dump()
    assert spine.head_hash() == GENESIS_PREV
    assert spine.verify() is True                          # an empty spine is vacuously intact


# --- torn tail (crash mid-append) -------------------------------------------------------------------


def test_torn_tail_is_dropped_good_prefix_survives(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    spine.write_state(AgentState(engagement_slug="e", iteration=1), seq=1)
    spine.write_state(AgentState(engagement_slug="e", iteration=2), seq=2)

    # simulate a crash mid-append: a partial JSON line with NO trailing newline
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 99, "prev_hash": "x", "cert_digest": "y", "entry_hash')  # truncated

    fresh = VigilCoreSpine(kp, path)
    assert fresh.rebuild().iteration == 2                  # the torn tail is dropped; seq=2 survives
    assert fresh.verify() is True                          # verify tolerates the torn tail over a good prefix
    # a brand-new append after the torn write still lands on a clean chain
    fresh.write_state(AgentState(engagement_slug="e", iteration=3), seq=3)
    assert fresh.rebuild().iteration == 3
    assert fresh.verify() is True


# --- THE SOVEREIGN INVARIANT (the red-pen attacks exactly this) -------------------------------------


def test_SOVEREIGN_INVARIANT_signed_forged_evidenceless_fact_is_unrebuildable(tmp_path):
    """A fact can NEVER be rebuilt off the real spine without its signed evidence ref — even when the
    forgery is VALIDLY SIGNED at every layer.

    Attack: an adversary who can write the spine AND holds the signing key appends a snapshot whose
    ``state_json`` claims a ``status="fact"`` finding but STRIPS the evidence ref. It is made fully
    consistent: a matching content hash, a valid record signature, a valid file-chain entry signature — so
    the FILE itself verifies. The only thing standing between the attacker and a laundered fact is the
    checkpoint layer's fact/evidence invariant, re-run on rebuild. It must hold: the evidence-less fact is
    un-rebuildable (appears in NEITHER facts NOR leads), and rebuild falls back to the genuine signed fact."""
    kp = _kp()
    spine = _spine(tmp_path, kp)
    good = spine.write_state(_state_with_fact(), seq=1)

    payload = json.loads(good.state_json)
    assert payload["facts"][0]["status"] == "fact"
    payload["facts"][0]["evidence_ref"] = ""               # <-- the laundering attempt
    forged_json = _canonical(payload)
    forged_hash = _content_hash(2, good.engagement, good.hash, forged_json)   # a LATER, higher checkpoint seq
    forged = SnapshotRecord(seq=2, hash=forged_hash, engagement=good.engagement,
                            state_json=forged_json, prev_hash=good.hash,
                            signature_ref=spine.signer(forged_hash))
    spine.writer(forged)                                   # append it as a fully-signed spine line — succeeds

    # the FILE is a valid signed append-only chain (the forgery is correctly signed at both layers) ...
    assert spine.verify() is True
    assert spine.verify_record(forged.hash, forged.signature_ref) is True
    # ... yet the evidence-less fact is UN-REBUILDABLE — rebuild falls back to the genuine signed fact
    back = spine.rebuild()
    assert [f.ref for f in back.facts] == ["f-sqli"]
    assert back.facts[0].evidence_ref == "cert:evi-1"      # the ORIGINAL signed evidence, not the stripped one
    assert all("f-sqli" == f.ref for f in back.facts)      # no evidence-less fact materialised
    assert all(ld.ref != "f-sqli" for ld in back.leads)    # nor was it silently downgraded to a lead


@pytest.mark.parametrize("bad_status,ev", [
    ("fact", "   \t "),      # whitespace-only evidence ref is as empty as ""
    ("Fact", ""), ("FACT", ""), ("fact ", ""), (" fact", ""),   # case/whitespace status variants
    ("lead", ""), ("confirmed", ""), ("proven", ""),            # non-fact statuses
])
def test_SOVEREIGN_INVARIANT_status_spelling_cannot_launder_a_fact(tmp_path, bad_status, ev):
    """Finding-1 root-cause regression on the REAL spine: the whole class, not one spelling. A validly
    signed forged line whose ``facts[]`` carries a status variant with an empty/whitespace evidence ref is
    still un-rebuildable — the checkpoint facts-store soundness re-check catches every spelling."""
    kp = _kp()
    spine = _spine(tmp_path, kp, name=f"eng-{hash((bad_status, ev)) & 0xffff}.spine")
    good = spine.write_state(_state_with_fact(), seq=1)

    payload = json.loads(good.state_json)
    payload["facts"] = [{"ref": "f-laundered", "status": bad_status, "evidence_ref": ev}]
    sj = _canonical(payload)
    h = _content_hash(2, good.engagement, good.hash, sj)
    forged = SnapshotRecord(seq=2, hash=h, engagement=good.engagement, state_json=sj,
                            prev_hash=good.hash, signature_ref=spine.signer(h))
    spine.writer(forged)

    assert spine.verify() is True                          # the file is validly signed ...
    back = spine.rebuild()                                 # ... but the forgery cannot launder a fact
    assert [f.ref for f in back.facts] == ["f-sqli"], f"status={bad_status!r} laundered an evidence-less fact"
    assert back.facts[0].evidence_ref == "cert:evi-1"
    assert all(ld.ref != "f-laundered" for ld in back.leads), f"status={bad_status!r} downgraded to a lead"


# --- tamper / forgery detection ---------------------------------------------------------------------


def test_tampered_record_signature_is_rejected_on_rebuild_and_verify(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    spine.write_state(_state_with_fact(), seq=1)

    lines = _raw_lines(path)
    obj = json.loads(lines[0])
    sig = obj["record"]["signature_ref"]
    obj["record"]["signature_ref"] = sig[:-2] + ("AA" if not sig.endswith("AA") else "BB")   # flip the sig
    _rewrite(path, [_canonical(obj)])

    fresh = VigilCoreSpine(kp, path)
    assert fresh.verify() is False                         # the audit rejects a bad record signature
    assert fresh.rebuild().model_dump() == AgentState().model_dump()   # rebuild skips it → empty state


def test_tampered_record_bytes_break_the_digest_binding(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    spine.write_state(_state_with_fact(), seq=1)

    lines = _raw_lines(path)
    obj = json.loads(lines[0])
    obj["record"]["state_json"] = obj["record"]["state_json"] + "TAMPER"   # edit the record, keep cert_digest
    _rewrite(path, [_canonical(obj)])

    fresh = VigilCoreSpine(kp, path)
    assert fresh.verify() is False                         # cert_digest no longer binds the record bytes
    assert fresh.rebuild().model_dump() == AgentState().model_dump()   # and the record hash no longer recomputes


def test_deleted_middle_line_is_detected_by_verify(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    for i in range(1, 4):
        spine.write_state(AgentState(engagement_slug="e", iteration=i), seq=i)

    lines = _raw_lines(path)
    _rewrite(path, [lines[0], lines[2]])                   # excise the middle line (a deletion)

    fresh = VigilCoreSpine(kp, path)
    assert fresh.verify() is False                         # the vigil_core chain break is caught
    assert fresh.rebuild().iteration == 3                  # rebuild stays tolerant (latest valid still wins)


def test_reordered_lines_are_detected_by_verify(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    for i in range(1, 4):
        spine.write_state(AgentState(engagement_slug="e", iteration=i), seq=i)

    lines = _raw_lines(path)
    _rewrite(path, [lines[1], lines[0], lines[2]])         # swap the first two (a reorder)
    assert VigilCoreSpine(kp, path).verify() is False


def test_forged_entry_signature_without_the_key_fails_verify(tmp_path):
    """An attacker WITHOUT the signing key relinks/forges a chain entry and signs it with their OWN key.
    Our verifier uses OUR public key, so the forged entry signature fails — a relinked deletion cannot be
    hidden without the private key."""
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    spine.write_state(AgentState(engagement_slug="e", iteration=1), seq=1)

    attacker = generate_keypair()
    lines = _raw_lines(path)
    obj = json.loads(lines[0])
    # re-sign the SAME entry_hash with the attacker's key (a "valid signature by the wrong key")
    obj["signature"] = sv.sign(attacker.private_key_b64, obj["entry_hash"].encode("utf-8"))
    _rewrite(path, [_canonical(obj)])
    assert VigilCoreSpine(kp, path).verify() is False


def test_extra_field_on_a_persisted_line_is_rejected(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    spine.write_state(AgentState(engagement_slug="e", iteration=1), seq=1)
    lines = _raw_lines(path)
    obj = json.loads(lines[0])
    obj["smuggled"] = "extra"                              # SpineLine forbids extras
    _rewrite(path, [_canonical(obj)])
    assert VigilCoreSpine(kp, path).verify() is False


# --- fail-closed on a bad keypair -------------------------------------------------------------------


class _BadKey:
    public_key_b64 = ""
    private_key_b64 = ""


def test_bad_keypair_is_fail_closed(tmp_path):
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(_BadKey(), path)
    assert spine.signer("abc") == ""                       # no key → no signature (never fabricated)
    assert spine.verify_record("abc", "sig") is False      # no key → verify rejects
    with pytest.raises(SpineWriteError):                   # writer refuses to persist an unsigned append
        spine.writer(serialize(AgentState(engagement_slug="e"), seq=1, signer=spine.signer))
    assert not os.path.exists(path)                        # nothing partial was written


def test_write_state_fail_closed_leaves_no_partial_file(tmp_path):
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(_BadKey(), path)
    with pytest.raises(SpineWriteError):
        spine.write_state(AgentState(engagement_slug="e", iteration=1), seq=1)
    assert not os.path.exists(path)


# --- deny-by-default inherited from the checkpoint read path ----------------------------------------


def test_rebuild_denies_by_default_without_a_verifier(tmp_path):
    kp = _kp()
    spine = _spine(tmp_path, kp)
    spine.write_state(_state_with_fact(), seq=1)
    # reader wired but NO verifier and NO opt-out → deny-by-default: a fresh empty state
    assert rebuild_from(reader=spine.reader).model_dump() == AgentState().model_dump()
    # the spine's own rebuild() always wires verify_record, so it DOES reconstruct
    assert spine.rebuild().facts[0].ref == "f-sqli"


# --- engagement isolation ---------------------------------------------------------------------------


def test_engagement_isolation_on_one_file(tmp_path):
    kp = _kp()
    spine = _spine(tmp_path, kp)
    spine.write_state(_state_with_fact(slug="engagement-a"), seq=1)
    spine.write_state(AgentState(engagement_slug="engagement-b", iteration=99), seq=2)
    assert spine.verify() is True
    assert spine.rebuild().engagement_slug == "engagement-b"           # global latest wins unfiltered
    only_a = spine.rebuild(engagement="engagement-a")
    assert only_a.engagement_slug == "engagement-a"
    assert [f.ref for f in only_a.facts] == ["f-sqli"]                 # b's higher seq cannot contaminate a


# --- secret-free: the private key never touches disk ------------------------------------------------


def test_private_key_never_written_to_the_spine(tmp_path):
    kp = _kp()
    path = str(tmp_path / "eng.spine")
    spine = VigilCoreSpine(kp, path)
    for i in range(1, 4):
        spine.write_state(_state_with_fact(slug=f"eng-{i}"), seq=i)
    raw = open(path, "r", encoding="utf-8").read()
    assert kp.private_key_b64 not in raw                   # the signing key is never persisted
    # only the public-key-verifiable signatures appear; the raw private material is absent
    assert kp.public_key_b64 not in raw                    # nor is the pubkey embedded (only signatures are)


# --- determinism + spine-safety (no wallclock/RNG) --------------------------------------------------


def test_persisted_line_is_deterministic(tmp_path):
    kp = _kp()
    a = VigilCoreSpine(kp, str(tmp_path / "a.spine"))
    b = VigilCoreSpine(kp, str(tmp_path / "b.spine"))
    a.write_state(_state_with_fact(), seq=1)
    b.write_state(_state_with_fact(), seq=1)
    assert _raw_lines(str(tmp_path / "a.spine")) == _raw_lines(str(tmp_path / "b.spine"))


def test_module_uses_no_wallclock_or_rng():
    """Spine-safety on the AST: the module imports no wallclock/RNG source and calls no
    time/random/datetime/uuid/secrets API. The only temporal coordinates are the injected checkpoint
    ``seq`` and the deterministic monotonic ``vigil_core`` chain seq."""
    banned = {"time", "random", "datetime", "uuid", "secrets"}
    tree = ast.parse(inspect.getsource(sv))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not (banned & {n.name.split(".")[0] for n in node.names}), "imports a wallclock/RNG"
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in banned, "imports from a wallclock/RNG module"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id not in banned, f"calls into {node.value.id} (wallclock/RNG)"


def test_spineline_shape_is_strict():
    # a well-formed line coerces; an unexpected field is forbidden (tamper surface)
    ok = SpineLine(seq=0, cert_digest="d", entry_hash="e")
    assert ok.prev_hash == GENESIS_PREV and ok.signature == "" and ok.record == {}
    with pytest.raises(Exception):
        SpineLine.model_validate({"seq": 0, "cert_digest": "d", "entry_hash": "e", "x": 1})
