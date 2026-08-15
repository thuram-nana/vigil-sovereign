"""engage --resume (W2b): continue a prior run from its last SIGNED checkpoint instead of starting fresh.

Proven here (incl. the two red-pen BLOCKs, now driven off a REAL spine, not a fabricated seam):
  * resume seeds the loop from the checkpointed iteration and the monotonic seq at head_seq+1 (no seq
    collides an already-persisted turn), carrying prior facts/leads into the report;
  * a fresh run (the default) ignores the rebuild seam entirely;
  * a COMPLETED run PERSISTS done=True (terminal checkpoint) and a --resume off the real spine is a true
    no-op — the OODA loop never re-executes and no tool re-fires (BLOCK-1);
  * head_seq returns the SAME record rebuild returns — it never counts a record rebuild rejects (BLOCK-2);
  * fail-CLOSED: a restored state without a real seq, a raising/empty seam, all degrade to a fresh start;
  * head_seq + rebuild_head off a real spine are chain-contiguous across a fresh binder (the restart path).
"""
from __future__ import annotations

from types import SimpleNamespace

from vigil_core import generate_keypair
from vigil_integration.agent import checkpoint as cp
from vigil_integration.agent.checkpoint import GENESIS_PREV, SnapshotRecord, _content_hash
from vigil_integration.agent.state import ActionType, AgentState, Finding, LLMDecision, ToolCall
from vigil_integration.live.engine import EngineSeams, VigilEngine
from vigil_integration.live.spine_vigilcore import VigilCoreSpine
from vigil_integration.live.think_claude import ReplayThinker

TARGET = "http://127.0.0.1:18080/"


def _attest_allow(**kw):
    return SimpleNamespace(allowed=True, reason="attested",
                           attestation=SimpleNamespace(record_hash="att-" + "a" * 60))


def _complete():
    return LLMDecision(action=ActionType.COMPLETE, summary="done")


def _use_tool():
    return LLMDecision(action=ActionType.USE_TOOL,
                       tool=ToolCall(tool_name="nmap", tool_args={"target": TARGET}))


def _prior_state(iteration: int = 3) -> AgentState:
    st = AgentState(engagement_slug="loopback", iteration=iteration, objective="own the box")
    st.record_lead(Finding(ref="l-xss", bug_class="xss", title="reflected xss?", severity="medium",
                           source="zap"))
    return st


def _engine(seams: EngineSeams, **kw) -> VigilEngine:
    return VigilEngine(slug="loopback", seams=seams, max_iterations=kw.pop("max_iterations", 6), **kw)


# --- resume seeding (injected (state, head_seq) seam) ----------------------------------------------
def test_resume_continues_from_the_checkpointed_iteration_and_carries_progress():
    prior = _prior_state(iteration=3)
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: (prior, 7))            # ONE read → (state, head_seq)
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is True
    # a COMPLETE-first run from iteration 4 (prior.iteration+1) reports iterations == 5 — NOT 1 (fresh).
    assert rep.iterations == 5
    assert any(ld.ref == "l-xss" for ld in rep.leads)         # the report reflects total progress


def test_fresh_start_ignores_the_rebuild_seam():
    prior = _prior_state(iteration=3)
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: (prior, 7))
    rep = _engine(seams).engage(TARGET)                        # resume defaults False
    assert rep.resumed is False
    assert rep.iterations == 1                                 # started at iteration 0
    assert not rep.leads


def test_resume_fails_closed_when_a_restored_state_has_no_real_seq():
    # head_seq==0 for a non-empty state is an inconsistency → do NOT reseed seq=1 and collide; fall back
    # to a fresh start (fail-closed, not a partial resume).
    prior = _prior_state(iteration=3)
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: (prior, 0))
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is False                                # refused the partial resume
    assert rep.iterations == 1                                 # fresh start


def test_resume_of_a_paused_at_zero_run_resumes_honestly():
    # a run that paused at iteration 0 (awaiting approval, no facts/leads/trace) is real progress: resume
    # must continue it (resumed=True, seeded at head_seq+1), not silently start fresh.
    prior = AgentState(engagement_slug="loopback", iteration=0)
    prior.awaiting_approval = True
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: (prior, 1))
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is True


def test_resume_with_no_prior_state_degrades_to_a_fresh_start():
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]),
                        rebuild=lambda: (AgentState(), 0))
    rep = _engine(seams).engage(TARGET, resume=True)
    assert rep.resumed is False
    assert rep.iterations == 1


def test_resume_survives_a_rebuild_seam_that_raises():
    def _boom():
        raise RuntimeError("spine unreadable")
    seams = EngineSeams(attest=_attest_allow, think=ReplayThinker([_complete()]), rebuild=_boom)
    rep = _engine(seams).engage(TARGET, resume=True)           # must not crash
    assert rep.refused is False
    assert rep.iterations == 1                                 # degraded to a fresh start


# --- BLOCK-1: a COMPLETED run persists done and resume is a REAL no-op (real signed spine) ----------
def test_completed_run_persists_done_and_resume_off_the_real_spine_is_a_noop(tmp_path):
    kp = generate_keypair()
    path = str(tmp_path / "loopback.spine")
    ran = {"n": 0}

    def _run_tool(tool, phase, seq, **kw):
        ran["n"] += 1
        return SimpleNamespace(ran=True, outcome="ran", stdout="x", stderr="", tool=tool.tool_name,
                               tier="A1", target="127.0.0.1", destructive=False,
                               record=SimpleNamespace(record_id="r%d" % ran["n"]))

    def _mk(think, sp):
        # a fresh spine binder per engine = a real restart; the checkpoint + rebuild seams share the file.
        return VigilEngine(slug="loopback", max_iterations=6, seams=EngineSeams(
            attest=_attest_allow, think=think,
            gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
            run_tool=_run_tool,
            checkpoint=lambda st, sq: sp.write_state(st, seq=sq, engagement="loopback"),
            rebuild=lambda: sp.rebuild_head(engagement="loopback")))

    # run 1: a tool, then COMPLETE early (iteration 1 of 6) — the case the red-pen proved re-fired offense.
    rep1 = _mk(ReplayThinker([_use_tool(), _complete()]), VigilCoreSpine(kp, path)).engage(TARGET)
    assert rep1.done is True
    assert ran["n"] >= 1
    # the terminal checkpoint persisted done=True to the REAL spine (a fresh binder sees it)
    restored, hs = VigilCoreSpine(kp, path).rebuild_head(engagement="loopback")
    assert restored.done is True and hs >= 1

    # run 2: --resume off the SAME spine (fresh binder) — a REAL no-op: loop never runs, NO tool re-fires.
    before = ran["n"]
    rep2 = _mk(ReplayThinker([_use_tool()]), VigilCoreSpine(kp, path)).engage(TARGET, resume=True)
    assert rep2.resumed is True
    assert rep2.done is True
    assert not rep2.tool_calls
    assert ran["n"] == before                                 # offense did NOT re-fire after completion


# --- BLOCK-2: head_seq returns the SAME record rebuild returns (never one rebuild rejects) ----------
def test_head_seq_never_counts_a_record_rebuild_rejects():
    good = cp.serialize(AgentState(engagement_slug="e", iteration=2), seq=2,
                        signer=lambda h: "sig", prev_hash=GENESIS_PREV, engagement="e")
    # a record that is INTACT (its content hash recomputes) but whose state_json will NOT load into a
    # sound AgentState (facts must be a list) — exactly the divergence the red-pen found: head_seq used to
    # count this higher-seq record that rebuild rejects. It must not.
    bad_json = '{"facts": "not-a-list"}'
    bad_hash = _content_hash(9, "e", good.hash, bad_json)
    bad = SnapshotRecord(seq=9, engagement="e", prev_hash=good.hash, state_json=bad_json,
                         hash=bad_hash, signature_ref="sig")
    recs = [good, bad]
    assert cp.rebuild(recs, engagement="e", trust_unverified=True).iteration == 2
    assert cp.head_seq(recs, engagement="e", trust_unverified=True) == 2      # NOT 9
    # rebuild_head returns the SAME (state, seq) pair — parity by construction
    st, sq = cp.rebuild_head(recs, engagement="e", trust_unverified=True)
    assert st.iteration == 2 and sq == 2


# --- head_seq / rebuild_head off a REAL spine file (the actual crash/restart path) ------------------
def test_rebuild_head_is_chain_contiguous_across_a_fresh_binder(tmp_path):
    kp = generate_keypair()
    path = str(tmp_path / "eng.spine")
    s1 = VigilCoreSpine(kp, path)
    for i in (1, 2, 3):
        s1.write_state(AgentState(engagement_slug="e", iteration=i), seq=i, engagement="e")
    st, sq = VigilCoreSpine(kp, path).rebuild_head(engagement="e")   # fresh binder = restart
    assert st.iteration == 3 and sq == 3
    # continue at head_seq+1 — contiguous; a third binder sees it
    VigilCoreSpine(kp, path).write_state(AgentState(engagement_slug="e", iteration=4), seq=4, engagement="e")
    st2, sq2 = VigilCoreSpine(kp, path).rebuild_head(engagement="e")
    assert st2.iteration == 4 and sq2 == 4
    assert VigilCoreSpine(kp, path).rebuild_head(engagement="other") == (AgentState(), 0) or \
        VigilCoreSpine(kp, path).rebuild_head(engagement="other")[1] == 0   # unrelated slug: no head


def test_rebuild_head_is_empty_on_an_empty_spine(tmp_path):
    st, sq = VigilCoreSpine(generate_keypair(), str(tmp_path / "empty.spine")).rebuild_head()
    assert sq == 0 and st.iteration == 0
