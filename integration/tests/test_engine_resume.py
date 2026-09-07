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
from vigil_integration.live.engine import _MAX_IDENTICAL_REPROPOSALS, EngineSeams, VigilEngine
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


# --- BLOCK-3 (finding #3): RUN-scoped checkpoint partitions — a PAUSED run resumes to ITS OWN state, never
# a sibling/foreign COMPLETED run's done=True head that shares the same per-slug {slug}.spine file. Before the
# fix, checkpoint/rebuild keyed the partition by the SLUG ("loopback" for every loopback run), so a paused
# run's --resume read the GLOBAL-latest loopback snapshot (a prior completed run, done=True) and NO-OP'd.
def test_run_keyed_partition_lets_a_paused_run_resume_over_a_completed_siblings_head(tmp_path):
    kp = generate_keypair()
    path = str(tmp_path / "loopback.spine")           # ONE shared per-slug spine file for BOTH runs
    ran = {"n": 0}

    def _run_tool(tool, phase, seq, **kw):
        ran["n"] += 1
        return SimpleNamespace(ran=True, outcome="ran", stdout="x", stderr="", tool=tool.tool_name,
                               tier="A1", target="127.0.0.1", destructive=False,
                               record=SimpleNamespace(record_id="r%d" % ran["n"]))

    def _allow(*a):
        return SimpleNamespace(allowed=True, outcome="allow", reason="ok")

    def _queue(*a):
        return SimpleNamespace(allowed=False, outcome="queue", reason="A2 requires owner approval")

    def _mk(think, sp, key, *, gate=_allow, approval=None):
        # a fresh spine binder per engine = a real restart; the WRITE + READ seams share ONE file but are
        # partitioned by `key` (the run_key). approval=None ⇒ a queued tool stays unapproved (pauses).
        return VigilEngine(slug="loopback", max_iterations=6, seams=EngineSeams(
            attest=_attest_allow, think=think, gate=gate, run_tool=_run_tool, approval=approval,
            checkpoint=lambda st, sq: sp.write_state(st, seq=sq, engagement=key),
            rebuild=lambda: sp.rebuild_head(engagement=key)))

    # run A (run_key "RA"): a tool then COMPLETE — done=True at a HIGH seq into loopback.spine.
    repA = _mk(ReplayThinker([_use_tool(), _complete()]), VigilCoreSpine(kp, path), "RA").engage(TARGET)
    assert repA.done is True

    # run B (run_key "RB"): the gate QUEUEs + no approval → PAUSE at awaiting_approval, a LOW seq, SAME file.
    repB = _mk(ReplayThinker([_use_tool()]), VigilCoreSpine(kp, path), "RB",
               gate=_queue, approval=lambda *a: False).engage(TARGET)
    assert repB.paused == "awaiting_approval" and repB.done is False
    b_fired_at_pause = ran["n"]                        # exactly A's one tool; B fired none (queued upstream)

    # ISOLATION over ONE file: RB reads B's PAUSED state; RA reads A's DONE state; and the BARE-SLUG partition
    # is EMPTY — both runs wrote under their run_key, NOT the slug. That emptiness is the direct proof the fix
    # keys by run_key (a slug-keyed regression would put both runs in the "loopback" partition).
    b_state, b_hs = VigilCoreSpine(kp, path).rebuild_head(engagement="RB")
    a_state, a_hs = VigilCoreSpine(kp, path).rebuild_head(engagement="RA")
    slug_state, slug_hs = VigilCoreSpine(kp, path).rebuild_head(engagement="loopback")
    assert b_state.awaiting_approval is True and b_state.done is False, "RB partition = B's OWN paused state"
    assert a_state.done is True, "RA partition = A's completed state"
    assert a_hs >= b_hs, "A completed at a seq >= B's pause"
    assert slug_hs == 0 and slug_state.done is False, "bare-slug partition is EMPTY — writes are run-keyed, not slug-keyed"

    # PRE-FIX BUG demonstration: had both runs written under the SLUG (the old key), a slug read returns the
    # GLOBAL-latest (A' completed, done=True) even when we mean to resume B' — so B's slug-keyed resume hits
    # the done-guard and NO-OPs. This is exactly finding #3, reproduced on a separate file.
    old = str(tmp_path / "old-slugkeyed.spine")
    _mk(ReplayThinker([_use_tool(), _complete()]), VigilCoreSpine(kp, old), "loopback").engage(TARGET)      # A' done
    _mk(ReplayThinker([_use_tool()]), VigilCoreSpine(kp, old), "loopback",
        gate=_queue, approval=lambda *a: False).engage(TARGET)                                              # B' paused
    old_state, _old_hs = VigilCoreSpine(kp, old).rebuild_head(engagement="loopback")
    assert old_state.done is True, "PRE-FIX: a shared slug partition returns A's done=True — B's resume would no-op"

    # RESUME B off ITS OWN partition (approval now satisfied) → the OODA loop RE-ENTERS, re-proposes, the
    # previously-queued tool FIRES exactly once (approval now True). This is the finding-#3 fix end to end.
    before = ran["n"]
    repB2 = _mk(ReplayThinker([_use_tool(), _complete()]), VigilCoreSpine(kp, path), "RB",
                gate=_allow, approval=lambda *a: True).engage(TARGET, resume=True)
    assert repB2.resumed is True, "resume restored B's OWN paused state (not a no-op off A's done head)"
    assert repB2.decisions, "the OODA loop re-entered (non-empty decisions) instead of the 12-empty-iteration no-op"
    assert ran["n"] > before, "the previously-queued tool fired on resume once approval was satisfied"


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


# --- BLOCK-4 (finding #1): ANTI-SPIN — a run that re-proposes the IDENTICAL action must STOP, not flood ----
def _ran_ns(tool):
    return SimpleNamespace(ran=True, outcome="ran", stdout="x", stderr="", tool=tool.tool_name,
                           tier="A1", target="127.0.0.1", destructive=False,
                           record=SimpleNamespace(record_id="r"))


def _refused_ns(tool):
    # the executor HARD-refused the tool (out of scope) — ran=False, no progress, and NOT an approval pause
    # (a needs-owner-approval refusal now PAUSES at awaiting_approval instead — see
    # test_executor_deny_awaiting_approval_pauses_resumably_not_antispin). A hard-refused identical action
    # still accumulates toward anti-spin.
    return SimpleNamespace(ran=False, outcome="", stdout="", stderr="",
                           reason="authorization denied: target out of scope (fail-closed)",
                           tool=tool.tool_name, record=SimpleNamespace(record_id="r"))


def test_anti_spin_stops_a_run_that_re_proposes_a_REFUSED_identical_action():
    # the executor HARD-refuses the identical action every turn (out of scope — NOT a needs-approval pause),
    # so it never advances → the counter accumulates → the run STOPS as PAUSED anti-spin. (A needs-owner-
    # approval refusal instead pauses at awaiting_approval so the operator can sign + resume.)
    tries = {"n": 0}
    def _run_refused(tool, phase, seq, **kw):
        tries["n"] += 1
        return _refused_ns(tool)
    rep = VigilEngine(slug="loopback", max_iterations=8, seams=EngineSeams(
        attest=_attest_allow, think=lambda st: _use_tool(),                       # ALWAYS the identical action
        gate=lambda *a: SimpleNamespace(allowed=False, outcome="queue", reason="A2 requires owner approval"),
        approval=lambda *a: True,                                                 # reach execute; executor refuses
        run_tool=_run_refused)).engage(TARGET)
    assert rep.iterations <= _MAX_IDENTICAL_REPROPOSALS + 1, f"anti-spin did not stop the refused spin ({rep.iterations})"
    assert rep.decisions[-1] == "stopped(anti-spin)"
    assert rep.paused == "anti-spin"                            # a give-up is marked distinctly, NOT as done
    assert rep.done is False                                    # ...so it is NOT mistaken for objective-met
    assert tries["n"] <= _MAX_IDENTICAL_REPROPOSALS + 1         # the refused tool was not attempted 8 times


def test_an_already_run_action_is_SKIPPED_not_re_refused():
    # Operator ask: re-proposing a tool that ALREADY RAN must NOT surface "refused by executor" (its spent
    # single-use approval would otherwise deny it). The engine runs it ONCE, then SKIPS the duplicates —
    # a benign skip, never a refusal, never a second execution, and it never trips anti-spin as a "stop".
    ran = {"n": 0}
    def _run_ok(tool, phase, seq, **kw):
        ran["n"] += 1
        return _ran_ns(tool)
    rep = VigilEngine(slug="loopback", max_iterations=5, seams=EngineSeams(
        attest=_attest_allow, think=lambda st: _use_tool(),          # ALWAYS the identical action
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_ok)).engage(TARGET)
    assert ran["n"] == 1, "the identical action must run exactly ONCE — duplicates are skipped, not re-run"
    assert "skip(already-ran)" in rep.decisions, "the duplicate re-proposals must be SKIPPED"
    assert "stopped(anti-spin)" not in rep.decisions            # a skip is not an anti-spin give-up
    assert not rep.denied_edges, "a skipped duplicate must NEVER show as refused/denied"


def test_anti_spin_does_not_trip_on_varied_actions():
    # distinct target each turn (distinct signatures) then an explicit complete — the guard must NOT fire.
    varied = [LLMDecision(action=ActionType.USE_TOOL,
                          tool=ToolCall(tool_name="httpx", tool_args={"url": f"http://127.0.0.1:18080/p{i}"}))
              for i in range(4)] + [_complete()]
    rep = VigilEngine(slug="loopback", max_iterations=8, seams=EngineSeams(
        attest=_attest_allow, think=ReplayThinker(varied),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=lambda tool, phase, seq, **kw: _ran_ns(tool))).engage(TARGET)
    assert "stopped(anti-spin)" not in rep.decisions, "anti-spin wrongly tripped on VARIED actions"
    assert rep.done is True                                     # completed via the explicit _complete()


# --- awaiting-approval pause (approve-then-continue fix) -------------------------------------------
def test_executor_deny_awaiting_approval_pauses_resumably_not_antispin():
    """When the executor denies because the action needs a SIGNED owner approval (the WARDEN queue
    condition — pending already published), the engine PAUSES at awaiting_approval on the FIRST deny, so the
    operator can sign + RESUME. It must NOT let the model re-propose the identical tool into anti-spin (which
    killed approve-then-continue right as the signature landed)."""
    calls = {"n": 0}

    def _run_tool(tool, phase, seq, **kw):
        calls["n"] += 1
        return SimpleNamespace(
            ran=False, outcome="deny", tool=tool.tool_name, record=None,
            reason="authorization denied: in envelope, but WARDEN needs owner approval: "
                   "A2 requires owner approval (>= A2 or above the offense ceiling A1)")

    seams = EngineSeams(
        attest=_attest_allow,
        think=ReplayThinker([_use_tool(), _use_tool(), _use_tool(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_tool)
    rep = _engine(seams).engage(TARGET)
    assert rep.paused == "awaiting_approval", f"expected awaiting_approval, got {rep.paused!r}"
    assert calls["n"] == 1, f"paused on the FIRST deny, not after re-proposing (ran {calls['n']}x)"


def test_hard_deny_is_not_treated_as_an_approval_pause():
    """A HARD deny (out of scope / kill-switch) is NOT an approval pause — the run must not stop at
    awaiting_approval for it (it pivots / eventually anti-spins), so a real refusal is never mistaken for
    'waiting for your signature'."""
    def _run_tool(tool, phase, seq, **kw):
        return SimpleNamespace(ran=False, outcome="deny", tool=tool.tool_name, record=None,
                               reason="authorization denied: target out of scope (fail-closed)")
    seams = EngineSeams(
        attest=_attest_allow,
        think=ReplayThinker([_use_tool(), _use_tool(), _use_tool(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_tool)
    rep = _engine(seams).engage(TARGET)
    assert rep.paused != "awaiting_approval", "a hard deny must not pause as awaiting_approval"


def test_is_awaiting_approval_denial_helper():
    from vigil_integration.live.engine import _is_awaiting_approval_denial
    assert _is_awaiting_approval_denial("... WARDEN needs owner approval: A2 requires owner approval")
    assert _is_awaiting_approval_denial("A2 requires owner approval (>= A2 ...)")
    assert not _is_awaiting_approval_denial("target out of scope")
    assert not _is_awaiting_approval_denial("kill-switch tripped")
    assert not _is_awaiting_approval_denial("")


# --- ENH1: a FOUND-but-REJECTED approval pauses DISTINCTLY (approval_rejected), not awaiting -------
def test_executor_reject_pauses_approval_rejected():
    """When the executor denies because a FOUND owner-signed token was REJECTED (expired / already spent —
    the M2 gate's approval_rejected marker), the engine pauses at 'approval_rejected' on the FIRST deny (so
    the operator is told to APPROVE AGAIN), never the generic 'awaiting_approval' invisible loop."""
    calls = {"n": 0}

    def _run_tool(tool, phase, seq, **kw):
        calls["n"] += 1
        return SimpleNamespace(
            ran=False, outcome="deny", tool=tool.tool_name, record=None,
            reason="authorization denied: owner approval rejected: your last approval expired or was "
                   "already used — approve again")

    seams = EngineSeams(
        attest=_attest_allow,
        think=ReplayThinker([_use_tool(), _use_tool(), _use_tool(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_tool)
    rep = _engine(seams).engage(TARGET)
    assert rep.paused == "approval_rejected", f"expected approval_rejected, got {rep.paused!r}"
    assert calls["n"] == 1, f"paused on the FIRST deny, not after re-proposing (ran {calls['n']}x)"
    assert rep.done is False


def test_no_token_deny_pauses_awaiting_not_rejected():
    """NEGATIVE CONTROL: a WARDEN 'needs owner approval' deny (NO token yet) still pauses at
    awaiting_approval, NOT approval_rejected — the two are distinct and the ordering never misclassifies."""
    def _run_tool(tool, phase, seq, **kw):
        return SimpleNamespace(ran=False, outcome="deny", tool=tool.tool_name, record=None,
                               reason="authorization denied: in envelope, but WARDEN needs owner approval: "
                                      "A2 requires owner approval (>= A2 or above the offense ceiling A1)")
    seams = EngineSeams(
        attest=_attest_allow,
        think=ReplayThinker([_use_tool(), _use_tool(), _use_tool(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_tool)
    rep = _engine(seams).engage(TARGET)
    assert rep.paused == "awaiting_approval", f"a no-token deny must stay awaiting_approval, got {rep.paused!r}"


def test_rejected_first_ordering_wins_over_awaiting_substring():
    """A reason that contains BOTH the approval_rejected marker AND the WARDEN 'requires owner approval'
    phrase must resolve to approval_rejected — the engine's rejected-FIRST check ORDERING (not string
    disjointness) is the guarantee (a consume key-id-mismatch reason can legitimately carry 'owner approval')."""
    def _run_tool(tool, phase, seq, **kw):
        return SimpleNamespace(ran=False, outcome="deny", tool=tool.tool_name, record=None,
                               reason="authorization denied: owner approval rejected: ... A2 requires owner approval")
    seams = EngineSeams(
        attest=_attest_allow,
        think=ReplayThinker([_use_tool(), _use_tool(), _use_tool(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        run_tool=_run_tool)
    rep = _engine(seams).engage(TARGET)
    assert rep.paused == "approval_rejected", f"rejected-first ordering must win, got {rep.paused!r}"


def test_is_rejected_approval_denial_helper():
    from vigil_integration.live.engine import _is_rejected_approval_denial, _is_awaiting_approval_denial
    r = "authorization denied: owner approval rejected: your last approval expired or was already used"
    assert _is_rejected_approval_denial(r)
    assert not _is_rejected_approval_denial("authorization denied: A2 requires owner approval")
    # a both-marker reason: rejected matches; awaiting also matches its own phrase — the ENGINE resolves by
    # checking rejected FIRST (see test_rejected_first_ordering_wins_over_awaiting_substring).
    both = "authorization denied: owner approval rejected: ... A2 requires owner approval"
    assert _is_rejected_approval_denial(both) and _is_awaiting_approval_denial(both)


# --- Phase 3: deploy_fireteam is approve-then-run (pauses without approval, deploys with it) --------
def test_deploy_fireteam_pauses_without_approval_then_deploys_with_it():
    from vigil_integration.agent.state import ActionType, LLMDecision
    ft = [{"member_id": "m1", "role": "auth", "capped_tier": "A1", "tools": ["httpx"]}]

    def _dep():
        return LLMDecision(action=ActionType.DEPLOY_FIRETEAM, fireteam=ft)

    def _outcome():
        return SimpleNamespace(facts=[], leads=[], escalations=[], spine_refs=[], refused=False)

    # (a) NO approval → pause at awaiting_approval; the fan-out must NOT deploy.
    calls = {"n": 0}
    seams = EngineSeams(
        attest=_attest_allow, think=ReplayThinker([_dep(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        approval=lambda *a: False,
        deploy_fireteam=lambda d, s, seq: (calls.__setitem__("n", calls["n"] + 1) or _outcome()))
    rep = _engine(seams).engage(TARGET)
    assert rep.paused == "awaiting_approval", f"a deploy_fireteam without approval must pause, got {rep.paused!r}"
    assert calls["n"] == 0, "the fan-out must NOT deploy without a signed approval"

    # (b) approval satisfied → the fan-out runs exactly once (approve-then-run).
    calls2 = {"n": 0}
    seams2 = EngineSeams(
        attest=_attest_allow, think=ReplayThinker([_dep(), _complete()]),
        gate=lambda *a: SimpleNamespace(allowed=True, outcome="allow", reason="ok"),
        approval=lambda *a: True,
        deploy_fireteam=lambda d, s, seq: (calls2.__setitem__("n", calls2["n"] + 1) or _outcome()))
    rep2 = _engine(seams2).engage(TARGET)
    assert calls2["n"] == 1, "an approved deploy_fireteam must run the fan-out exactly once"
    assert rep2.done is True
