"""INV4 — REAL Anthropic reachability, proven to stay ORACLE-GATED and SOVEREIGNTY-GATED.

The investor-deploy question this closes is narrow and concrete: *when a real Anthropic key is wired and
``vigil engage``'s think step actually calls the model, is the sovereign contract still intact?* Three
properties, each asserted against the SAME real ``think()`` seam the engine runs:

  (a) a PROPOSAL returns — one real Messages call reaches the model and yields an ``LLMDecision`` (never a
      raise, never a transport fail-close); and
  (b) the deterministic ORACLE STILL GATES it — that proposal, by itself, mints NO ``FACT``. Even the
      model's strongest possible claim (``exploit_succeeded=True``) is only a LEAD until a deterministic
      oracle re-fires; with no oracle wired, nothing is a fact (fail-closed). The mutation control shows a
      fired oracle is what turns the same claim into a fact — so the authority is the oracle, not the model;
  (c) ``AIR_GAPPED`` refuses the egress BEFORE the Anthropic SDK is imported or a socket is opened — the
      real key is present, the tier is flipped, and the client-construction chokepoint (``_build_live_client``,
      which both imports ``anthropic`` and constructs the networked client) is a trip-wire that must never
      fire. Same SHAPE as (a) — real key, real seam — with the tier the only difference, so it is the
      safe negative control for the positive: the identical call that egresses under PERMISSIVE must NOT
      egress under AIR_GAPPED, and must flag nothing.

The keyed tests (a), (b-over-the-real-decision) and the keyed negative control SKIP cleanly when no
``ANTHROPIC_API_KEY`` is set and are behind the ``keyed`` marker, so the default CI leg is unaffected (it
has no key → they skip). The oracle-gating KEYSTONE (b) and an AIR_GAPPED refusal with a FAKE key run
ALWAYS — they need no network — so every PR still exercises the gating wiring and the safe negative.

FATAL-2 is re-asserted out of band by ``integration/tests/test_two_env_boundary.py`` (run alongside this
file): the offense/engine side imports no ``vigil_integration`` and holds no owner key; the only secret this
path ever touches is ``ANTHROPIC_API_KEY``, forwarded to the SDK constructor and never logged or spined.
"""

from __future__ import annotations

import os

import pytest

from vigil_integration.agent import (
    ActionType,
    AgentState,
    IntakeResult,
    LLMDecision,
    OutputAnalysis,
    Phase,
    intake_result,
)
from vigil_integration.live import think_claude
from vigil_integration.live.think_claude import think

_TIER_ENV = "CRUCIBLE_SOVEREIGNTY_TIER"
_LEGACY_ENV = "CRUCIBLE_SOVEREIGN_MODE"
_KEY_ENV = "ANTHROPIC_API_KEY"

# Skip the network-touching tests cleanly when no real key is wired (default CI). Evaluated at collection
# time against the ambient environment — exactly what "keyed" means.
_requires_key = pytest.mark.skipif(
    not (os.environ.get(_KEY_ENV) or "").strip(),
    reason="no ANTHROPIC_API_KEY — the real-reachability tests are keyed + marker-gated (skip is clean)",
)


@pytest.fixture()
def state() -> AgentState:
    return AgentState(engagement_slug="inv4-reachability",
                      objective="probe http://127.0.0.1:18080/ for a web misconfiguration",
                      phase=Phase.INFORMATIONAL)


@pytest.fixture(autouse=True)
def _clean_sovereignty_env(monkeypatch):
    """Each test states its own tier; clear any ambient tier/seal + the injected policy holder. The real
    ``ANTHROPIC_API_KEY`` is deliberately LEFT ALONE so the keyed tests can make a genuine call; the tests
    that must run keyless/faked set the key themselves (monkeypatch wins over the ambient value)."""
    try:
        from framework.v2.kernel import sovereignty
    except Exception:  # noqa: BLE001 — framework not importable here ⇒ env-only clean is enough
        sovereignty = None
    for var in (_TIER_ENV, _LEGACY_ENV, "CRUCIBLE_SOVEREIGNTY_SEALED", "CRUCIBLE_ANTHROPIC_ZDR"):
        monkeypatch.delenv(var, raising=False)
    if sovereignty is not None:
        sovereignty.set_policy(None)
    yield
    if sovereignty is not None:
        sovereignty.set_policy(None)


@pytest.fixture()
def no_client_may_be_built(monkeypatch):
    """Trip-wire at the exact chokepoint where the ``anthropic`` SDK is imported and the networked client is
    constructed. A sovereignty refusal must happen strictly BEFORE this point — if it fires, egress began."""
    def _boom(_key):
        raise AssertionError(
            "a live Claude client was constructed (anthropic imported + socket about to open) despite the "
            "refusal path — EGRESS")
    monkeypatch.setattr(think_claude, "_build_live_client", _boom)


# ---------------------------------------------------------------------------------------------------
# (a) + (c-same-shape): a REAL call returns a proposal under PERMISSIVE; the identical call is REFUSED
#     under AIR_GAPPED before any socket — these two are each other's control (tier is the only change).
# ---------------------------------------------------------------------------------------------------


@pytest.mark.keyed
@_requires_key
def test_real_think_call_returns_a_proposal(state, monkeypatch):
    """(a) ONE real Messages call is made through the production ``think()`` seam (no injected client), so it
    exercises the real key path → ``_build_live_client`` → ``anthropic.Anthropic`` → a streamed/plain
    Messages call. It always returns a non-authoritative ``LLMDecision`` (``think`` is total — it never
    raises), and it stays secret-free.

    Reachability is asserted HONESTLY against what the wired key actually permits:
      * a VALID key → ``error_class == ""`` and a usable proposal of the documented shape (the ideal path);
      * a key PRESENT BUT REJECTED by Anthropic → ``error_class == "api"``: the request provably LEFT THE
        HOST and Anthropic answered (an ``AuthenticationError`` / permission error can only originate
        server-side), so the gated real-SDK egress path is exercised AND ``think`` fail-closed to the inert
        ASK_USER pause rather than raising or synthesising an action-bearing edge. Both outcomes are
        sound reachability evidence; a ``network`` fail-close (nothing reached Anthropic) SKIPS."""
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")      # explicit: permit the egress regardless of ambient
    key = (os.environ.get(_KEY_ENV) or "").strip()

    decision = think(state, {"prior": "httpx banner: nginx/1.25.0 on http://127.0.0.1:18080/"},
                     max_tokens=1024)

    # `think` is TOTAL: a proposal of the documented shape always comes back (never a raise).
    assert isinstance(decision, LLMDecision)
    assert isinstance(decision.action, ActionType)
    # Secret-free on EVERY outcome: the key never surfaces in the operator-facing proposal text.
    blob = f"{decision.reasoning} {decision.question} {decision.summary}"
    assert key and key not in blob

    if decision.error_class == "network":
        pytest.skip("nothing reached Anthropic (network fail-close) — cannot assert reachability here")
    if decision.error_class == "api":
        # The key was present but rejected server-side: the request reached Anthropic (reachability proven)
        # and the think seam fail-closed to the inert human pause — never an action-bearing edge from a
        # failed call.
        assert decision.action == ActionType.ASK_USER
        return
    # A valid key: a real, usable proposal came back with no backend error.
    assert decision.error_class == ""


@pytest.mark.keyed
@_requires_key
def test_real_key_under_air_gapped_refuses_before_any_socket(state, monkeypatch, no_client_may_be_built):
    """(c) SAME SHAPE as the positive — the real key is present and the real seam is used — but the tier is
    AIR_GAPPED. The call must be REFUSED before the SDK is imported or a socket opens: the client-construction
    trip-wire never fires, the decision is the inert human pause naming the tier, and the key never leaks.
    This is the safe negative control for the positive above (tier is the only difference)."""
    key = (os.environ.get(_KEY_ENV) or "").strip()
    assert key, "keyed test precondition: a real key must be present"
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    decision = think(state, {"prior": "httpx banner: nginx"}, max_tokens=1024)

    assert decision.action == ActionType.ASK_USER                 # inert pause, never an action-bearing edge
    blob = f"{decision.reasoning} {decision.question}"
    assert "AIR_GAPPED" in blob and _TIER_ENV in blob             # names the tier + how to change it
    assert key not in blob                                        # still secret-free
    # no_client_may_be_built proves _build_live_client (anthropic import + socket) was never reached.


# ---------------------------------------------------------------------------------------------------
# (b) the ORACLE is the sole authority: the model's proposal — real or maximal — mints NO fact on its own.
# ---------------------------------------------------------------------------------------------------


@pytest.mark.keyed
@_requires_key
def test_the_real_proposal_mints_no_fact_without_an_oracle(state, monkeypatch):
    """(b), over the REAL decision: take whatever the live model proposed and run its inline analysis
    through the intake keystone with NO oracle wired. The result carries ZERO facts — the model's own
    proposal can never be a fact. (Leads are fine; a fact is not.)"""
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    decision = think(state, {"prior": "httpx banner: nginx/1.25.0"}, max_tokens=1024)
    assert isinstance(decision, LLMDecision)

    result = intake_result("<raw tool output the model never saw>", decision.output_analysis, oracle=None)
    assert isinstance(result, IntakeResult)
    assert result.facts == [], "the live model's proposal minted a FACT with no oracle — oracle authority broken"


def test_oracle_gating_keystone_is_load_bearing():
    """(b) KEYSTONE — runs ALWAYS (no network), so every PR exercises the gating wiring. Even the model's
    STRONGEST claim (exploit_succeeded=True) is only a LEAD with no oracle; a FIRED oracle (returning a
    signed evidence ref) is what turns the SAME claim into a FACT. The pair is the mutation control that
    proves the authority is the deterministic oracle, not the proposal."""
    maximal_claim = OutputAnalysis(exploit_succeeded=True,
                                   extracted_info={"bug_class": "open_redirect"},
                                   findings=[{"title": "the model is sure it popped"}])

    # No oracle wired → fail-closed: the maximal claim yields a LEAD, never a FACT.
    without = intake_result("raw", maximal_claim, oracle=None)
    assert without.facts == []
    assert any(f.status == "lead" for f in without.leads)

    # A fired deterministic oracle (returns a signed evidence ref) → the SAME claim becomes a FACT.
    def _fired_oracle(_raw: str, _analysis: OutputAnalysis):
        return "web:open_redirect:deadbeef"      # a signed-evidence-ref shape the re-drive would mint

    with_oracle = intake_result("raw", maximal_claim, oracle=_fired_oracle)
    assert len(with_oracle.facts) == 1
    fact = with_oracle.facts[0]
    assert fact.status == "fact" and fact.evidence_ref == "web:open_redirect:deadbeef"
    assert fact.bug_class == "open_redirect"     # labelled by the class the ORACLE confirmed


def test_air_gapped_refuses_before_sdk_socket_with_a_fake_key(state, monkeypatch, no_client_may_be_built):
    """(c) the ALWAYS-ON safe negative control (no network, no real key needed): an AIR_GAPPED tier with a
    key present must refuse before the SDK/socket chokepoint. A FAKE key overrides any ambient real key, so
    this never egresses even on a box where a real key is set. This keeps the refusal wiring under test on
    every PR, next to the keyless-boundary proof."""
    monkeypatch.setenv(_KEY_ENV, "sk-ant-not-a-real-key")     # override the ambient real key — stays offline
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    decision = think(state, {"prior": "x"}, max_tokens=256)

    assert decision.action == ActionType.ASK_USER
    blob = f"{decision.reasoning} {decision.question}"
    assert "AIR_GAPPED" in blob and _TIER_ENV in blob
    assert "sk-ant-not-a-real-key" not in blob               # secret-free
    # no_client_may_be_built proves no client was constructed (no anthropic import, no socket).


def test_legacy_air_gapped_flag_also_refuses_before_socket(state, monkeypatch, no_client_may_be_built):
    """(c) defense in depth: the legacy binary ``CRUCIBLE_SOVEREIGN_MODE`` alias for AIR_GAPPED refuses the
    real key path too — an operator who set it long ago gets the LLM egress governed without any change."""
    monkeypatch.setenv(_KEY_ENV, "sk-ant-not-a-real-key")
    monkeypatch.setenv(_LEGACY_ENV, "1")

    decision = think(state, {"prior": "x"}, max_tokens=256)

    assert decision.action == ActionType.ASK_USER
    assert "sk-ant-not-a-real-key" not in f"{decision.reasoning} {decision.question}"
