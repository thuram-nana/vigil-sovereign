"""MUST-FIX #2 — the sovereignty ladder GOVERNS the model egress of ``vigil engage``.

The question a national agency asks first is "what leaves our machine, and what stops it?". Before this
suite, the answer for the LLM path was "nothing": ``live.think_claude`` read ``ANTHROPIC_API_KEY`` and
built an ``anthropic.Anthropic`` client with no reference to ``framework.v2.kernel.sovereignty`` anywhere
in ``integration/`` — so setting ``CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED`` did not stop the call.

What is proved here:
  * an AIR_GAPPED (or SOVEREIGN_CLOUD / TRUSTED_CLOUD) tier REFUSES the model call fail-closed — no SDK
    import, no client construction, no request — and the refusal names the tier and how to change it;
  * a PERMISSIVE tier still allows it. That pair is the MUTATION CONTROL: the block is caused by the
    TIER, not by something unconditional. A second, explicit mutation control neuters the guard and
    shows the very same AIR_GAPPED call then goes through — so the assertions are load-bearing on the
    guard itself;
  * the tier is READ from the environment on the real path (flipped mid-process, no re-import), and the
    canonical ``sovereignty.set_policy()`` holder governs it too — i.e. this reuses the existing ladder
    rather than parsing the env into a parallel mechanism;
  * the keyless paths are UNCHANGED: no key + no replay still yields the same safest action, and the
    offline ``replay`` path runs normally under AIR_GAPPED (it never egresses).
"""

from __future__ import annotations

import json
import sys

import pytest

from framework.v2.kernel import sovereignty
from vigil_integration.agent import ActionType, AgentState, Phase
from vigil_integration.live import think_claude
from vigil_integration.live.think_claude import ReplayThinker, llm_egress_refusal, think

_TIER_ENV = "CRUCIBLE_SOVEREIGNTY_TIER"
_LEGACY_ENV = "CRUCIBLE_SOVEREIGN_MODE"


# --- fakes -----------------------------------------------------------------------------------------


class _Block:
    def __init__(self, text: str) -> None:
        self.type, self.text = "text", text


class _Response:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]


class _Messages:
    def __init__(self, outer: "FakeClient") -> None:
        self._outer = outer

    def create(self, **kwargs):
        self._outer.calls += 1
        self._outer.captured = kwargs
        return _Response(self._outer.text)


class FakeClient:
    """A stand-in for ``anthropic.Anthropic`` that COUNTS calls — a refused egress must leave it at 0."""

    def __init__(self, text: str = "") -> None:
        self.text = text or json.dumps({"action": "use_tool",
                                        "tool": {"tool_name": "nmap", "tool_args": {}}})
        self.calls = 0
        self.captured: dict = {}
        self.messages = _Messages(self)


@pytest.fixture()
def state() -> AgentState:
    return AgentState(engagement_slug="loopback", objective="probe http://127.0.0.1:18080",
                      phase=Phase.INFORMATIONAL)


@pytest.fixture(autouse=True)
def _clean_sovereignty_env(monkeypatch):
    """Every test states its own tier explicitly; no ambient key, no injected policy, no seal latch."""
    for var in (_TIER_ENV, _LEGACY_ENV, "CRUCIBLE_SOVEREIGNTY_SEALED", "CRUCIBLE_ANTHROPIC_ZDR",
                "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    sovereignty.set_policy(None)
    yield
    sovereignty.set_policy(None)


@pytest.fixture()
def no_client_may_be_built(monkeypatch):
    """Trip-wire: constructing a live client (which imports the SDK and would egress) is a test FAILURE.
    A sovereignty refusal must happen strictly BEFORE this point."""
    def _boom(_key):
        raise AssertionError("a live Claude client was constructed despite a sovereign tier — EGRESS")
    monkeypatch.setattr(think_claude, "_build_live_client", _boom)


# --- the block: a sovereign tier refuses the key-derived (real) egress path ---------------------------


@pytest.mark.parametrize("tier", ["AIR_GAPPED", "SOVEREIGN_CLOUD", "TRUSTED_CLOUD"])
def test_sovereign_tier_blocks_the_key_path_before_any_client_is_built(
        state, monkeypatch, no_client_may_be_built, tier):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, tier)

    d = think(state, {"prior": "banner: nginx"})

    assert d.action == ActionType.ASK_USER            # the inert human pause, never an action-bearing edge
    blob = f"{d.reasoning} {d.question}"
    assert tier in blob                                # names the tier that refused
    assert _TIER_ENV in blob                           # names how to change it deliberately
    assert "sk-ant-not-a-real-key" not in blob         # still secret-free


def test_permissive_tier_still_allows_the_key_path(state, monkeypatch):
    """MUTATION CONTROL (tier axis): identical call, tier flipped to PERMISSIVE → the client IS built and
    called. This is what proves the block above is caused by the TIER and not by something unconditional
    (a missing SDK, the fake key, the trip-wire fixture)."""
    built = FakeClient()
    monkeypatch.setattr(think_claude, "_build_live_client", lambda _key: built)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")

    d = think(state, {"prior": "banner: nginx"})

    assert built.calls == 1
    assert d.action == ActionType.USE_TOOL


def test_unset_tier_is_unchanged_permissive_behaviour(state, monkeypatch):
    """The default is PERMISSIVE and stays PERMISSIVE: with no sovereignty env at all the live path runs
    exactly as it did before the gate existed."""
    built = FakeClient()
    monkeypatch.setattr(think_claude, "_build_live_client", lambda _key: built)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")

    d = think(state, {"prior": "x"})

    assert built.calls == 1 and d.action == ActionType.USE_TOOL


def test_guard_is_load_bearing_mutation_control(state, monkeypatch):
    """MUTATION CONTROL (guard axis): break the guard — make ``llm_egress_refusal`` always permit, the
    exact regression this fix prevents — and the AIR_GAPPED call goes straight through. Repairing it (the
    test above) blocks again. So the AIR_GAPPED assertions hang on THIS guard, not on an unrelated
    failure path."""
    built = FakeClient()
    monkeypatch.setattr(think_claude, "_build_live_client", lambda _key: built)
    monkeypatch.setattr(think_claude, "llm_egress_refusal", lambda backend=None: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    d = think(state, {"prior": "x"})

    assert built.calls == 1 and d.action == ActionType.USE_TOOL   # the guard, removed, permits the egress


# --- the injected-client path is gated too (it is otherwise a hole straight through the ladder) -------


def test_sovereign_tier_blocks_an_injected_client(state, monkeypatch):
    fake = FakeClient()
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    d = think(state, {"prior": "x"}, client=fake)

    assert fake.calls == 0                              # never even called
    assert d.action == ActionType.ASK_USER
    assert "AIR_GAPPED" in f"{d.reasoning} {d.question}"


def test_an_injected_client_declared_local_is_allowed_under_air_gapped(state, monkeypatch):
    """An air-gapped operator running a local model injects its client and DECLARES it. The ladder
    classifies `ollama` as `local`, which AIR_GAPPED permits — the gate constrains egress, it does not
    ban injected clients."""
    fake = FakeClient()
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    d = think(state, {"prior": "x"}, client=fake, backend="ollama")

    assert fake.calls == 1 and d.action == ActionType.USE_TOOL


def test_an_undeclared_or_unknown_injected_backend_fails_closed(state, monkeypatch):
    """No declaration, or a name the policy does not know, classifies `cloud_only` — refused under a
    sovereign tier. Deny-by-default."""
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    for backend in (None, "", "some-future-provider"):
        fake = FakeClient()
        d = think(state, {"prior": "x"}, client=fake, backend=backend)
        assert fake.calls == 0, backend
        assert d.action == ActionType.ASK_USER, backend


@pytest.mark.parametrize("tier", ["AIR_GAPPED", "TRUSTED_CLOUD"])
def test_backend_declaration_cannot_relabel_the_real_sdk_path(state, monkeypatch,
                                                              no_client_may_be_built, tier):
    """A declared LOCAL backend ROUTES to a real loopback-enforced local provider (GAP-1) and can NEVER
    reach the direct Anthropic SDK — so a caller cannot pass backend="ollama" to launder a cloud call, under
    ANY tier, INCLUDING one that PERMITS cloud (TRUSTED_CLOUD). The `no_client_may_be_built` trip-wire proves
    no direct Anthropic client is ever constructed; with no local daemon present the local route fails CLOSED
    (ASK_USER — never a cloud fallback), and the key never leaks. (Pre-GAP-1 the backend label was advisory
    and the key path always built the SDK, so the tier caught it; now the label ROUTES, so the guarantee is
    stronger — a local declaration never even reaches the cloud path.)"""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, tier)

    d = think(state, {"prior": "x"}, backend="ollama")

    assert d.action == ActionType.ASK_USER                       # fail-closed: no cloud fallback
    assert "sk-ant-not-a-real-key" not in f"{d.reasoning} {d.question}"   # secret-free


# --- the tier is read from the real environment / the real policy holder ------------------------------


def test_tier_is_read_from_the_environment_on_the_real_path(state, monkeypatch):
    """Not captured at import time: flipping the env between two calls in ONE process flips the verdict.
    This is what makes the operator-facing control (an env var in the unit file / sigil.env / shell)
    actually govern the running engine."""
    built = FakeClient()
    monkeypatch.setattr(think_claude, "_build_live_client", lambda _key: built)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")

    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    assert think(state, {}).action == ActionType.ASK_USER
    assert built.calls == 0

    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    assert think(state, {}).action == ActionType.USE_TOOL
    assert built.calls == 1


def test_legacy_sovereign_mode_flag_blocks_the_llm_path(state, monkeypatch, no_client_may_be_built):
    """Session 7's binary flag is the canonical alias for AIR_GAPPED — an operator who set it years ago
    gets the LLM path governed too, without changing anything."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_LEGACY_ENV, "1")

    assert think(state, {}).action == ActionType.ASK_USER


def test_unrecognised_tier_value_fails_closed(state, monkeypatch, no_client_may_be_built):
    """A typo'd tier is not a licence to egress: the canonical policy resolves an unknown value to
    AIR_GAPPED, so the LLM path refuses."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, "AIRGAPPED")          # not a real tier name

    assert think(state, {}).action == ActionType.ASK_USER


def test_injected_policy_object_governs_too(state, monkeypatch, no_client_may_be_built):
    """The gate consults ``sovereignty.current()`` — the canonical holder — so an injected policy (what a
    long-running process or a test harness uses) governs the LLM path as well. Proof that this REUSES the
    ladder rather than re-parsing the environment on the side."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    sovereignty.set_policy(sovereignty.SovereigntyPolicy(tier=sovereignty.Tier.AIR_GAPPED))

    assert think(state, {}).action == ActionType.ASK_USER


def test_trusted_cloud_permits_the_direct_call_only_with_the_zdr_attestation(state, monkeypatch):
    """TRUSTED_CLOUD is documented as "adds Anthropic ZDR ... requires explicit operator attestation".
    The think step honours exactly that rule — the same one the URK ``AnthropicBackend`` uses — so the
    two do not disagree about the same environment."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, "TRUSTED_CLOUD")

    monkeypatch.setattr(think_claude, "_build_live_client",
                        lambda _k: (_ for _ in ()).throw(AssertionError("egress without attestation")))
    assert think(state, {}).action == ActionType.ASK_USER          # no attestation → refused

    built = FakeClient()
    monkeypatch.setattr(think_claude, "_build_live_client", lambda _k: built)
    monkeypatch.setenv("CRUCIBLE_ANTHROPIC_ZDR", "1")
    assert think(state, {}).action == ActionType.USE_TOOL          # attested → permitted
    assert built.calls == 1


# --- the offline paths are untouched -----------------------------------------------------------------


@pytest.mark.parametrize("tier", [None, "PERMISSIVE", "AIR_GAPPED"])
def test_the_no_key_no_replay_case_is_unchanged(state, monkeypatch, tier):
    """No key, no replay → the same "nothing wired" safest action at every tier. The gate must not
    change what a keyless deployment sees, and must not claim a sovereignty refusal that did not
    happen (there was no egress to refuse)."""
    if tier:
        monkeypatch.setenv(_TIER_ENV, tier)

    d = think(state, {"prior": "x"})

    assert d.action == ActionType.ASK_USER
    assert "no Claude client, no API key, and no replay were wired" in d.reasoning


@pytest.mark.parametrize("tier", ["AIR_GAPPED", "PERMISSIVE"])
def test_the_replay_path_runs_normally_under_every_tier(state, monkeypatch, tier):
    """The scripted/offline path never egresses, so it is never gated — an AIR_GAPPED run keeps working."""
    monkeypatch.setenv(_TIER_ENV, tier)
    replay = ReplayThinker([json.dumps({"action": "use_tool",
                                        "tool": {"tool_name": "nmap", "tool_args": {}}})])

    d = think(state, {"prior": "x"}, replay=replay)

    assert d.action == ActionType.USE_TOOL


# --- the gate helper itself ---------------------------------------------------------------------------


def test_llm_egress_refusal_reuses_the_policy_message(monkeypatch):
    """The refusal text is the POLICY's own, so the operator gets the ladder's canonical explanation
    (classification, what the tier permits, and the env var to change) rather than a paraphrase that
    could drift from the real rule."""
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    msg = llm_egress_refusal(None)
    assert msg is not None
    assert "anthropic" in msg and "AIR_GAPPED" in msg and _TIER_ENV in msg
    assert llm_egress_refusal("ollama") is None          # a local backend is permitted at AIR_GAPPED


def test_gate_fails_closed_when_the_policy_module_is_unimportable(monkeypatch):
    """A deployment where ``framework.v2`` is not on the path cannot evaluate the ladder. With a tier
    configured that is a REFUSAL, never a silent egress. With no tier configured the canonical policy
    would have been PERMISSIVE, so behaviour is unchanged — the fallback only ever over-refuses."""
    # A None entry makes `from framework.v2.kernel import sovereignty` raise ImportError, exactly as an
    # engine-less deployment would.
    monkeypatch.setitem(sys.modules, "framework.v2.kernel", None)

    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    msg = llm_egress_refusal(None)
    assert msg is not None and "not importable" in msg and _TIER_ENV in msg

    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    assert llm_egress_refusal(None) is None

    monkeypatch.delenv(_TIER_ENV)
    assert llm_egress_refusal(None) is None             # not opted in ⇒ unchanged

    monkeypatch.setenv(_LEGACY_ENV, "1")
    assert llm_egress_refusal(None) is not None         # legacy flag alone still refuses


def test_gate_fails_closed_when_the_policy_raises(monkeypatch):
    """"Could not decide" is never "permitted"."""
    def _explode():
        raise RuntimeError("policy store corrupt")
    monkeypatch.setattr(sovereignty, "current", _explode)

    msg = llm_egress_refusal(None)
    assert msg is not None and "could not be evaluated" in msg


# --- the auto-patch coder is the OTHER model egress on the offense side -------------------------------
#
# `CodefixSession.propose` reuses think_claude's `_build_live_client` / `_resolve_key` directly, so it
# bypassed `think()`'s gate. It is the highest-stakes egress in the system: the prompt carries REAL
# SOURCE from the operator's repository. It must obey the same ladder.


class _SimpleFinding:
    ref = "F-001"
    target = "http://127.0.0.1:18080/login"
    bug_class = "sqli"
    severity = "high"
    title = "SQL injection on /login"
    evidence = ""
    target_repo = ""


class _Request:
    finding = _SimpleFinding()


def _codefix_session(client=None):
    from vigil_integration.live.codefix_runner import CodefixConfig, CodefixSession
    return CodefixSession(CodefixConfig(target_repo="", base_dir="", target_branch="main"), client=client)


def test_codefix_coder_refuses_to_egress_source_under_a_sovereign_tier(monkeypatch):
    from vigil_integration.live import codefix_runner
    monkeypatch.setattr(codefix_runner, "_build_live_client",
                        lambda _k: (_ for _ in ()).throw(AssertionError("client built — SOURCE EGRESS")))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")

    assert _codefix_session().propose(_Request()) == ""      # no proposal, no egress


def test_codefix_coder_refuses_even_an_injected_client(monkeypatch):
    """An injected coder client is opaque, so it is classified as a direct cloud client — fail-closed."""
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    fake = FakeClient(text="--- a/x\n+++ b/x\n")

    assert _codefix_session(client=fake).propose(_Request()) == ""
    assert fake.calls == 0


def test_codefix_coder_still_works_at_the_permissive_tier(monkeypatch):
    """MUTATION CONTROL (tier axis) for the coder."""
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    fake = FakeClient(text="--- a/x\n+++ b/x\n")

    out = _codefix_session(client=fake).propose(_Request())

    assert fake.calls == 1 and out.startswith("--- a/x")


# --- install path: the tier must actually REACH the offense children ----------------------------------


def test_the_sovereignty_tier_is_bridged_to_the_offense_children():
    """`vigil up` builds each offense child's env from a closed allowlist. If the tier vars are not on it,
    an operator's AIR_GAPPED choice is silently DROPPED and the child runs PERMISSIVE — the install-path
    half of this same bug."""
    from vigil_integration import uiproxy
    for var in ("CRUCIBLE_SOVEREIGNTY_TIER", "CRUCIBLE_SOVEREIGN_MODE", "CRUCIBLE_SOVEREIGNTY_SEALED"):
        assert var in uiproxy._OFFENSE_ENV_ALLOWLIST, var


# --- version skew between engine copies must not become an outage NOR a bypass -------------------------


def test_version_skew_degrades_to_the_stricter_name_never_to_permission(state, monkeypatch,
                                                                        no_client_may_be_built):
    """An engine copy on the path that predates ``direct_anthropic_backend_name`` (a stale install, a
    mixed deployment) must not turn every LLM call into a self-inflicted outage, and must not become a
    bypass either. The DECISION stays the engine's ``assert_permitted``; only the backend NAME degrades
    to a local mirror that yields the STRICTER classification."""
    monkeypatch.delattr(sovereignty, "direct_anthropic_backend_name")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")

    # PERMISSIVE: still permitted — skew is not an outage.
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    assert llm_egress_refusal(None) is None

    # AIR_GAPPED: still refused by the engine's own policy — skew is not a bypass.
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    assert think(state, {}).action == ActionType.ASK_USER

    # TRUSTED_CLOUD without the attestation → the stricter `anthropic` name → refused.
    monkeypatch.setenv(_TIER_ENV, "TRUSTED_CLOUD")
    assert llm_egress_refusal(None) is not None
    monkeypatch.setenv("CRUCIBLE_ANTHROPIC_ZDR", "1")
    assert llm_egress_refusal(None) is None            # the mirror reads the same attestation


def test_a_helper_that_raises_still_degrades_to_the_stricter_name(monkeypatch):
    def _explode():
        raise RuntimeError("skewed helper")
    monkeypatch.setattr(sovereignty, "direct_anthropic_backend_name", _explode)
    monkeypatch.setenv(_TIER_ENV, "PERMISSIVE")
    assert llm_egress_refusal(None) is None
    monkeypatch.setenv(_TIER_ENV, "AIR_GAPPED")
    assert llm_egress_refusal(None) is not None


# --- W10-2: the RE-RESOLVED tier reaches a real CHILD PROCESS, which then refuses the cloud call ------
#
# The tests above prove the tier gates egress IN-PROCESS. This one closes the deployment loop the issue
# names: `PlaneControl` (uiproxy) re-resolves the tier on an offense-plane restart and spawns the children
# with it, and the child — a genuine subprocess, exactly like the offense console/api under `vigil up` —
# then REFUSES a cloud-model backend at construction. It runs in the OFFENSE leg because the child imports
# `framework.v2.kernel.sovereignty`. It is the criterion-3 negative control: with the re-resolved tier set
# to AIR_GAPPED a child refuses `anthropic`, and with PERMISSIVE the very same child permits it — so the
# refusal is caused by the tier that reached the process, not by anything unconditional.

_CHILD_PROBE = r"""
import os, sys
# `_child_env` strips PYTHONPATH from a spawned child (the boot children are launched via absolute venv
# bins that already have `framework` installed); in the test the child re-adds the paths it needs.
sys.path[:0] = sys.argv[1:]
from framework.v2.kernel import sovereignty as S
tier = os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER", "<unset>")
try:
    S.current().assert_permitted("anthropic")
    verdict = "PERMITTED"
except S.SovereigntyViolation:
    verdict = "REFUSED"
sys.stdout.write("TIER=%s VERDICT=%s\n" % (tier, verdict))
sys.stdout.flush()
"""


def _child_verdict_after_reresolve_to(tmp_path, tier: str) -> str:
    """Drive `PlaneControl.start_offense` with a resolver that returns ``tier``, spawn a REAL child that
    asks the sovereignty policy whether a cloud backend may be built, and return its ``TIER=.. VERDICT=..``
    line. Proves the RE-RESOLVED tier actually reached the child process (not just the UI)."""
    import sys as _sys
    from pathlib import Path

    from vigil_integration import uiproxy

    repo = Path(__file__).resolve().parents[2]
    probe = tmp_path / "probe.py"
    probe.write_text(_CHILD_PROBE, encoding="utf-8")
    log = tmp_path / f"child-{tier}.log"

    # a free port so start_offense treats the backend as "down" and actually spawns it
    s = __import__("socket").socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    argv = [_sys.executable, str(probe), str(repo / "engine" / "crucible"),
            str(repo / "packages" / "core" / "vigil_core")]

    def _resolver():
        # the operator's CURRENT tier, re-read at restart — the boot snapshot (below) is deliberately the
        # OPPOSITE, so a stale snapshot would give the wrong verdict.
        return True, {"CRUCIBLE_SOVEREIGNTY_TIER": tier}

    boot_snapshot = {"CRUCIBLE_SOVEREIGNTY_TIER": ("PERMISSIVE" if tier == "AIR_GAPPED" else "AIR_GAPPED")}
    specs = [("offense-console", argv, log, {}, "127.0.0.1", port)]
    pc = uiproxy.PlaneControl(specs, env_resolver=_resolver, dynamic_env=boot_snapshot)
    res = pc.start_offense()
    assert res["result"] == "started", res
    child = pc._children["offense-console"]
    child.wait(timeout=120)
    return log.read_text(encoding="utf-8").strip()


def test_reresolved_air_gapped_tier_makes_a_real_child_refuse_a_cloud_call(tmp_path):
    """AIR_GAPPED re-resolved on restart → the child refuses `anthropic`; PERMISSIVE → the same child
    permits it. The pair is the mutation control (criterion 3/6). Note the boot snapshot is the OPPOSITE
    tier in each case, so a pre-fix snapshot-respawn would yield the wrong verdict — this fails on a tree
    without the re-resolve fix."""
    air = _child_verdict_after_reresolve_to(tmp_path, "AIR_GAPPED")
    assert air == "TIER=AIR_GAPPED VERDICT=REFUSED", air

    perm = _child_verdict_after_reresolve_to(tmp_path, "PERMISSIVE")
    assert perm == "TIER=PERMISSIVE VERDICT=PERMITTED", perm
