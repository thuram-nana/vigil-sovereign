"""W13-2 (#495) — the sovereign_bridge FACADE composes the EXISTING gates and never re-decides.

These tests run in the SOVEREIGN leg of the required "integration two-env boundary (P5)" CI job — they
import ``framework`` NOWHERE, so they exercise the pure composition core with injected stub gates. What they
pin, per the acceptance criteria of #495:

  * ``authorize()`` returns a normalized ALLOW/DENY/QUEUE with a reason code + capability, composed from the
    gates it is given.
  * STRUCTURAL: the facade contains no independent policy decision — with all-ALLOW gates the verdict is
    ALLOW for ANY request content (the facade never inspects the request), and EVERY non-ALLOW traces to an
    underlying gate (``denied_by`` is a real gate name). The invariant ``effect != ALLOW  <=>  denied_by is
    not None`` holds across a battery of gate configurations, including gates that raise / return garbage.
  * NEGATIVE CONTROLS: a production profile refuses OBSERVE_ONLY; an empty chain is refused; a deliberately
    denying / raising / garbage-returning gate is refused (the gate is not a no-op). And a repo-wide AST scan
    proves there is NO ``skip_security_checks``-equivalent flag anywhere in the source.
  * FAILS WITHOUT THE FIX: this whole module imports ``vigil_integration.sovereign_bridge``; on a tree
    without W13-2 that import ERRORs and every test here fails at collection (observed, not assumed — see the
    decision record docs/decisions/W13-2-sovereign-bridge-facade.md for the recorded observation).
  * FATAL-2: importing the facade loads neither ``framework`` nor ``strix`` nor ``sigil``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from vigil_integration.sovereign_bridge import (
    AuthorizeRequest,
    DeploymentProfile,
    Effect,
    EnforcementMode,
    Gate,
    GateOutcome,
    SovereignBridge,
    authorize,
    compose_authorization,
)

_REPO = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------------------------------------
# helpers — stub gates that DECLARE their verdict, so the test controls exactly what each gate "returns".
# --------------------------------------------------------------------------------------------------------
def _allow(name: str, *, capability: str | None = None) -> Gate:
    return Gate(name, lambda req: GateOutcome(Effect.ALLOW, f"{name} ok", capability=capability))


def _deny(name: str, reason: str = "refused") -> Gate:
    return Gate(name, lambda req: GateOutcome(Effect.DENY, reason))


def _queue(name: str, reason: str = "needs approval") -> Gate:
    return Gate(name, lambda req: GateOutcome(Effect.QUEUE, reason))


def _raises(name: str) -> Gate:
    def _boom(req):
        raise RuntimeError("gate exploded")

    return Gate(name, _boom)


def _garbage(name: str) -> Gate:
    # returns a GateOutcome-shaped object whose verdict is NOT an Effect → must fail closed
    return Gate(name, lambda req: GateOutcome(verdict="totally-allowed"))  # type: ignore[arg-type]


_ANY_REQ = AuthorizeRequest(tool_name="http.get", target_url="https://example.test")


# --------------------------------------------------------------------------------------------------------
# authorize() — normalized composition
# --------------------------------------------------------------------------------------------------------
def test_all_allow_yields_allow_with_reason_code():
    d = authorize(_ANY_REQ, [_allow("kill_switch"), _allow("scope"), _allow("warden")])
    assert d.effect is Effect.ALLOW and d.allowed is True
    assert d.reason_code == "ALLOW"
    assert d.denied_by is None
    assert [t.gate for t in d.trace] == ["kill_switch", "scope", "warden"]


def test_facade_does_not_inspect_request_content_when_gates_allow():
    # STRUCTURAL: the facade has no policy of its own. With all-ALLOW gates, a deliberately "bad-looking"
    # request (destructive, hostile tool name, empty target) is STILL allowed — because only the gates
    # decide, and here they all allow. A facade that re-decided on request content would refuse this.
    hostile = AuthorizeRequest(tool_name="shell.exec; rm -rf /", target_url="", destructive=True,
                               backend="anthropic", capability=None)
    d = authorize(hostile, [_allow("kill_switch"), _allow("scope"), _allow("warden")])
    assert d.effect is Effect.ALLOW, "the facade must not re-decide on request content — only gates decide"


def test_first_non_allow_wins_and_is_attributed_and_short_circuits():
    reached: list[str] = []

    def tracking_allow(name: str) -> Gate:
        def dec(req):
            reached.append(name)
            return GateOutcome(Effect.ALLOW, "ok")

        return Gate(name, dec)

    d = authorize(_ANY_REQ, [tracking_allow("kill_switch"), _deny("scope", "out of scope"),
                             tracking_allow("warden")])
    assert d.effect is Effect.DENY
    assert d.denied_by == "scope"
    assert "out of scope" in d.reason
    assert reached == ["kill_switch"], "gates after the first non-ALLOW must not run (first-failure-wins)"


def test_queue_is_a_non_allow_that_short_circuits_and_is_attributed():
    d = authorize(_ANY_REQ, [_allow("kill_switch"), _queue("warden", "owner must approve")])
    assert d.effect is Effect.QUEUE and d.allowed is False
    assert d.denied_by == "warden"
    assert d.blocks() is True  # ENFORCE (default) + non-ALLOW → blocks


def test_capability_is_passed_through_from_the_entitlement_gate():
    d = authorize(_ANY_REQ, [_allow("kill_switch"), _allow("entitlement", capability="active_recon")])
    assert d.effect is Effect.ALLOW
    assert d.capability == "active_recon"


def test_reason_code_defaults_to_gate_and_verdict_when_gate_supplies_none():
    d = authorize(_ANY_REQ, [Gate("sovereignty", lambda r: GateOutcome(Effect.DENY, "tier forbids"))])
    assert d.reason_code == "SOVEREIGNTY_DENY"  # derived from gate name + verdict, not invented policy


# --------------------------------------------------------------------------------------------------------
# fail-closed — the facade never turns a broken/garbage gate into a pass
# --------------------------------------------------------------------------------------------------------
def test_raising_gate_fails_closed_attributed_to_that_gate():
    d = authorize(_ANY_REQ, [_allow("kill_switch"), _raises("scope"), _allow("warden")])
    assert d.effect is Effect.DENY
    assert d.denied_by == "scope"
    assert d.reason_code == "GATE_ERROR"
    assert "raised" in d.reason


def test_unrecognised_verdict_fails_closed_attributed_to_that_gate():
    d = authorize(_ANY_REQ, [_allow("kill_switch"), _garbage("warden")])
    assert d.effect is Effect.DENY
    assert d.denied_by == "warden"
    assert d.reason_code == "GATE_ERROR"


# --------------------------------------------------------------------------------------------------------
# STRUCTURAL invariant: every non-ALLOW traces to a gate (no independent policy decision)
# --------------------------------------------------------------------------------------------------------
def test_every_non_allow_traces_to_a_real_gate_across_a_battery():
    # A battery of chains covering allow/deny/queue/raise/garbage in every position. For EACH, the invariant
    # must hold: effect is ALLOW  <=>  denied_by is None; and a non-ALLOW's denied_by is a gate in the chain.
    makers = {"allow": _allow, "deny": _deny, "queue": _queue, "raise": _raises, "garbage": _garbage}
    kinds = list(makers)
    for a in kinds:
        for b in kinds:
            for c in kinds:
                names = ["g_kill", "g_scope", "g_warden"]
                chain = [makers[a](names[0]), makers[b](names[1]), makers[c](names[2])]
                d = compose_authorization(_ANY_REQ, chain, mode=EnforcementMode.ENFORCE,
                                          profile=DeploymentProfile.PRODUCTION)
                if d.effect is Effect.ALLOW:
                    assert d.denied_by is None, f"an ALLOW must not name a denier: {(a, b, c)}"
                    assert (a, b, c) == ("allow", "allow", "allow")
                else:
                    assert d.denied_by is not None, f"a non-ALLOW MUST name the deciding gate: {(a, b, c)}"
                    assert d.denied_by in names, f"denied_by must be a gate in the chain: {(a, b, c)}"
                    # and the deciding gate is the FIRST non-allow position (first-failure-wins)
                    first_bad = next(i for i, k in enumerate((a, b, c)) if k != "allow")
                    assert d.denied_by == names[first_bad], f"must attribute to the FIRST non-allow: {(a, b, c)}"


# --------------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — construction fail-closed guards (config errors RAISE, never a silent allow)
# --------------------------------------------------------------------------------------------------------
def test_empty_chain_is_refused():
    with pytest.raises(ValueError, match="at least one gate"):
        authorize(_ANY_REQ, [])
    with pytest.raises(ValueError, match="at least one gate"):
        SovereignBridge([])


def test_production_profile_rejects_observe_only():
    # The W13-2 negative control: a production deployment MUST ENFORCE; OBSERVE_ONLY is refused at build.
    with pytest.raises(ValueError, match="OBSERVE_ONLY"):
        SovereignBridge([_allow("kill_switch")], mode=EnforcementMode.OBSERVE_ONLY,
                        profile=DeploymentProfile.PRODUCTION)
    with pytest.raises(ValueError, match="OBSERVE_ONLY"):
        authorize(_ANY_REQ, [_allow("kill_switch")], mode="observe_only", profile="production")


def test_duplicate_gate_names_are_refused_so_attribution_is_unambiguous():
    with pytest.raises(ValueError, match="unique"):
        SovereignBridge([_allow("warden"), _deny("warden")])


def test_unknown_mode_or_profile_fails_closed():
    with pytest.raises(ValueError, match="enforcement mode"):
        authorize(_ANY_REQ, [_allow("g")], mode="advisory")
    with pytest.raises(ValueError, match="deployment profile"):
        authorize(_ANY_REQ, [_allow("g")], profile="prod-ish")


# --------------------------------------------------------------------------------------------------------
# OBSERVE_ONLY → ENFORCE — the mode governs blocking, not the composed verdict
# --------------------------------------------------------------------------------------------------------
def test_observe_only_records_the_verdict_but_does_not_block():
    b = SovereignBridge([_deny("scope", "out of scope")], mode=EnforcementMode.OBSERVE_ONLY,
                        profile=DeploymentProfile.STAGING)
    d = b.authorize(_ANY_REQ)
    assert d.effect is Effect.DENY, "the true composed verdict is still computed in OBSERVE_ONLY"
    assert d.denied_by == "scope"
    assert d.enforced is False
    assert d.blocks() is False, "OBSERVE_ONLY records but does not block (rollout measurement)"


def test_enforce_blocks_a_non_allow():
    b = SovereignBridge([_deny("scope")], mode=EnforcementMode.ENFORCE, profile=DeploymentProfile.PRODUCTION)
    d = b.authorize(_ANY_REQ)
    assert d.blocks() is True


def test_staging_and_development_permit_observe_only():
    for prof in (DeploymentProfile.STAGING, DeploymentProfile.DEVELOPMENT):
        b = SovereignBridge([_allow("g")], mode=EnforcementMode.OBSERVE_ONLY, profile=prof)
        assert b.mode is EnforcementMode.OBSERVE_ONLY


# --------------------------------------------------------------------------------------------------------
# repo-wide: NO skip_security_checks-equivalent flag anywhere in the source (AST, not grep — robust to
# comments/docstrings; a real parameter/assignment/keyword is what would matter)
# --------------------------------------------------------------------------------------------------------
_SOURCE_ROOTS = [
    _REPO / "integration" / "vigil_integration",
    _REPO / "packages" / "core" / "vigil_core",
    _REPO / "gateway" / "vigil_gateway",
]

# Normalized (lowercase, underscores removed) identifier fragments that would mean "turn the gates off".
# A binary flag named any of these is the exact anti-pattern W13-2 forbids.
_FORBIDDEN_IDENT_FRAGMENTS = (
    "skipsecuritychecks", "skipsecurity", "skipgate", "skipgates", "skipwarden", "skipgovernor",
    "skipauthorization", "skipauthz", "skipauthcheck", "bypassgate", "bypassgates", "bypasssecurity",
    "bypasswarden", "bypassgovernor", "bypassauthorization", "disablesecuritychecks", "disablesecurity",
    "disablegate", "disablegates", "disablewarden", "disableauthorization", "ignoresecurity", "ignoregate",
    "unsafeskipsecurity", "forceallowall",
)


def _normalize(ident: str) -> str:
    return ident.replace("_", "").lower()


def _identifiers_defined(tree: ast.AST) -> set[str]:
    """Every place a *program* could introduce a security-off switch: function/lambda arg names, assignment
    targets, keyword-argument names at call sites, and attribute names. String/number literals and comments
    are deliberately NOT scanned — prose mentioning the forbidden name (as this facade's own docstring does)
    must not trip the guard; only a real identifier does."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                found.add(a.arg)
            if args.vararg:
                found.add(args.vararg.arg)
            if args.kwarg:
                found.add(args.kwarg.arg)
        elif isinstance(node, ast.arg):
            found.add(node.arg)
        elif isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            found.add(node.arg)
    return found


def test_no_skip_security_checks_equivalent_flag_anywhere_in_source():
    offenders: list[str] = []
    scanned = 0
    for root in _SOURCE_ROOTS:
        if not root.is_dir():
            continue
        for py in root.rglob("*.py"):
            if "/tests/" in py.as_posix() or py.name.startswith("test_"):
                continue  # tests may name the forbidden thing to assert its absence (this file does)
            scanned += 1
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
            for ident in _identifiers_defined(tree):
                norm = _normalize(ident)
                if any(frag in norm for frag in _FORBIDDEN_IDENT_FRAGMENTS):
                    offenders.append(f"{py.relative_to(_REPO)}: identifier {ident!r}")
    assert scanned > 50, f"source scan found too few files ({scanned}); the roots may be wrong"
    assert not offenders, (
        "found a security-bypass-shaped identifier — the sovereign bridge forbids any "
        f"skip_security_checks-equivalent flag: {offenders}"
    )


# --------------------------------------------------------------------------------------------------------
# FATAL-2 — importing the facade loads no offense/sovereign engine. Proven in an ISOLATED subprocess (so it
# holds even under the offense venv, where framework IS installed but must not be pulled in by this import).
# The canonical whole-venv proof is test_two_env_boundary.py, which also names this module.
# --------------------------------------------------------------------------------------------------------
def test_import_is_two_env_clean():
    import subprocess

    probe = (
        "import sys; import vigil_integration.sovereign_bridge as m; "
        "assert 'framework' not in sys.modules, 'framework leaked'; "
        "assert 'strix' not in sys.modules, 'strix leaked'; "
        "assert 'sigil' not in sys.modules, 'sigil leaked'; "
        "assert hasattr(m, 'authorize'); print('CLEAN')"
    )
    # PYTHONPATH is ONLY the sovereign-safe seams (integration + gateway); engine/crucible is deliberately
    # absent so the only way framework could appear in sys.modules is if this module imported it — it must not.
    env = {
        "PYTHONPATH": f"{_REPO / 'integration'}:{_REPO / 'gateway'}",
        "PATH": __import__("os").environ.get("PATH", ""),
    }
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0 and "CLEAN" in out.stdout, f"FATAL-2 probe failed: {out.stdout}\n{out.stderr}"
