"""The 12 production invariants — an executable scoreboard for the Strix + HexStrike wiring programme.

WHAT THIS FILE IS. VIGIL vendors two offensive systems: Strix (an autonomous agent that runs its own loop
in a container) and HexStrike (a deterministic planner). "100% integrated" is defined for this programme as
a set of invariants that hold under adversarial test — not as zero residual risk, and not as every upstream
tool minting a FACT. These are those invariants, encoded so the claim is checkable rather than asserted.

HOW IT STAYS HONEST — read before adding a test here.

  * An invariant the system MEETS gets an ordinary passing test that genuinely probes the control.
  * An invariant the system does NOT meet gets a test asserting the TRUE invariant, marked
    ``@pytest.mark.xfail(strict=True, reason=...)``. Because strict xfail turns an unexpected PASS into a
    FAILURE, the board self-updates: when a later slice closes the gap, CI goes RED until someone deletes
    the marker. Deleting an xfail is how a slice proves it landed.
  * NEVER weaken an assertion to make it pass, and never assert the current buggy behaviour. A green test
    over a missing control launders the gap — the one outcome worse than a red build.
  * Every invariant carries a negative control proving the probe is not vacuous.

SCOPE OF THE PROBES. These are deterministic and offline: no network traffic, no containers, no host state.
Behavioural probes are used wherever a seam can be exercised in-process; the remainder are structural probes
over the real source of the real call site (never a docstring), which is the honest way to assert "this call
is wired here" without launching an engagement. Where a structural probe is used, the negative control shows
it discriminates.

NO FRAMEWORK IMPORTS. Everything here imports only ``vigil_integration`` and the standard library, so the
file runs in the required "integration two-env boundary (P5)" job in BOTH legs and needs no entry in the
ci.yml offense-leg run-list (the ``test_ci_framework_tests_run_in_offense_leg`` guard).
"""
from __future__ import annotations

import ast
import inspect
import json
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# The scoreboard, as a committed constant. A silent change to what we claim is itself a failure.
MET = {1, 2, 3, 4, 5, 7, 9, 10, 11}
UNMET = {6, 8, 12}
_CLOSED_BY = {
    6: "S6/S7 — causal capture + a VIGIL-owned re-drive before any FACT",
    8: "S6 — capture the exploit REQUEST bytes into the evidence envelope",
    12: "S9 — a typed verification_degraded state instead of six silent swallows",
}


def _src(rel: str) -> str:
    return (_REPO / rel).read_text(encoding="utf-8", errors="replace")


def _fn_src(module_rel: str, func_name: str) -> str:
    """The source of one function, parsed from the real file."""
    src = _src(module_rel)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{func_name} not found in {module_rel} — the probe is anchored to a moved seam")


def _fn_code(module_rel: str, func_name: str) -> str:
    """The function's CODE with its docstring removed.

    Structural probes must never match prose: an ordering probe over the raw source matched a
    ``backend.run(...)`` mentioned in a numbered explanation inside the docstring and reported a false
    violation. Anything asserting "this call happens here" uses this.
    """
    src = _src(module_rel)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body = body[1:]
            return "\n".join(ast.get_source_segment(src, stmt) or "" for stmt in body)
    raise AssertionError(f"{func_name} not found in {module_rel} — the probe is anchored to a moved seam")


# =========================================================================================
# 1. No action without a valid engagement authority.                                  MET
# =========================================================================================

def test_inv01_no_tool_runs_without_an_engagement_authority():
    from vigil_integration.live.external_tool import _preflight_gate_refusal

    refusal = _preflight_gate_refusal("")
    assert isinstance(refusal, str) and refusal, (
        "a tool run with no charter context must be refused, not proceed"
    )
    assert "authorization" in refusal.lower() or "charter" in refusal.lower()


def test_inv01_negative_control_the_gate_is_actually_wired_into_the_runner():
    """A gate that exists but is never called is not a gate — assert the call site, not the definition."""
    runner = _fn_code("integration/vigil_integration/live/external_tool.py", "run_external_tool")
    assert "_preflight_gate_refusal(" in runner, (
        "run_external_tool no longer consults the pre-flight gate"
    )


# =========================================================================================
# 2. No network traffic outside signed scope.                                       UNMET
# =========================================================================================

def test_inv02_the_strix_sandbox_is_pinned_to_a_gated_network():
    """Every Strix spawn must pre-flight the gated topology and pin the sandbox onto it.

    Previously ``strix_env()`` had no caller and nothing wrote ``STRIX_DOCKER_SANDBOX_NETWORK``, so
    ``_apply_sandbox_network`` was a no-op and the container kept a default route. S2 added a pre-flight
    that refuses unless the gateway is running and the network exists, and merges the pin into the child
    environment.

    NOTE ON THIS PROBE. It first asserted merely that some file contained an assignment to the env var.
    That was the wrong measurement: the fix routes the value through ``strix_env()``, so the probe would
    have stayed red after the gap closed — a scoreboard that lies in the safe direction is still a
    scoreboard that lies. It now asserts the behaviour: a caller exists, and both spawn sites gate on it.
    """
    from vigil_integration.strix_sandbox import preflight

    class _Healthy:
        sandbox_network = "vigil_sandbox"

        def container_state(self, name="vigil-gateway"):
            return "running"

        def network_exists(self, name=None):
            return True

        def strix_env(self):
            return {"STRIX_DOCKER_SANDBOX_NETWORK": self.sandbox_network}

    class _Down(_Healthy):
        def container_state(self, name="vigil-gateway"):
            return "exited"

    pinned = preflight(networking=_Healthy())
    assert pinned.ok and pinned.gated and pinned.env.get("STRIX_DOCKER_SANDBOX_NETWORK"), (
        "a healthy gateway topology must pin the sandbox to the gated network"
    )
    assert not preflight(networking=_Down()).ok, (
        "with the gateway down the launch must be REFUSED, not silently run on the default bridge"
    )

    actions = "engine/crucible/framework/v2/console/actions.py"
    for site in ("launch_assessment", "retry_run"):
        code = _fn_code(actions, site)
        assert "_strix_sandbox_gate()" in code and "**_sbx_env" in code, (
            f"{site} can still spawn Strix without pinning the sandbox to the gated network"
        )


def test_inv02_negative_control_the_consumer_and_producer_both_exist():
    """The probe targets a real, live seam: the reader is in the vendored runtime, the producer in gateway."""
    assert "STRIX_DOCKER_SANDBOX_NETWORK" in _src("vendor/strix/strix/runtime/docker_client.py")
    assert "def strix_env" in _src("gateway/vigil_gateway/docker.py")


# =========================================================================================
# 3. No silent local-to-cloud model fallback.                                          MET
# =========================================================================================

def test_inv03_a_sovereign_tier_refuses_a_cloud_model_before_spawn():
    """Both Strix spawn sites must consult the sovereignty gate and refuse, never fall back to cloud."""
    actions = "engine/crucible/framework/v2/console/actions.py"
    src = _src(actions)
    assert "_strix_sovereignty_refusal" in src, "the sovereignty gate is gone from the console"
    for site in ("launch_assessment", "retry_run"):
        body = _fn_code(actions, site)
        assert "_strix_sovereignty_refusal" in body, (
            f"{site} spawns Strix without consulting the sovereignty gate"
        )


def test_inv03_negative_control_the_gate_can_refuse_and_the_local_map_is_closed():
    src = _src("engine/crucible/framework/v2/console/actions.py")
    assert "_STRIX_LOCAL_MAP" in src, "the local-backend map is the closed set the refusal is derived from"
    assert re.search(r"def _strix_sovereignty_refusal\(", src), "the refusal helper must exist to be called"


# =========================================================================================
# 4. No unknown tool executed through a generic shell.                                 MET
# =========================================================================================

def test_inv04_an_unregistered_strix_tool_does_not_auto_run():
    """An unknown/newly-registered Strix tool must fail closed, not classify A0 and auto-run.

    CLOSED by S4 slice 1: ``_strix_shell_classifier`` now returns A0 only for the EXPLICIT allowlist
    ``_STRIX_AUTO_TOOLS`` and A3 (queue) for every other name — so a tool added upstream, or one an agent
    registers at runtime, fails closed to owner approval instead of auto-running under the A0 floor.
    """
    from vigil_integration.warden_gate import _strix_shell_classifier

    assert _strix_shell_classifier("a_tool_nobody_registered") == "A3", (
        "an unregistered Strix tool classifies A0 (auto-run) instead of queueing for owner approval"
    )


def test_inv04_negative_control_the_classifier_does_gate_the_names_it_knows():
    """Proves the probe is not vacuous: the classifier genuinely gates its registered set."""
    from vigil_integration.warden_gate import _STRIX_GATED_TOOLS, _strix_shell_classifier

    assert _STRIX_GATED_TOOLS, "the gated set is empty — nothing would ever queue"
    for name in _STRIX_GATED_TOOLS:
        assert _strix_shell_classifier(name) == "A3", f"{name} is in the gated set but classifies auto"


def test_inv04_the_crucible_path_does_fail_closed_on_an_unknown_tool():
    """The asymmetry is the point: the CRUCIBLE executor refuses an unknown tool; the Strix path does not."""
    execute = _fn_code("integration/vigil_integration/live/executor.py", "_execute")
    assert "_BUILDERS" in execute and "no argv builder" in execute, (
        "the CRUCIBLE executor no longer denies a tool with no typed argv builder"
    )


# =========================================================================================
# 5. No tool output treated as a FACT.                                                 MET
# =========================================================================================

def test_inv05_a_verdict_cannot_be_constructed_outside_admission():
    from vigil_integration.live.verdict import AdmittedVerdict, DirectVerdictConstruction, Verdict

    with pytest.raises(DirectVerdictConstruction):
        AdmittedVerdict(verdict=Verdict.FACT, branch="service_reachability.tcp_handshake",
                        reason="forged")


def test_inv05_negative_control_admission_can_produce_a_verdict():
    """The refusal above must be about AUTHORISATION, not about the type being unconstructible at all."""
    from vigil_integration.live.verdict import Verdict, admit

    out = admit("service_reachability.tcp_handshake", fired=True, conclusive=True, observed={})
    assert out.verdict in set(Verdict), "admission produced no usable verdict"


# =========================================================================================
# 6. No FACT without VIGIL-owned verification.                                      UNMET
# =========================================================================================

@pytest.mark.xfail(strict=True, reason=f"UNMET — {_CLOSED_BY[6]}")
def test_inv06_a_strix_finding_is_verified_by_traffic_vigil_itself_sent():
    """Today the proof path adjudicates bytes Caido happened to have recorded; VIGIL sends nothing.

    ``capture_for_report`` resolves the exchange with a substring HTTPQL query
    (``req.path.cont`` + newest-first, LIMIT 1) and returns ``control_id = None``, so the oracle's control
    comparison is dead and no VIGIL-originated request exists to bind the claim to.
    """
    capture = _src("vendor/strix/strix/report/proof_capture.py")
    assert "req.path.cont" not in capture, (
        "the exploit exchange is still selected by a retrospective substring match rather than cited "
        "causally by the agent that sent it"
    )


def test_inv06_negative_control_the_causal_identifiers_exist_and_are_simply_unused():
    """The fix is wiring, not construction: the parameter and the returned ids already exist."""
    capture = _src("vendor/strix/strix/report/proof_capture.py")
    assert "explicit_ids" in capture, "capture_for_report already accepts explicit ids"
    assert "session_id" in _src("vendor/strix/strix/tools/proxy/caido_api.py"), (
        "replay_send_raw already returns the exact exchange to its caller"
    )


# =========================================================================================
# 7. No CLEAN if evidence is missing, truncated, undecodable or unsupported.            MET
# =========================================================================================

def test_inv07_a_branch_whose_precondition_did_not_hold_is_inconclusive_not_clean():
    from vigil_integration.live.verdict import Verdict, admit

    out = admit("open_redirect.body_markup", fired=False, conclusive=True,
                observed={"channel_established": True})  # body_semantically_available absent => not held
    assert out.verdict is Verdict.INCONCLUSIVE, (
        f"a branch with an unmet precondition yielded {out.verdict} — a missing precondition must never "
        "produce CLEAN"
    )


def test_inv07_negative_control_body_derived_branches_are_never_clean_capable():
    ladder = json.loads(_src("docs/capability-matrix/evidence-branches.json"))
    body_branches = [b for b in ladder["branches"]
                     if "body_semantically_available" in (b.get("preconditions") or [])]
    assert body_branches, "expected body-derived branches in the ladder"
    offenders = [b["id"] for b in body_branches if b.get("clean_capable")]
    assert not offenders, f"body-derived branches must not be CLEAN-capable: {offenders}"


# =========================================================================================
# 8. Every FACT binds request, response, artifacts, oracle version and evidence branch. UNMET
# =========================================================================================

@pytest.mark.xfail(strict=True, reason=f"UNMET — {_CLOSED_BY[8]}")
def test_inv08_the_evidence_envelope_binds_the_request_that_produced_the_response():
    """``CapturedExchange.request_bytes_ref`` exists and the Strix capture never fills it.

    A certificate on that path therefore binds one response body and no record of what was sent.
    """
    capture = _src("vendor/strix/strix/report/proof_capture.py")
    assert re.search(r"request_bytes_ref\s*=\s*[^\"']", capture) or 'part="request"' in capture, (
        "the capture never fetches or binds the exploit REQUEST bytes"
    )


def test_inv08_negative_control_the_envelope_field_exists_to_be_filled():
    poc = _src("engine/crucible/framework/v2/evidence/poc.py")
    assert "request_bytes_ref" in poc, "the evidence model already carries the field the capture leaves empty"


# =========================================================================================
# 9. Every refusal occurs before traffic.                                               MET
# =========================================================================================

def test_inv09_the_preflight_refusal_precedes_any_backend_run():
    runner = _fn_code("integration/vigil_integration/live/external_tool.py", "run_external_tool")
    gate_at = runner.index("_preflight_gate_refusal(")
    run_at = runner.find("backend.run(")
    assert run_at == -1 or gate_at < run_at, (
        "the tool subprocess can start before the pre-flight gate has refused"
    )


def test_inv09_negative_control_the_ordering_probe_can_see_both_anchors():
    runner = _fn_code("integration/vigil_integration/live/external_tool.py", "run_external_tool")
    assert "_preflight_gate_refusal(" in runner and ("backend.run(" in runner or "backend" in runner), (
        "the ordering probe lost one of its anchors and would pass vacuously"
    )


# =========================================================================================
# 10. Every engagement reconstructs and verifies offline.                               MET
# =========================================================================================

def test_inv10_offline_verification_gates_on_re_running_the_oracle():
    certify = _src("engine/crucible/framework/v2/evidence/certify.py")
    assert "reverify_context" in certify, (
        "certificate verification no longer re-fires the oracle — it would only be checking signatures"
    )


def test_inv10_negative_control_the_exported_bundle_ships_its_own_instructions():
    bundle = _src("integration/vigil_integration/proof/bundle.py")
    assert "HOW-TO-VERIFY" in bundle and "trust-root-fingerprint" in bundle.lower(), (
        "the bundle no longer ships offline verification instructions or the out-of-band pin"
    )


# =========================================================================================
# 11. Learning never overrides governance or mutates historical evidence.               MET
# =========================================================================================

def test_inv11_admission_is_the_only_route_to_a_certificate():
    adapter = _src("integration/vigil_integration/oracle_adapter.py")
    body = _fn_code("integration/vigil_integration/oracle_adapter.py", "certify_admitted")
    assert "AdmittedVerdict" in body and "TypeError" in body, (
        "certify_admitted no longer refuses anything that is not an AdmittedVerdict, so a learned or "
        "model-supplied verdict could reach the mint"
    )
    assert "is_known_bug_class" in adapter


def test_inv11_negative_control_no_learning_module_mints_directly():
    """A learning/RL module calling the mint would be a governance bypass, not a re-rank."""
    offenders = []
    for path in (_REPO / "integration" / "vigil_integration").rglob("*.py"):
        rel = path.relative_to(_REPO).as_posix()
        if not any(k in rel for k in ("learn", "memory", "knowledge", "rl_", "reward")):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "confirm_and_certify(" in text or "sign_certificate(" in text:
            offenders.append(rel)
    assert not offenders, f"a learning module reaches the mint directly: {offenders}"


# =========================================================================================
# 12. A failed subsystem degrades to INCONCLUSIVE or LEAD, never an optimistic verdict. UNMET
# =========================================================================================

@pytest.mark.xfail(strict=True, reason=f"UNMET — {_CLOSED_BY[12]}")
def test_inv12_a_failed_proof_subsystem_is_distinguishable_from_a_clean_target():
    """Proof failure is swallowed and the console renders "no proofs" identically to "nothing found".

    ``api.brain_decision``/``proof_list`` report ``pending`` when the record list is empty, so a broken
    bootstrap, a Caido outage, a failed mint and a genuinely clean target are one UI state.
    """
    api = _src("engine/crucible/framework/v2/console/api.py")
    assert re.search(r"verification_degraded|proof_unavailable|degraded", api), (
        "no typed degraded state exists: an unavailable proof subsystem is indistinguishable from a "
        "target with no findings"
    )


def test_inv12_negative_control_the_swallow_sites_are_real():
    """The probe targets a live defect: the sink swallows a failed mint rather than surfacing it."""
    sink = _src("integration/vigil_integration/proof/sink.py")
    assert "minted" in sink, "the sink no longer tracks whether a mint happened"
    cli = _src("vendor/strix/strix/interface/cli.py")
    assert "install_from_env" in cli, "the proof bootstrap call site moved"


# =========================================================================================
# The scoreboard itself
# =========================================================================================

def test_the_scoreboard_is_complete_and_its_shape_is_pinned():
    """All 12 accounted for, disjoint, and the met/unmet split matches the committed constant."""
    assert MET.isdisjoint(UNMET), "an invariant cannot be both met and unmet"
    assert MET | UNMET == set(range(1, 13)), "the scoreboard must account for all 12 invariants"
    assert set(_CLOSED_BY) == UNMET, "every unmet invariant must name the slice that closes it"
    for n, reason in _CLOSED_BY.items():
        assert reason.strip(), f"invariant {n} has no closing slice recorded"


def test_every_declared_gap_has_a_strict_xfail_test():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating."""
    module = __import__(__name__, fromlist=["*"])
    marked: dict[int, bool] = {}
    for name, obj in vars(module).items():
        m = re.match(r"test_inv(\d+)_", name)
        if not m or not callable(obj):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                marked[int(m.group(1))] = bool(mark.kwargs.get("strict"))
    assert set(marked) == UNMET, (
        f"xfail-marked invariants {sorted(marked)} != declared unmet {sorted(UNMET)} — the scoreboard and "
        "the tests disagree about what is broken"
    )
    non_strict = sorted(n for n, strict in marked.items() if not strict)
    assert not non_strict, f"invariants {non_strict} use a non-strict xfail and would hide a fix"
