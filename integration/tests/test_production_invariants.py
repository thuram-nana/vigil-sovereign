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
ci.yml offense-leg run-list (the ``test_ci_framework_tests_run_in_offense_leg`` guard). The three inv-12
behavioural probes that drive a REAL vendored swallow site guard on ``pytest.importorskip("strix")`` — the
vendored tree is present in the offense env and absent in the sovereign env, so those probes run offense-side
and skip cleanly sovereign-side without ever importing ``framework``.
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
MET = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
UNMET: set[int] = set()
_CLOSED_BY: dict[int, str] = {}


def _src(rel: str) -> str:
    return (_REPO / rel).read_text(encoding="utf-8", errors="replace")


def _import_vendored_strix(name: str):
    """Import a submodule of the vendored strix UNDER REVIEW (``<repo>/vendor/strix``), not whatever copy an
    editable-install ``.pth`` may have appended to ``sys.path`` from a different checkout. In CI the checkout
    IS the branch, so the two coincide; in a shared dev venv this pins the behavioural inv-12 probes to the
    code being reviewed — which is REQUIRED, not mere convenience: if a probe imported strix from another
    checkout, deleting a vendored ``_vigil_degrade`` call in THIS tree would not be caught (the exact
    green-wash inv 12 guards). Skips (like ``importorskip``) when the vendored tree is absent — e.g. the
    sovereign env, where strix is deliberately not installed."""
    import importlib
    import sys

    vendored = _REPO / "vendor" / "strix"
    if not (vendored / "strix" / "__init__.py").is_file():
        pytest.skip("vendored strix tree not present (sovereign env)")
    p = str(vendored)
    if sys.path[:1] != [p]:                                  # pin the tree-under-review to the front
        sys.path[:] = [p] + [x for x in sys.path if x != p]
    for mod in [m for m in list(sys.modules) if m == "strix" or m.startswith("strix.")]:
        f = getattr(sys.modules[mod], "__file__", None) or ""
        if not f.startswith(p):                              # evict any strix resolved from OUTSIDE this tree
            del sys.modules[mod]
    try:
        return importlib.import_module(name)
    except ImportError as exc:                               # a genuinely broken/absent vendored tree
        pytest.skip(f"vendored strix not importable: {exc}")


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
# 6. No FACT without VIGIL-owned verification.                                        MET
# =========================================================================================

def test_inv06_no_minted_fact_rests_on_bytes_vigil_did_not_send():
    """MET. Every FACT path is now VIGIL-owned. Two closures:

      * WEB column (S7): a web finding reaches a FACT ONLY by VIGIL re-sending its own gated probe (pinned
        behaviourally by ``test_inv06_web_column_...`` below; proven live in ``test_web_redrive_proof_sink``).
      * ERROR-SIGNATURE column (this slice): ``build_report_mint`` REFUSES a FACT for an error-signature
        capture that binds no exploit REQUEST (the ``request_bytes_ref`` gate below) — so a certificate can
        no longer rest on a RESPONSE with no record of what was sent; the finding stays a LEAD until the
        request is bound (which ``proof_capture`` now does, inv 8). The gate mirrors the ORACLE's observed-
        exchange selection (not a literal role filter) and requires the request to RESOLVE to non-empty
        bytes (not merely a non-empty ref string) — both were reproduced bypasses, now closed. Behaviour is
        proven in ``test_proof_run``: ``..._without_a_bound_request_stays_a_lead`` (response-only → LEAD),
        ``..._with_a_bound_request_can_mint`` (request-bound → FACT), ``..._role_bypass_is_closed`` (role=""
        → LEAD), ``..._dangling_or_whitespace_request_ref_is_closed`` (unresolvable ref → LEAD)."""
    mint_code = _fn_code("integration/vigil_integration/proof/run.py", "build_report_mint")
    # structural: the gate must RESOLVE the request ref (not just check the string) — a reverted string-only
    # gate would drop the _resolve()/strip() enforcement. The behavioural tests above are the real guard.
    assert "request_bytes_ref" in mint_code and "_resolve(" in mint_code and ".strip()" in mint_code, (
        "the captured-bytes mint no longer resolves + non-empty-checks the exploit REQUEST binding — a FACT "
        "could rest on response-only bytes VIGIL did not send (dangling/whitespace ref or role bypass)"
    )


def test_inv06_web_column_a_web_finding_is_re_driven_by_traffic_vigil_sends():
    """LANDED (S7 web column): a web-re-drivable finding routes into the VIGIL-owned web re-drive, and the
    sink admits it to the mint even without a producer capture. Routing is asserted BEHAVIOURALLY (not by a
    source grep); the full live behaviour — a benign endpoint mints nothing, a vulnerable one mints an
    offline-verifiable FACT tied to the CLAIMED class — is in ``test_web_redrive_proof_sink.py``."""
    from vigil_integration.proof.run import _web_redrive_class
    from vigil_integration.proof.sink import _web_redrivable
    # behavioural routing: the three web classes (and their CWEs) route in; SQLi routes OUT to the LEAD path
    assert _web_redrive_class({"bug_class": "open_redirect"}) == "open_redirect"
    assert _web_redrive_class({"cwe": "CWE-942"}) == "cors"
    assert _web_redrive_class({"bug_class": "error_based_sqli"}) is None
    assert _web_redrive_class({"cwe": "CWE-89"}) is None
    assert _web_redrivable({"bug_class": "host_header_injection"}) is True
    assert _web_redrivable({"bug_class": "error_based_sqli"}) is False
    # and the mint actually CALLS the re-drive on the live code path (not merely names it)
    assert "web_redrive(" in _fn_code("integration/vigil_integration/proof/run.py", "_web_redrive_mint")


def test_inv06_slice1_the_retrospective_substring_correlation_is_removed():
    """S6 slice 1 (landed): the exploit exchange is cited causally, never selected by 'the most recent
    request whose path contains this substring'. Pinned so the unsound selector cannot silently return."""
    capture = _src("vendor/strix/strix/report/proof_capture.py")
    assert "req.path.cont" not in capture, "the retrospective path-substring correlation is back"
    assert "list_requests" not in capture, (
        "a most-recent/listing correlation is back on the capture path — the selector must be a cited id only"
    )


def test_inv06_negative_control_the_causal_identifiers_exist_and_are_simply_unused():
    """The remaining fix is wiring, not construction: the parameter and the returned ids already exist."""
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
# 8. Every FACT binds request, response, artifacts, oracle version and evidence branch.  MET
# =========================================================================================

def test_inv08_the_evidence_envelope_binds_the_request_that_produced_the_response():
    """MET: ``proof_capture`` now fetches the exploit REQUEST bytes (``_request_bytes`` reads
    ``result.request.raw``) and binds them as ``request_bytes_ref`` on the mutated exchange, so the
    certificate records what was SENT, not only the response. The mint refuses a FACT when that binding is
    absent (inv 6), so an unbound response can never be certified."""
    capture = _src("vendor/strix/strix/report/proof_capture.py")
    assert "_request_bytes" in capture and "request_bytes_ref" in capture, (
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
# 12. A failed subsystem degrades to INCONCLUSIVE or LEAD, never an optimistic verdict.  MET
# =========================================================================================

def test_inv12_a_failed_proof_subsystem_is_distinguishable_from_a_clean_target(tmp_path):
    """MET (S9). Six proof-path sites used to swallow a failure silently, so "target clean", "sink never
    installed", "capture failed" and "mint crashed" were ONE UI state (``proof_list`` reported ``pending``
    whenever the record list was empty). Now each site records a TYPED cause under
    ``<run_dir>/proofs/_degraded.json`` and the disposition distinguishes them. While degraded a CLEAN
    reading is IMPOSSIBLE — the exact conflation this invariant forbids.

    Behavioural: exercises the real recorder + summary directly (imports only ``vigil_integration``)."""
    from vigil_integration.proof import degradation as deg

    # A genuinely clean run: no records, no degradations — the ONLY honest "clean" state.
    clean = deg.summarize(n_records=0, facts=0, leads=0, denied=0,
                          degradations=deg.read_degradations(tmp_path))
    assert clean["disposition"] == deg.NOTHING_FOUND and clean["clean"], (
        "a healthy run with no findings must read as clean/nothing-found"
    )
    assert not clean["verification_degraded"]

    # A degraded run: the proof sink never installed. The record list is STILL empty, but the run must NOT
    # read as clean — it reads as a distinct, typed "subsystem unavailable" state.
    assert deg.record_degradation(tmp_path, deg.PROOF_SUBSYSTEM_UNAVAILABLE, where="probe")
    degraded = deg.summarize(n_records=0, facts=0, leads=0, denied=0,
                             degradations=deg.read_degradations(tmp_path))
    assert degraded["verification_degraded"] and not degraded["clean"], (
        "CLEAN must be impossible while the proof subsystem is degraded"
    )
    assert degraded["disposition"] != clean["disposition"], (
        "a down proof subsystem renders identically to a clean target — the inv-12 conflation is back"
    )

    # The three degradation kinds are mutually distinguishable dispositions, never one collapsed state.
    seen = {
        deg.summarize(n_records=0, facts=0, leads=0, denied=0,
                      degradations=[{"kind": k, "where": "x", "count": 1}])["disposition"]
        for k in (deg.PROOF_SUBSYSTEM_UNAVAILABLE, deg.CAPTURE_FAILED, deg.MINT_FAILED)
    }
    assert seen == {deg.PROOF_SUBSYSTEM_UNAVAILABLE, deg.CAPTURE_FAILED, deg.MINT_FAILED}, (
        "nothing-found / subsystem-unavailable / capture-failed / mint-failed must be distinguishable"
    )


def test_inv12_the_sink_records_a_typed_cause_when_the_mint_crashes(tmp_path):
    """Site behavioural: a crashed mint over a captured finding records MINT_FAILED and the finding stays a
    LEAD (never a FACT) — the failure is surfaced, not swallowed."""
    from vigil_integration.proof import degradation as deg
    from vigil_integration.proof.sink import CAPTURE_KEY, ProofSink

    def _boom(_report):
        raise RuntimeError("mint blew up")

    sink = ProofSink(run_dir=tmp_path, mint=_boom)
    report = {"id": "f1", "poc_script_code": "print('benign')",
              CAPTURE_KEY: {"exchanges": [{"channel": "request_payload", "role": "q"}], "blobs": {}}}
    res = sink(report)
    assert res.gate == "allow" and not res.minted, "a crashed mint must not yield a FACT (stays a LEAD)"
    assert deg.MINT_FAILED in {c["kind"] for c in deg.read_degradations(tmp_path)}, (
        "a crashed mint was swallowed silently instead of recording a typed mint_failed cause"
    )


def test_inv12_the_bootstrap_records_when_the_proof_sink_never_installs(tmp_path, monkeypatch):
    """Site behavioural: with a VIGIL run context set, an install failure records PROOF_SUBSYSTEM_UNAVAILABLE
    and NEVER raises (the scan keeps running) — instead of the silent "no proofs" that read as clean."""
    from vigil_integration.proof import bootstrap
    from vigil_integration.proof import degradation as deg

    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))

    def _boom(**_kwargs):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(bootstrap, "install", _boom)
    assert bootstrap.install_from_env() is None, "a failed install must degrade to None, never raise"
    assert deg.PROOF_SUBSYSTEM_UNAVAILABLE in {c["kind"] for c in deg.read_degradations(tmp_path)}, (
        "a proof-sink that never installed was swallowed silently (indistinguishable from a clean run)"
    )


def test_inv12_negative_control_a_healthy_run_is_clean_and_the_console_surfaces_the_state():
    """Proves the probe is not vacuous two ways: (1) with NO degradation recorded the summary is not
    degraded and reads as clean/has-proofs (so the degraded assertions above are meaningful), and (2) the
    console render actually CONSUMES the typed state (asserted structurally — the console lives in
    ``framework``, which this file must not import)."""
    from vigil_integration.proof import degradation as deg

    healthy = deg.summarize(n_records=2, facts=1, leads=1, denied=0, degradations=[])
    assert not healthy["verification_degraded"] and healthy["disposition"] == deg.HAS_PROOFS
    assert healthy["degraded_causes"] == []

    api = _src("engine/crucible/framework/v2/console/api.py")
    assert "verification_degraded" in api and "_proof_degradation_summary(" in api, (
        "the console proof_list no longer surfaces the typed verification-degraded state"
    )
    assert "_degraded.json" in api, (
        "the console proof reader no longer reads/skips the degradation manifest (it would mis-read it, or "
        "miss the degraded state entirely)"
    )


def test_inv12_the_vendored_bridge_kind_strings_match_the_typed_causes():
    """The vendored swallow sites route through a strix-internal degradation bridge that carries its OWN copy
    of the typed-cause strings (to avoid coupling the vendored tree to the integration package at module
    scope). Pin them to the integration constants so they can never drift — a drifted string would be dropped
    by ``read_degradations`` and silently vanish from the UI.

    Iterates ``sorted(deg._KINDS)`` (never a hand-maintained literal) so a NEW cause added to the source of
    truth is force-checked into BOTH the vendored bridge AND the console — a kind present in only one surface
    would degrade inconsistently."""
    from vigil_integration.proof import degradation as deg

    bridge = _src("vendor/strix/strix/report/degradation_hook.py")
    api = _src("engine/crucible/framework/v2/console/api.py")
    for val in sorted(deg._KINDS):
        assert f'"{val}"' in bridge, (
            f"the vendored degradation bridge drifted from the typed cause {val!r} — a mismatched kind is "
            "dropped at read time and never reaches the UI"
        )
        assert f'"{val}"' in api, (
            f"the console drifted from the typed cause {val!r} — a mismatched kind is dropped at read time "
            "and never reaches the proof screen"
        )


def test_inv12_a_web_redrive_that_RAISES_degrades_and_is_not_clean(tmp_path, monkeypatch):
    """RED-PEN regression (7th swallow). The mint callback's OWN web re-drive used to catch the re-drive
    EXCEPTION internally (``_web_redrive_mint`` ``except: return None``) and return the normal LEAD ``None``,
    so the sink saw ``minted=False`` with NO exception and recorded NO degradation → ``_degraded.json`` empty
    → the console read ``disposition=nothing_found`` / ``clean=True``. A VIGIL-owned re-drive EXECUTION
    failure (gateway down / network crash / framework import error) was thus indistinguishable from a clean
    target on the exact proof screen inv 12 governs.

    Now a RAISED re-drive records a typed ``REDRIVE_FAILED`` cause before returning None, so the run reads as
    ``verification_degraded`` / not clean. Reverting the fix makes this test fail.

    Runs the REAL ``build_report_mint`` callback (the sink's own MINT_FAILED path never sees this exception —
    the callback swallowed it), driving a web-re-drivable report whose ``web_redrive`` raises."""
    from vigil_integration.live import web_redrive as wr_mod
    from vigil_integration.proof import degradation as deg
    from vigil_integration.proof.run import build_report_mint

    def _boom(*_a, **_k):
        raise RuntimeError("gateway down / re-drive could not RUN")

    monkeypatch.setattr(wr_mod, "web_redrive", _boom)
    mint = build_report_mint(run_dir=tmp_path, signers=[], engagement_slug="x")

    # A web-re-drivable finding (CWE-601 → open_redirect) whose re-drive EXECUTION raises.
    res = mint({"cwe": "CWE-601", "endpoint": "http://target.example/redir", "check_id": "f-redir"})
    assert res is None, "a re-drive failure still drops the mint to a LEAD (None), never raises into Strix"

    degs = deg.read_degradations(tmp_path)
    assert deg.REDRIVE_FAILED in {c["kind"] for c in degs}, (
        "a RAISED web re-drive was swallowed silently — no typed redrive_failed cause recorded (the 7th swallow)"
    )
    summary = deg.summarize(n_records=0, facts=0, leads=0, denied=0, degradations=degs)
    assert summary["verification_degraded"] and not summary["clean"], (
        "a re-drive EXECUTION failure must read as verification_degraded / not clean, never clean"
    )
    assert summary["disposition"] != deg.NOTHING_FOUND, (
        "a down re-drive rendered identically to a clean target — the inv-12 conflation is back"
    )


def test_inv12_a_legitimate_web_non_confirmation_does_NOT_degrade(tmp_path, monkeypatch):
    """The critical distinction: only a RAISED execution failure degrades. A LEGITIMATE non-confirmation —
    a missing endpoint, or a re-drive that ran cleanly and simply did not confirm the class (gate refusal /
    oracle non-fire) — returns None WITHOUT raising and stays a plain, clean-eligible LEAD. If this path
    degraded, every unconfirmed web finding would poison the run's clean reading (an over-degradation FP)."""
    from vigil_integration.proof import degradation as deg
    from vigil_integration.proof.run import build_report_mint

    mint = build_report_mint(run_dir=tmp_path, signers=[], engagement_slug="x")

    # Missing endpoint: nothing to re-drive → LEAD, no execution attempted, must NOT degrade.
    assert mint({"cwe": "CWE-601", "check_id": "f-noendpoint"}) is None
    assert deg.read_degradations(tmp_path) == [], "a missing-endpoint LEAD must not record a degradation"

    # A re-drive that RUNS and returns a non-confirming result (oracle non-fire) → LEAD, still clean-eligible.
    from vigil_integration.live import web_redrive as wr_mod

    class _NoFire:
        facts: list = []
        refused = False
        notes: list = []
        url = "http://target.example/redir"

        def family_verdict(self, _c):
            return "INCONCLUSIVE"

        def family_verdicts(self):
            return {}

    monkeypatch.setattr(wr_mod, "web_redrive", lambda *_a, **_k: _NoFire())
    res = mint({"cwe": "CWE-601", "endpoint": "http://target.example/redir", "check_id": "f-nofire"})
    assert getattr(res, "is_fact", None) is False, "an oracle non-fire is a LEAD, not a FACT"
    assert deg.read_degradations(tmp_path) == [], (
        "a re-drive that ran cleanly but did not confirm must stay clean-eligible (no degradation)"
    )
    summary = deg.summarize(n_records=0, facts=0, leads=0, denied=0,
                            degradations=deg.read_degradations(tmp_path))
    assert summary["clean"] and summary["disposition"] == deg.NOTHING_FOUND


def test_inv12_a_malformed_capture_that_RAISES_records_capture_failed(tmp_path):
    """The other swallowed EXCEPTION path inside the mint callback: building the executor ``CapturedExchange``
    objects from the attached capture RAISED (malformed/hostile capture). The capture was PRESENT but
    unusable, so the finding cannot reach a FACT and its absence must not read as clean. An empty/absent
    capture (nothing to build) returns None ABOVE without raising and stays a plain, clean-eligible LEAD."""
    import importlib.util

    # The executor-capture mint imports ``framework.v2.evidence.poc.CapturedExchange`` BEFORE the guarded
    # construction, so this exception path only exists where ``framework`` is on the path — the offense leg.
    # ``find_spec`` LOCATES framework without importing it, so this file stays framework-import-free and keeps
    # running in BOTH legs (no framework-importorskip marker → it does not join the offense-only run-list the
    # ci-offense-leg guard enforces); the test simply skips sovereign-side, where the path under test cannot
    # exist.
    if importlib.util.find_spec("framework") is None:
        pytest.skip("executor-capture mint requires framework (offense env only)")

    from vigil_integration.proof import degradation as deg
    from vigil_integration.proof.run import build_report_mint
    from vigil_integration.proof.sink import CAPTURE_KEY

    mint = build_report_mint(run_dir=tmp_path, signers=[], engagement_slug="x")
    # A capture whose exchange dict carries keys CapturedExchange rejects → construction RAISES.
    report = {"check_id": "f-bad",
              CAPTURE_KEY: {"exchanges": [{"not_a_real_field": "boom", "another": object()}], "blobs": {}}}
    assert mint(report) is None, "a malformed capture drops the mint to a LEAD (None), never raises"
    assert deg.CAPTURE_FAILED in {c["kind"] for c in deg.read_degradations(tmp_path)}, (
        "a malformed-capture exception was swallowed silently instead of recording a typed capture_failed cause"
    )


def test_inv12_the_vendored_bridge_records_against_the_exported_run(tmp_path, monkeypatch):
    """Behavioural (MEDIUM): the vendored bridge is not a dead constant. With ``VIGIL_PROOF_RUN_DIR`` set,
    ``degradation_hook.record(kind, where, exc)`` routes a typed cause into the run manifest the console
    reads — deleting a vendored ``_vigil_degrade`` call would make this (and the per-site tests) fail."""
    hook = _import_vendored_strix("strix.report.degradation_hook")  # offense-env only; skips sovereign-side
    from vigil_integration.proof import degradation as deg

    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))
    hook.record(hook.CAPTURE_FAILED, "unit.bridge", RuntimeError("caido down"))
    assert deg.CAPTURE_FAILED in {c["kind"] for c in deg.read_degradations(tmp_path)}, (
        "the vendored bridge did not route the typed cause into the exported run manifest"
    )


def test_inv12_the_vendored_bridge_stdlib_fallback_when_integration_unimportable(tmp_path, monkeypatch):
    """Behavioural (MEDIUM): when ``vigil_integration`` is itself unimportable — the most extreme 'subsystem
    unavailable' — the bridge's stdlib fallback still writes the SAME manifest shape, so even a broken
    integration install stays distinguishable from a clean target."""
    import builtins

    hook = _import_vendored_strix("strix.report.degradation_hook")  # offense-env only; skips sovereign-side
    from vigil_integration.proof import degradation as deg

    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))
    real_import = builtins.__import__

    def _blocked_import(name, *a, **k):
        if name.startswith("vigil_integration"):
            raise ImportError("integration package unavailable")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    hook.record(hook.MINT_FAILED, "unit.fallback", RuntimeError("boom"))
    monkeypatch.setattr(builtins, "__import__", real_import)

    # Read back with the real reader (integration importable again): the stdlib fallback wrote the same shape.
    causes = deg.read_degradations(tmp_path)
    assert deg.MINT_FAILED in {c["kind"] for c in causes}, (
        "the stdlib fallback did not write a reader-compatible manifest when integration was unimportable"
    )


def test_inv12_a_real_vendored_site_records_capture_failed(tmp_path, monkeypatch):
    """Behavioural (MEDIUM): drive a REAL vendored swallow site end-to-end — ``proof_capture.capture_for_report``
    with a forced Caido raise — and assert a ``capture_failed`` cause lands in the exported run manifest.
    This is the behavioural coverage the green-wash finding demanded: the site actually CALLS the bridge."""
    import asyncio

    proof_capture = _import_vendored_strix("strix.report.proof_capture")  # offense-env only; skips sovereign
    from vigil_integration.proof import degradation as deg

    monkeypatch.setenv("VIGIL_PROOF_RUN_DIR", str(tmp_path))

    class _CaidoRaises:
        async def view_request(self, *_a, **_k):
            raise RuntimeError("caido unreachable")

    report = {"finding_class": "error_based_sqli", "check_id": "f-cap"}
    out = asyncio.run(
        proof_capture.capture_for_report(report, caido=_CaidoRaises(), explicit_ids=["exp1"])
    )
    assert out is None, "a failed capture drops the finding to a LEAD (None), never raises"
    assert deg.CAPTURE_FAILED in {c["kind"] for c in deg.read_degradations(tmp_path)}, (
        "the real vendored capture site did not record a capture_failed cause — its bridge call is dead"
    )


def _module_str_tuple(module_rel: str, name: str) -> set[str]:
    """The set of string constants in a module-level ``name = (...)`` tuple/list literal, parsed from the
    real source (never imported — the console lives in ``framework``, which this file must not import)."""
    tree = ast.parse(_src(module_rel))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ) and isinstance(node.value, (ast.Tuple, ast.List)):
            return {e.value for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise AssertionError(f"{name} tuple literal not found in {module_rel} — the probe is anchored to a moved seam")


def test_inv12_the_console_kind_tuple_is_pinned_to_the_typed_causes():
    """Drift guard (LOW): the console carries its OWN copy of the typed-cause strings (``_PROOF_DEGRADED_KINDS``
    in ``console/api.py``) so it can render with stdlib only. Iterate ``sorted(deg._KINDS)`` (never a
    hand-maintained literal) and pin every integration cause into BOTH the console AND the vendored bridge —
    a drifted/missing string would be dropped at read time and vanish from the proof screen. Then assert the
    console tuple is EXACTLY the source-of-truth set, so an extra/stale console kind is caught too."""
    from vigil_integration.proof import degradation as deg

    api = _src("engine/crucible/framework/v2/console/api.py")
    bridge = _src("vendor/strix/strix/report/degradation_hook.py")
    for val in sorted(deg._KINDS):
        assert f'"{val}"' in api, (
            f"the console _PROOF_DEGRADED_KINDS tuple drifted from the typed cause {val!r} — a mismatched "
            "kind is dropped at read time and never reaches the proof screen"
        )
        assert f'"{val}"' in bridge, (
            f"the vendored bridge drifted from the typed cause {val!r} — a mismatched kind is dropped at "
            "read time and never reaches the UI"
        )
    console_tuple = _module_str_tuple("engine/crucible/framework/v2/console/api.py", "_PROOF_DEGRADED_KINDS")
    assert console_tuple == set(deg._KINDS), (
        f"the console _PROOF_DEGRADED_KINDS set {sorted(console_tuple)} != the source-of-truth "
        f"deg._KINDS {sorted(deg._KINDS)} — the two disagree about the typed causes"
    )


def test_inv12_the_dossier_kind_tuple_is_pinned_to_the_typed_causes():
    """Drift guard (MEDIUM): the signed dossier hand-off (``report/dossier.py``) carries a THIRD stdlib copy
    of the typed-cause tuple (``_PROOF_DEGRADED_KINDS``), alongside the console and the vendored bridge. If a
    future 5th cause is added to ``deg._KINDS`` + console + bridge (to satisfy the other two guards) but
    forgotten here, ``_read_proof_degradation`` drops that kind at BUILD time -> counts empty -> degraded=False
    -> the governance-SIGNED index.html renders a degraded run with the clean banner. Pin it to the source of
    truth so a new cause is force-checked into ALL THREE copies."""
    from vigil_integration.proof import degradation as deg

    dossier = _src("engine/crucible/framework/v2/report/dossier.py")
    for val in sorted(deg._KINDS):
        assert f'"{val}"' in dossier, (
            f"the dossier _PROOF_DEGRADED_KINDS drifted from the typed cause {val!r} — a mismatched kind is "
            "dropped at build time and the SIGNED hand-off renders a degraded run as clean"
        )
    dossier_tuple = _module_str_tuple("engine/crucible/framework/v2/report/dossier.py", "_PROOF_DEGRADED_KINDS")
    assert dossier_tuple == set(deg._KINDS), (
        f"the dossier _PROOF_DEGRADED_KINDS set {sorted(dossier_tuple)} != the source-of-truth "
        f"deg._KINDS {sorted(deg._KINDS)} — the two disagree about the typed causes"
    )


def test_inv12_the_dossier_hand_off_renders_a_degraded_run_differently_from_a_clean_run(tmp_path):
    """The RED-PEN BLOCK this slice closes: the recorder/API were sound but the OPERATOR SURFACES were never
    wired, so a degraded-with-zero-records run rendered IDENTICALLY to a clean run. This drives the REAL
    dossier build over two zero-finding runs — one clean, one with a recorded degradation — and asserts the
    rendered ``index.html`` hand-off text DIFFERS: the clean run reads "nothing asserts an attacker
    capability", the degraded run reads "VERIFICATION DEGRADED — this run is NOT clean". Offense leg only:
    ``build_dossier`` touches ``framework``; ``find_spec`` locates it without importing (keeps this file
    framework-import-free), and the test skips sovereign-side."""
    import importlib.util
    if importlib.util.find_spec("framework") is None:
        pytest.skip("dossier build requires framework (offense env only)")

    import zipfile
    from framework.v2.report import dossier  # function-local (FATAL-2): never at module scope
    from vigil_integration.proof import degradation as deg

    def _index_html(run_dir) -> str:
        out_zip = run_dir / "dossier.zip"
        res = dossier.build_dossier(run_dir=str(run_dir), out_zip=str(out_zip),
                                    engagement_slug="inv12-probe")
        assert res.get("ok"), f"dossier build failed: {res}"
        with zipfile.ZipFile(out_zip) as z:
            return z.read("index.html").decode("utf-8"), res

    clean_run = tmp_path / "clean"
    (clean_run / "proofs").mkdir(parents=True)
    clean_html, clean_res = _index_html(clean_run)

    degraded_run = tmp_path / "degraded"
    (degraded_run / "proofs").mkdir(parents=True)
    assert deg.record_degradation(degraded_run, deg.PROOF_SUBSYSTEM_UNAVAILABLE, where="probe")
    degraded_html, degraded_res = _index_html(degraded_run)

    assert clean_html != degraded_html, (
        "a degraded-zero-records run renders identically to a clean run in the dossier hand-off — the "
        "inv-12 conflation the RED-PEN BLOCK named is back"
    )
    assert "VERIFICATION DEGRADED" in degraded_html and "NOT clean" in degraded_html, (
        "the degraded dossier hand-off does not surface the degraded/not-clean state"
    )
    assert "Nothing here asserts an attacker capability" in clean_html, (
        "the clean dossier hand-off lost its honest clean banner"
    )
    assert "VERIFICATION DEGRADED" not in clean_html, "a clean run must NOT render the degraded banner"
    # And the machine-readable hand-off summary agrees: degraded is never reported clean.
    assert degraded_res.get("verification_degraded") is True
    assert clean_res.get("verification_degraded") is False


def test_inv12_the_proof_screen_source_branches_on_the_typed_degraded_state():
    """No JS test runner exists, so this is a SOURCE-LEVEL guard (accepted by the slice) proving the operator
    proof screen was actually wired: ``drawProof`` must branch on the typed ``verification_degraded`` /
    ``disposition`` state, and the empty state must NOT key off the old conflating ``d.pending`` boolean. A
    degraded-zero-records run must look VISIBLY different from a clean 'no proofs yet' run."""
    src = _src("packages/vigil-ui/app.js")
    start = src.find("function drawProof(body)")
    assert start != -1, "drawProof not found in app.js — the probe is anchored to a moved seam"
    end = src.find("function route(", start)
    assert end != -1, "could not bound drawProof's source"
    body = src[start:end]

    assert "verification_degraded" in body, (
        "drawProof no longer branches on d.verification_degraded — a down subsystem renders like a clean run"
    )
    assert "disposition" in body, (
        "drawProof no longer branches on d.disposition — the four degraded causes collapse to one state"
    )
    # The regression this slice fixes: the empty-state text used to key off d.pending, conflating the four.
    assert "d.pending" not in body, (
        "the proof empty-state still keys off d.pending — the exact inv-12 conflation this slice removes"
    )


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
