"""Lane C / C1 — the RE-EXECUTABLE GENERAL oracle tier (close the audit-package reproduction gap).

The posture tier (test_posture_reexecutable) re-derives the SIX posture oracles standalone; the
predicate kernel re-derives ACHIEVED_STATE. This slice extends that to the GENERAL (non-posture,
non-predicate) oracle set whose bodies are PURE and STDLIB-ONLY — the web-vuln differential /
statistical / structural families. The standalone VIGIL-free verifier (docs/proof-carrying-finding/
verify_vf.py) now carries a BYTE-FOR-BYTE port of each of those oracle bodies + a context reader
(``reexecute_general_oracle``) that re-fires them over a retained ``oracle_context``.

These tests prove:
  1. byte-PARITY: for EVERY ported class, the standalone kernel equals the REAL framework oracle
     (framework.v2.verify.oracles.<fn>) on BOTH ``fired`` AND ``conclusive``, over a representative
     retained-evidence battery (fired + non-fired + conclusive/inconclusive cases);
  2. DISPATCH parity: ``reexecute_general_oracle`` over a retained verifier-context re-derives the
     SAME verdict the in-tree ``OracleVerifier.confirm`` reaches, incl. the protocol-constant pins
     (the differential discriminator / timing alpha are the AUTHORITY's, never the producer ctx) and
     the ``request_smuggling`` baseline-refusal;
  3. SOUND + FORGE-A-FALSE: a real confirmed-finding ``oracle_context`` re-derives SOUND standalone,
     and a TAMPERED copy (retained values edited so the oracle no longer fires) is REFUSED — the
     signed verdict's lie is caught by re-execution, producer-independently of the kernel copy;
  4. ZERO-VIGIL: verify_vf.py imports no framework/vigil/crucible code (AST over its import graph);
  5. HONEST BOUND: an IRREDUCIBLE oracle key (live/browser/subprocess/heavy-dep/collector) is
     REPORTED as not-reproduced, never faked as re-derived; the standalone CLI runs over a crafted
     context.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Two-env boundary: this parity test imports the offense framework (framework.v2.verify.*) to compare the
# zero-VIGIL standalone verifier against the REAL oracles, so it RUNS in the offense CI leg (engine/crucible
# on PYTHONPATH) and SKIPS cleanly in the keyless boundary leg where framework is intentionally absent.
pytest.importorskip("framework.v2")

from framework.v2.verify import oracles as O  # noqa: E402
from framework.v2.verify.adapter import FindingContext  # noqa: E402
from framework.v2.verify.verifier import OracleVerifier  # noqa: E402

_VERIFY_VF = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding" / "verify_vf.py"


def _load_verify_vf():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_vf_general_reexec", _VERIFY_VF)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # register before exec (dataclasses + future-annotations resolution)
    spec.loader.exec_module(mod)
    return mod


VF = _load_verify_vf()


# ---- 1. oracle-level byte-parity battery: kernel == real oracle on (fired, conclusive) ----------
# Each case: (oracle_name, args, kwargs). The battery spans a FIRE and a NON-FIRE (and, where the
# oracle has a channel-confirmed negative, a conclusive non-fire) for every ported class.
_DIFF_DISC = {"dimensions": ["status", "length", "lexical"], "length_threshold": 0.05,
              "lexical_threshold": 0.10, "expect": "differ"}
_SIG_BASE = [{"status": 200, "body": "NOROWS"} for _ in range(6)]


def _bool_round(true_body: str, false_body: str, k: int = 4):
    t = [{"status": 200, "body": true_body} for _ in range(k)]
    f = [{"status": 200, "body": false_body} for _ in range(k)]
    return {"trues": t, "falses": f, "true_repeats": [dict(x) for x in t],
            "false_repeats": [dict(x) for x in f]}


_ORACLE_CASES = [
    # differential_response — fire (status+body differ) and non-fire (indistinguishable)
    ("differential_response_oracle", ({"status": 200, "body": "aaaa"},
                                      {"status": 500, "body": "zzzzzzzz"}, _DIFF_DISC), {}),
    ("differential_response_oracle", ({"status": 200, "body": "same"},
                                      {"status": 200, "body": "same"}, _DIFF_DISC), {}),
    # timing — conclusive no-signal (adequate samples, no shift) and a fire (big dose)
    ("timing_oracle", ([100, 101, 102, 103, 104], [100, 101, 102, 103, 104]), {"alpha": 0.01}),
    ("timing_oracle", ([100, 101, 102, 103, 104], [2000, 2100, 2050, 1990, 2200]),
     {"injected_ms": 2000, "alpha": 0.01}),
    ("timing_oracle", ([100, 101], [200, 201]), {"alpha": 0.01}),  # insufficient samples -> inconclusive
    # boolean_inference — fire (clean 2-cluster partition) and refute (empty)
    ("boolean_inference_oracle", ([_bool_round("ROWDATA", "NOROWS") for _ in range(3)],),
     {"false_baseline_samples": _SIG_BASE}),
    ("boolean_inference_oracle", ([],), {}),
    # side_effect — marker in sink (fire) / absent (non-fire)
    ("side_effect_oracle", ("CANARY123XYZ", "x CANARY123XYZ y"), {}),
    ("side_effect_oracle", ("CANARY123XYZ", "nothing here"), {}),
    # reflection_context — canary in <script> (fire) / inert text (non-fire)
    ("reflection_context_oracle", ("cAnx9z", "<script>var a='cAnx9z'</script>"), {}),
    ("reflection_context_oracle", ("cAnx9z", "<p>cAnx9z</p>"), {}),
    # evaluation — computed product echoed (fire) / raw expression only (non-fire)
    ("evaluation_oracle", ("${7*7}", "49", "result is 49"), {}),
    ("evaluation_oracle", ("${7*7}", "49", "result is ${7*7}"), {}),
    # ssi_evaluation
    ("ssi_evaluation_oracle", ("<!--#exec cmd=...-->", "UNIQ42", "out UNIQ42 here", None), {}),
    ("ssi_evaluation_oracle", ("<!--#exec cmd=...-->", "UNIQ42", "out <!--#exec cmd=...--> here", None), {}),
    # error_signature — distinctive datastore error (fire) / benign (non-fire)
    ("error_signature_oracle", ("you have an error in your SQL syntax near '1''",), {}),
    ("error_signature_oracle", ("welcome to the homepage",), {}),
    # sanitizer_signal — ASAN (fire) / clean (non-fire)
    ("sanitizer_signal_oracle", ("==1==ERROR: AddressSanitizer: heap-buffer-overflow",), {}),
    ("sanitizer_signal_oracle", ("all tests passed",), {}),
    # system_prompt_disclosure — canary verbatim (fire) / absent (non-fire)
    ("system_prompt_disclosure_oracle", ("SENTINELcanary8charsXYZ123hi", "my prompt was SENTINELcanary8charsXYZ123hi"), {}),
    ("system_prompt_disclosure_oracle", ("SENTINELcanary8charsXYZ123hi", "I can't share that"), {}),
    # prompt_injection — tool flip (fire) / no flip (non-fire)
    ("prompt_injection_oracle", ({"tool_called": False, "text": "ok"}, {"tool_called": True, "text": "ok"}), {}),
    ("prompt_injection_oracle", ({"tool_called": False, "text": "ok"}, {"tool_called": False, "text": "ok"}), {}),
    # sql/command/nosql breakouts — fire + benign
    ("sql_injection_breakout_oracle", ("1' OR '1'='1",), {"param": "id"}),
    ("sql_injection_breakout_oracle", ("hello world",), {"param": "q"}),
    ("command_injection_breakout_oracle", ("x; cat /etc/passwd",), {"param": "q"}),
    ("command_injection_breakout_oracle", ("plain value",), {"param": "q"}),
    ("nosql_injection_breakout_oracle", ('{"$ne": null}',), {"param": "u"}),
    ("nosql_injection_breakout_oracle", ("alice",), {"param": "u"}),
    # weak_crypto_artifact — SHA1 sig (fire) / SHA256 (non-fire)
    ("weak_crypto_artifact_oracle", ({"kind": "signature", "signature_algorithm": "sha1WithRSAEncryption"},), {}),
    ("weak_crypto_artifact_oracle", ({"kind": "signature", "signature_algorithm": "sha256WithRSAEncryption"},), {}),
    # prototype_pollution — polluted readback (fire) / empty (non-fire)
    ("prototype_pollution_oracle",
     ({"polluted_key": "__proto__", "sentinel": "POLLUTEDv", "readback": {"POLLUTEDv": True},
       "benign_key": "other"},), {}),
    ("prototype_pollution_oracle", ({},), {}),
    # smuggling_desync — canary echoed in conflict leg only (fire) / absent both (non-fire)
    ("smuggling_desync_oracle",
     ({"canary": "ABCDEF123456", "technique": "CL.TE",
       "conflict": {"channel": True, "status": 200, "reason": "OK", "body": "x ABCDEF123456 y"},
       "control": {"channel": True, "status": 200, "reason": "OK", "body": "clean"}},), {}),
    ("smuggling_desync_oracle",
     ({"canary": "ABCDEF123456", "technique": "CL.TE",
       "conflict": {"channel": True, "status": 200, "reason": "OK", "body": "clean"},
       "control": {"channel": True, "status": 200, "reason": "OK", "body": "clean"}},), {}),
]


@pytest.mark.parametrize("name,args,kw", _ORACLE_CASES)
def test_kernel_matches_real_oracle(name, args, kw):
    real = getattr(O, name)(*args, **kw)
    port = getattr(VF, name)(*args, **kw)
    assert (port.fired, port.conclusive) == (real.fired, real.conclusive), (name, args, kw,
        (real.fired, real.conclusive), (port.fired, port.conclusive))


# ---- 2+3. dispatch parity + SOUND + FORGE-A-FALSE over REAL finding contexts --------------------
# (constructor, fire-kwargs, a mutator that turns the retained values benign). Each produces a REAL
# FindingContext for a ported class; the dispatch must agree with OracleVerifier.confirm, the real
# context must re-derive SOUND, and the tampered one must be REFUSED (not fired) — standalone.
def _ctx_sql_fire():
    return FindingContext.from_request_payload("1' OR '1'='1", bug_class="sqli_attempt", param="id")


def _ctx_cmd_fire():
    return FindingContext.from_request_payload("x; cat /etc/passwd", bug_class="command_injection_attempt",
                                               param="q")


def _ctx_nosql_fire():
    return FindingContext.from_request_payload('{"$ne": null}', bug_class="nosql_injection_attempt", param="u")


def _ctx_sanitizer_fire():
    return FindingContext.from_process_output("==1==ERROR: AddressSanitizer: heap-buffer-overflow",
                                              bug_class="crash")


def _ctx_error_fire():
    return FindingContext.from_error_signature("you have an error in your SQL syntax near '1''",
                                               bug_class="error_based_sqli")


def _ctx_side_fire():
    return FindingContext.from_side_effect("CANARY123XYZ", "reflected: CANARY123XYZ", bug_class="path_traversal")


def _ctx_weak_crypto_fire():
    return FindingContext.from_crypto_artifact({"kind": "signature",
                                                "signature_algorithm": "sha1WithRSAEncryption"})


_REAL_CTX_CASES = [
    ("sqli_attempt", _ctx_sql_fire, lambda oc: oc.update({"request_payload": "hello world"})),
    ("command_injection_attempt", _ctx_cmd_fire, lambda oc: oc.update({"request_payload": "plain value"})),
    ("nosql_injection_attempt", _ctx_nosql_fire, lambda oc: oc.update({"request_payload": "alice"})),
    ("crash", _ctx_sanitizer_fire, lambda oc: oc.update({"process_output": "all good"})),
    ("error_based_sqli", _ctx_error_fire, lambda oc: oc.update({"error_observed": "welcome home"})),
    ("path_traversal", _ctx_side_fire, lambda oc: oc.update({"observed_sink": "nothing"})),
    ("weak_crypto_artifact", _ctx_weak_crypto_fire,
     lambda oc: oc["crypto_artifact"].update({"signature_algorithm": "sha256WithRSAEncryption"})),
]


@pytest.mark.parametrize("bug_class,make,benign", _REAL_CTX_CASES)
def test_dispatch_sound_and_forged_negative_refused(bug_class, make, benign):
    ctx = make()
    oc = ctx.to_verifier_context()
    # dispatch parity vs the in-tree verifier
    real = OracleVerifier().confirm(oc)
    res = VF.reexecute_general_oracle(oc)
    assert res["reproduced"], (bug_class, oc)
    assert res["fired"] == real.confirmed, (bug_class, res, real.confirmed)
    assert res["fired"] is True, bug_class        # SOUND: the real evidence re-derives a positive
    # FORGE-A-FALSE: edit the retained values so the oracle no longer fires -> REFUSED standalone
    tampered = json.loads(json.dumps(oc))
    benign(tampered)
    res_t = VF.reexecute_general_oracle(tampered)
    assert res_t["fired"] is False, (bug_class, res_t)
    assert OracleVerifier().confirm(tampered).confirmed is False, bug_class


def test_request_smuggling_baseline_refused_like_verifier():
    """RED-PEN B3: a request_smuggling baseline/mutated pair is NOT admissible differential evidence;
    the standalone dispatch refuses it exactly as verifier._run does (no differential signal)."""
    oc = {"bug_class": "request_smuggling", "baseline": {"status": 200, "body": "a"},
          "mutated": {"status": 500, "body": "zzzz"}}
    res = VF.reexecute_general_oracle(oc)
    assert res["fired"] is False
    assert all(s["kind"] != "differential_response" for s in res["signals"])
    assert OracleVerifier().confirm(oc).confirmed is False


# ---- 4. ZERO-VIGIL: the standalone verifier imports no framework/vigil/crucible code -------------
def test_verify_vf_is_zero_vigil():
    src = _VERIFY_VF.read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden = ("framework", "vigil_core", "vigil_integration", "vigil_gateway", "gateway",
                 "crucible", "strix")
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in forbidden:
                    offenders.append(f"import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in forbidden:
                offenders.append(f"from {node.module} import ...")
    assert not offenders, f"verify_vf.py must be VIGIL-free: {offenders}"


# ---- 5. HONEST BOUND: irreducible key reported, and the standalone CLI runs over a crafted ctx ---
def test_irreducible_key_reported_not_faked():
    # After G1 the SERVICE_REACHABILITY handshake path is PORTED (re-derived over retained bytes), so the
    # only genuinely-irreducible general keys left are version_advisory (packaging), saml_xml (signxml/
    # lxml) and oob_hits (external collector). A FACT resting ONLY on one of those is REPORTED, never
    # faked as reproduced.
    for key, val in (("version_advisory", {"advisory": "x"}),
                     ("saml_xml", "<samlp:Response/>"),
                     ("oob_hits", [{"token": "t"}])):
        res = VF.reexecute_general_oracle({"bug_class": "generic", key: val})
        assert res["reproduced"] is False, (key, res)
        assert key in res["unported_keys"], (key, res)
        assert res["fired"] is False, (key, res)
    # and a PORTED handshake re-derives standalone (no longer reported irreducible)
    hs = VF.reexecute_general_oracle({"bug_class": "service_reachable",
                                      "handshake": {"transport": "tcp", "port": 22, "connected": True,
                                                    "banner": "SSH-2.0-OpenSSH"}})
    assert "handshake" not in hs["unported_keys"]
    assert hs["reproduced"] is True


def test_standalone_cli_reexec_general(tmp_path):
    import os

    oc = FindingContext.from_request_payload("1' OR '1'='1", bug_class="sqli_attempt",
                                             param="id").to_verifier_context()
    p = tmp_path / "ctx.json"
    p.write_text(json.dumps(oc), encoding="utf-8")
    # Run from a neutral cwd with the VIGIL PYTHONPATH stripped. NOTE: --prove-standalone is NOT
    # used here because this repo's .venv has the framework pip-INSTALLED, so it is importable
    # regardless of PYTHONPATH (a known local-env caveat); the ZERO-VIGIL guarantee is proven
    # STRUCTURALLY by test_verify_vf_is_zero_vigil (AST over the import graph) instead. This test
    # proves the CLI functionally re-derives a ported general verdict standalone.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith("CRUCIBLE_")}
    r = subprocess.run([sys.executable, str(_VERIFY_VF), "reexec-general", "--context", str(p)],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    out = (r.stdout + r.stderr)
    assert "sql_injection_breakout" in out and "RE-DERIVED" in out
    assert "producer-supplied" in out and "live re-run" in out


# ---- 6. ENFORCED A/B classification: the irreducible set is exactly the non-stdlib-closure oracles --
# This pins the HONESTY of LIMIT-audit-package-reproduction objectively: an oracle is "genuinely
# irreducible" iff re-firing its body needs a non-stdlib import (its AST import-closure over
# framework.v2.verify.oracles pulls a module outside the stdlib + the one Ed25519 lib). Every PORTED
# family must be stdlib-closure (so the port is sound), and every oracle the inventory calls
# PURE-BUT-DEFERRED must ALSO be stdlib-closure (so it is honestly "portable", never mislabelled
# irreducible). The genuinely-irreducible set must be EXACTLY the three named oracles.
import framework.v2.verify.oracles as _oracles_mod  # noqa: E402

_STDLIB_OK = {"ast", "base64", "binascii", "difflib", "hashlib", "hmac", "html", "ipaddress", "json",
              "math", "re", "collections", "dataclasses", "statistics", "typing", "urllib", "enum",
              "datetime", "functools", "itertools", "string", "unicodedata", "decimal", "cryptography"}

_PORTED = [
    "differential_response_oracle", "smuggling_desync_oracle", "timing_oracle",
    "boolean_inference_oracle", "side_effect_oracle", "reflection_context_oracle",
    "evaluation_oracle", "ssi_evaluation_oracle", "error_signature_oracle",
    "sanitizer_signal_oracle", "system_prompt_disclosure_oracle", "prompt_injection_oracle",
    "sql_injection_breakout_oracle", "command_injection_breakout_oracle",
    "nosql_injection_breakout_oracle", "weak_crypto_artifact_oracle", "prototype_pollution_oracle",
    # --- G1: the A-prime set Lane C left PURE-BUT-DEFERRED, now re-derived standalone (section 8c-G1).
    #     Each is stdlib+cryptography-closure (asserted below) and byte-faithfully ported. ---
    "service_reachability_oracle", "tls_weakness_oracle", "anonymous_reachable_oracle",
    "dom_execution_oracle", "dom_execution_csp_bypass_oracle", "credential_stuffing_oracle",
    "honeypot_hit_oracle", "jwt_forgery_oracle", "static_rule_oracle", "session_fixation_oracle",
    "mfa_bypass_oracle", "password_reset_invariant_oracle", "csrf_achieved_oracle",
    "workflow_abuse_oracle", "clickjacking_posture_oracle", "csrf_posture_oracle",
    "postmessage_posture_oracle", "csp_posture_oracle", "email_auth_posture_oracle",
    "identity_posture_oracle", "imds_credential_capture_oracle", "exposed_secret_validity_oracle",
    "gcp_sa_impersonation_oracle", "iam_escalation_oracle", "k8s_rbac_verb_grant_oracle",
    # cryptography is the ONE non-stdlib dep this verifier already carries, so an oracle whose only
    # extra need is cryptography is PORTABLE (not irreducible): x509 cert parsing / key classification.
    "certificate_validity_oracle", "mobile_posture_oracle",
    # credential_acceptance_oracle (M-11.3) — Lane C left it untracked; its closure is stdlib-only.
    "credential_acceptance_oracle",
]
# G1 completed the A-prime port: every formerly-deferred general oracle is now in _PORTED above, so
# the PURE-BUT-DEFERRED residual is EMPTY. The only general oracles NOT re-derived standalone are the
# three genuinely-irreducible ones (_IRREDUCIBLE below), whose import-closure needs a non-stdlib dep.
_PURE_BUT_DEFERRED: list[str] = []
# Genuinely irreducible-by-dependency: the body's import-closure needs a module NOT in
# stdlib + cryptography — packaging (version_range), signxml/lxml (saml_forgery), or a framework
# module backing an EXTERNAL collector's receipt crypto (oob_callback -> verify.oob).
_IRREDUCIBLE = {"oob_callback_oracle", "version_range_oracle", "saml_forgery_oracle"}


def _oracle_closure_needs_nonstdlib(seed: str) -> bool:
    """Does re-firing ``seed``'s body need a non-stdlib import? Compute the transitive closure of
    ``seed`` over oracles.py's module-level symbols and scan each for an import outside _STDLIB_OK."""
    src = Path(_oracles_mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    sym: dict = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            sym[node.name] = node
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    sym[t.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            sym[node.target.id] = node
    closure: set = set()
    stack = [seed]
    while stack:
        n = stack.pop()
        if n in closure or n not in sym:
            continue
        closure.add(n)
        for ref in {x.id for x in ast.walk(sym[n]) if isinstance(x, ast.Name)}:
            if ref in sym and ref not in closure:
                stack.append(ref)
    for n in closure:
        for node in ast.walk(sym[n]):
            if isinstance(node, ast.Import):
                if any(a.name.split(".")[0] not in _STDLIB_OK for a in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] not in _STDLIB_OK:
                    return True
    return False


def test_bucket_classification_is_enforced():
    # every PORTED family must be stdlib-closure (the port is sound) AND callable in verify_vf
    for name in _PORTED:
        assert not _oracle_closure_needs_nonstdlib(name), f"{name} ported but needs a non-stdlib dep"
        assert callable(getattr(VF, name, None)), f"{name} not present in verify_vf"
    # every PURE-BUT-DEFERRED oracle must be stdlib-closure (honestly portable, not irreducible)
    for name in _PURE_BUT_DEFERRED:
        assert not _oracle_closure_needs_nonstdlib(name), (
            f"{name} is listed PURE-BUT-DEFERRED but its closure needs a non-stdlib dep "
            f"— reclassify it as irreducible")
    # the genuinely-irreducible set must be EXACTLY the three named oracles (each needs a non-stdlib dep)
    for name in _IRREDUCIBLE:
        assert _oracle_closure_needs_nonstdlib(name), (
            f"{name} is named irreducible but its closure is stdlib-only — it is actually portable")
    # and none of the irreducibles were silently ported into verify_vf
    for name in _IRREDUCIBLE:
        assert not callable(getattr(VF, name, None)), f"{name} is irreducible but was ported — remove it"


# ---- 7. G1 A-PRIME oracle-level parity battery + dispatch SOUND/FORGE ----------------------------
# The battery (integration/tests/g1_aprime_battery.json) was HARVESTED by instrumenting the real
# oracles while their existing unit-test suites ran (a crib, per the C1 lesson), capturing one FIRED
# and one NON-FIRED real call per newly-ported A-prime family. Each entry asserts the standalone
# kernel == the real framework oracle on BOTH (fired, conclusive) — the byte-faithful-port guarantee
# proven over real retained evidence, independently of the AST byte-equality check.
_BATTERY_PATH = Path(__file__).resolve().parent / "g1_aprime_battery.json"


def _g1_decode(o):
    if isinstance(o, dict):
        if set(o) == {"__bytes__"}:
            import base64
            return base64.b64decode(o["__bytes__"])
        if set(o) == {"__tuple__"}:
            return tuple(_g1_decode(x) for x in o["__tuple__"])
        if set(o) == {"__fset__"}:
            return frozenset(_g1_decode(x) for x in o["__fset__"])
        if set(o) == {"__set__"}:
            return {_g1_decode(x) for x in o["__set__"]}
        return {k: _g1_decode(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_g1_decode(x) for x in o]
    return o


_G1_BATTERY = _g1_decode(json.loads(_BATTERY_PATH.read_text(encoding="utf-8")))

# Every A-prime family must be present in the battery with BOTH a fired and a non-fired real case.
_G1_FAMILIES = sorted(_G1_BATTERY)
_G1_BATTERY_CASES = [(name, slot) for name in _G1_FAMILIES for slot in ("fire", "nofire")]


def test_g1_battery_covers_every_ported_aprime_family():
    # the ported A-prime oracle functions (the G1 block of _PORTED) all appear in the battery
    aprime = set(_PORTED[17:])  # everything after the original Lane-C ports
    covered = set(_G1_BATTERY)
    # dom_execution_csp_bypass is exercised by the DOM battery entry under its own key
    missing = aprime - covered
    assert not missing, f"A-prime families with no parity battery case: {sorted(missing)}"
    for name, slots in _G1_BATTERY.items():
        assert slots.get("fire", {}).get("fired") is True, f"{name} battery has no genuine FIRED case"
        assert slots.get("nofire", {}).get("fired") is False, f"{name} battery has no NON-FIRED case"


@pytest.mark.parametrize("name,slot", _G1_BATTERY_CASES)
def test_g1_kernel_matches_real_oracle(name, slot):
    e = _G1_BATTERY[name][slot]
    args, kw = e["args"], e["kwargs"]
    real = getattr(O, name)(*args, **kw)
    port = getattr(VF, name)(*args, **kw)
    assert (port.fired, port.conclusive) == (real.fired, real.conclusive), (
        name, slot, (real.fired, real.conclusive), (port.fired, port.conclusive))
    # the captured verdict must also match (guards against battery drift)
    assert (port.fired, port.conclusive) == (e["fired"], e["conclusive"]), (name, slot)


# dispatch SOUND + FORGE-A-FALSE for every A-prime family: build the verifier-context the family's
# retained evidence occupies (mirroring verifier._run's ctx keys), and assert the standalone dispatch
# re-derives a POSITIVE over the real fire evidence and REFUSES the non-firing (tampered-benign) copy.
_G1_SINGLE_KEY = {
    "service_reachability_oracle": "handshake", "anonymous_reachable_oracle": "anon_get",
    "tls_weakness_oracle": "tls", "certificate_validity_oracle": "cert_validity",
    "credential_acceptance_oracle": "credential_acceptance", "csp_posture_oracle": "csp_control",
    "mobile_posture_oracle": "mobile_control", "email_auth_posture_oracle": "email_auth_control",
    "identity_posture_oracle": "identity_control", "imds_credential_capture_oracle": "imds_capture",
    "exposed_secret_validity_oracle": "secret_capture",
    "gcp_sa_impersonation_oracle": "gcp_impersonation_capture",
    "iam_escalation_oracle": "iam_escalation_capture",
    "k8s_rbac_verb_grant_oracle": "k8s_rbac_grant_control",
    "clickjacking_posture_oracle": "clickjacking_control", "csrf_posture_oracle": "csrf_control",
    "postmessage_posture_oracle": "postmessage_control", "static_rule_oracle": "static_rule",
    "session_fixation_oracle": "session_fixation", "mfa_bypass_oracle": "mfa_bypass",
    "password_reset_invariant_oracle": "password_reset_invariant",
    "csrf_achieved_oracle": "csrf_achieved", "workflow_abuse_oracle": "workflow_abuse",
}


def _g1_build_ctx(name, e):
    a, kw = e["args"], e["kwargs"]
    if name in _G1_SINGLE_KEY:
        return {_G1_SINGLE_KEY[name]: a[0]}
    if name == "honeypot_hit_oracle":
        return {"requested_path": a[0], "honeypot_paths": a[1],
                "crawler_allowlisted": bool(kw.get("crawler_allowlisted", False))}
    if name == "credential_stuffing_oracle":
        c = {"auth_events": a[0]}
        if kw.get("benign_sources") is not None:
            c["benign_sources"] = kw["benign_sources"]
        for k in ("alpha", "beta", "p1", "p0", "fwer"):
            if k in kw:
                c[f"credstuff_{k}"] = kw[k]
        return c
    if name == "jwt_forgery_oracle":
        c = {"jwt_token": a[0]}
        if kw.get("candidate_keys"):
            c["jwt_candidate_keys"] = kw["candidate_keys"]
        return c
    if name == "dom_execution_oracle":
        return {"dom_binding_calls": a[0], "dom_canary": a[1]}
    if name == "dom_execution_csp_bypass_oracle":
        return {"dom_binding_calls": a[0], "dom_canary": a[1], "csp_block_control": a[2]}
    raise KeyError(name)


@pytest.mark.parametrize("name", _G1_FAMILIES)
def test_g1_dispatch_sound_and_forged_refused(name):
    fire_ctx = _g1_build_ctx(name, _G1_BATTERY[name]["fire"])
    benign_ctx = _g1_build_ctx(name, _G1_BATTERY[name]["nofire"])
    rf = VF.reexecute_general_oracle(fire_ctx)
    rn = VF.reexecute_general_oracle(benign_ctx)
    assert rf["reproduced"] is True, (name, rf)      # a ported oracle re-fired over the retained keys
    assert rf["fired"] is True, (name, rf)           # SOUND: real evidence re-derives a positive
    assert rn["fired"] is False, (name, rn)          # FORGE-A-FALSE: tampered-benign copy is REFUSED


def test_g1_dispatch_standalone_cli_over_crafted_cert(tmp_path):
    """The standalone CLI re-derives a ported A-prime family (certificate_validity) over a retained
    context with the framework PYTHONPATH stripped (structural zero-VIGIL is proven separately)."""
    import os
    e = _G1_BATTERY["certificate_validity_oracle"]["fire"]
    oc = {"bug_class": "weak_tls_or_cert", "cert_validity": e["args"][0]}
    p = tmp_path / "cert_ctx.json"
    p.write_text(json.dumps(oc), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith("CRUCIBLE_")}
    r = subprocess.run([sys.executable, str(_VERIFY_VF), "reexec-general", "--context", str(p)],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "certificate_validity" in out and "RE-DERIVED" in out
