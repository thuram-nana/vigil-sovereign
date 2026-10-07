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

from framework.v2.verify import oracles as O
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.verifier import OracleVerifier

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
    # a FACT resting on a LIVE handshake (SERVICE_REACHABILITY) is IRREDUCIBLE — reported, never fired
    res = VF.reexecute_general_oracle({"bug_class": "service_reachable", "handshake": {"banner": "x"}})
    assert res["reproduced"] is False
    assert "handshake" in res["unported_keys"]
    assert res["fired"] is False


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
