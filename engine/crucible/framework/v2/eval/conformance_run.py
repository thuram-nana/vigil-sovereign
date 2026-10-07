"""Lane C / C2 — the SIGNED conformance run (certifiable-ready attestation).

This is the capstone over C1's standalone re-execution tier. C1 ported the PURE general oracle bodies
into the VIGIL-FREE verifier (``docs/proof-carrying-finding/verify_vf.py``) and proved byte-parity
against the in-tree oracles. C2 turns that capability into a RE-RUNNABLE, OFFLINE-VERIFIABLE
conformance run over a FROZEN corpus, and emits a governance-signed scorecard that records EXACTLY
what was verified.

What a conformance run does (all three legs, in one deterministic pass):

  (a) FROZEN-CORPUS re-verification (the zero-VIGIL leg). For every fact-capable general family the
      corpus covers, one SOUND signed bundle — a real PCF v0.1 certificate minted by the real producer
      (``evidence.pcf.to_pcf``) over a reproducing ``oracle_context`` — is re-checked with the two
      STANDALONE verifiers (stdlib + the one Ed25519 lib, NO framework/vigil import):
        * ``verify_pcf.verify_pcf_cert`` → authenticity (m-of-n over the embedded certificate) + binding
          (the carried oracle_context re-hashes to the signed digest) + faithful projection + the
          out-of-band trust-root pin; and
        * ``verify_vf.reexecute_general_oracle`` → the verdict is RE-DERIVED from the retained evidence
          (the oracle re-fires standalone), closing the "trust the signer's verdict" gap for the pure
          families.
      Then the FULL TAMPER BATTERY: per bundle, a set of single-field / single-byte / re-signed /
      benign-retained-value tampers, EACH of which must be REFUSED by the appropriate standalone
      verifier. A tamper that slips through fails the run.

  (b) DIFFERENTIAL PARITY (the C1 check). The standalone re-execution kernel must equal the REAL
      framework oracle on BOTH ``fired`` AND ``conclusive`` over C1's representative oracle-case battery,
      and the standalone dispatch must agree with ``OracleVerifier.confirm`` over the frozen contexts.
      This leg necessarily runs BOTH the kernel and the real oracle (that is the whole point of a
      parity check), so it is not a zero-VIGIL leg — it is the authority the zero-VIGIL kernel is
      checked against.

  (c) SIGNED SCORECARD. A deterministic scorecard records the per-family SOUND+reproduced result, the
      tamper-battery tally (every tamper REFUSED), the parity result, the zero-VIGIL AST proof over both
      standalone verifiers, and — named honestly, never faked — the irreducible boundary (the oracle
      families whose body cannot be re-fired with stdlib + cryptography, and the producer-supplied
      liveness bound on every re-derivation). It is signed via the existing
      ``eval.benchmark_run.sign_scorecard`` path (m-of-n Ed25519 over the canonical bytes) and written
      under ``docs/conformance/``. The signature verifies OFFLINE — both with ``verify_scorecard`` and,
      zero-VIGIL, with ``verify_vf.verify_threshold`` over the SAME canonical bytes.

HONESTY BAR (this lane builds a certifiable-READY artifact; it does NOT fake an external certification):
  * The default signing key is a DETERMINISTIC CONFORMANCE-FIXTURE key, derived at runtime from a
    committed PUBLIC seed string (no private key sits in the repo). It makes the whole run — mint,
    verify, sign — byte-stable and re-runnable in CI with nothing provisioned, which is exactly what a
    self-attestation needs. It is NOT a governance key and the scorecard says so. A PUBLISHED attestation
    re-runs this with the operator's real governance key passed in (``--signing-key``; FATAL-2 — keys are
    provided, never minted here), producing the same scorecard CONTENT under the operator's trust root.
  * Re-execution proves the verdict is the correct FUNCTION of the retained evidence; it does NOT prove
    the evidence is live (that still needs an in-VIGIL re-run). That bound is recorded on every family.
  * The genuinely-irreducible oracle families (import-closure needs a module outside stdlib +
    cryptography) are NAMED in the scorecard, never counted as reproduced.

Re-run it:
    make conformance                               # mint (if absent) + verify + sign + offline-verify
    python3 -m framework.v2.eval.conformance_run verify     # the run proper (writes the signed scorecard)
    python3 -m framework.v2.eval.conformance_run mint       # (re)mint the frozen corpus (deterministic)
    python3 -m framework.v2.eval.conformance_run check      # verify-only, no write (CI / determinism)
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

_REPO_ROOT = Path(__file__).resolve().parents[5]
_PCF_DIR = _REPO_ROOT / "docs" / "proof-carrying-finding"
_VERIFY_VF = _PCF_DIR / "verify_vf.py"
_VERIFY_PCF = _PCF_DIR / "verify_pcf.py"
_CONF_DIR = _REPO_ROOT / "docs" / "conformance"
_CORPUS_DIR = _CONF_DIR / "corpus"
_SCORECARD = _CONF_DIR / "conformance-scorecard.json"
_TRUST_ROOT = _CORPUS_DIR / "trust-root.json"
_FINGERPRINT = _CORPUS_DIR / "TRUST-ROOT-FINGERPRINT.txt"

_C1_PARITY = _REPO_ROOT / "integration" / "tests" / "test_general_reexecutable.py"

# The committed PUBLIC seed the deterministic conformance-fixture key is derived from. Deriving the key
# at runtime (rather than storing a private key) keeps the repo free of a key file while making the run
# byte-stable. This key signs a SELF-attestation; it is NOT a governance key (see the honesty bar).
_FIXTURE_SEED = b"vigil-conformance-fixture-key/1 (NOT a governance key -- self-attestation only)"
_FIXTURE_KEY_ID = "conformance-fixture"
_FIXTURE_KEY_NAME = "VIGIL Conformance Fixture (deterministic, non-governance)"

_SCHEMA = "vigil-conformance-run/1"
_HIGH_CONFIDENCE = 0.90  # the confirm-threshold the general oracles fire at (mirrors verify.verifier)


# --------------------------------------------------------------------------------------------------
# Deterministic fixture key (Ed25519 private key == the 32-byte seed; the verifier only needs the pub).
# --------------------------------------------------------------------------------------------------
def fixture_keypair() -> tuple[str, str]:
    """Return ``(public_key_b64, private_key_b64)`` for the deterministic conformance-fixture key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seed = hashlib.sha256(_FIXTURE_SEED).digest()  # 32 bytes
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(pub).decode("ascii"), base64.b64encode(seed).decode("ascii")


# --------------------------------------------------------------------------------------------------
# The fact-capable general families. Each builder returns a real FindingContext whose retained
# oracle_context (a) reproduces in the in-tree verifier (so it mints a FACT) AND (b) re-fires in the
# zero-VIGIL kernel. A family that does not reproduce is REFUSED at mint — never faked into the corpus.
# `benign` edits the retained values so the oracle no longer fires (the FORGE-A-FALSE tamper).
# --------------------------------------------------------------------------------------------------
def _families() -> list[dict[str, Any]]:
    from framework.v2.verify.adapter import FindingContext as FC

    return [
        {"key": "sqli_attempt", "bug_class": "sqli_attempt", "ref": "CONF-sqli-breakout",
         "build": lambda: FC.from_request_payload("1' OR '1'='1", bug_class="sqli_attempt", param="id"),
         "benign": lambda oc: oc.update({"request_payload": "hello world"})},
        {"key": "command_injection_attempt", "bug_class": "command_injection_attempt",
         "ref": "CONF-command-breakout",
         "build": lambda: FC.from_request_payload("x; cat /etc/passwd",
                                                  bug_class="command_injection_attempt", param="q"),
         "benign": lambda oc: oc.update({"request_payload": "plain value"})},
        {"key": "nosql_injection_attempt", "bug_class": "nosql_injection_attempt",
         "ref": "CONF-nosql-breakout",
         "build": lambda: FC.from_request_payload('{"$ne": null}',
                                                  bug_class="nosql_injection_attempt", param="u"),
         "benign": lambda oc: oc.update({"request_payload": "alice"})},
        {"key": "crash_sanitizer", "bug_class": "crash", "ref": "CONF-sanitizer-signal",
         "build": lambda: FC.from_process_output(
             "==1==ERROR: AddressSanitizer: heap-buffer-overflow", bug_class="crash"),
         "benign": lambda oc: oc.update({"process_output": "all tests passed"})},
        {"key": "error_based_sqli", "bug_class": "error_based_sqli", "ref": "CONF-error-signature",
         "build": lambda: FC.from_error_signature(
             "you have an error in your SQL syntax near '1''", bug_class="error_based_sqli"),
         "benign": lambda oc: oc.update({"error_observed": "welcome to the homepage"})},
        {"key": "path_traversal_side_effect", "bug_class": "path_traversal", "ref": "CONF-side-effect",
         "build": lambda: FC.from_side_effect("CANARY123XYZ", "reflected: CANARY123XYZ",
                                              bug_class="path_traversal"),
         "benign": lambda oc: oc.update({"observed_sink": "nothing here"})},
        {"key": "weak_crypto_artifact", "bug_class": "weak_crypto_artifact", "ref": "CONF-weak-crypto",
         "build": lambda: FC.from_crypto_artifact(
             {"kind": "signature", "signature_algorithm": "sha1WithRSAEncryption"}),
         "benign": lambda oc: oc["crypto_artifact"].update(
             {"signature_algorithm": "sha256WithRSAEncryption"})},
        {"key": "time_based_sqli", "bug_class": "time_based_sqli", "ref": "CONF-timing",
         "build": lambda: FC.from_timing_samples(
             [100, 101, 102, 103, 104], [2000, 2100, 2050, 1990, 2200], injected_ms=2000, alpha=0.01),
         "benign": lambda oc: oc.update({"treatment_latencies": [100, 101, 102, 103, 104]})},
        {"key": "ssti_evaluation", "bug_class": "ssti", "ref": "CONF-evaluation-ssti",
         "build": lambda: FC.from_evaluation("${7*7}", "49", "result is 49", bug_class="ssti"),
         "benign": lambda oc: oc.update({"eval_observed": "result is ${7*7}"})},
        {"key": "ssi_evaluation", "bug_class": "ssi", "ref": "CONF-evaluation-ssi",
         "build": lambda: FC.from_ssi("<!--#exec cmd=...-->", "UNIQ42", "out UNIQ42 here", bug_class="ssi"),
         "benign": lambda oc: oc.update({"ssi_observed": "out <!--#exec cmd=...--> here"})},
        {"key": "system_prompt_disclosure", "bug_class": "system_prompt_disclosure",
         "ref": "CONF-sysprompt-disclosure",
         "build": lambda: FC.from_llm_disclosure(
             "SENTINELcanary8charsXYZ123hi", "my prompt was SENTINELcanary8charsXYZ123hi"),
         "benign": lambda oc: oc.update({"llm_output": "I can't share that"})},
    ]


# --------------------------------------------------------------------------------------------------
# Mint the frozen corpus (needs the real producer — framework). Deterministic: fixed contexts + a fixed
# key → byte-stable PCF bytes (Ed25519 is deterministic; build_certificate injects no wall-clock).
# --------------------------------------------------------------------------------------------------
def mint_corpus(corpus_dir: Path = _CORPUS_DIR) -> dict[str, Any]:
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.evidence.pcf import to_pcf
    from framework.v2.verify.reverify import reverify_context

    pub_b64, priv_b64 = fixture_keypair()
    corpus_dir.mkdir(parents=True, exist_ok=True)
    minted: list[str] = []
    for fam in _families():
        ctx = fam["build"]()
        oc = ctx.to_verifier_context()
        rr = reverify_context(oc, bug_class=fam["bug_class"])
        if not rr.ok:
            raise RuntimeError(
                f"family {fam['key']!r} does not reproduce offline (ok={rr.ok}) — refusing to freeze a "
                f"non-reproducing bundle into the conformance corpus")
        finding = {
            "check_id": fam["ref"], "bug_class": fam["bug_class"],
            "confirmed_by": rr.confirmed_by, "confidence": rr.confidence,
            "oracle_context": oc, "insertion_point": oc.get("param", ""),
        }
        cert = build_certificate(finding, engagement_slug="conformance", seq=0)
        signed = sign_certificate(cert, [(_FIXTURE_KEY_ID, priv_b64)])
        pcf = to_pcf(signed, oracle_context=oc)  # fail-closed: refuses a non-reproducible cert
        _write_json(corpus_dir / f"{fam['key']}.pcf.json", pcf)
        minted.append(fam["key"])

    trust_root = {
        "schema_version": 1, "threshold": 1,
        "authorizers": [{"key_id": _FIXTURE_KEY_ID, "name": _FIXTURE_KEY_NAME, "public_key_b64": pub_b64}],
    }
    _write_json(corpus_dir / "trust-root.json", trust_root)
    # the standalone verify_pcf fingerprint over the trust root (its wire format), pinned out of band
    pcf_mod = _load_module("verify_pcf", _VERIFY_PCF)
    fp = pcf_mod.trust_root_fingerprint(trust_root)
    (corpus_dir / "TRUST-ROOT-FINGERPRINT.txt").write_text(fp + "\n", encoding="utf-8")
    return {"minted": minted, "fingerprint": fp}


# --------------------------------------------------------------------------------------------------
# The zero-VIGIL verification leg + the full tamper battery.
# --------------------------------------------------------------------------------------------------
def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # register before exec (dataclasses / future-annotations)
    spec.loader.exec_module(mod)
    return mod


def _tamper_cases(pcf: dict, pcf_mod, trust_root: dict, fp: str,
                  benign: Callable[[dict], Any]) -> list[dict[str, Any]]:
    """Every case here MUST be refused (verdict==False). `refuted_by` names which standalone check
    catches it, for the scorecard record."""
    cases: list[dict[str, Any]] = []

    def pcf_refuses(label: str, mutate: Callable[[dict], Any]) -> None:
        t = deepcopy(pcf)
        mutate(t)
        ok, _ = pcf_mod.verify_pcf_cert(t, trust_root, pin=fp)
        cases.append({"tamper": label, "refuted_by": "verify_pcf", "refused": ok is False})

    # 1. flip a signed view field → lying-wrapper / signature mismatch
    pcf_refuses("flip-claim-class", lambda t: t["claim"].__setitem__("class", "xss"))
    # 2. strip the signatures → not authentic
    pcf_refuses("strip-signatures", lambda t: t["signature"].__setitem__("signatures", []))
    # 3. flip a byte inside the retained oracle_context value → digest no longer binds
    pcf_refuses("tamper-oracle-context-value",
                lambda t: t["evidence"]["oracle_context"]["value"].__setitem__("_x", "injected"))
    # 4. flip a signature byte → bad signature
    def _flip_sig(t: dict) -> None:
        sig = t["signature"]["signatures"][0]
        raw = bytearray(base64.b64decode(sig["sig"]))
        raw[-1] ^= 0x01
        sig["sig"] = base64.b64encode(bytes(raw)).decode()
    pcf_refuses("flip-signature-byte", _flip_sig)

    # 5. wrong out-of-band pin (a forged fresh trust root) → refused before any signature
    ok5, _ = pcf_mod.verify_pcf_cert(pcf, trust_root, pin="sha256:" + "0" * 64)
    cases.append({"tamper": "wrong-trust-root-pin", "refuted_by": "verify_pcf", "refused": ok5 is False})

    # 6. FORGE-A-FALSE: edit the retained values benign so the pure oracle no longer fires → the
    #    zero-VIGIL re-execution refuses the signed verdict's lie, independently of the signature.
    vf_mod = _load_module("verify_vf_conf", _VERIFY_VF)
    oc_t = deepcopy(pcf["evidence"]["oracle_context"]["value"])
    benign(oc_t)
    res_t = vf_mod.reexecute_general_oracle(oc_t)
    cases.append({"tamper": "benign-retained-value", "refuted_by": "verify_vf.reexecute",
                  "refused": res_t["fired"] is False})
    return cases


def run_frozen_corpus(corpus_dir: Path = _CORPUS_DIR) -> dict[str, Any]:
    """Re-verify every frozen bundle with the two STANDALONE verifiers + run the full tamper battery."""
    pcf_mod = _load_module("verify_pcf_conf", _VERIFY_PCF)
    vf_mod = _load_module("verify_vf_conf2", _VERIFY_VF)
    trust_root = json.loads((corpus_dir / "trust-root.json").read_text(encoding="utf-8"))
    fp = (corpus_dir / "TRUST-ROOT-FINGERPRINT.txt").read_text(encoding="utf-8").strip()
    fam_by_key = {f["key"]: f for f in _families()}

    families: list[dict[str, Any]] = []
    tamper_total = 0
    tamper_refused = 0
    for fam in _families():
        pcf_path = corpus_dir / f"{fam['key']}.pcf.json"
        pcf = json.loads(pcf_path.read_text(encoding="utf-8"))
        authentic, note = pcf_mod.verify_pcf_cert(pcf, trust_root, pin=fp)
        oc = pcf["evidence"]["oracle_context"]["value"]
        res = vf_mod.reexecute_general_oracle(oc)
        cases = _tamper_cases(pcf, pcf_mod, trust_root, fp, fam_by_key[fam["key"]]["benign"])
        tamper_total += len(cases)
        tamper_refused += sum(1 for c in cases if c["refused"])
        families.append({
            "family": fam["key"], "bug_class": fam["bug_class"],
            "confirmed_by": pcf["oracle"].get("id", ""),
            "pcf_sound": bool(authentic),
            "reproduced": bool(res["reproduced"]),
            "re_derived_fired": bool(res["fired"]),
            "re_fired_signals": sorted({s["kind"] for s in res["signals"] if s["fired"]}),
            "unported_keys": sorted(res["unported_keys"]),
            "sound": bool(authentic and res["reproduced"] and res["fired"] and not res["unported_keys"]),
            "tampers": cases,
            "tampers_all_refused": all(c["refused"] for c in cases),
            "note": note,
        })
    return {
        "families": families,
        "families_sound": sum(1 for f in families if f["sound"]),
        "families_total": len(families),
        "all_families_sound": all(f["sound"] for f in families),
        "tamper_total": tamper_total,
        "tamper_refused": tamper_refused,
        "all_tampers_refused": tamper_total > 0 and tamper_refused == tamper_total,
        "trust_root_fingerprint": fp,
    }


# --------------------------------------------------------------------------------------------------
# The C1 differential-parity leg (standalone kernel == real oracle). Reuses C1's exact case battery.
# --------------------------------------------------------------------------------------------------
def run_parity() -> dict[str, Any]:
    import framework.v2.verify.oracles as O
    from framework.v2.verify.verifier import OracleVerifier

    c1 = _load_module("c1_parity", _C1_PARITY)  # executes C1's module-level battery + loads its VF
    vf = c1.VF

    oracle_total = 0
    oracle_agree = 0
    for name, args, kw in c1._ORACLE_CASES:
        oracle_total += 1
        real = getattr(O, name)(*args, **kw)
        port = getattr(vf, name)(*args, **kw)
        if (port.fired, port.conclusive) == (real.fired, real.conclusive):
            oracle_agree += 1

    dispatch_total = 0
    dispatch_agree = 0
    for _bug_class, make, _benign in c1._REAL_CTX_CASES:
        dispatch_total += 1
        oc = make().to_verifier_context()
        real = OracleVerifier().confirm(oc)
        res = vf.reexecute_general_oracle(oc)
        if res["reproduced"] and res["fired"] == real.confirmed and res["fired"] is True:
            dispatch_agree += 1

    return {
        "oracle_case_total": oracle_total, "oracle_case_agree": oracle_agree,
        "dispatch_total": dispatch_total, "dispatch_agree": dispatch_agree,
        "parity_holds": oracle_total > 0 and oracle_agree == oracle_total
        and dispatch_total > 0 and dispatch_agree == dispatch_total,
    }


# --------------------------------------------------------------------------------------------------
# ZERO-VIGIL proof: both standalone verifiers import no framework/vigil/crucible code (AST, as C1).
# --------------------------------------------------------------------------------------------------
_FORBIDDEN = ("framework", "vigil_core", "vigil_integration", "vigil_gateway", "gateway",
              "crucible", "strix")


def _zero_vigil_offenders(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [f"import {a.name}" for a in node.names
                          if a.name.split(".")[0] in _FORBIDDEN]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _FORBIDDEN:
                offenders.append(f"from {node.module} import ...")
    return offenders


def run_zero_vigil() -> dict[str, Any]:
    vf = _zero_vigil_offenders(_VERIFY_VF)
    pcf = _zero_vigil_offenders(_VERIFY_PCF)
    return {"verify_vf_offenders": vf, "verify_pcf_offenders": pcf,
            "zero_vigil": not vf and not pcf}


def _irreducible_boundary() -> dict[str, Any]:
    """The honest residual, named — never faked as reproduced. Mirrors verify_vf's section header +
    LIMIT-audit-package-reproduction (pinned by test_bucket_classification_is_enforced)."""
    return {
        "liveness_bound": ("re-execution proves the verdict is the correct FUNCTION of the retained "
                           "evidence; it does NOT prove the evidence is live — that still needs an "
                           "in-VIGIL live re-run (the producer-supplied honesty bound)."),
        "irreducible_by_dependency": ["version_range_oracle (packaging)",
                                      "saml_forgery_oracle (signxml/lxml)",
                                      "oob_callback_oracle (framework verify.oob, external collector)"],
    }


# --------------------------------------------------------------------------------------------------
# Scorecard: deterministic, signed via eval.benchmark_run.sign_scorecard, offline-verifiable.
# --------------------------------------------------------------------------------------------------
def build_scorecard(corpus: dict[str, Any], parity: dict[str, Any],
                    zero_vigil: dict[str, Any]) -> dict[str, Any]:
    green = bool(corpus["all_families_sound"] and corpus["all_tampers_refused"]
                 and parity["parity_holds"] and zero_vigil["zero_vigil"])
    return {
        "schema": _SCHEMA,
        "tool": "VIGIL",
        "run": "lane-c/c2-conformance",
        "green": green,
        "attestation_key": {
            "kind": "conformance-fixture",
            "note": ("deterministic non-governance key derived from a committed public seed; signs a "
                     "SELF-attestation so the run is byte-stable and re-runnable with nothing "
                     "provisioned. A PUBLISHED attestation re-runs with the operator's governance key "
                     "(passed in; FATAL-2), yielding the same scorecard CONTENT under the operator's "
                     "trust root."),
        },
        "frozen_corpus": {
            "families_total": corpus["families_total"],
            "families_sound": corpus["families_sound"],
            "all_families_sound": corpus["all_families_sound"],
            "tamper_total": corpus["tamper_total"],
            "tamper_refused": corpus["tamper_refused"],
            "all_tampers_refused": corpus["all_tampers_refused"],
            "trust_root_fingerprint": corpus["trust_root_fingerprint"],
            "families": [
                {"family": f["family"], "bug_class": f["bug_class"], "confirmed_by": f["confirmed_by"],
                 "pcf_sound": f["pcf_sound"], "reproduced": f["reproduced"],
                 "re_derived_fired": f["re_derived_fired"], "re_fired_signals": f["re_fired_signals"],
                 "sound": f["sound"],
                 "tampers": [{"tamper": c["tamper"], "refuted_by": c["refuted_by"],
                              "refused": c["refused"]} for c in f["tampers"]]}
                for f in corpus["families"]
            ],
        },
        "differential_parity": parity,
        "zero_vigil": zero_vigil,
        "verified_standalone_with": [
            "docs/proof-carrying-finding/verify_pcf.py (authenticity + binding + pin)",
            "docs/proof-carrying-finding/verify_vf.py (reexecute_general_oracle — verdict re-derivation)",
        ],
        "irreducible_boundary": _irreducible_boundary(),
    }


def sign_scorecard_file(scorecard: dict[str, Any], *, signing_key_b64: str | None = None,
                        key_id: str | None = None, scorecard_path: Path = _SCORECARD) -> dict[str, Any]:
    """Write the scorecard JSON and sign it via the existing benchmark_run.sign_scorecard path."""
    from framework.v2.eval.benchmark_run import sign_scorecard

    if signing_key_b64 is None:
        pub_b64, signing_key_b64 = fixture_keypair()
        key_id = _FIXTURE_KEY_ID
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = base64.b64decode(signing_key_b64)
        pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(pub).decode("ascii")
        key_id = key_id or "operator"

    scorecard_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(scorecard_path, scorecard)
    authorizers = [{"key_id": key_id, "public_key_b64": pub_b64}]
    sig = sign_scorecard(scorecard_path, signers=[(key_id, signing_key_b64)],
                         authorizers=authorizers, threshold=1)
    return sig


def verify_scorecard_offline(scorecard_path: Path = _SCORECARD) -> dict[str, Any]:
    """Verify the signed scorecard OFFLINE two ways: the framework verify_scorecard (with the pinned
    fingerprint) AND the zero-VIGIL verify_vf.verify_threshold over the SAME canonical bytes."""
    from framework.v2.eval.benchmark_run import _scorecard_fingerprint, verify_scorecard

    sig = json.loads(scorecard_path.with_suffix(".sig.json").read_text(encoding="utf-8"))
    pin = scorecard_path.with_suffix(".fingerprint.txt").read_text(encoding="utf-8").strip()
    authorizers = sig["trust_root"]["authorizers"]
    fw_ok = verify_scorecard(scorecard_path, sig, trust_root_fingerprint=pin, expected_threshold=1)
    pin_ok = _scorecard_fingerprint(authorizers) == pin

    vf = _load_module("verify_vf_sc", _VERIFY_VF)
    body = vf.canonical_json(json.loads(scorecard_path.read_text(encoding="utf-8")))
    standalone_ok, _valid, _reason = vf.verify_threshold(body, sig["signatures"], sig["trust_root"])
    return {"framework_verify_scorecard": bool(fw_ok), "pin_matches": bool(pin_ok),
            "standalone_verify_vf_threshold": bool(standalone_ok),
            "offline_ok": bool(fw_ok and pin_ok and standalone_ok)}


def _write_json(path: Path, doc: Any) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# Orchestration.
# --------------------------------------------------------------------------------------------------
def conformance_run(*, corpus_dir: Path = _CORPUS_DIR) -> dict[str, Any]:
    """Run all three legs and return the result dict (no writes)."""
    corpus = run_frozen_corpus(corpus_dir)
    parity = run_parity()
    zero_vigil = run_zero_vigil()
    scorecard = build_scorecard(corpus, parity, zero_vigil)
    return {"corpus": corpus, "parity": parity, "zero_vigil": zero_vigil, "scorecard": scorecard}


# --------------------------------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------------------------------
def _cmd_mint(args: argparse.Namespace) -> int:
    out = mint_corpus()
    print(f"minted {len(out['minted'])} frozen bundles under {_CORPUS_DIR}")
    print(f"trust-root fingerprint (pin out of band): {out['fingerprint']}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    res = conformance_run()
    sig = sign_scorecard_file(res["scorecard"], signing_key_b64=args.signing_key or None,
                              key_id=args.key_id or None)
    offline = verify_scorecard_offline()
    sc = res["scorecard"]
    print(f"conformance run: GREEN={sc['green']}")
    print(f"  families: {res['corpus']['families_sound']}/{res['corpus']['families_total']} sound; "
          f"tampers: {res['corpus']['tamper_refused']}/{res['corpus']['tamper_total']} refused")
    print(f"  parity: oracle {res['parity']['oracle_case_agree']}/{res['parity']['oracle_case_total']}, "
          f"dispatch {res['parity']['dispatch_agree']}/{res['parity']['dispatch_total']}, "
          f"holds={res['parity']['parity_holds']}")
    print(f"  zero-VIGIL: {res['zero_vigil']['zero_vigil']}")
    print(f"  signed scorecard: {_SCORECARD}  (sig: {_SCORECARD.with_suffix('.sig.json').name})")
    print(f"  offline verify: {offline}")
    _ = sig
    return 0 if (sc["green"] and offline["offline_ok"]) else 2


def _cmd_check(args: argparse.Namespace) -> int:
    """Verify-only: run the legs and confirm the COMMITTED scorecard verifies offline. No writes."""
    res = conformance_run()
    offline = verify_scorecard_offline()
    sc = res["scorecard"]
    print(f"conformance CHECK: green={sc['green']} offline_ok={offline['offline_ok']}")
    return 0 if (sc["green"] and offline["offline_ok"]) else 2


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="conformance_run",
                                description="VIGIL Lane C/C2 — signed conformance run over a frozen corpus.")
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint", help="(re)mint the frozen corpus (deterministic; needs the producer)")
    m.set_defaults(fn=_cmd_mint)
    v = sub.add_parser("verify", help="run all legs, write + sign the scorecard, verify it offline")
    v.add_argument("--signing-key", default="", help="operator Ed25519 private seed b64 (FATAL-2: "
                   "passed in). Default: the deterministic conformance-fixture key.")
    v.add_argument("--key-id", default="", help="key id for --signing-key")
    v.set_defaults(fn=_cmd_verify)
    c = sub.add_parser("check", help="verify-only (no write): legs green + committed scorecard verifies")
    c.set_defaults(fn=_cmd_check)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
