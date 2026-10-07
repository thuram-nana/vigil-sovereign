#!/usr/bin/env python3
"""verify_vf.py — a STANDALONE, VIGIL-FREE verifier for the whole Verifiable-Fact remediation lifecycle.

This is the negative/continuous counterpart to ``verify_pcf.py``. Where that file lets a third party
re-derive a POSITIVE proof-carrying finding ("the exploit provably worked") without trusting or running
VIGIL, this file lets the same third party re-derive the REMEDIATION lifecycle:

    vulnerable  →  proven-fixed  →  still-proven  (witnessed, no-later-than T)

with ZERO VIGIL code. It imports only the Python standard library and one Ed25519 library
(``cryptography``) — no ``framework``, no ``vigil_core``, no ``vigil_integration``, no ``strix``, no
``gateway``. Every byte format below is re-implemented FROM THE PRODUCERS' documented wire spec (the VF
design specs + the module docstrings), not by importing them; a differential test
(``integration/tests/test_vf_differential.py``) proves this verifier agrees with the in-tree VIGIL
verifiers byte-for-byte on real artifacts and on a battery of tampers.

WHAT IT PROVES (offline, no target, no network):
  * prove-cert authenticity — the whole four-state prove-certificate's Ed25519 signature validates
    against a pinned governance key, so state / reason / every bound digest is tamper-evident;
  * verdict agreement — verdict.remediation_state == state and verdict.oracle_fired == (STILL_VULNERABLE);
  * REMEDIATED cross-binding — the embedded RemediationCertificate's OWN signature verifies, its retained
    contexts re-hash to their signed digests, it carries a live target response, and it is cross-bound to
    the outer cert (same finding / bug_class / freshness challenge / evidence digest) — so a valid embedded
    cert from another run cannot be spliced in;
  * attestation series — a signed, hash-chained, anti-rollback monotonic series of re-proof ticks: the
    chain rebuilds from the tick digests, the governance-signed head binds it (head↔chain + m-of-n
    signature), the durable high-water floor refuses a rolled-back / truncated series (entry_count PRIMARY,
    last_seq secondary), every tick re-verifies, and the drift series
    (present → proven-fixed → still-proven → regressed) is derived;
  * witnessed time bound — a strict-majority witness quorum (2t > n over distinct, canonical, non-low-order
    keys) TIMED-co-signed the attestation head, yielding a median no-later-than ``T``; and, when the bundle
    carries an A1 external RFC3161 time anchor and a pinned TSA cert is supplied (``--tsa-cert-pin``), the
    token is verified over ``checkpoint_hash`` with the system ``openssl ts`` (still VIGIL-free) and its
    genTime SUPERSEDES the median — a witness-honesty-independent "existed no-later-than T".

WHAT IT DOES: this file re-fires the oracle STANDALONE for every oracle whose body is PURE and
STDLIB-ONLY, re-deriving the verdict from the retained ``oracle_context`` with ZERO VIGIL import — the
check that turns "the bytes are authentic and bound" into "the oracle is genuinely silent / genuinely
fired". It covers, as byte-for-byte VIGIL-FREE ports of the in-tree ``verify.oracles`` bodies:
(1) the ACHIEVED_STATE predicate RE-EXECUTABLE probe kernel (a pure JSON-AST evaluator, ``_reexecute_posture``);
(2) the SIX posture oracle bodies
(``verify.oracles.{policy_path,k8s_posture,k8s_workload_posture,cloud_posture,mesh_posture,cicd_posture}_oracle``)
as ``posture_*_fires`` + the ``reexecute_posture_oracle`` context reader (section 8b); and (3) — Lane C/C1 —
the GENERAL pure families (section 8c) via ``reexecute_general_oracle``: differential_response (+ the
smuggling-desync differential), timing, boolean_inference, side_effect, reflection_context, evaluation
(+ ssi), error_signature, sanitizer_signal, system_prompt_disclosure, prompt_injection, the sql/command/
nosql injection-breakout parse-proofs, weak_crypto_artifact and prototype_pollution. A byte-for-byte
semantic-parity test pins every ported family to the in-tree oracle on BOTH ``fired`` AND ``conclusive``
(integration/tests/test_{posture,general}_reexecutable.py). Each re-derivation confirms the verdict is the
correct FUNCTION of the retained values, WITHOUT proving the values are live (that still needs a VIGIL
re-run — the producer-supplied honesty bound). Otherwise this file checks SIGNATURES, BINDING, and
STRUCTURE — authenticity, cross-binding, digest binding, chain, anti-rollback, quorum, and the median
clock — all fully checkable standalone. A single flipped byte anywhere flips a standalone verdict to NOT SOUND.

WHAT IT DOES NOT DO (two honestly-distinct remainders — see docs/limitations/inventory.json
LIMIT-audit-package-reproduction, pinned by test_general_reexecutable.py::test_bucket_classification_is
_enforced): (1) GENUINELY IRREDUCIBLE — three oracle bodies cannot be re-fired with stdlib + the one
Ed25519 lib (cryptography) because their import-closure needs a module NOT in that surface: version_range
(packaging), saml_forgery (signxml / lxml), and oob_callback (the framework verify.oob receipt verification
backing an EXTERNAL collector). Those rest on the signature + an in-VIGIL re-run, NAMED here, never faked as
reproduced. (2) PURE-BUT-NOT-YET-PORTED — a residual of oracles whose bodies ARE re-fireable with stdlib +
cryptography (same producer-supplied honesty bound as the ported families) that this slice did not yet port:
service_reachability, tls_weakness (live-handshake path), active_exposure, dom_execution (+ csp_bypass),
credential_stuffing, automated_access/honeypot, jwt_forgery (HS/structural), static_rule, session_fixation,
mfa_bypass, password_reset_invariant, csrf_achieved, workflow_abuse, the client-side posture oracles
(clickjacking/csrf/postmessage/csp), email_auth/identity posture, certificate_validity (cryptography.x509)
and mobile_posture (cryptography), and the WARDEN-gated cloud/cluster capture oracles
(imds/secret/gcp/iam/k8s_rbac). Until ported they rest on the signature + an in-VIGIL re-run. This boundary
is stated precisely, not faked closed.

Verification only — no offensive capability, never writes, never phones home, deterministic.

Usage:
    verify_vf.py verify --bundle bundle.json
        [--signer-pubkeys keys.json]           # {key_id: pubkey_b64} — prove-cert + tick admission
        [--trust-root gov-trust-root.json]     # governance TrustRoot for the attestation head
        [--witness-trust-root wit-trust-root.json]
        [--fingerprint sha256:<hex>]           # out-of-band pin on --trust-root
        [--witness-fingerprint sha256:<hex>]   # out-of-band pin on --witness-trust-root
        [--min-distinct-signers N]             # strict witness roster requirement
        [--prove-standalone]                   # first assert no VIGIL module is imported/importable

    bundle.json := { "prove_cert": {...}?,
                     "attestation": {"ticks":[...], "head":{...}|null, "floor":{...}|null}?,
                     "witnessed":   {"checkpoint":{...}, "witness_signatures":[...]}? }

Exit 0 iff every present component is SOUND; 2 if any is NOT SOUND; 3 on a usage / I/O error.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import datetime
import difflib
import hashlib
import hmac
import html
import ipaddress
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from statistics import median
from typing import Any, Optional, Sequence
from urllib.parse import quote as _urlquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# 0. VIGIL-free self-proof (optional, --prove-standalone). Same guarantee as verify_pcf: this verifier
#    imports only stdlib + cryptography; this check lets a caller *demonstrate* the running interpreter
#    has no VIGIL module reachable at all (used by the conformance test's clean subprocess).
# ---------------------------------------------------------------------------
# Every importable VIGIL package name a standalone env must NOT be able to reach. NOTE the offense egress
# gateway package is `vigil_gateway` (gateway/vigil_gateway) — checking only "gateway" would MISS it (the
# whole point of --prove-standalone is that NO vigil code is importable); "gateway" is kept as a defensive
# alias, and the crucible engine is reached as `framework`.
_VIGIL_MODULES = ("framework", "vigil_core", "vigil_integration", "vigil_gateway", "gateway", "strix")


def _assert_vigil_free() -> None:
    import importlib.util
    leaked = [m for m in _VIGIL_MODULES if m in sys.modules]
    if leaked:
        raise SystemExit(f"[FAIL] VIGIL modules already imported: {leaked} — not a standalone env")
    reachable = []
    for m in _VIGIL_MODULES:
        try:
            if importlib.util.find_spec(m) is not None:
                reachable.append(m)
        except (ImportError, ValueError, ModuleNotFoundError):
            pass
    if reachable:
        raise SystemExit(f"[FAIL] VIGIL modules are importable here: {reachable} — not a standalone env")
    print("  [standalone] confirmed VIGIL-free: framework / vigil_core / vigil_integration / vigil_gateway / "
          "gateway / strix are neither imported nor importable in this interpreter")


# ---------------------------------------------------------------------------
# 1. Canonical bytes + digests + domain separation.
#    TWO canonicalizers, because the producers use two:
#      * canonical_json      — ensure_ascii=False  (vigil_core.canonical / the crucible spine): used for
#        the prove-cert signing bytes, digest_payload, the chain entry/head bytes, and the timed-witness
#        bytes. This is the same function verify_pcf.py re-implements.
#      * canonical_json_ascii — ensure_ascii=True  (remediation_cert._canon): used ONLY for the embedded
#        RemediationCertificate's context digests and whole-cert signing bytes. For ASCII content the two
#        are byte-identical; they diverge ONLY on non-ASCII — so both are pinned against the producers on a
#        NON-ASCII payload in test_vf_differential.py::test_byte_parity_with_the_producers (an ASCII-only
#        parity test would not catch a swap of the two; the non-ASCII row does).
# ---------------------------------------------------------------------------
GENESIS_PREV = "0" * 64
_EVIDENCE_DOMAIN = b"crucible-evidence-v1\x00"
_PROVE_CERT_DOMAIN = b"vigil-remediation-prove-cert-v1\x00"
_REM_CERT_DOMAIN = b"vigil-remediation-cert-v2\x00"
_WITNESS_TIME_DOMAIN = b"vigil-attestation-witness-time-v1\x00"
# The timeless transparency checkpoint domain — used to recompute checkpoint_hash (what the RFC3161
# external time anchor binds). Byte-identical to transparency._WITNESS_DOMAIN. v2 (C-S1): the checkpoint
# now commits the prune boundary (base_seq/base_count) in to_dict; the domain suffix is bumped v1->v2 in
# lockstep so this standalone verifier recomputes the SAME checkpoint_hash the in-tree code signs.
_TRANSPARENCY_CHECKPOINT_DOMAIN = b"vigil-transparency-checkpoint-v2\x00"
# The Z1 channel-binding notary-cosign domain — byte-identical to channel_binding._CHANNEL_BINDING_DOMAIN.
_CHANNEL_BINDING_DOMAIN = b"vigil-zktls-channel-binding-v1\x00"
_CHANNEL_BINDING_SCHEMA = "vigil-zktls-channel-binding-v1"
_CHANNEL_BINDING_KINDS = ("tls-exporter", "tls-transcript", "test-vector")

_PROVE_CERT_SCHEMA = "vigil-remediation-prove-cert-v1"
_REM_CERT_SCHEMA = "vigil-remediation-cert-v2"


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_json_ascii(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def evidence_signing_bytes(payload: dict) -> bytes:
    return _EVIDENCE_DOMAIN + canonical_json(payload)


def _context_digest(context: dict) -> str:
    """The remediation-cert context digest: sha256 of the ASCII-canonical context bytes (byte-identical
    to remediation_cert._context_digest / fix_oracle.build_fix_signer)."""
    return sha256_hex(canonical_json_ascii(context))


# ---------------------------------------------------------------------------
# 2. Ed25519 primitives + m-of-n threshold, with weak-key rejection (identical to verify_pcf / vigil_core).
# ---------------------------------------------------------------------------
_ED25519_P = 2**255 - 19
_Y_MASK = (1 << 255) - 1
_SMALL_ORDER_POINTS = (
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    b"\xec" + b"\xff" * 31,
    b"\xed" + b"\xff" * 31,
    b"\xee" + b"\xff" * 31,
)


class WeakKey(Exception):
    """A public key that must never be admitted (non-canonical y>=p, or a low-order point)."""


def _reject_weak_public_key(raw: bytes) -> None:
    if (int.from_bytes(raw, "little") & _Y_MASK) >= _ED25519_P:
        raise WeakKey("Ed25519 public key is non-canonical (y >= p)")
    for entry in _SMALL_ORDER_POINTS:
        if raw[:31] == entry[:31] and (raw[31] & 0x7F) == (entry[31] & 0x7F):
            raise WeakKey("Ed25519 public key is a low-order point (weak key)")


def _b64_exact(value: str, n: int, what: str) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != n:
        raise ValueError(f"{what} decodes to {len(raw)} bytes, expected {n}")
    return raw


def verify_one(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """True iff a valid Ed25519 signature over ``message``. False on a bad signature OR any malformed
    key/signature material (fail-closed) — a caller never has to catch. Weak keys are rejected first."""
    try:
        raw = _b64_exact(str(public_key_b64), 32, "Ed25519 public key")
        _reject_weak_public_key(raw)
        sig = _b64_exact(str(signature_b64), 64, "Ed25519 signature")
    except (WeakKey, ValueError, binascii.Error):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except InvalidSignature:
        return False


def verify_threshold(message: bytes, signatures: list, trust_root: dict) -> tuple[bool, list, str]:
    """Count DISTINCT trust-root authorisers with a valid signature; compare to the threshold. Signatures
    carry ``key_id`` + a base64 signature under ``signature_b64`` (spine wire) or ``sig`` (rem-cert wire).
    Returns (satisfied, valid_key_ids, reason)."""
    by_id = {a.get("key_id"): a for a in trust_root.get("authorizers", []) if isinstance(a, dict)}
    threshold = int(trust_root.get("threshold", 0))
    valid: list[str] = []
    seen: set = set()
    for s in signatures:
        if not isinstance(s, dict):
            continue
        kid = s.get("key_id")
        if kid in seen:
            continue
        seen.add(kid)
        auth = by_id.get(kid)
        if auth is None:
            continue
        sig_b64 = s.get("signature_b64") if s.get("signature_b64") is not None else s.get("sig")
        if verify_one(str(auth.get("public_key_b64", "")), message, str(sig_b64)):
            valid.append(str(kid))
    satisfied = len(valid) >= threshold and threshold >= 1
    return satisfied, valid, f"{len(valid)} valid distinct signature(s) vs threshold {threshold}"


def trust_root_fingerprint(trust_root: dict) -> str:
    return "sha256:" + digest_payload(trust_root)


def _check_pin(trust_root: dict, pin: str) -> tuple[bool, str]:
    fp = trust_root_fingerprint(trust_root)
    pin = (pin or "").strip()
    if not pin:
        return True, f"UNPINNED ({fp}) — authenticity NOT anchored; obtain the operator's fingerprint OOB"
    want = pin if pin.startswith("sha256:") else ("sha256:" + pin)
    if want.lower() != fp.lower():
        return False, f"fingerprint pin MISMATCH — expected {want}, got {fp}"
    return True, f"PINNED OK ({fp})"


# ---------------------------------------------------------------------------
# 3. RemediationCertificate (the embedded negative proof) — authenticity + digest binding + liveness.
#    Boundary: silence/control-fire (oracle re-fire) is NOT checked standalone (needs the oracle bodies).
# ---------------------------------------------------------------------------
# Response-bearing FindingContext keys: a NON-EMPTY value means the target actually ANSWERED (the same
# single-source-of-truth set remediation_cert._RESPONSE_KEYS uses for its liveness control). Connection-
# style capture fields are DELIBERATELY excluded (their helpers return a non-empty dict on FAILURE).
_RESPONSE_KEYS = frozenset({
    "baseline", "mutated", "probe_rounds", "baseline_latencies", "treatment_latencies",
    "observed_state", "observed_evidence", "observed_sink", "eval_observed", "eval_control",
    "error_observed", "error_control", "dom_binding_calls", "process_output", "oob_hits",
    "llm_output", "pi_treatment", "pi_control", "auth_events",
})


def _has_live_response(context: Any) -> bool:
    if not isinstance(context, dict):
        return False
    return any(context.get(k) not in (None, "", [], {}) for k in _RESPONSE_KEYS)


def _rem_cert_signing_bytes(cert_without_sig: dict) -> bytes:
    return _REM_CERT_DOMAIN + canonical_json_ascii(cert_without_sig)


def verify_remediation_cert(cert: dict, *, signer_pubkeys: dict) -> tuple[bool, str]:
    """Standalone verification of an embedded RemediationCertificate — the SUBSET checkable without the
    oracle: (bound) both retained contexts re-hash to their signed digests; (live) the patched context
    carries a target response; (authentic) the whole-cert Ed25519 signature over the rem-cert domain +
    ASCII-canonical cert-minus-signature verifies against the pinned key (so no control was stripped).
    Does NOT check silence/control-fire — that is the oracle-re-fire boundary the VIGIL verifier owns."""
    if not isinstance(cert, dict) or cert.get("schema") != _REM_CERT_SCHEMA:
        return False, "not a vigil-remediation-cert-v2"
    patched = cert.get("patched_oracle_context")
    control = cert.get("positive_control_context")
    if not (isinstance(patched, dict) and patched and isinstance(control, dict) and control):
        return False, "missing patched_oracle_context / positive_control_context"

    if not _has_live_response(patched):
        return False, "no captured response in the patched context — unreachable, not a proven fix (INDETERMINATE)"
    if (_context_digest(patched) != str(cert.get("patched_context_sha256") or "")
            or _context_digest(control) != str(cert.get("positive_control_sha256") or "")):
        return False, "context digest mismatch (patched or positive-control tampered)"

    sigblk = cert.get("signature")
    if not (isinstance(sigblk, dict) and sigblk.get("key_id") and sigblk.get("sig")):
        return False, "missing/malformed signature block"
    key_id, sig = str(sigblk["key_id"]), str(sigblk["sig"])
    pub = signer_pubkeys.get(key_id) if isinstance(signer_pubkeys, dict) else None
    if not pub:
        return False, f"no pinned public key for signer {key_id!r}"
    msg = _rem_cert_signing_bytes({k: v for k, v in cert.items() if k != "signature"})
    if not verify_one(pub, msg, sig):
        return False, "signature invalid (forged/tampered/stripped-control/wrong key)"
    return True, "bound + live + authentic (oracle silence/fire NOT checked standalone — needs VIGIL)"


# ---------------------------------------------------------------------------
# 4. The four-state ProveCertificate.
# ---------------------------------------------------------------------------
class State:
    REMEDIATED = "REMEDIATED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    REFUSED = "REFUSED"


_STATES = (State.REMEDIATED, State.STILL_VULNERABLE, State.INCONCLUSIVE, State.REFUSED)


def _prove_cert_signing_bytes(cert_without_signer: dict) -> bytes:
    return _PROVE_CERT_DOMAIN + canonical_json(cert_without_signer)


def verify_prove_cert(cert: dict, *, signer_pubkeys: dict) -> tuple[bool, str]:
    """Offline verification of a four-state prove-certificate (mirrors the checkable subset of
    ``prove_driver.verify_prove_certificate``, minus the oracle re-fire):

      1. the whole-cert Ed25519 signature over the prove-cert domain + canonical cert-minus-signer
         verifies against a pinned governance key (state / reason / every bound digest tamper-evident);
      2. verdict.remediation_state == state and verdict.oracle_fired == (state == STILL_VULNERABLE);
      3. for REMEDIATED, the embedded RemediationCertificate is present, its own signature verifies +
         digests bind + it is live, and it is CROSS-BOUND to this outer cert (finding_id / bug_class /
         freshness_challenge / fresh_oracle_context_digest) — so a valid embedded cert from another run
         cannot be spliced in.

    Fail-closed. Does NOT re-fire the oracle (documented boundary — see the module docstring)."""
    if not isinstance(cert, dict) or cert.get("schema") != _PROVE_CERT_SCHEMA:
        return False, "not a vigil-remediation-prove-cert-v1"
    state = str(cert.get("state") or "")
    if state not in _STATES:
        return False, f"unknown state {state!r}"

    sigblk = cert.get("signer")
    if not (isinstance(sigblk, dict) and sigblk.get("key_id") and sigblk.get("signature")):
        return False, "missing/malformed signer block"
    key_id, sig = str(sigblk["key_id"]), str(sigblk["signature"])
    pub = signer_pubkeys.get(key_id) if isinstance(signer_pubkeys, dict) else None
    if not pub:
        return False, f"no pinned public key for signer {key_id!r}"
    msg = _prove_cert_signing_bytes({k: v for k, v in cert.items() if k != "signer"})
    if not verify_one(pub, msg, sig):
        return False, "signature invalid (forged/tampered/wrong key)"

    verdict = cert.get("verdict") or {}
    if str(verdict.get("remediation_state")) != state:
        return False, "verdict.remediation_state disagrees with the certificate state"
    if bool(verdict.get("oracle_fired")) != (state == State.STILL_VULNERABLE):
        return False, "verdict.oracle_fired disagrees with the state"

    if state == State.REMEDIATED:
        embedded = (cert.get("evidence") or {}).get("embedded_remediation_cert")
        if not isinstance(embedded, dict):
            return False, "REMEDIATED cert has no embedded RemediationCertificate"
        of = cert.get("original_finding") or {}
        ex = cert.get("execution") or {}
        ev = cert.get("evidence") or {}
        if str(embedded.get("finding_ref")) != str(of.get("finding_id")):
            return False, "embedded remediation cert finding_ref != outer finding_id"
        if str(embedded.get("bug_class")) != str(of.get("bug_class")):
            return False, "embedded remediation cert bug_class != outer bug_class"
        if str((embedded.get("controls") or {}).get("freshness_nonce")) != str(ex.get("freshness_challenge")):
            return False, "embedded remediation cert freshness_nonce != outer freshness_challenge"
        if str(embedded.get("patched_context_sha256")) != str(ev.get("fresh_oracle_context_digest")):
            return False, "embedded patched-context digest != outer fresh_oracle_context_digest"
        ok, reason = verify_remediation_cert(embedded, signer_pubkeys=signer_pubkeys)
        if not ok:
            return False, f"embedded remediation cert not verifiable standalone: {reason}"
        return True, "REMEDIATED: signed + cross-bound + embedded remediation authentic/bound/live"
    return True, f"{state}: signed and internally consistent"


# ---------------------------------------------------------------------------
# 5. Chain + signed head (identical bytes to vigil_core.chain / verify_pcf).
# ---------------------------------------------------------------------------
_HEAD_V2_FIELDS = ("base_seq", "base_prev_hash", "base_count", "cumulative_merkle_root",
                   "snapshot_seq", "prev_head_hash")


def _entry_hash(seq: int, prev_hash: str, cert_digest: str) -> str:
    return sha256_hex(canonical_json({"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))


def build_chain(cert_digests: list) -> list[dict]:
    entries: list[dict] = []
    prev = GENESIS_PREV
    for i, cd in enumerate(cert_digests):
        eh = _entry_hash(i, prev, cd)
        entries.append({"seq": i, "prev_hash": prev, "cert_digest": cd, "entry_hash": eh})
        prev = eh
    return entries


def verify_chain(entries: list, *, genesis_prev: str = GENESIS_PREV) -> tuple[bool, str]:
    prev = genesis_prev
    for i, e in enumerate(entries):
        if e.get("prev_hash") != prev:
            return False, f"chain break at seq {e.get('seq')}: prev_hash mismatch (entry deleted/reordered)"
        if e.get("entry_hash") != _entry_hash(int(e["seq"]), str(e["prev_hash"]), str(e["cert_digest"])):
            return False, f"chain break at seq {e.get('seq')}: entry_hash mismatch (entry tampered)"
        if i > 0 and int(e["seq"]) != int(entries[i - 1]["seq"]) + 1:
            return False, f"chain break: seq gap at {e.get('seq')}"
        prev = str(e["entry_hash"])
    return True, f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} link cleanly"


def _head_payload(head: dict) -> dict:
    d = dict(head)
    d.pop("signatures", None)
    if int(d.get("schema_version", 1)) < 2:
        for f in _HEAD_V2_FIELDS:
            d.pop(f, None)
    return d


def verify_head(head: dict, entries: list, trust_root: dict,
                *, prev_highwater: Optional[int] = None, genesis_prev: str = GENESIS_PREV) -> tuple[bool, str]:
    ok_chain, reason = verify_chain(entries, genesis_prev=genesis_prev)
    if not ok_chain:
        return False, reason
    exp_hash = str(entries[-1]["entry_hash"]) if entries else genesis_prev
    exp_seq = int(entries[-1]["seq"]) if entries else int(head.get("base_seq", 0))
    if (head.get("head_hash") != exp_hash or int(head.get("last_seq", -1)) != exp_seq
            or int(head.get("entry_count", -1)) != int(head.get("base_count", 0)) + len(entries)):
        return False, "head does not match the chain (log truncated or head rewritten)"
    satisfied, _valid, thr_reason = verify_threshold(
        evidence_signing_bytes(_head_payload(head)), head.get("signatures", []), trust_root)
    if not satisfied:
        return False, f"head signature invalid: {thr_reason}"
    if prev_highwater is not None and int(head.get("last_seq", 0)) < prev_highwater:
        return False, (f"rollback rejected: head last_seq {head.get('last_seq')} < accepted "
                       f"high-water {prev_highwater}")
    return True, (f"chain of {len(entries)} entr{'y' if len(entries)==1 else 'ies'} anchored by a "
                  f"valid signed head")


# ---------------------------------------------------------------------------
# 6. The Continuous Attestation Log — monotonic drift series over a signed, anti-rollback tick chain.
# ---------------------------------------------------------------------------
LABEL_PRESENT = "present"
LABEL_PROVEN_FIXED = "proven-fixed"
LABEL_STILL_PROVEN = "still-proven"
LABEL_REGRESSED = "regressed"
LABEL_INCONCLUSIVE = "inconclusive"
LABEL_REFUSED = "refused"
LABEL_UNKNOWN = "unknown"


def _derive_series(ticks: list) -> list[dict]:
    """Fold consecutive tick states into the VISION drift vocabulary (mirrors
    ``attestation_log._derive_series``). Each entry is {seq, state, label, reason_code}."""
    series: list[dict] = []
    proven = False
    for i, t in enumerate(ticks):
        state = str(t.get("state") or "")
        if state == State.REMEDIATED:
            label = LABEL_STILL_PROVEN if proven else LABEL_PROVEN_FIXED
            proven = True
        elif state == State.STILL_VULNERABLE:
            label = LABEL_REGRESSED if proven else LABEL_PRESENT
            proven = False
        elif state == State.INCONCLUSIVE:
            label = LABEL_INCONCLUSIVE
        elif state == State.REFUSED:
            label = LABEL_REFUSED
        else:
            label = LABEL_UNKNOWN
        reason = str((t.get("verdict") or {}).get("reason_code") or "")
        series.append({"seq": i, "state": state, "label": label, "reason_code": reason})
    return series


def _normalize_floor(floor: Optional[dict]) -> Optional[dict]:
    """Return {"entry_count": N, "last_seq": M} or None (absent). Raise ValueError on a PRESENT-but-corrupt
    floor (fail-closed — reading a corrupt floor as absent would fail-OPEN the anti-rollback guarantee)."""
    if floor is None:
        return None
    if not isinstance(floor, dict):
        raise ValueError("durable high-water floor is not a JSON object (possible tamper)")
    ec, ls = floor.get("entry_count"), floor.get("last_seq")

    def _nonneg_int(x: object) -> bool:
        return isinstance(x, int) and not isinstance(x, bool) and x >= 0

    if not (_nonneg_int(ec) and _nonneg_int(ls)):
        raise ValueError(f"floor has a missing/invalid entry_count/last_seq (possible tamper): "
                         f"entry_count={ec!r} last_seq={ls!r}")
    return {"entry_count": int(ec), "last_seq": int(ls)}


def verify_attestation_series(ticks: list, head: Optional[dict], floor: Optional[dict],
                              *, trust_root: dict, signer_pubkeys: dict) -> tuple[bool, str, list]:
    """Offline-verify the whole Continuous Attestation Log and derive its monotonic drift series
    (mirrors ``attestation_log.verify_log``). ``trust_root`` (head signature) and ``signer_pubkeys``
    (per-tick admission) are CALLER-PINNED out-of-band. FAIL-CLOSED — returns (False, reason, []) on any
    failure:

      1. the durable floor is consulted FIRST (it is the only component that can catch a FULL truncation
         to empty: an emptied log + removed head is validly 'empty' to the in-band signature);
      2. the chain rebuilds from the tick digests; ``verify_head`` binds the head to that chain
         (integrity + head↔chain + m-of-n signature) with the last_seq anti-rollback floor;
      3. the entry_count PRIMARY floor guard (last_seq is 0 for BOTH an empty and a 1-tick log);
      4. every tick re-verifies via ``verify_prove_cert``;
      5. only then is the drift series derived + returned."""
    try:
        floor = _normalize_floor(floor)
    except ValueError as e:
        return False, f"durable high-water unreadable: {e}", []

    if not ticks and head is None:
        if floor is not None and int(floor["entry_count"]) > 0:
            return False, (f"ROLLBACK: empty tick log + no signed head, but the durable floor records "
                           f"entry_count={floor['entry_count']} (the series was truncated to empty)"), []
        return True, "empty attestation log (no ticks)", []
    if head is None:
        return False, "tick log has entries but no signed head (truncated/removed head — fail closed)", []

    digests = [digest_payload(t) for t in ticks]
    entries = build_chain(digests)
    prev_seq = int(floor["last_seq"]) if floor else None
    ok, reason = verify_head(head, entries, trust_root, prev_highwater=prev_seq)
    if not ok:
        return False, f"chain/head not authentic or rolled back: {reason}", []
    if floor is not None:
        if int(head.get("entry_count", -1)) < int(floor["entry_count"]):
            return False, (f"ROLLBACK: head entry_count {head.get('entry_count')} < durable floor "
                           f"entry_count {floor['entry_count']} (truncated log / stale head replay)"), []
        if int(head.get("last_seq", -1)) < int(floor["last_seq"]):
            return False, (f"ROLLBACK: head last_seq {head.get('last_seq')} < durable floor last_seq "
                           f"{floor['last_seq']} (stale head / truncated log replay)"), []

    for i, t in enumerate(ticks):
        vok, vreason = verify_prove_cert(t, signer_pubkeys=signer_pubkeys)
        if not vok:
            return False, f"tick {i} failed re-verification (tampered/forged): {vreason}", []

    series = _derive_series(ticks)
    return True, (f"{len(ticks)} tick(s) authentic, chain unbroken, head signed, un-rolled-back "
                  f"(floor entry_count={floor['entry_count'] if floor else 0})"), series


# ---------------------------------------------------------------------------
# 7. Witnessed, time-bounded checkpoint (mirrors attestation_witness.verify_timed_witnessed +
#    transparency.is_split_view_resistant).
# ---------------------------------------------------------------------------
def is_split_view_resistant(witness_trust_root: dict) -> bool:
    """True iff the witness set is a STRICT MAJORITY (2*threshold > n) over ``n`` DISTINCT, canonical,
    non-low-order Ed25519 keys (dedup over the DECODED 32-byte key). Fail-closed on an empty set, any
    duplicate/shared public key (defeats quorum intersection), or any weak/malformed key. Byte-identical
    to ``transparency.is_split_view_resistant``."""
    auths = witness_trust_root.get("authorizers", [])
    distinct: set = set()
    try:
        for a in auths:
            raw = _b64_exact(str(a.get("public_key_b64", "")), 32, "witness key")
            _reject_weak_public_key(raw)
            distinct.add(raw)
    except (WeakKey, ValueError, binascii.Error):
        return False
    n = len(distinct)
    if n != len(auths):
        return False
    return n > 0 and 2 * int(witness_trust_root.get("threshold", 0)) > n


def _timed_signing_bytes(checkpoint: dict, observed_time: int) -> bytes:
    """The exact bytes a witness signs for a TIMED co-signature: the distinct timed domain over a
    canonical payload binding BOTH the checkpoint identity AND the witness's observed time (byte-identical
    to attestation_witness._timed_signing_bytes)."""
    return _WITNESS_TIME_DOMAIN + canonical_json(
        {"checkpoint": checkpoint, "observed_time": int(observed_time)})


def checkpoint_hash(checkpoint: dict) -> str:
    """sha256 of the domain-separated canonical checkpoint — the stable identity the RFC3161 external time
    anchor binds (byte-identical to ``transparency.checkpoint_hash``)."""
    return sha256_hex(_TRANSPARENCY_CHECKPOINT_DOMAIN + canonical_json(checkpoint))


def openssl_ts_available() -> bool:
    """True iff a usable ``openssl`` binary with the ``ts`` subcommand is reachable (needed to check the A1
    anchor). openssl ts ships on ubuntu-latest CI runners; this stays VIGIL-free (external process)."""
    if shutil.which("openssl") is None:
        return False
    try:
        r = subprocess.run(["openssl", "ts", "-help"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    combined = r.stdout + r.stderr
    return "ts [options]" in combined or "Query options" in combined


def _anchor_gentime_epoch(token_path: Path) -> Optional[int]:
    """Read genTime ONLY from the signature-covered TimeStampToken as an integer UNIX epoch (UTC); None on
    parse failure (fail-closed). Reads the SIGNED token, NOT the verifier wall clock.

    SECURITY: the ``TimeStampResp`` wraps the signed token in an UNSIGNED ``PKIStatusInfo`` that
    ``ts -verify`` does not cover and that openssl prints BEFORE the signed section — so a producer can
    inject a ``statusString`` free-text ``Time stamp:`` line to backdate the anchor while the signature
    still verifies. We therefore extract the signed token alone with ``ts -token_out`` (dropping the status
    wrapper) and parse genTime from THAT via ``-token_in``, so genTime comes only from TSA-signed bytes."""
    with tempfile.TemporaryDirectory() as td:
        tst = Path(td) / "tst.der"
        r0 = subprocess.run(["openssl", "ts", "-reply", "-in", str(token_path), "-token_out", "-out",
                             str(tst)], capture_output=True, text=True)
        if r0.returncode != 0 or not tst.exists():
            return None
        r = subprocess.run(["openssl", "ts", "-reply", "-in", str(tst), "-token_in", "-text"],
                           capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.lower().startswith("time stamp:"):
            value = s.split(":", 1)[1].strip()
            try:
                dt = datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                return None
            return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
    return None


def verify_external_time_anchor(checkpoint: dict, token_b64: str, *,
                                tsa_cert_pin: str) -> tuple[bool, Optional[int]]:
    """VIGIL-FREE offline check of the A1 RFC3161 external time anchor. Re-hash the checkpoint to
    ``checkpoint_hash``, then ``openssl ts -verify`` the base64 token over that hash against the PINNED TSA
    cert, and extract genTime — the "existed no-later-than T" bound. A TAMPERED checkpoint hashes
    differently → imprint mismatch → FAIL; a token from a WRONG/unpinned TSA → chain failure → FAIL. Uses
    only the system openssl binary via subprocess (no VIGIL import, no hand-parsed ASN.1). Fail-closed."""
    if not tsa_cert_pin or not Path(tsa_cert_pin).exists():
        return False, None
    if not openssl_ts_available():
        return False, None
    try:
        token = base64.b64decode(str(token_b64), validate=True)
    except (binascii.Error, ValueError):
        return False, None
    digest_hex = checkpoint_hash(checkpoint)
    with tempfile.TemporaryDirectory() as td:
        tok = Path(td) / "token.tsr"
        tok.write_bytes(token)
        r = subprocess.run(["openssl", "ts", "-verify", "-digest", digest_hex, "-sha256", "-in", str(tok),
                            "-CAfile", tsa_cert_pin], capture_output=True, text=True)
        if r.returncode != 0 or "Verification: OK" not in (r.stdout + r.stderr):
            return False, None
        gen = _anchor_gentime_epoch(tok)
        if gen is None:
            return False, None
        return True, gen


def verify_timed_witnessed(checkpoint: dict, timed_sigs: list, *, witness_trust_root: dict,
                           min_distinct_signers: Optional[int] = None,
                           external_time_anchor: Optional[str] = None,
                           tsa_cert_pin: Optional[str] = None) -> tuple[bool, Optional[int], str]:
    """Verify a strict-majority witness quorum TIMED-co-signed ``checkpoint`` and return its no-later-than
    bound (mirrors ``attestation_witness.verify_timed_witnessed``). Returns (ok, T, reason), FAIL-CLOSED:

      1. quorum SHAPE — refuse unless :func:`is_split_view_resistant` holds;
      2. verify + de-duplicate — per sig resolve the authoriser by key_id and verify over the timed bytes
         (each commits to its OWN observed_time); collect DISTINCT verifying witnesses by decoded key. An
         unknown key_id / weak-or-malformed key / non-verifying-or-malformed signature is IGNORED (never
         counted, never raised);
      3. quorum COUNT — distinct verifying witnesses >= max(threshold, min_distinct_signers);
      4. no-later-than median T — the (n//2)-th of the sorted distinct-verifying observed times (exact
         median for odd n; upper-median for even n — deterministic integer);
      5. external anchor (A1) — if ``external_time_anchor`` (base64 RFC3161 token) AND ``tsa_cert_pin`` are
         supplied, verify the token over ``checkpoint_hash`` against the pinned cert (VIGIL-free openssl):
         on success its genTime SUPERSEDES the median (witness-honesty-independent); a present-but-bad anchor
         FAILS CLOSED. With no anchor supplied the median stands (unchanged behaviour).

    HONEST LIMIT (does NOT overclaim, per WITNESS-TRUST §4): the median T bounds when the head was WITNESSED,
    not when the oracle re-fired; independence of the distinct keyholders is a deployment assumption
    uncheckable by code; a fully-dishonest PRODUCER curates which sigs are presented (raise
    min_distinct_signers toward n, or use the external anchor, for a hard guarantee) — and a *local*
    self-signed TSA proves the anchor MECHANISM only, not third-party independence (the A1 residual)."""
    if not is_split_view_resistant(witness_trust_root):
        return False, None, "not split-view resistant: sub-majority / duplicate / weak witness key"

    by_id = {a.get("key_id"): a for a in witness_trust_root.get("authorizers", []) if isinstance(a, dict)}
    distinct_verified: dict = {}  # decoded 32-byte key -> observed_time
    for ts in timed_sigs:
        if not isinstance(ts, dict):
            continue
        auth = by_id.get(ts.get("key_id"))
        if auth is None:
            continue
        try:
            decoded = _b64_exact(str(auth.get("public_key_b64", "")), 32, "witness key")
            _reject_weak_public_key(decoded)
        except (WeakKey, ValueError, binascii.Error):
            continue
        if decoded in distinct_verified:
            continue
        try:
            observed = int(ts.get("observed_time"))
        except (TypeError, ValueError):
            continue
        if verify_one(str(auth.get("public_key_b64", "")), _timed_signing_bytes(checkpoint, observed),
                      str(ts.get("signature_b64"))):
            distinct_verified[decoded] = observed

    required = int(witness_trust_root.get("threshold", 0))
    if min_distinct_signers is not None:
        required = max(required, int(min_distinct_signers))
    if len(distinct_verified) < required:
        return (False, None,
                f"quorum not met (need {required} distinct verifying witnesses, got {len(distinct_verified)})")

    observed_times = sorted(distinct_verified.values())
    median_T = observed_times[len(observed_times) // 2]

    # 5. external RFC3161 anchor (A1) — SUPERSEDES the median when present + verifiable against the pin. A
    #    present-but-unverifiable anchor FAILS CLOSED (a tampered checkpoint / wrong TSA cert must not fall
    #    back silently to the weaker median). The token is a SIDECAR; genTime is read from the SIGNED token.
    if external_time_anchor is not None and tsa_cert_pin is not None:
        anchor_ok, anchored_T = verify_external_time_anchor(
            checkpoint, external_time_anchor, tsa_cert_pin=tsa_cert_pin)
        if not anchor_ok or anchored_T is None:
            return (False, None,
                    "external time anchor present but did NOT verify against the pinned TSA cert over "
                    "checkpoint_hash (tampered checkpoint / wrong TSA cert / malformed token) — fail-closed")
        return (True, anchored_T,
                f"{len(distinct_verified)} distinct witness(es) co-signed; no-later-than T={anchored_T} = "
                f"RFC3161 external anchor genTime (SUPERSEDES the quorum-median {median_T}; witness-honesty-"
                f"independent — a local self-signed TSA proves the MECHANISM only, third-party independence "
                f"is the A1 residual)")

    return (True, median_T,
            f"{len(distinct_verified)} distinct witness(es) co-signed; no-later-than T={median_T} = median of "
            f"the PRESENTED signing quorum's clocks (sound only if that quorum is strict-majority honest — a "
            f"hard time guarantee needs the external anchor)")


# ---------------------------------------------------------------------------
# 7b. Z1 — channel-binding (zkTLS) notary co-sign, VIGIL-free. Mirrors
#     vigil_integration.channel_binding.verify_channel_binding_evidence byte-for-byte.
# ---------------------------------------------------------------------------
def channel_bound_signing_bytes(cbr: dict) -> bytes:
    """Domain tag + canonical channel-bound response — the exact bytes a notary signs / a verifier checks
    (byte-identical to ``channel_binding.channel_bound_signing_bytes``)."""
    return _CHANNEL_BINDING_DOMAIN + canonical_json(cbr)


def verify_channel_binding_evidence(evidence: dict, *,
                                    notary_public_key_pin_b64: str) -> tuple[bool, str]:
    """VIGIL-FREE offline check that a Z1 channel-binding envelope binds its carried response bytes to a TLS
    session under a co-signature from the PINNED notary — WITHOUT trusting the producer. Byte-identical to
    ``channel_binding.verify_channel_binding_evidence``. Checks: schema; the co-signing key equals the
    out-of-band pinned notary key; the carried ``response_b64`` bytes hash to the bound ``response_sha256``;
    the binding is a known non-empty TLS session binding; the notary Ed25519 co-signature verifies over the
    domain-separated (session-binding, response-hash) tuple. Fail-closed.

    HONEST LIMIT: passing proves the notary co-signed THIS (session, bytes) tuple and the bytes match — a
    SOFTWARE notary can be handed a fabricated tuple, so this is the verifier SHAPE + mechanism, NOT genuine
    producer-unforgeability (needs zkTLS/MPC-TLS + a third-party notary — the Z1 residual)."""
    if not isinstance(evidence, dict):
        return False, "evidence is not an object"
    if evidence.get("schema") != _CHANNEL_BINDING_SCHEMA:
        return False, f"wrong schema (expected {_CHANNEL_BINDING_SCHEMA!r})"
    if not notary_public_key_pin_b64:
        return False, "no notary public-key pin supplied (fail-closed: the pin is the only trust anchor)"

    cosign = evidence.get("notary_cosign") or {}
    sig_b64 = str(cosign.get("signature_b64", ""))
    if not sig_b64:
        return False, "no notary co-signature present (a producer-fabricated response is rejected)"
    if str(cosign.get("notary_public_key_b64", "")) != notary_public_key_pin_b64:
        return False, "co-signing key is not the pinned notary key (untrusted / producer-supplied signer)"

    cbr = evidence.get("channel_bound_response") or {}
    binding = cbr.get("binding") or {}
    response_sha256 = str(cbr.get("response_sha256", ""))

    try:
        body = base64.b64decode(str(evidence.get("response_b64", "")), validate=True)
    except (binascii.Error, ValueError):
        return False, "response_b64 is not valid base64"
    if sha256_hex(body) != response_sha256:
        return False, "carried response bytes do not hash to the bound response_sha256"

    if binding.get("kind") not in _CHANNEL_BINDING_KINDS:
        return False, f"unknown session-binding kind {binding.get('kind')!r}"
    if not str(binding.get("binding_hex", "")):
        return False, "empty session binding (response is not tied to any TLS session)"

    msg = channel_bound_signing_bytes(cbr)
    try:
        ok = verify_one(notary_public_key_pin_b64, msg, sig_b64)
    except Exception:
        return False, "malformed notary key/signature material"
    if not ok:
        return False, "notary co-signature does not verify over the (session-binding, response-hash) tuple"
    kind = binding.get("kind")
    return True, (
        f"channel-bound response verified: {kind} binding to {binding.get('host')}:{binding.get('port')}, "
        f"notary-cosigned by pinned key {cosign.get('notary_key_id')} (MECHANISM — a software notary is not "
        f"producer-unforgeable; see Z1 residual)")


# ---------------------------------------------------------------------------
# 8. Bundle verification (compose everything) + CLI
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 8. PostureCertificate (the Certificate of Non-Exploitability) — standalone, VIGIL-free.
#    Re-checks: the m-of-n governance signature over the canonical bytes + the out-of-band AUTHORIZER
#    fingerprint pin (byte-identical to eval.benchmark_run._scorecard_fingerprint, the idiom the
#    posture/coverage/M1 certs sign under); that posture_claims re-project byte-identically from the
#    embedded coverage cert (a forged claim, detached from its evidence, is refused; a CLOSED with no
#    conclusive oracle is refused); and the owner-signed target IdentityAttestation binds the certificate
#    to the scanned target (closes target-swap).
#    TIERS: a "binding" CLOSED claim has its signed coverage verdict re-checked (not re-derived); a
#    "re-executable" CLOSED claim additionally has its verdict RE-DERIVED here (`_reexecute_posture` re-runs
#    the pure predicate oracle over the retained values), confirming the verdict↔evidence binding WITHOUT
#    trusting the producer's verdict.
#    BOUNDARY (the honest residual): the retained values are producer-supplied — re-execution does NOT prove
#    they reflect the live target. Trusting the negative reflects reality (for BOTH tiers) still needs a
#    live VIGIL re-run (a coverage re-run / `framework.v2 evidence verify`); true producer-independence of
#    the OBSERVATION needs a channel-bound live capture.
# ---------------------------------------------------------------------------
_IDENTITY_ATT_DOMAIN = b"vigil-identity-attestation-v1\x00"  # == vigil_core.spine_domains DOMAIN_TAGS["identity"]


def _authorizer_fingerprint(authorizers: list) -> str:
    """sha256 over the canonical authorizer set — byte-identical to eval.benchmark_run._scorecard_fingerprint
    (the pin the posture/coverage/benchmark certs publish out-of-band)."""
    return "sha256:" + sha256_hex(canonical_json(sorted(authorizers, key=lambda a: a.get("key_id", ""))))


def _identity_core(att: dict) -> dict:
    """Rebuild the signed core of an IdentityAttestation from its dict — byte-identical to
    vigil_core.capability.IdentityAttestation._core()."""
    return {
        "schema_version": att.get("schema_version"),
        "owner_pubkey": att.get("owner_pubkey"),
        "engagement": att.get("engagement"),
        "policy": {k: sorted(v) for k, v in sorted((att.get("policy") or {}).items())},
        "not_after": att.get("not_after"),
    }


def _policy_wellformed(policy: Any) -> bool:
    if not isinstance(policy, dict) or not policy:
        return False
    for dim, allowed in policy.items():
        if not isinstance(dim, str) or not dim.strip():
            return False
        if not isinstance(allowed, list) or not allowed:
            return False
        if any((not isinstance(v, str)) or (not v.strip()) for v in allowed):
            return False
    return True


def _verify_identity_attestation(att: dict, owner_pubkey: str, engagement: str, now: int) -> tuple[bool, str]:
    """VIGIL-free mirror of vigil_core.capability.verify_identity_attestation (fail-closed)."""
    if not isinstance(att, dict):
        return False, "identity attestation missing"
    if int(att.get("schema_version", -1)) != 1:
        return False, f"unsupported identity schema_version {att.get('schema_version')!r}"
    if not owner_pubkey or att.get("owner_pubkey") != owner_pubkey:
        return False, "identity attestation is not by the pinned owner key"
    if att.get("engagement") != engagement:
        return False, f"identity engagement {att.get('engagement')!r} != required {engagement!r}"
    if not _policy_wellformed(att.get("policy")):
        return False, "identity attestation carries a malformed policy"
    sig = att.get("sig")
    if not sig or not isinstance(sig, str):
        return False, "identity attestation is unsigned"
    if not verify_one(str(owner_pubkey), _IDENTITY_ATT_DOMAIN + canonical_json(_identity_core(att)), str(sig)):
        return False, "identity signature does not verify against the owner key"
    if int(now) > int(att.get("not_after", 0)):
        return False, f"identity attestation expired (now {int(now)} > not_after {att.get('not_after')})"
    return True, "identity OK"


def _identity_matches(policy: dict, sample: Any) -> bool:
    """VIGIL-free mirror of vigil_core.capability.identity_matches."""
    if not _policy_wellformed(policy) or not isinstance(sample, dict):
        return False
    for dim, allowed in policy.items():
        observed = sample.get(dim)
        if not isinstance(observed, str) or observed not in set(allowed):
            return False
    return True


# --- the re-executable posture tier (VIGIL-FREE): re-derive the verdict over retained values ---------
# A faithful port of verify.oracles._eval_predicate / predicate_oracle (eager eval + same exception→
# non-conclusive semantics; a parity test in integration/tests pins it to the real oracle). Pure stdlib —
# no framework, no vigil_core. It re-derives the VERDICT from the retained values, so a relying party
# confirms the verdict WITHOUT trusting the producer's asserted verdict. HONEST BOUND: the values are
# producer-supplied; this proves the verdict↔evidence binding, NOT that the evidence is live (trusting the
# negative reflects reality — for both tiers — still needs a live re-run).


def _reexec_probe_evidence(probe: dict):
    """The re-execution kernel input a coverage-cert probe row carries, or None. Must match
    posture.certificate._probe_reexec_evidence exactly (so the tier projection agrees byte-for-byte)."""
    ev = probe.get("evidence")
    if not isinstance(ev, dict):
        return None
    pred, obs = ev.get("predicate"), ev.get("observed_evidence")
    if isinstance(pred, dict) and isinstance(obs, dict):
        kernel = {"predicate": pred, "observed_evidence": obs}
        # Lane S: the provenance-ref slot is part of the oracle INPUT the structural grammar gate reads, so a
        # faithful re-execution carries it when present. Absent it the kernel is the two-key dict as before.
        # Identical to posture.certificate._probe_reexec_evidence, so the tier projection agrees byte-for-byte.
        pref = ev.get("provenance_refs")
        if isinstance(pref, dict) and pref:
            kernel["provenance_refs"] = pref
        return kernel
    return None


def _reexec_resolve_operand(operand, observed: dict):
    if isinstance(operand, dict) and set(operand.keys()) == {"var"}:
        return observed.get(operand["var"])
    return operand


def _reexec_eval_predicate(pred, observed: dict) -> bool:
    """Port of oracles._eval_predicate (the 'fired' half). EAGERLY evaluates all/any children (like the
    real oracle — no short-circuit) so a type error in any child surfaces identically. Raises on a
    malformed node / bad operand; the caller (_reexec_fired_conclusive) turns any raise into a
    NON-CONCLUSIVE result, matching predicate_oracle's except-(ValueError,TypeError)->conclusive=False."""
    if not isinstance(pred, dict) or len(pred) != 1:
        raise ValueError(f"malformed re-execution predicate node: {pred!r}")
    op, args = next(iter(pred.items()))
    if op == "all":
        return all([_reexec_eval_predicate(p, observed) for p in args])   # eager, matches the oracle
    if op == "any":
        return any([_reexec_eval_predicate(p, observed) for p in args])   # eager, matches the oracle
    if op == "not":
        return not _reexec_eval_predicate(args, observed)
    a = _reexec_resolve_operand(args[0], observed)
    b = _reexec_resolve_operand(args[1], observed) if len(args) > 1 else None
    if op == "eq":
        return a == b
    if op == "ieq":
        return str(a).lower() == str(b).lower()
    if op == "contains":
        return bool(a) and bool(b) and str(b) in str(a)
    if op == "icontains":
        return bool(a) and bool(b) and str(b).lower() in str(a).lower()
    if op == "in":
        return a in (b or [])
    if op == "min_len":
        return len(str(a or "")) >= int(b)
    if op == "gt":
        return a is not None and b is not None and a > b
    if op == "ge":
        return a is not None and b is not None and a >= b
    raise ValueError(f"unknown re-execution predicate op {op!r}")


# --- Lane S (S1, re-slice): the STRUCTURAL FACT-ELIGIBILITY GRAMMAR, ported BYTE-FAITHFULLY from -------
# verify.oracles._fact_eligible (+ its helpers) and the _predicate_binds_and_const pre-gate, so this
# ZERO-VIGIL kernel renders the IDENTICAL (fired, conclusive) verdict predicate_oracle mints over the SAME
# (predicate, observed, provenance_refs) — not merely RAW predicate truth. Without this gate a bare shape
# (eq[a,b] a==b, contains[body, LIT], in[status,[3xx]], min_len[tok,3], ge[n,5], not(eq[a,b]), the
# canary-less open_redirect all/any) re-derives True here while the grammar-gated oracle REFUSES it — so the
# moat must reject offline exactly what the oracle rejects. A predicate is FACT-eligible only when every
# firing path carries a POSITIVE DISCRIMINATOR sound by SHAPE: PD2 (var-vs-provenance-ref canary, order-
# insensitive), PD3 (strict gt[PR, int>=0] reduction floor — ge/min_len at the floor is vacuous, refused),
# PD-NUM (gt/ge over two DISTINCT captured vars), PD-VALUE (eq/gt of a captured var vs a NUMERIC/BOOL non-
# status literal), PD4 (present/absent differential pos(CV_a,needle) AND not(pos(CV_b,needle)) over DISTINCT
# captured bodies sharing one DISTINCTIVE needle). provenance_refs names the observed_evidence keys that are
# VIGIL-injected (a PR); a var NOT listed there but present+non-None in observed is a captured var (CV); any
# other inline value is a producer literal (LIT). all => ANY child eligible OR a PD4 pair; any => EVERY child
# eligible; not => never a positive fire-driver. Pure stdlib — NO framework / vigil import (zero-VIGIL moat).
_DISTINCTIVENESS_MIN_LEN = 6
_POSITIVE_MATCH_OPS = frozenset({"eq", "ieq", "contains", "icontains", "in"})
_PROTOCOL_STATUS_CONSTANTS = frozenset({100, 200, 300, 301, 302, 303, 307, 308, 400, 401, 403})
_REFLEXIVE_TRUE_OPS = frozenset({"eq", "ieq", "ge", "contains", "icontains", "in"})
_REFLEXIVE_FALSE_OPS = frozenset({"gt"})


def _is_var_operand(operand) -> bool:
    return isinstance(operand, dict) and set(operand.keys()) == {"var"}


def _operand_is_provenance_ref(operand, provenance_refs: dict) -> bool:
    return _is_var_operand(operand) and operand["var"] in (provenance_refs or {})


def _operand_is_captured_var(operand, observed: dict, provenance_refs: dict) -> bool:
    return (_is_var_operand(operand) and operand["var"] not in (provenance_refs or {})
            and observed.get(operand["var"]) is not None)


def _operand_binds_captured(operand, observed: dict) -> bool:
    if _is_var_operand(operand):
        return observed.get(operand["var"]) is not None
    return False


def _needle_sig(operand):
    if _is_var_operand(operand):
        return ("var", operand["var"])
    try:
        hash(operand)
        return ("lit", operand)
    except TypeError:
        return ("lit", repr(operand))


def _needle_is_distinctive(sig) -> bool:
    kind, val = sig
    if kind == "var":
        return True
    return isinstance(val, str) and len(val) >= _DISTINCTIVENESS_MIN_LEN


def _is_scalar_value_literal(operand) -> bool:
    if isinstance(operand, bool):
        return True
    if isinstance(operand, (int, float)) and not isinstance(operand, bool):
        return operand not in _PROTOCOL_STATUS_CONSTANTS
    return False


# Auto-check LIVENESS / AVAILABILITY flags (BYTE-FAITHFUL mirror of oracles._LIVENESS_AVAILABILITY_KEYS). A
# captured var of one of these names compared to a scalar literal (eq[body_available,True], gt[probe_count,0],
# eq[reachable,True]) is true for any merely-reachable target and adjudicates NOTHING about a vuln — a
# CORROBORATOR, never a self-sufficient PD-VALUE. It is structurally indistinguishable from a genuine
# achieved-state scalar (bizlogic eq[qty,-5] / eq[checked_out,True] / gt[redeemed_count,1]; gt[qty,0] has the
# SAME shape as gt[probe_count,0]), and the owner-signed-spec authority that would separate them is not
# reachable inside the pure predicate oracle, so this NAMED set is the structural stand-in (mirrors
# _PROTOCOL_STATUS_CONSTANTS). A leaf over one of these keys is FACT-eligible only when the enclosing predicate
# ALSO carries a real PD (PR canary/reduction or a PD4 differential). Matched case-insensitively.
_LIVENESS_AVAILABILITY_KEYS = frozenset({
    "body_available", "body_semantically_available",
    "reachable", "available", "responsive", "responded",
    "alive", "is_alive", "is_live",
    "host_up", "online", "port_open",
    "probe_count", "probes", "response_count", "reply_count",
})


def _operand_is_liveness_flag(operand, observed: dict, provenance_refs: dict) -> bool:
    """A captured var whose KEY is a known auto-check liveness/availability flag — a gate corroborator, NEVER
    a self-sufficient PD-VALUE."""
    return (_operand_is_captured_var(operand, observed, provenance_refs)
            and str(operand["var"]).lower() in _LIVENESS_AVAILABILITY_KEYS)


def _leaf_is_self_sufficient_pd(op, args, observed: dict, provenance_refs: dict) -> bool:
    if not isinstance(args, (list, tuple)) or len(args) != 2:
        return False
    a, b = args[0], args[1]
    if op in _POSITIVE_MATCH_OPS:
        if (_operand_is_provenance_ref(a, provenance_refs)
                and _operand_is_captured_var(b, observed, provenance_refs)):
            return True
        if (_operand_is_provenance_ref(b, provenance_refs)
                and _operand_is_captured_var(a, observed, provenance_refs)):
            return True
        if op in ("eq", "ieq"):
            if (_operand_is_captured_var(a, observed, provenance_refs)
                    and not _operand_is_liveness_flag(a, observed, provenance_refs)
                    and _is_scalar_value_literal(b)):
                return True
            if (_operand_is_captured_var(b, observed, provenance_refs)
                    and not _operand_is_liveness_flag(b, observed, provenance_refs)
                    and _is_scalar_value_literal(a)):
                return True
        return False
    if op == "gt" and _operand_is_provenance_ref(a, provenance_refs) and isinstance(b, int) \
            and not isinstance(b, bool) and b >= 0:
        return True
    if op in ("gt", "ge") and _operand_is_captured_var(a, observed, provenance_refs) \
            and _operand_is_captured_var(b, observed, provenance_refs) and a != b:
        return True
    if op == "gt":
        if (_operand_is_captured_var(a, observed, provenance_refs)
                and not _operand_is_liveness_flag(a, observed, provenance_refs)
                and _is_scalar_value_literal(b)):
            return True
        if (_operand_is_captured_var(b, observed, provenance_refs)
                and not _operand_is_liveness_flag(b, observed, provenance_refs)
                and _is_scalar_value_literal(a)):
            return True
    return False


def _collect_match_relations(pred, observed: dict, provenance_refs: dict, negated: bool,
                             pos: set, neg: set) -> None:
    if not isinstance(pred, dict) or len(pred) != 1:
        return
    op, args = next(iter(pred.items()))
    if op in ("all", "any"):
        if isinstance(args, (list, tuple)):
            for c in args:
                _collect_match_relations(c, observed, provenance_refs, negated, pos, neg)
        return
    if op == "not":
        _collect_match_relations(args, observed, provenance_refs, not negated, pos, neg)
        return
    if op in _POSITIVE_MATCH_OPS and isinstance(args, (list, tuple)) and len(args) == 2:
        body, needle = args[0], args[1]
        if _operand_is_captured_var(body, observed, provenance_refs):
            (neg if negated else pos).add((body["var"], _needle_sig(needle)))


def _pd4_present(pred, observed: dict, provenance_refs: dict) -> bool:
    pos: set = set()
    neg: set = set()
    _collect_match_relations(pred, observed, provenance_refs, False, pos, neg)
    for a_key, a_needle in pos:
        if not _needle_is_distinctive(a_needle):
            continue
        for b_key, b_needle in neg:
            if b_needle == a_needle and b_key != a_key:
                return True
    return False


def _fact_eligible(pred, observed: dict, provenance_refs: dict) -> bool:
    """Decidable FACT-eligibility over the frozen predicate AST — BYTE-IDENTICAL to oracles._fact_eligible:
    leaf => a self-sufficient PD; all => ANY child eligible OR a PD4 pair; any => EVERY disjunct eligible;
    not => False."""
    if not isinstance(pred, dict) or len(pred) != 1:
        return False
    op, args = next(iter(pred.items()))
    if op == "all":
        if not isinstance(args, (list, tuple)) or not args:
            return False
        if any(_fact_eligible(c, observed, provenance_refs) for c in args):
            return True
        return _pd4_present(pred, observed, provenance_refs)
    if op == "any":
        if not isinstance(args, (list, tuple)) or not args:
            return False
        return all(_fact_eligible(c, observed, provenance_refs) for c in args)
    if op == "not":
        return False
    return _leaf_is_self_sufficient_pd(op, args, observed, provenance_refs)


def _predicate_binds_and_const(pred, observed: dict):
    """(binds_captured, constant_true, constant_false) over the AST — BYTE-IDENTICAL to
    oracles._predicate_binds_and_const. Raises ValueError on a malformed node (the caller funnels that into
    the non-conclusive malformed branch, as predicate_oracle does)."""
    if not isinstance(pred, dict) or len(pred) != 1:
        raise ValueError(f"predicate node must be a single-op mapping, got {pred!r}")
    op, args = next(iter(pred.items()))
    if op in ("all", "any"):
        if not isinstance(args, (list, tuple)) or not args:
            raise ValueError(f"{op!r} requires a non-empty list of sub-predicates")
        binds = False
        child_true = []
        child_false = []
        for p in args:
            b, ct, cf = _predicate_binds_and_const(p, observed)
            binds = binds or b
            child_true.append(ct)
            child_false.append(cf)
        if op == "all":
            return binds, all(child_true), any(child_false)
        return binds, any(child_true), all(child_false)
    if op == "not":
        b, ct, cf = _predicate_binds_and_const(args, observed)
        return b, cf, ct
    if op not in ("eq", "ieq", "contains", "icontains", "in", "min_len", "gt", "ge"):
        raise ValueError(f"unknown predicate op {op!r}")
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError(f"{op!r} requires operand(s)")
    has_second = len(args) > 1
    left, right = args[0], (args[1] if has_second else None)
    identical = has_second and left == right
    const_true = identical and op in _REFLEXIVE_TRUE_OPS
    const_false = identical and op in _REFLEXIVE_FALSE_OPS
    binds = _operand_binds_captured(left, observed) or (has_second and _operand_binds_captured(right, observed))
    return binds, const_true, const_false


def _reexec_fired_conclusive(pred, observed: dict, provenance_refs: dict | None = None):
    """Re-run the predicate → (fired, conclusive), mirroring predicate_oracle's decision sequence EXACTLY so
    the verdict is byte-identical over the SAME (predicate, observed, provenance_refs):

      1. a malformed predicate (the binds/const walk raises) is NON-conclusive (the oracle's malformed branch);
      2. a predicate NOT FACT-eligible under the structural grammar is REFUSED — non-firing, NON-conclusive
         (the S1 soundness gate: no positive discriminator adjudicates nothing SOUND);
      3. a constant-true tautology, or a predicate binding no captured value, is REFUSED (non-conclusive);
      4. otherwise the predicate is evaluated — a well-formed evaluation is conclusive; ANY evaluation error
         is (False, False), non-conclusive, never a silent pass.

    Fail-closed by construction."""
    prefs = dict(provenance_refs or {})
    try:
        binds_captured, constant_true, _constant_false = _predicate_binds_and_const(pred, observed)
    except Exception:  # a malformed predicate is NON-CONCLUSIVE (predicate_oracle's malformed branch)
        return False, False
    if not _fact_eligible(pred, observed, prefs):
        return False, False
    if constant_true or not binds_captured:
        return False, False
    try:
        return bool(_reexec_eval_predicate(pred, observed)), True
    except Exception:  # a malformed/ill-typed kernel is NON-CONCLUSIVE, never fired-clean
        return False, False


def _reexecute_posture(coverage_cert: dict) -> tuple[bool, str]:
    """Re-derive the verdict of every re-executable probe from its retained values; refuse a forged
    negative (a 'clean' probe whose predicate fires OR is non-conclusive over its own values) or a forged
    positive (a 'finding' probe that does not conclusively fire). This confirms the verdict↔evidence
    binding without trusting the producer's verdict; it does NOT prove the values are live (see header)."""
    n = 0
    for probe in coverage_cert.get("probes") or []:
        if not isinstance(probe, dict):
            continue
        kernel = _reexec_probe_evidence(probe)
        if kernel is None:
            continue
        fired, conclusive = _reexec_fired_conclusive(kernel["predicate"], dict(kernel["observed_evidence"]),
                                                     kernel.get("provenance_refs"))
        n += 1
        verdict = probe.get("verdict")
        if verdict == "clean" and (fired or not conclusive):
            return False, (f"re-execution REFUTED a CLOSED claim: retained values do not support a "
                           f"conclusive non-firing verdict (fired={fired}, conclusive={conclusive}; "
                           f"surface={probe.get('surface')!r} class={probe.get('class')!r})")
        if verdict == "finding" and not (fired and conclusive):
            return False, (f"re-execution REFUTED an OPEN claim: predicate does not conclusively fire over "
                           f"the probe's own retained values (surface={probe.get('surface')!r} class={probe.get('class')!r})")
    return True, f"re-derived {n} probe verdict(s) from retained evidence"


def _project_posture_claims(coverage_cert: dict) -> list:
    """VIGIL-free mirror of posture.certificate.project_posture_claims (fail-closed on a false-CLOSED
    source: a 'clean' probe with no conclusive oracle). The ``verification`` tier is computed here
    IDENTICALLY to the in-tree projection, so posture_claims re-project byte-for-byte."""
    probes = coverage_cert.get("probes")
    if not isinstance(probes, list):
        raise ValueError("coverage certificate has no probes list")
    groups: dict = {}
    for p in probes:
        if not isinstance(p, dict):
            raise ValueError("malformed probe row")
        verdict = p.get("verdict")
        kinds = p.get("oracle_kinds_run") or []
        if not isinstance(kinds, (list, tuple)):
            raise ValueError("oracle_kinds_run is not a list — invalid coverage certificate")
        if verdict == "clean" and not kinds:
            raise ValueError("a 'clean' probe carries no oracle_kinds_run — invalid coverage certificate")
        key = (str(p.get("surface", "")), str(p.get("param", "")), str(p.get("class", "")))
        g = groups.setdefault(
            key, {"finding": 0, "clean": 0, "inconclusive": 0, "kinds": set(), "n": 0, "clean_reexec": 0})
        g["n"] += 1
        if verdict in ("finding", "clean", "inconclusive"):
            g[verdict] += 1
        if verdict == "clean":
            g["kinds"].update(str(k) for k in kinds)
            if _reexec_probe_evidence(p) is not None:
                g["clean_reexec"] += 1
    claims = []
    for (surface, param, cls), g in groups.items():
        if g["finding"] > 0:
            status, kinds = "OPEN", []
        elif g["clean"] > 0:
            status, kinds = "CLOSED", sorted(g["kinds"])
        else:
            status, kinds = "UNPROVEN", []
        if status == "CLOSED" and g["clean"] > 0 and g["clean_reexec"] == g["clean"]:
            verification = "re-executable"
        else:
            verification = "binding"
        claims.append({"surface": surface, "param": param, "class": cls, "status": status,
                       "verification": verification, "evidence_oracle_kinds": kinds, "n_probes": g["n"]})
    claims.sort(key=lambda c: (c["surface"], c["param"], c["class"]))
    return claims


# S9c: VIGIL-free mirror of posture.certificate._normalize_incomplete / posture_overall_verdict — so a
# third party enforces the SAME coverage-incomplete downgrade the in-tree verifier does. A certificate that
# declares an UNASSESSED surface (``coverage_incomplete``) must carry the downgraded overall verdict and can
# never read as a clean whole-target CLOSED. Additive: absent the disclosure block this is a no-op, so an
# existing (web-only) bundle verifies byte-for-byte as before.
def _pp_normalize_incomplete(coverage_incomplete: Any) -> list:
    seen = set()
    for item in coverage_incomplete or ():
        try:
            if isinstance(item, dict):
                sensor = str(item.get("sensor") or "").strip()
                missing = str(item.get("missing_prerequisite") or "").strip()
            else:
                sensor, missing = item
                sensor, missing = str(sensor or "").strip(), str(missing or "").strip()
        except Exception:
            continue
        if sensor:
            seen.add((sensor, missing))
    return [{"sensor": s, "missing_prerequisite": m} for (s, m) in sorted(seen)]


def _pp_overall_verdict(claims: list, unassessed: list) -> str:
    if any(c.get("status") == "OPEN" for c in claims):
        return "OPEN"
    if unassessed:
        return "COVERAGE_INCOMPLETE"
    n_closed = sum(1 for c in claims if c.get("status") == "CLOSED")
    n_unproven = sum(1 for c in claims if c.get("status") == "UNPROVEN")
    if n_closed and not n_unproven:
        return "CLOSED"
    if n_closed:
        return "PARTIAL"
    return "UNPROVEN"


def verify_posture(posture: dict, *, pin: str, owner_pubkey: str, engagement: str, now: int) -> tuple[bool, str]:
    """Standalone-verify a PostureCertificate. ``posture`` = {"certificate": {...}, "signature": {...}}.
    Fail-closed: authenticity + pin, then coverage-projection binding, then owner target-binding."""
    cert = posture.get("certificate") or {}
    sig_env = posture.get("signature") or {}
    tr = sig_env.get("trust_root") or {}
    authz = tr.get("authorizers") or []
    # 1. out-of-band pin over the authorizer set (REQUIRED — fail-closed, the H4 lesson)
    fp = _authorizer_fingerprint(authz)
    pin_s = (pin or "").strip()
    if not pin_s:
        return False, f"UNPINNED — supply the out-of-band posture fingerprint ({fp})"
    want = pin_s if pin_s.startswith("sha256:") else ("sha256:" + pin_s)
    if want.lower() != fp.lower():
        return False, f"posture trust-root pin MISMATCH — expected {want}, got {fp}"
    # 2. m-of-n signature over the canonical certificate bytes (+ digest-field integrity)
    msg = canonical_json(cert)
    want_digest = "sha256:" + sha256_hex(msg)
    if sig_env.get("scorecard_digest") is not None and sig_env.get("scorecard_digest") != want_digest:
        return False, "posture certificate digest field does not match the canonical bytes"
    ok, valid, reason = verify_threshold(msg, sig_env.get("signatures") or [], tr)
    if not ok:
        return False, f"posture signature: {reason}"
    # 3. coverage-projection binding (claims cannot drift from their evidence; no false CLOSED)
    try:
        rederived = _project_posture_claims(cert.get("coverage") or {})
    except ValueError as e:
        return False, f"posture coverage invalid: {e}"
    if rederived != cert.get("posture_claims"):
        return False, "posture_claims do not match the projection of the embedded coverage certificate"
    for c in rederived:
        if c["status"] == "CLOSED" and not c.get("evidence_oracle_kinds"):
            return False, "a CLOSED claim names no conclusive oracle"
    # 3a. S9c coverage-incomplete disclosure: a cert that declares an UNASSESSED surface must carry the
    #     downgraded overall verdict and cannot read as a clean whole-target CLOSED (no disclosure => no-op).
    _disc = cert.get("coverage_incomplete")
    if isinstance(_disc, dict) and _disc.get("incomplete"):
        _unassessed = _pp_normalize_incomplete(_disc.get("unassessed_surfaces"))
        if not _unassessed:
            return False, "coverage_incomplete is set but names no unassessed surface"
        _want = _pp_overall_verdict(cert.get("posture_claims") or [], _unassessed)
        _got = (cert.get("summary") or {}).get("overall")
        if _got != _want:
            return False, (f"posture overall verdict {_got!r} disagrees with the coverage-incomplete "
                           f"projection {_want!r} — a clean reading over an unassessed surface")
        if _got == "CLOSED":
            return False, "a coverage-incomplete certificate must not read CLOSED (whole-target)"
    # 3b. RE-EXECUTION (the re-executable tier): re-run the oracle over every re-executable probe's
    #     retained values and refuse a forged negative/positive — a tamper-check that re-derives the verdict
    #     (NOT a liveness proof; values are producer-supplied), run
    #     here with NO VIGIL installed. Binding-tier probes carry no kernel and are skipped (the H4
    #     residual). A claim marked "re-executable" whose clean probes carried no kernel would have
    #     failed the byte-for-byte projection binding above, so the tier label cannot be forged.
    rok, rreason = _reexecute_posture(cert.get("coverage") or {})
    if not rok:
        return False, f"posture re-execution: {rreason}"
    # 4. target binding (closes target-swap)
    iok, ireason = _verify_identity_attestation(cert.get("target_identity") or {}, owner_pubkey, engagement, now)
    if not iok:
        return False, f"posture target-binding: {ireason}"
    if not _identity_matches((cert.get("target_identity") or {}).get("policy") or {}, cert.get("target_sample") or {}):
        return False, "posture target_sample does not satisfy the owner's identity policy"
    s = cert.get("summary") or {}
    n_reexec = s.get("n_closed_re_executable", 0) or 0
    n_binding = s.get("n_closed_binding_only", s.get("n_closed", "?"))
    tier_note = (f"{n_reexec} CLOSED verdict(s) re-derived from retained evidence (re-executable tier; "
                 f"values are producer-supplied — trusting the negative reflects the live target needs a "
                 f"live re-run), "
                 f"{n_binding} binding-only (re-firing those needs VIGIL)")
    _incov = cert.get("coverage_incomplete")
    _incov_note = ""
    if isinstance(_incov, dict) and _incov.get("incomplete"):
        _names = "; ".join(f"{u.get('sensor')} (missing: {u.get('missing_prerequisite') or 'unknown'})"
                           for u in (_incov.get("unassessed_surfaces") or []))
        _incov_note = (f" — COVERAGE INCOMPLETE (overall={s.get('overall', 'COVERAGE_INCOMPLETE')}): "
                       f"declared surface(s) NOT ASSESSED: {_names}")
    return True, (f"SOUND: {s.get('n_closed', '?')} CLOSED / {s.get('n_open', '?')} OPEN / "
                  f"{s.get('n_unproven', '?')} UNPROVEN over {cert.get('target_sample')} — {tier_note}"
                  f"{_incov_note}")


# ---------------------------------------------------------------------------
# 8b. L3 — VIGIL-FREE ports of the SIX posture ORACLE bodies + a canonical-context reader.
#
# Each ``posture_*_fires`` is a faithful, byte-for-byte-semantic port of the corresponding oracle in
# ``framework.v2.verify.oracles`` (policy_path / k8s_posture / k8s_workload_posture / cloud_posture /
# mesh_posture / cicd_posture). A posture FACT retains, under its ``oracle_context``, exactly the observed
# control the oracle judges (``ctx["policy"]`` / ``ctx["k8s_control"]`` / … — see verify.adapter.from_* +
# verifier._run_oracle's dispatch). ``reexecute_posture_oracle`` re-fires the right one over that context
# with ZERO VIGIL import and returns the SAME fire/no-fire verdict the in-tree oracle would.
#
# These are the whole point of the L3 bar: a third party re-executes the posture check itself — not just the
# signature/binding — without VIGIL. A byte-for-byte differential test (integration/tests/test_vf_differential
# .py) pins every family to the in-tree oracle over both a FIRED and a HARDENED fixture.
#
# HONEST BOUND (identical to _reexecute_posture / the module header): the retained control is producer-
# supplied. Re-firing proves the verdict is the correct FUNCTION of the retained evidence — it does NOT
# prove the evidence reflects the live target (that still needs a VIGIL live re-run; and an OBSERVATION whose
# truth does not rest on the producer's word needs a channel-bound live capture).
# ---------------------------------------------------------------------------
def _pp_coerce_text(value: Any) -> str:
    """Byte-identical to oracles._coerce_text (the single text-coercion the posture oracles use)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


# --- policy_path_oracle: an IAM grant PATH exists over the retained policy graph (BFS closure) -----------
_PP_ACCESS_LEVEL: dict[str, int] = {
    "list": 1, "read": 2, "get": 2, "describe": 2, "readonly": 2, "read_only": 2, "view": 2,
    "write": 3, "put": 3, "modify": 3, "update": 3, "delete": 3, "create": 3,
    "read_write": 3, "readwrite": 3,
    "admin": 4, "owner": 4, "full": 4, "root": 4, "all": 4, "*": 4, "manage": 4,
}


def _pp_norm_id(value: Any) -> str:
    return str(value or "").strip().lower()


def _pp_access_level(access: Any) -> int:
    a = str(access or "").strip().lower().replace("-", "_")
    if not a:
        return 1
    return _PP_ACCESS_LEVEL.get(a, 2)


def _pp_access_grants(granted: Any, requested: Any) -> bool:
    if not str(requested or "").strip():
        return True
    return _pp_access_level(granted) >= _pp_access_level(requested)


def posture_policy_path_fires(observed_policy: Any) -> bool:
    """Port of oracles.policy_path_oracle (fire iff a grant path exists). BFS from the query principal over
    the assume/member_of closure; fire iff some reachable principal holds a grant over the resource whose
    access dominates the requested access (empty access = any grant path). (Adjacency/grant SORTING in the
    oracle only makes the reconstructed PATH deterministic — it never changes WHETHER a hit exists — so the
    fired verdict is byte-identical without it.)"""
    if not isinstance(observed_policy, Mapping):
        return False
    start = _pp_norm_id(observed_policy.get("principal"))
    target = _pp_norm_id(observed_policy.get("resource"))
    requested = str(observed_policy.get("access") or "").strip()
    if not start or not target:
        return False
    adj: dict[str, list[str]] = {}
    for rel_key in ("assume", "member_of"):
        for e in observed_policy.get(rel_key) or []:
            if not isinstance(e, Mapping):
                continue
            src, dst = _pp_norm_id(e.get("src")), _pp_norm_id(e.get("dst"))
            if src and dst:
                adj.setdefault(src, []).append(dst)
    grants: dict[str, list[tuple[str, str]]] = {}
    for g in observed_policy.get("grants") or []:
        if not isinstance(g, Mapping):
            continue
        p, r = _pp_norm_id(g.get("principal")), _pp_norm_id(g.get("resource"))
        if p and r:
            grants.setdefault(p, []).append((r, str(g.get("access") or "")))
    order = [start]
    seen = {start}
    i = 0
    while i < len(order):
        cur = order[i]
        i += 1
        for res, acc in grants.get(cur, ()):
            if res == target and _pp_access_grants(acc, requested):
                return True
        for nxt in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                order.append(nxt)
    return False


# --- k8s_posture_oracle: a kube-bench control hard-FAILED with a concrete insecure --flag ---------------
_PP_K8S_VALUE_CAP = 8192
_PP_INSECURE_SETTING_RULES: tuple["re.Pattern[str]", ...] = (
    re.compile(r"(?i)--anonymous-auth[=:\s]+true\b"),
    re.compile(r"(?i)--authorization-mode[=:\s]+\S*alwaysallow"),
    re.compile(r"(?i)--insecure-port[=:\s]+0*[1-9]\d*"),
    re.compile(r"(?i)--read-only-port[=:\s]+0*[1-9]\d*"),
    re.compile(r"(?i)--basic-auth-file[=:\s]+\S+"),
    re.compile(r"(?i)--token-auth-file[=:\s]+\S+"),
    re.compile(r"(?i)--client-cert-auth[=:\s]+false\b"),
    re.compile(r"(?i)--profiling[=:\s]+true\b"),
)


def posture_k8s_fires(observed_control: Any) -> bool:
    """Port of oracles.k8s_posture_oracle: fire iff status is a hard FAIL AND the retained actual_value
    literally carries a recognised dangerous flag. WARN/PASS/INFO, an empty value, or a value showing the
    SECURE setting all do not fire."""
    if not isinstance(observed_control, Mapping):
        return False
    status = _pp_coerce_text(observed_control.get("status")).strip().upper()
    actual = _pp_coerce_text(observed_control.get("actual_value"))[:_PP_K8S_VALUE_CAP]
    if status != "FAIL" or not actual.strip():
        return False
    return any(pattern.search(actual) is not None for pattern in _PP_INSECURE_SETTING_RULES)


# --- k8s_workload_posture_oracle: an anonymous subject bound to a dangerous built-in ClusterRole --------
_PP_K8S_WL_STR_CAP = 4096
_PP_K8S_ANON_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})
_PP_K8S_DANGEROUS_ROLES = frozenset({"cluster-admin", "admin", "edit"})
_PP_K8S_RBAC_APIGROUP = "rbac.authorization.k8s.io"


def _pp_k8s_norm(value: Any) -> str:
    return _pp_coerce_text(value)[:_PP_K8S_WL_STR_CAP].strip().lower()


def _pp_k8s_subject_is_anon(s: Any) -> bool:
    """Port of oracles._k8s_subject_is_anon: a TYPED subject {kind,name,api_group} is anon only when a User is
    named system:anonymous / a Group named system:unauthenticated AND the RBAC apiGroup is present (required
    for an unapplied manifest); a legacy STRING subject (live-read) matches by the bare reserved name."""
    if isinstance(s, Mapping):
        # kind/name/apiGroup are compared EXACTLY (case- and whitespace-sensitive); mirrors oracles.py so the
        # L3 re-verifier and the in-tree oracle agree (a padded/case-variant subject is a DIFFERENT principal).
        if _pp_coerce_text(s.get("api_group") or s.get("apiGroup")) != _PP_K8S_RBAC_APIGROUP:
            return False
        kind = _pp_coerce_text(s.get("kind"))
        name = _pp_coerce_text(s.get("name"))
        return (kind == "User" and name == "system:anonymous") or \
               (kind == "Group" and name == "system:unauthenticated")
    # Legacy STRING subject (live-read): match EXACTLY (mirrors oracles.py — the reserved names are always
    # lowercase; a case/whitespace variant is a different principal).
    return _pp_coerce_text(s) in _PP_K8S_ANON_SUBJECTS


def posture_k8s_workload_fires(observed_control: Any) -> bool:
    """Port of oracles.k8s_workload_posture_oracle: fire iff a subject is system:anonymous /
    system:unauthenticated AND the bound role is a dangerous built-in ClusterRole (cluster-admin / admin /
    edit) in the RBAC apiGroup (a non-ClusterRole kind or non-RBAC apiGroup is rejected; empty is tolerated
    for hand-authored evidence)."""
    if not isinstance(observed_control, Mapping):
        return False
    ctl = observed_control
    state = ctl.get("achieved_state") if isinstance(ctl.get("achieved_state"), Mapping) else ctl
    raw_subjects = state.get("subjects")
    subjects = raw_subjects if isinstance(raw_subjects, (list, tuple)) else []
    # The roleRef NAME is case- AND whitespace-SENSITIVE in k8s; match the built-in EXACTLY (a case/whitespace
    # variant like "Cluster-Admin" is a DISTINCT custom role, not the built-in). Mirrors oracles.py exactly so
    # the L3 re-verifier and the in-tree oracle agree (test_vf_differential pins them together).
    role_name = _pp_coerce_text(state.get("role"))[:_PP_K8S_WL_STR_CAP]
    role_kind = _pp_k8s_norm(state.get("role_kind"))
    role_apigroup = _pp_k8s_norm(state.get("role_apigroup"))
    anon = any(_pp_k8s_subject_is_anon(s) for s in subjects)
    dangerous = (role_name in _PP_K8S_DANGEROUS_ROLES
                 and role_kind in ("clusterrole", "")
                 and role_apigroup in ("rbac.authorization.k8s.io", ""))
    return bool(anon and dangerous)


# --- cloud_posture_oracle: encryption-at-rest-disabled / public-exposure / wildcard-principal -----------
_PP_CLOUD_STR_CAP = 4096
_PP_CLOUD_MAX_PRINCIPALS = 4096
_PP_CLOUD_COMPLIANT_STATUSES = frozenset({
    "pass", "passed", "ok", "compliant", "pass_manual", "info", "informational", "not_applicable",
    "na", "n/a", "skipped", "manual",
})
_PP_CLOUD_ANON_PRINCIPALS = frozenset({
    "*", "allusers", "anonymous", "public", "everyone", "authenticatedusers", "allauthenticatedusers",
    "principal:*", "arn:aws:iam::*:root", "**",
})


def _pp_cloud_tri_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "on", "enabled", "enable"):
            return True
        if v in ("false", "0", "no", "off", "disabled", "disable"):
            return False
    return None


def _pp_cloud_norm_principal(p: Any) -> str:
    return _pp_coerce_text(p)[:_PP_CLOUD_STR_CAP].strip().lower().replace("-", "").replace("_", "")


def _pp_cloud_is_anon_principal(p: Any) -> bool:
    norm = _pp_cloud_norm_principal(p)
    return norm in {a.replace("-", "").replace("_", "") for a in _PP_CLOUD_ANON_PRINCIPALS}


def _pp_cloud_achieved_state(control: Mapping[str, Any]) -> dict[str, Any]:
    src = control.get("achieved_state") if isinstance(control.get("achieved_state"), Mapping) else control
    principals: list[str] = []
    raw_principals = src.get("principals")
    if isinstance(raw_principals, (list, tuple)):
        principals.extend(_pp_coerce_text(p) for p in raw_principals[:_PP_CLOUD_MAX_PRINCIPALS])
    grants = src.get("grants")
    if isinstance(grants, (list, tuple)):
        for g in grants[:_PP_CLOUD_MAX_PRINCIPALS]:
            if isinstance(g, Mapping) and g.get("principal") is not None:
                principals.append(_pp_coerce_text(g.get("principal")))
    return {
        "encrypted": _pp_cloud_tri_bool(src.get("encrypted")),
        "public": _pp_cloud_tri_bool(src.get("public")),
        "sensitive": _pp_cloud_tri_bool(src.get("sensitive")),
        "principals": principals,
    }


def posture_cloud_fires(observed_control: Any) -> bool:
    """Port of oracles.cloud_posture_oracle (fixed rule order): an EXPLICIT compliant status never fires;
    otherwise fire iff (1) encrypted is explicitly false AND sensitive is explicitly true, OR (2) public is
    explicitly true, OR (3) a wildcard/anonymous principal is named in the retained policy. Absent/unknown
    flags never fire."""
    if not isinstance(observed_control, Mapping):
        return False
    status = _pp_coerce_text(observed_control.get("status")).strip().lower()
    if status in _PP_CLOUD_COMPLIANT_STATUSES:
        return False
    state = _pp_cloud_achieved_state(observed_control)
    if state["encrypted"] is False and state["sensitive"] is True:
        return True
    if state["public"] is True:
        return True
    return any(_pp_cloud_is_anon_principal(p) for p in state["principals"])


# --- mesh_posture_oracle: permissive-mtls / authz-allow-all / linkerd-unauthenticated -------------------
_PP_MESH_STR_CAP = 4096
_PP_MESH_MAX_RULES = 4096
_PP_MESH_PERMISSIVE_MTLS = frozenset({"permissive", "disable"})
_PP_MESH_UNAUTH_INBOUND = frozenset({"all-unauthenticated", "all_unauthenticated"})
_PP_MESH_ANON_PRINCIPALS = frozenset({"*"})
_PP_MESH_COMPLIANT_STATUSES = frozenset({
    "pass", "passed", "ok", "compliant", "info", "informational", "not_applicable",
    "na", "n/a", "skipped", "manual",
})


def _pp_mesh_authz_allows_all(action: Any, rules: Any) -> bool:
    """Port of oracles._mesh_authz_allows_all (the boolean half). ALLOW/unset action AND a rule matching
    everyone: an empty catch-all rule, or a `*` PEER principal in a from.source.principals clause
    (requestPrincipals `*` is deliberately NOT allow-all — it requires a valid JWT)."""
    act = _pp_coerce_text(action).strip().upper() or "ALLOW"
    if act != "ALLOW":
        return False
    if not isinstance(rules, (list, tuple)):
        return False
    for rule in list(rules)[:_PP_MESH_MAX_RULES]:
        if not isinstance(rule, Mapping):
            continue
        froms, tos, whens = rule.get("from"), rule.get("to"), rule.get("when")
        if not froms and not tos and not whens:
            return True
        if isinstance(froms, (list, tuple)):
            for f in froms:
                if not isinstance(f, Mapping):
                    continue
                src = f.get("source")
                if not isinstance(src, Mapping):
                    continue
                vals = src.get("principals")
                if isinstance(vals, (list, tuple)) and any(
                        _pp_coerce_text(v).strip() in _PP_MESH_ANON_PRINCIPALS for v in vals):
                    return True
    return False


def posture_mesh_fires(observed_control: Any) -> bool:
    """Port of oracles.mesh_posture_oracle (fixed rule order): an EXPLICIT compliant status never fires;
    otherwise fire iff (1) effective mTLS mode is PERMISSIVE/DISABLE, OR (2) an ALLOW AuthorizationPolicy
    admits every caller, OR (3) a Linkerd default-inbound-policy is all-unauthenticated."""
    if not isinstance(observed_control, Mapping):
        return False
    ctl = observed_control
    status = _pp_coerce_text(ctl.get("status")).strip().lower()
    if status in _PP_MESH_COMPLIANT_STATUSES:
        return False
    mtls_mode = _pp_coerce_text(ctl.get("mtls_mode")).strip().lower()
    if mtls_mode in _PP_MESH_PERMISSIVE_MTLS:
        return True
    if _pp_mesh_authz_allows_all(ctl.get("action"), ctl.get("rules")):
        return True
    inbound = _pp_coerce_text(ctl.get("default_inbound_policy") or ctl.get("inbound_policy")).strip().lower()
    return inbound in _PP_MESH_UNAUTH_INBOUND


# --- cicd_posture_oracle: unpinned-action / pwn-request / script-injection ------------------------------
_PP_CICD_VALUE_CAP = 8192
_PP_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_PP_CICD_FIRST_PARTY = frozenset({"actions", "github"})
_PP_ACTION_REF_RE = re.compile(r"^([^/@\s]+)/([^@\s]+)@(\S+)$")
_PP_QUOTED_LIT_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_PP_UNTRUSTED_CTX_RES: tuple["re.Pattern[str]", ...] = tuple(re.compile(p, re.I) for p in (
    r"(?<![\w.])github\.head_ref(?![\w.])",
    r"(?<![\w.])github\.event\.issue\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.pull_request\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.pull_request\.head\.(?:ref|label)(?![\w.])",
    r"(?<![\w.])github\.event\.comment\.body(?![\w.])",
    r"(?<![\w.])github\.event\.(?:review|review_comment)\.body(?![\w.])",
    r"(?<![\w.])github\.event\.discussion\.(?:title|body)(?![\w.])",
    r"(?<![\w.])github\.event\.head_commit\.(?:message|author\.(?:name|email))(?![\w.])",
    r"(?<![\w.])github\.event\.commits(?:\[[^\]]*\]|\.\*)?\.(?:message|author\.(?:name|email))(?![\w.])",
    r"(?<![\w.])github\.event\.pages(?:\[[^\]]*\]|\.\*)?\.page_name(?![\w.])",
))
_PP_UNTRUSTED_PR_CHECKOUT_RE = re.compile(
    r"(?i)(github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/)")
_PP_INTERP_RE = re.compile(r"\$\{\{(.+?)\}\}", re.S)


def posture_cicd_fires(observed_control: Any) -> bool:
    """Port of oracles.cicd_posture_oracle: fire per the retained ``rule`` — unpinned_action (a third-party
    owner/repo@ref pinned to a MUTABLE ref, i.e. not SHA-40, not first-party/local/docker), pwn_request
    (pull_request_target checking out the UNTRUSTED PR head), or script_injection (a `run:` body
    interpolating an untrusted github.event.* / github.head_ref expression, quoted literals stripped). An
    unrecognised rule never fires."""
    if not isinstance(observed_control, Mapping):
        return False
    ctl = observed_control
    rule = _pp_coerce_text(ctl.get("rule")).strip().lower()

    if rule == "unpinned_action":
        uses = _pp_coerce_text(ctl.get("uses"))[:_PP_CICD_VALUE_CAP].strip()
        m = _PP_ACTION_REF_RE.match(uses)
        if m is None:
            return False
        owner, ref = m.group(1), m.group(3)
        if owner.lower() in _PP_CICD_FIRST_PARTY or uses.startswith("./") or uses.startswith("docker://"):
            return False
        if _PP_SHA40_RE.match(ref):
            return False
        return True

    if rule == "pwn_request":
        trigger = _pp_coerce_text(ctl.get("trigger")).strip().lower()
        checkout = _pp_coerce_text(ctl.get("checkout_ref"))[:_PP_CICD_VALUE_CAP]
        if trigger != "pull_request_target":
            return False
        return _PP_UNTRUSTED_PR_CHECKOUT_RE.search(checkout) is not None

    if rule == "script_injection":
        run = _pp_coerce_text(ctl.get("run"))[:_PP_CICD_VALUE_CAP]
        for m in _PP_INTERP_RE.finditer(run):
            body = _PP_QUOTED_LIT_RE.sub(" ", m.group(1))   # a quoted literal never dereferences a context
            if any(rx.search(body) is not None for rx in _PP_UNTRUSTED_CTX_RES):
                return True
        return False

    return False


# --- the canonical-context reader: dispatch a posture oracle_context to its ported oracle ----------------
# (surface_key -> ported oracle, kind label). Mirrors verifier._run_oracle's posture dispatch: a posture
# FACT retains exactly ONE of these keys (the observed control the oracle judges). First present wins.
_POSTURE_ORACLE_DISPATCH: tuple[tuple[str, Any, str], ...] = (
    ("policy", posture_policy_path_fires, "policy_path"),
    ("k8s_control", posture_k8s_fires, "k8s_posture"),
    ("k8s_workload_control", posture_k8s_workload_fires, "k8s_workload_posture"),
    ("cloud_control", posture_cloud_fires, "cloud_posture"),
    ("mesh_control", posture_mesh_fires, "mesh_posture"),
    ("cicd_control", posture_cicd_fires, "cicd_posture"),
)


def reexecute_posture_oracle(oracle_context: Any) -> tuple[Optional[bool], str]:
    """VIGIL-FREE re-execution of a posture FACT's ``oracle_context``. Reads the canonical retained context
    (as produced by verify.adapter.FindingContext.to_verifier_context), picks the first present posture key,
    re-fires the ported standalone oracle over its retained observed control, and returns (fired, kind).
    Returns (None, "") when the context carries no posture key (nothing to re-fire standalone).

    This is the L3 bar: a third party re-executes the posture CHECK itself, ZERO VIGIL import, and gets the
    same fire/no-fire verdict the in-tree oracle would. HONEST BOUND: the retained values are producer-
    supplied — this proves the verdict↔evidence binding, NOT that the evidence is live (needs a live re-run)."""
    if not isinstance(oracle_context, Mapping):
        return None, ""
    for key, fn, kind in _POSTURE_ORACLE_DISPATCH:
        if key in oracle_context:
            return bool(fn(oracle_context[key])), kind
    return None, ""




# ---------------------------------------------------------------------------
# 8c. L3-GENERAL — VIGIL-FREE ports of the PURE, STDLIB-ONLY general oracle bodies
#     + a canonical-context reader that re-fires them over a retained oracle_context.
#
# The posture tier (section 8b) and the predicate kernel (section 8) re-execute the
# posture + achieved-state ACHIEVED_STATE oracles standalone. This section extends that to the
# GENERAL (non-posture, non-predicate) oracle set whose bodies are PURE and STDLIB-ONLY — the
# web-vuln differential / statistical / structural families. Each ``*_oracle`` below is a
# BYTE-FOR-BYTE copy of the corresponding body in ``framework.v2.verify.oracles`` (extracted by
# AST over its exact source + the transitive closure of its pure module-level helpers; the
# closure is provably stdlib-only — see the parity harness integration/tests/
# test_general_reexecutable.py, which pins every ported class to the in-tree oracle on BOTH
# ``fired`` AND ``conclusive`` over a representative retained-evidence battery).
#
# The two shims below (``OracleKind`` string constants + an ``OracleSignal`` dataclass that
# reproduces the Pydantic model's ``fired -> conclusive`` coercion) let the oracle bodies compile
# UNCHANGED with zero VIGIL import — the whole point: a third party re-derives these general FACT
# verdicts with nothing installed (stdlib + the one Ed25519 lib this file already uses).
#
# WHAT THIS DOES (Step 2 of the audit package — see docs/limitations/inventory.json
# LIMIT-audit-package-reproduction): for a FACT whose retained ``oracle_context`` carries one of
# the ported families' keys, ``reexecute_general_oracle`` re-RUNS the deterministic oracle and
# returns the SAME fire/no-fire + conclusive verdict the in-tree oracle would — so the audit
# package no longer merely binds the verdict, it RE-DERIVES it standalone.
#
# HONEST BOUND (identical to the posture tier): re-firing proves the verdict is the correct
# FUNCTION of the retained evidence — it does NOT prove the retained evidence reflects the live
# target (that still needs an in-VIGIL live re-run). Two sets are NOT ported here (both named in
# LIMIT-audit-package-reproduction, and their split enforced by test_general_reexecutable.py::
# test_bucket_classification_is_enforced): the GENUINELY-IRREDUCIBLE oracles whose import-closure
# needs a module outside stdlib + cryptography (version_range -> packaging; saml_forgery ->
# signxml/lxml; oob_callback -> the framework verify.oob receipt crypto backing an EXTERNAL
# collector); and a PURE-BUT-NOT-YET-PORTED residual whose bodies ARE re-fireable with stdlib +
# cryptography (follow-up work). Both rest, for now, on the signature + an in-VIGIL re-run (the
# sound maximum), never faked as reproduced.
# ---------------------------------------------------------------------------
class OracleKind:
    """String-valued stand-in for ``framework.v2.verify.models.OracleKind`` (the ``.value`` of each
    member). The ported bodies only read ``OracleKind.X`` to stamp a signal's kind; parity is on
    ``fired``/``conclusive``, so the string value is sufficient and keeps the bodies byte-identical."""
    DIFFERENTIAL_RESPONSE = "differential_response"
    TIMING = "timing"
    BOOLEAN_INFERENCE = "boolean_inference"
    SIDE_EFFECT = "side_effect"
    REFLECTION_CONTEXT = "reflection_context"
    EVALUATION = "evaluation"
    ERROR_SIGNATURE = "error_signature"
    SANITIZER_SIGNAL = "sanitizer_signal"
    SYSTEM_PROMPT_DISCLOSURE = "system_prompt_disclosure"
    PROMPT_INJECTION = "prompt_injection"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    SQL_INJECTION_BREAKOUT = "sql_injection_breakout"
    COMMAND_INJECTION_BREAKOUT = "command_injection_breakout"
    NOSQL_INJECTION_BREAKOUT = "nosql_injection_breakout"
    TLS_WEAKNESS = "tls_weakness"
    # --- Lane C/G1: the A-prime GENERAL families re-derived standalone in section 8c (string
    #     values mirror framework.v2.verify.models.OracleKind; parity is on fired/conclusive). ---
    ACHIEVED_STATE = "achieved_state"
    ACTIVE_EXPOSURE = "active_exposure"
    AUTOMATED_ACCESS = "automated_access"
    CERTIFICATE_VALIDITY = "certificate_validity"
    CLICKJACKING_POSTURE = "clickjacking_posture"
    CREDENTIAL_ACCEPTANCE = "credential_acceptance"
    CREDENTIAL_STUFFING = "credential_stuffing"
    CSP_POSTURE = "csp_posture"
    CSRF_POSTURE = "csrf_posture"
    DOM_EXECUTION = "dom_execution"
    EMAIL_AUTH_POSTURE = "email_auth_posture"
    GCP_SA_IMPERSONATION = "gcp_sa_impersonation"
    IAM_ESCALATION_PRIMITIVE = "iam_escalation_primitive"
    IDENTITY_POSTURE = "identity_posture"
    IMDS_CREDENTIAL_CAPTURE = "imds_credential_capture"
    K8S_RBAC_VERB_GRANT = "k8s_rbac_verb_grant"
    MFA_BYPASS = "mfa_bypass"
    MOBILE_POSTURE = "mobile_posture"
    PASSWORD_RESET_INVARIANT = "password_reset_invariant"
    POSTMESSAGE_POSTURE = "postmessage_posture"
    SECRET_CREDENTIAL_VALIDITY = "secret_credential_validity"
    SERVICE_REACHABILITY = "service_reachability"
    SESSION_FIXATION = "session_fixation"
    SSO_ASSERTION_FORGERY = "sso_assertion_forgery"
    STATIC_RULE = "static_rule"


@dataclass
class OracleSignal:
    """Stand-in for ``framework.v2.verify.models.OracleSignal`` carrying exactly the fields the
    ported bodies set, and reproducing the model's ``_fired_implies_conclusive`` validator (a FIRED
    signal is always conclusive). Parity is asserted on ``fired`` AND ``conclusive``."""
    kind: Any
    fired: bool
    confidence: float = 0.0
    evidence: str = ""
    observed: dict = field(default_factory=dict)
    conclusive: bool = False

    def __post_init__(self) -> None:
        if self.fired and not self.conclusive:
            self.conclusive = True


# --- the byte-faithful ported oracle bodies + their pure stdlib helper closure ------------------
_VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})


@dataclass(frozen=True)
class _Response:
    status: int | None
    body: str
    latency_ms: float | None


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _normalize_response(value: Any) -> _Response:
    """Accept a plain string/bytes body, or a mapping with any of
    {status|status_code, body|text|content, latency_ms|elapsed_ms}."""
    if isinstance(value, Mapping):
        status = value.get("status", value.get("status_code"))
        body = value.get("body", value.get("text", value.get("content", "")))
        latency = value.get("latency_ms", value.get("elapsed_ms"))
        return _Response(
            status=int(status) if status is not None else None,
            body=_coerce_text(body),
            latency_ms=float(latency) if latency is not None else None,
        )
    return _Response(status=None, body=_coerce_text(value), latency_ms=None)


def _json_signature(obj: Any, prefix: str = "") -> set[tuple[str, str]]:
    """The set of (json-pointer path, value-TYPE) pairs in a JSON document.
    Records structure, not values — so a changed timestamp/nonce (same path,
    same type) is invisible, but a new/removed record (a new path) shows."""
    out: set[tuple[str, str]] = set()
    if isinstance(obj, dict):
        out.add((prefix or "/", "object"))
        for k in obj:
            out |= _json_signature(obj[k], f"{prefix}/{k}")
    elif isinstance(obj, list):
        out.add((prefix or "/", "array"))
        for i, v in enumerate(obj):
            out |= _json_signature(v, f"{prefix}/{i}")
    else:
        out.add((prefix or "/", type(obj).__name__))
    return out


class _TagPathCounter(HTMLParser):
    """Builds a multiset of ancestor-tag-paths (e.g. ``html>body>table>tr``) over
    a document, using stdlib parsing only. The multiset is invariant to text/
    attribute values, so token noise does not move it, but an added element does."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[str] = []
        self.counter: Counter[str] = Counter()

    def handle_starttag(self, tag: str, attrs: object) -> None:
        self._stack.append(tag)
        self.counter[">".join(self._stack)] += 1
        if tag in _VOID_ELEMENTS:
            self._stack.pop()

    def handle_startendtag(self, tag: str, attrs: object) -> None:
        self._stack.append(tag)
        self.counter[">".join(self._stack)] += 1
        self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag in self._stack:
            while self._stack and self._stack[-1] != tag:
                self._stack.pop()
            if self._stack:
                self._stack.pop()


def _parse_structure(body: str) -> tuple[str, Any]:
    """Return ('json', path-type set) or ('html', tag-path multiset). JSON is
    tried first; anything else is parsed as HTML with the stdlib parser (no
    third-party dependency). A parse failure degrades to ('text', None) so the
    caller can skip cleanly."""
    import json as _json

    text = body if isinstance(body, str) else _coerce_text(body)
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            return "json", _json_signature(_json.loads(text))
        except (ValueError, TypeError):
            pass
    parser = _TagPathCounter()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return "text", None
    if not parser.counter:
        return "text", None
    return "html", parser.counter


def structural_diff(baseline_body: Any, mutated_body: Any) -> float:
    """A structure-aware divergence score in [0, 1], invariant to token noise
    (CSRF tokens, nonces, timestamps) and sensitive to real change (an added
    record, an extra ``<tr>``, a new form). 0 = structurally identical.

    JSON: symmetric difference of (path, type) sets over their union. HTML:
    multiset difference of tag-paths over the total. Different document kinds
    (JSON vs HTML) score 1.0. Unparseable bodies score 0.0 (no structural
    claim — the lexical dimension still applies)."""
    kind_b, sig_b = _parse_structure(baseline_body)
    kind_m, sig_m = _parse_structure(mutated_body)
    if kind_b == "text" or kind_m == "text":
        return 0.0
    if kind_b != kind_m:
        return 1.0
    if kind_b == "json":
        union = sig_b | sig_m
        return (len(sig_b ^ sig_m) / len(union)) if union else 0.0
    # html multisets
    diff = sum((sig_b - sig_m).values()) + sum((sig_m - sig_b).values())
    total = sum(sig_b.values()) + sum(sig_m.values())
    return (diff / total) if total else 0.0


def _noisy_or(weights: list[float]) -> float:
    """Combine independent evidence weights: 1 - prod(1 - w). Clamped to 0.99
    so a deterministic oracle never claims certainty it cannot have."""
    product = 1.0
    for w in weights:
        product *= 1.0 - max(0.0, min(1.0, w))
    return min(0.99, 1.0 - product)


_DEFAULT_DIFFERENTIAL_DIMENSIONS = frozenset({"status", "length", "lexical", "marker"})


def differential_response_oracle(
    baseline: Any,
    mutated: Any,
    discriminator: Mapping[str, Any] | str | None = None,
) -> OracleSignal:
    """Distinguish two observed responses.

    For a boolean-based blind bug the "true" condition yields a materially
    different response than the "false"/baseline condition; this oracle
    quantifies that divergence lexically and structurally. For a time-based
    blind bug a latency delta over threshold is the signal.

    discriminator (all optional):
      dimensions          : subset of {status,length,lexical,structural,latency,marker}
                            (default: status,length,lexical,marker — ``latency`` must be
                            asked for EXPLICITLY; see the AUDIT R6 note below)
      length_threshold    : min fractional length change to count (default 0.05)
      lexical_threshold   : min 1-similarity to count (default 0.10)
      latency_threshold_ms: min added latency to count (default 1000)
      true_marker         : string that must appear in `mutated` but not baseline
      expect              : "differ" (default) or "same"
    """
    if isinstance(discriminator, str):
        disc: dict[str, Any] = {"dimensions": [discriminator]}
    else:
        disc = dict(discriminator or {})

    b = _normalize_response(baseline)
    m = _normalize_response(mutated)

    # AUDIT R6 — ``latency`` is NOT in the DEFAULT set. Its weight is 0.7, which is
    # EXACTLY the verifier's HIGH_CONFIDENCE floor, so every caller that omitted a
    # discriminator inherited a latency-ONLY confirm path: a single timing delta over
    # two otherwise identical responses minted a FACT. That is a TIMING claim, and the
    # engine has a dedicated statistically-sound oracle for it (``timing_oracle``:
    # paired samples, alpha, dose-response). The fix is to remove the dimension from
    # the DEFAULT rather than to shave its weight to 0.69 — a weight just under the
    # floor still lets latency push a marginal second dimension over the line through
    # the noisy-OR, and it would say "timing is weak evidence" when the honest
    # statement is "timing is not part of this oracle's default proof at all".
    # AUDIT (this slice) — that last sentence USED to read "callers that genuinely
    # mean timing (the A12 request-smuggling LEAD probe) still ask for it
    # EXPLICITLY". It is now STALE and is corrected rather than deleted, because the
    # change of reachability matters: this slice removed that caller, and the
    # verifier now PINS the discriminator per bug class from the AUTHORITY's table
    # rather than accepting a producer-supplied one. So ZERO callers on the scan path
    # can request ``latency``. The dimension remains implemented and reachable only
    # by a direct, in-process ``differential_oracle`` call that names it — it is not
    # dead code, but nothing in the shipped pipeline asks for it.
    wanted = set(disc.get("dimensions") or _DEFAULT_DIFFERENTIAL_DIMENSIONS)
    length_thr = float(disc.get("length_threshold", 0.05))
    lexical_thr = float(disc.get("lexical_threshold", 0.10))
    latency_thr = float(disc.get("latency_threshold_ms", 1000.0))
    structural_thr = float(disc.get("structural_threshold", 0.02))
    true_marker = disc.get("true_marker")

    dims: list[dict[str, Any]] = []

    if "status" in wanted and b.status is not None and m.status is not None:
        differs = b.status != m.status
        dims.append({"dim": "status", "differs": differs, "weight": 0.6 if differs else 0.0,
                     "detail": f"{b.status} -> {m.status}"})

    if "length" in wanted:
        lb, lm = len(b.body), len(m.body)
        ratio = abs(lb - lm) / max(lb, lm, 1)
        differs = ratio > length_thr
        dims.append({"dim": "length", "differs": differs,
                     "weight": min(1.0, ratio) if differs else 0.0,
                     "detail": f"{lb} vs {lm} bytes ({ratio:.2%})"})

    if "lexical" in wanted:
        sim = difflib.SequenceMatcher(None, b.body, m.body).ratio()
        diff = 1.0 - sim
        differs = diff > lexical_thr
        dims.append({"dim": "lexical", "differs": differs,
                     "weight": diff if differs else 0.0,
                     "detail": f"similarity {sim:.2%}"})

    if "structural" in wanted:
        # AST-level divergence: invariant to nonce/CSRF/timestamp noise, so a
        # page that merely reflects a per-request token does NOT read as a diff,
        # while an added record / DOM node does. Higher precision than lexical.
        score = structural_diff(b.body, m.body)
        differs = score > structural_thr
        dims.append({"dim": "structural", "differs": differs,
                     "weight": min(1.0, score) if differs else 0.0,
                     "detail": f"structural delta {score:.2%}"})

    if "latency" in wanted and b.latency_ms is not None and m.latency_ms is not None:
        delta = m.latency_ms - b.latency_ms
        differs = delta >= latency_thr
        dims.append({"dim": "latency", "differs": differs,
                     "weight": 0.7 if differs else 0.0,
                     "detail": f"+{delta:.0f} ms"})

    if "marker" in wanted and true_marker:
        present = true_marker in m.body and true_marker not in b.body
        dims.append({"dim": "marker", "differs": present,
                     "weight": 0.9 if present else 0.0,
                     "detail": f"true_marker {'present' if present else 'absent'}"})

    differing = [d for d in dims if d["differs"]]
    diff_conf = _noisy_or([d["weight"] for d in differing])

    expect = disc.get("expect", "differ")
    if expect == "same":
        fired = len(differing) == 0 and len(dims) > 0
        confidence = min(0.99, 1.0 - diff_conf) if fired else 0.0
        evidence = ("responses indistinguishable across "
                    + ", ".join(d["dim"] for d in dims)) if fired else (
            "responses diverge on " + ", ".join(d["dim"] for d in differing))
    else:
        fired = len(differing) > 0
        confidence = diff_conf if fired else 0.0
        evidence = ("responses diverge on "
                    + ", ".join(f"{d['dim']} ({d['detail']})" for d in differing)) if fired else (
            "responses indistinguishable")

    return OracleSignal(
        kind=OracleKind.DIFFERENTIAL_RESPONSE,
        fired=fired,
        confidence=confidence,
        evidence=evidence,
        observed={"dimensions": dims, "expect": expect},
    )


_SMUGGLING_MIN_CANARY_LEN = 12


_SMUGGLING_MIN_CANARY_ENTROPY = 2.5   # bits/char — a random alnum token clears ~4-6


_SMUGGLING_CANARY_RE = re.compile(r"^[A-Za-z0-9]{12,}$")


_SMUGGLING_MANGLED_STATUSES = frozenset({400, 405, 501, 502})


def _smuggling_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.95,
                      conclusive: bool = False) -> OracleSignal:
    # Reuses the FROZEN DIFFERENTIAL_RESPONSE kind (already in _ALL_ORACLES) but is reached
    # ONLY via the verifier's `smuggling_desync` ctx key, which no benchmark/scan/engage
    # finding carries — so `make gate` stays byte-identical and oracle_version is untouched.
    # A fire is always decisive; a NON-fire is `conclusive` only for a channel-confirmed
    # negative (both legs answered, no canary leaked) — an undecidable / low-entropy /
    # no-channel non-fire is a LEAD/INCONCLUSIVE, never a CLEAN.
    return OracleSignal(kind=OracleKind.DIFFERENTIAL_RESPONSE, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def _smuggling_leg(leg: Any) -> "dict | None":
    """Coerce one burst leg's retained record to ``{channel, status, reason, body}`` (pure).
    ``None`` when the leg is not a mapping (no observation to adjudicate)."""
    if not isinstance(leg, Mapping):
        return None
    status = leg.get("status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    return {"channel": bool(leg.get("channel", False)), "status": status,
            "reason": _coerce_text(leg.get("reason")), "body": _coerce_text(leg.get("body"))}


def smuggling_desync_oracle(observed: Any) -> OracleSignal:
    """Fire when VIGIL's OWN second request on a connection whose first request carried a
    framing conflict is DETERMINISTICALLY CORRUPTED by a leftover smuggled prefix — proven by
    a UNIQUE per-probe canary echoed in the conflict leg's second response AND absent from an
    identical no-conflict control leg's second response. The re-verifiable, timing-free
    achieved-state proof of HTTP request smuggling (CWE-444). Pure + deterministic; never
    raises. See the module comment above for the full contract."""
    obs = observed if isinstance(observed, Mapping) else {}
    canary = _coerce_text(obs.get("canary")).strip()
    technique = _coerce_text(obs.get("technique")).strip() or "CL.TE"
    base = {"technique": technique, "canary_len": len(canary)}

    # 1. The canary must be a UNIQUE, high-entropy VIGIL token, or a substring match could be
    #    coincidental (a benign body containing the token). A weak/absent canary is a LEAD.
    if (len(canary) < _SMUGGLING_MIN_CANARY_LEN or not _SMUGGLING_CANARY_RE.match(canary)
            or _shannon_bits_per_char(canary) < _SMUGGLING_MIN_CANARY_ENTROPY):
        return _smuggling_signal(
            False, observed=base,
            evidence=(f"the per-probe canary must be a unique VIGIL token (>= {_SMUGGLING_MIN_CANARY_LEN} "
                      "alnum chars AND >= 2.5 bits/char) so a substring match cannot be coincidental — "
                      "cannot adjudicate a desync (LEAD)"))

    conflict = _smuggling_leg(obs.get("conflict"))
    control = _smuggling_leg(obs.get("control"))
    if conflict is None or control is None:
        return _smuggling_signal(
            False, observed=base,
            evidence="the conflict and/or the no-conflict control second-request record is missing — "
                     "no differential to adjudicate (inconclusive)")

    # 2. BOTH VIGIL-owned second requests must have established a channel — a leg that read no
    #    response examined nothing (INCONCLUSIVE, never a desync and never a CLEAN).
    if not conflict["channel"] or not control["channel"]:
        return _smuggling_signal(
            False, observed={**base, "conflict_channel": conflict["channel"],
                             "control_channel": control["channel"]},
            evidence="a burst leg established no channel (the second request read no response) — "
                     "cannot adjudicate the desync differential (inconclusive)")

    echo_conflict = canary in conflict["body"]
    echo_control = canary in control["body"]
    mangled = conflict["status"] in _SMUGGLING_MANGLED_STATUSES and conflict["status"] != control["status"]
    detail = {**base, "echo_in_conflict": echo_conflict, "echo_in_control": echo_control,
              "conflict_status": conflict["status"], "control_status": control["status"],
              "mangled_method_status": mangled}

    # 3. The canary echoing in the CONTROL leg (identical bytes, WELL-FORMED framing) means the
    #    endpoint reflects the canary into the second response regardless of the conflict — the
    #    echo is NOT attributable to a desync. REFUSE (LEAD), never mint.
    if echo_control:
        return _smuggling_signal(
            False, observed=detail,
            evidence="the unique canary also appears in the NO-CONFLICT control's second response — the "
                     "echo is not attributable to a framing desync (an endpoint reflecting it regardless) "
                     "(REFUSE)")

    # 4. No echo in the conflict leg's second response: the back-end did not leak the smuggled
    #    prefix — no desync on this technique/origin. Both channels answered ⇒ channel-confirmed
    #    negative (a benign / anti-smuggling front-end that normalises the conflict lands here).
    if not echo_conflict:
        return _smuggling_signal(
            False, conclusive=True, observed=detail,
            evidence=(f"the {technique} conflict burst's second response did NOT echo the unique canary "
                      "(and neither did the control) — the origin did not desync this technique; a plain "
                      f"mangled-method status ({conflict['status']}) alone does not mint; did not fire"))

    # 5. The unique canary leaked into VIGIL's OWN second request's response on the conflict
    #    socket but NOT on the identical well-formed control socket — the ONLY difference (the
    #    framing conflict) caused the back-end to treat the smuggled prefix as the start of the
    #    next request. An achieved desync.
    return _smuggling_signal(
        True, conf=0.95, observed=detail,
        evidence=(f"HTTP request smuggling ({technique}): a UNIQUE per-probe canary embedded in the smuggled "
                  "prefix of VIGIL's first (conflict) request was ECHOED in VIGIL's OWN second request's "
                  "response on that socket, yet is ABSENT from an identical no-conflict control second "
                  "response — the back-end treated the smuggled prefix as the start of the next request "
                  "(a desync), proven by the differential, not by timing"
                  + (f"; the second request's method was also mangled (status {conflict['status']})"
                     if mangled else "")))


def _normal_cdf(z: float) -> float:
    """Standard-normal CDF via erf (pure stdlib)."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def _rank_average(values: Sequence[float]) -> tuple[list[float], list[int]]:
    """Average (fractional) ranks of ``values`` and the sizes of each tie group.

    Ties share the mean of the ranks they would occupy — the standard
    correction, so the Mann-Whitney statistic is exact under ties."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    tie_sizes: list[int] = []
    i = 0
    n = len(values)
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # ranks are 1-based
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        if j > i:
            tie_sizes.append(j - i + 1)
        i = j + 1
    return ranks, tie_sizes


def _mann_whitney(baseline: Sequence[float], treatment: Sequence[float]) -> tuple[float, float]:
    """One-sided Mann-Whitney U for H1: treatment stochastically GREATER than
    baseline. Returns (z, p_value) using the normal approximation with tie and
    continuity correction. p is the probability of a U this extreme under H0
    (no location shift). Small samples still get an honest — if conservative —
    normal-approximation p; there is no exact-distribution table here."""
    n1, n2 = len(baseline), len(treatment)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    ranks, tie_sizes = _rank_average(list(baseline) + list(treatment))
    r_treat = sum(ranks[n1:])
    u_treat = r_treat - n2 * (n2 + 1) / 2.0
    mu = n1 * n2 / 2.0
    n = n1 + n2
    tie_term = sum(t ** 3 - t for t in tie_sizes)
    var = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1))) if n > 1 else 0.0
    if var <= 0.0:
        # Zero variance: either everything tied (no signal) or perfectly
        # separated with n too small — treat as no usable statistic.
        return 0.0, 1.0
    sigma = math.sqrt(var)
    # continuity correction toward the null
    z = (u_treat - mu - 0.5) / sigma
    p = 1.0 - _normal_cdf(z)
    return z, p


def _hodges_lehmann(baseline: Sequence[float], treatment: Sequence[float]) -> float:
    """The Hodges-Lehmann estimator of the median shift (treatment - baseline):
    the median of all pairwise differences. A robust effect-size measure that
    resists outliers (one slow request cannot manufacture a shift)."""
    diffs = [t - b for t in treatment for b in baseline]
    return median(diffs) if diffs else 0.0


_TIMING_MAX_ALPHA = 0.01


def timing_oracle(
    baseline_samples: Any,
    treatment_samples: Any,
    *,
    injected_ms: float | None = None,
    alpha: float = 0.01,
    effect_floor_fraction: float = 0.5,
    absolute_floor_ms: float = 250.0,
    min_samples: int = 5,
    dose: Mapping[str, Any] | None = None,
) -> OracleSignal:
    """Confirm a time-based blind vulnerability with a real hypothesis test.

    A single averaged comparison or a fixed latency threshold (what sqlmap/Burp
    largely do) false-positives under jitter and false-negatives under load.
    This fires only when ALL of the following hold, which together are robust to
    both:

      1. **Rank-sum test.** A one-sided Mann-Whitney U rejects H0 (no shift) at
         ``alpha`` — the delay-injected requests are stochastically slower, by a
         distribution-free test that does not assume Gaussian latencies.
      2. **Effect-size floor.** The Hodges-Lehmann median shift is at least
         ``effect_floor_fraction`` of the injected delay (or ``absolute_floor_ms``
         when the delay is unknown) — a statistically-significant-but-tiny shift
         (network drift) is refused.
      3. **Dose-response (optional).** When ``dose`` supplies a second treatment
         at a different delay, the observed shift must scale with the injected
         delay (e.g. SLEEP(2) ~= 2x SLEEP(1)) — a constant offset cannot fake
         this. ``dose = {"low_ms": .., "low_samples": [..], "high_ms": .., "high_samples": [..]}``.

    Deterministic and pure: given the same samples it returns the same signal.

    RED-PEN B3b — MONOTONE RATCHET on the two firing knobs. ``alpha`` and
    ``injected_ms`` used to be read verbatim, and the ``framework.v2 verify`` path
    fed them straight out of an UNTRUSTED report's oracle context. Measured on
    samples ``[100..104]`` vs ``[105..109]`` (a 5 ms shift, i.e. ordinary jitter):
    defaults refused it ("median shift 5ms < floor 250ms"), but
    ``timing_injected_ms: 1.0`` drove the floor to 0 ms and CONFIRMED, and
    ``timing_alpha: 0.5`` accepted a p of 0.047 (and 0.028 on a bimodal set that
    cleared the 250 ms floor outright). Both are
    now clamped HERE, at the authority, so every caller is covered — including
    call sites this module does not own:

      * ``alpha`` is clamped to at most ``_TIMING_MAX_ALPHA`` — a caller may only
        make the test STRICTER, never more permissive;
      * ``injected_ms`` may only RAISE the effect floor
        (``floor = max(absolute_floor_ms, effect_floor_fraction * injected_ms)``),
        so a declared 5 s sleep still demands a ~2.5 s shift while a declared 1 ms
        one can no longer erase the 250 ms absolute floor.

    ``dose`` is NOT clamped, deliberately: it is DEMOTE-ONLY. ``fired`` requires
    ``dose_ok``, a malformed dose spec sets ``dose_ok=True``/``dose_conf=0.0``, and
    once ``alpha <= 0.01`` any fired signal already has ``p_conf = 0.9``, so
    ``dose_conf`` cannot lift a signal over a confirmation threshold it would not
    otherwise clear. A hostile dose can only REFUSE a fire; removing it would
    strictly WEAKEN this oracle. See ``test_timing_dose_is_demote_only``.
    """
    alpha = min(float(alpha), _TIMING_MAX_ALPHA)
    base = [float(x) for x in (baseline_samples or [])]
    treat = [float(x) for x in (treatment_samples or [])]
    if len(base) < min_samples or len(treat) < min_samples:
        return OracleSignal(
            kind=OracleKind.TIMING, fired=False, confidence=0.0,
            evidence=f"insufficient samples ({len(base)}/{len(treat)}, need >= {min_samples} each)",
            observed={"n_baseline": len(base), "n_treatment": len(treat)},
        )

    z, p = _mann_whitney(base, treat)
    shift = _hodges_lehmann(base, treat)
    # RED-PEN B3b: the declared injected delay may only RAISE the floor, never
    # lower it below the absolute floor (`injected_ms: 1.0` used to give floor 0).
    floor = (max(absolute_floor_ms, effect_floor_fraction * injected_ms)
             if injected_ms else absolute_floor_ms)

    reject = p < alpha
    effect_ok = shift >= floor

    dose_ok = True
    dose_detail = ""
    dose_conf = 0.0
    if dose is not None:
        low = [float(x) for x in (dose.get("low_samples") or [])]
        high = [float(x) for x in (dose.get("high_samples") or [])]
        low_ms = float(dose.get("low_ms", 0.0) or 0.0)
        high_ms = float(dose.get("high_ms", 0.0) or 0.0)
        if len(low) >= min_samples and len(high) >= min_samples and low_ms > 0 and high_ms > low_ms:
            low_shift = _hodges_lehmann(base, low)
            high_shift = _hodges_lehmann(base, high)
            expected_ratio = high_ms / low_ms
            observed_ratio = (high_shift / low_shift) if low_shift > 0 else 0.0
            # The observed shift must actually SCALE with the injected delay. A
            # constant offset (a slow proxy) gives ratio ~1.0 regardless; a real
            # dose gives ~expected_ratio. Require the ratio to sit above the
            # halfway point between "no scaling" (1) and full scaling, and not
            # wildly overshoot — so ratio 1.0 is refused, ratio ~expected passes.
            lower = 1.0 + 0.5 * (expected_ratio - 1.0)
            upper = 1.5 * expected_ratio
            dose_ok = lower <= observed_ratio <= upper
            dose_conf = 0.9 if dose_ok else 0.0
            dose_detail = f"; dose ratio {observed_ratio:.2f} vs expected {expected_ratio:.2f}"
        else:
            dose_ok = True  # malformed dose spec: do not penalise, just don't corroborate

    fired = reject and effect_ok and dose_ok

    if not fired:
        why = []
        if not reject:
            why.append(f"rank-sum p={p:.4g} >= alpha={alpha}")
        if not effect_ok:
            why.append(f"median shift {shift:.0f}ms < floor {floor:.0f}ms")
        if not dose_ok:
            why.append("dose-response failed")
        return OracleSignal(
            kind=OracleKind.TIMING, fired=False, confidence=0.0,
            # Channel-confirmed negative: this branch is past the min-samples guard, so a
            # real hypothesis test ran over adequate paired latencies and did not detect a
            # shift — a decisive "no timing channel" clean (the insufficient-samples early
            # return above stays non-conclusive → inconclusive, as it had no usable test).
            conclusive=True,
            evidence="no timing signal: " + "; ".join(why),
            observed={"z": z, "p_value": p, "median_shift_ms": shift, "floor_ms": floor},
        )

    p_conf = min(0.9, 1.0 - p)
    eff_conf = min(0.85, shift / injected_ms) if injected_ms else min(0.85, shift / (floor * 2))
    confidence = _noisy_or([p_conf, eff_conf, dose_conf])
    return OracleSignal(
        kind=OracleKind.TIMING,
        fired=True,
        confidence=confidence,
        evidence=(
            f"delay-injected requests are slower (Mann-Whitney z={z:.2f}, p={p:.3g}); "
            f"median shift {shift:.0f}ms >= floor {floor:.0f}ms{dose_detail}"
        ),
        observed={
            "z": z, "p_value": p, "median_shift_ms": shift, "floor_ms": floor,
            "n_baseline": len(base), "n_treatment": len(treat), "dose_ok": dose_ok,
        },
    )


def _sprt_decision(
    signals: Any,
    *,
    alpha: float,
    beta: float,
    p1: float,
    p0: float,
) -> tuple[str | None, float, int, int, float, float]:
    """The Wald SEQUENTIAL PROBABILITY RATIO TEST core, factored out so more than one oracle can
    share the SAME sequential test (``boolean_inference_oracle`` and ``credential_stuffing_oracle``).

    ``signals`` is an ITERABLE of bools consumed LAZILY: the loop stops pulling from the iterable
    at the first boundary, so a generator that computes each Bernoulli signal on demand does no
    work past the decision (this keeps ``boolean_inference_oracle`` byte-identical to its old
    inline loop — the same per-round work, in the same order, stopping at the same round).

    Returns ``(decided, llr, n_used, n_signal, upper, lower)`` where ``decided`` is ``"confirm"``
    (LLR >= log((1-beta)/alpha)), ``"refute"`` (LLR <= log(beta/(1-alpha))), or ``None`` (no
    boundary reached — inconclusive, a non-fire, never a guess). Pure + deterministic."""
    upper = math.log((1.0 - beta) / alpha)
    lower = math.log(beta / (1.0 - alpha))
    llr = 0.0
    n_used = 0
    n_signal = 0
    decided: str | None = None
    for sig in signals:
        n_used += 1
        n_signal += 1 if sig else 0
        llr += math.log(p1 / p0) if sig else math.log((1.0 - p1) / (1.0 - p0))
        if llr >= upper:
            decided = "confirm"
            break
        if llr <= lower:
            decided = "refute"
            break
    return decided, llr, n_used, n_signal, upper, lower


def _boolean_round_arm(r: Mapping[str, Any], key: str) -> list[Any]:
    """One truth-side arm of a boolean probe round as a list (``[]`` when absent/malformed).

    The round shape is ``{"trues": [...], "falses": [...], "true_repeats": [...],
    "false_repeats": [...]}`` — ``trues``/``falses`` are the responses to K DISTINCT,
    syntactically-VARIED clauses of one fixed truth value; ``*_repeats`` are their
    index-aligned BYTE-IDENTICAL repeats."""
    v = r.get(key)
    return list(v) if isinstance(v, (list, tuple)) else []


_BOOLEAN_DIMENSIONS = ("status", "length", "lexical", "structural")


_BOOLEAN_DEFAULT_DIMENSIONS = ("status", "length", "lexical")


def _boolean_discriminator(discriminator: Mapping[str, Any] | str | None) -> dict[str, Any]:
    """The effective discriminator for EVERY boolean comparison — fully protocol-pinned.

    Only the DIMENSIONS may be narrowed by a caller, and only within ``_BOOLEAN_DIMENSIONS``. The
    THRESHOLDS are pinned too (they are simply dropped): they set SENSITIVITY, and a threshold fitted to
    a particular set of retained bytes can manufacture "within-cluster same, across-cluster differ" out
    of noise — the same forgery the SPRT parameters allowed. No live caller passes thresholds (all three
    pass protocol constants), so pinning costs nothing and removes the seam entirely rather than leaving
    a comment claiming it is unreachable."""
    if isinstance(discriminator, str):
        disc: dict[str, Any] = {"dimensions": [discriminator]}
    else:
        disc = dict(discriminator or {})
    wanted = [d for d in (disc.get("dimensions") or _BOOLEAN_DEFAULT_DIMENSIONS)
              if d in _BOOLEAN_DIMENSIONS]
    return {"dimensions": wanted or list(_BOOLEAN_DEFAULT_DIMENSIONS), "expect": "differ"}


def _boolean_reflection_forms(clause: str) -> tuple[str, ...]:
    """Every encoding of ``clause`` that could appear reflected in a response body: the RAW clause,
    both HTML-escaped forms (quotes escaped and not), and both URL-encoded forms. Deduplicated and
    ordered LONGEST-first so a shorter encoding can never bite a substring of a longer one."""
    if not clause:
        return ()
    forms = {
        clause,
        html.escape(clause, quote=True),
        html.escape(clause, quote=False),
        _urlquote(clause, safe=""),
        _urlquote(clause),
    }
    return tuple(sorted((f for f in forms if f), key=len, reverse=True))


def _mask_boolean_reflection(resp: Any) -> Any:
    """Return ``resp`` with every occurrence of ITS OWN retained injected ``clause`` (raw /
    HTML-escaped / URL-encoded) stripped from the body. A response carrying no ``clause`` is returned
    UNCHANGED (an old context, or an arm that never reflected), so the behaviour on a non-reflecting
    target — and on every pre-existing retained context — is byte-for-byte what it was."""
    if not isinstance(resp, Mapping):
        return resp
    clause = resp.get("clause")
    if not clause:
        return resp
    body = _coerce_text(resp.get("body", resp.get("text", resp.get("content", ""))))
    for form in _boolean_reflection_forms(str(clause)):
        body = body.replace(form, "")
    out = dict(resp)
    out["body"] = body
    return out


def boolean_inference_oracle(
    probe_rounds: Any,
    *,
    alpha: float = 0.05,
    beta: float = 0.05,
    p1: float = 0.9,
    p0: float = 0.1,
    discriminator: Mapping[str, Any] | str | None = None,
    false_baseline_samples: Any = None,
    min_baseline_samples: int = 6,
    min_true_clauses: int = 4,
    min_false_clauses: int = 4,
) -> OracleSignal:
    """Confirm a boolean-blind vulnerability by a Wald SEQUENTIAL PROBABILITY RATIO TEST
    over repeated probes whose per-round signal is a TRUTH-VALUE ATTRIBUTION test.

    THE GUARANTEE (and the only one). A ``boolean_sqli`` FACT requires the response to be a
    deterministic FUNCTION OF THE INJECTED BOOLEAN'S TRUTH VALUE. It is NOT enough that the
    "true" request and the "false" request came back different: on a page whose body is drawn
    INDEPENDENTLY of the input (a rotating banner, an A/B bucket, a load-balanced pair of
    replicas) two draws differ by coincidence, and no amount of determinism *screening* removes
    that — a sample window that LOOKS deterministic still produces the coincidence inside it.
    This oracle therefore does not screen for determinism and then trust a single true/false
    pair; it demands that the response PARTITION BY TRUTH VALUE:

      * Each round carries ``K_T >= min_true_clauses`` responses to DISTINCT, syntactically
        VARIED clauses that are all logically TRUE (``trues``), and ``K_F >=
        min_false_clauses`` responses to DISTINCT, varied clauses that are all logically
        FALSE (``falses``) — plus an index-aligned BYTE-IDENTICAL repeat of each
        (``true_repeats`` / ``false_repeats``).
      * The round signals 1 only when ALL THREE hold:
          1. DETERMINISM       — every clause, sent twice byte-identically, does not differ
                                 (enforced globally as a HARD REFUTE, below).
          2. WITHIN-TRUTH      — every TRUE-side response agrees with every other TRUE-side
             AGREEMENT          response (ONE true cluster), and likewise for the FALSE side
                                 (``differential_response_oracle`` non-fire inside a cluster).
          3. ACROSS-TRUTH      — every TRUE-side response DIFFERS from every FALSE-side
             SEPARATION         response (the two clusters are disjoint).

    WHY AN INPUT-INDEPENDENT PAGE CANNOT PASS (the bound, and its exact scope). Say each
    response is an INDEPENDENT draw from an arbitrary variant distribution ``{p_v}`` — a
    rotating banner, an A/B bucket, two replicas behind a balancer. Then the ``2*K_T`` true-side
    and ``2*K_F`` false-side responses are ``2*(K_T+K_F)`` independent draws, and a clean
    2-cluster split by truth value needs every true-side draw to be the SAME variant ``a``,
    every false-side draw the same variant ``b``, and ``a != b``:

        s  =  SUM over a != b of  p_a**(2*K_T) * p_b**(2*K_F)   <=  2 * 2**-(2*K_T + 2*K_F)

    (maximised by a UNIFORM 2-variant page). At the ``K_T = K_F = 7`` the drivers ship that is
    ``s <= 2 * 2**-28 = 7.5e-9``; at the oracle's CONFIRM floor (``K_T = K_F = 4``) it is
    ``s <= 2 * 2**-16 = 3.1e-5``, still ~3300x below the SPRT's null rate ``p0 = 0.1``. With
    ``alpha = beta = 0.05, p1 = 0.9, p0 = 0.1`` the confirm boundary is two NET signalling
    rounds, so a gambler's-ruin bound puts the per-FINDING false-confirm probability at
    ``<= s**2 / (1 - 2s)`` — ``~5.6e-17`` at ``K = 7`` — and that bound holds with NO determinism
    pre-gate at all. The skew that defeated a 16-sample determinism pre-gate (a dominant variant
    ``p ~ 0.9`` passes ``0.9**16 ~ 19%`` of windows) makes this test STRICTER, not weaker.

    TWO THINGS THIS BOUND DOES NOT COVER. Both are real, both are demonstrated, and NEITHER is
    "impossible to observe" — an earlier revision of this docstring said so and was wrong:

      (a) A TRUTH-CORRELATED REQUEST FILTER — STATUS: OPEN. An interposer that partitions the
          probes by a property of the REQUEST that happens to track truth value, with no boolean
          channel behind it at all. The bound above says nothing about this, because it is a
          property of the CLAUSE SET, not of the page.

          WHY IT IS OPEN, STRUCTURALLY — this is the part to read, not the ladder. The oracle needs
          clauses whose truth value VIGIL knows A PRIORI: before the request is sent, without
          touching the target's database. A predicate knowable that way IS A CONSTANT EXPRESSION,
          and any constant expression the scanner can evaluate offline, a filter in front of a
          static page can also evaluate offline. So no clause set removes this residual; a clause
          set only raises the COMPLEXITY of the function the filter has to implement. Every
          mitigation in this area is therefore a TREADMILL, and the measured ladder below is that
          treadmill being climbed, one rung per revision.

          THE LADDER, all measured through the REAL mint path against a STATIC, NON-VULNERABLE page
          (no SQL anywhere, no boolean channel — every FACT is false by construction):

            literal-only set (`X = X` / `X = Y`)   vs CRS-942130 backreference regex   2000/2000
            shape-varied set                       vs the same CRS-942130 regex             0/2000
            shape-varied FOLDABLE subset (K=6)     vs a complete ~60-line CONSTANT FOLDER  200/200
            SHIPPED set (K=7, with `IN (SELECT)`)  vs that same folder                       0/200
            SHIPPED set                            vs that folder + a THREE-LINE `IN` rule  600/600
            SHIPPED set, literals randomised       vs folder + a NINE-STRING `IN` blocklist 300/300
            SHIPPED set                            vs an exact-string blocklist of its TRUEs 200/200
            SHIPPED set                            vs ANY filter blind to one shape           0 each

          Read the ladder as a whole. Each row that reaches 0 was called a fix; the next row is that
          fix being cleared by a filter one rule larger. The folder is ~60 lines and contains no SQL
          engine, no parser generator and no database; the `IN` rule that took the last 0 back to
          600/600 is three lines, because `LIT IN (SELECT LIT)` over a one-row constant select IS
          literal equality (sqlite3: `3 IN (SELECT 3)` -> 1, `3 IN (SELECT 5)` -> 0) — `X = X` vs
          `X = Y` in a costume, with the same separating surface feature. The randomised-literal row
          is the same lesson: the clause TEMPLATES are public in an open-source repo, so the filter
          derives its rules from them and only needs nine strings for the one randomised atom —
          which is why the literals are now a STABLE PUBLIC CONSTANT instead (correlatability and
          replayability are worth more than a mitigation that measures zero).

          PROVENANCE, so no row is taken for more than it is. Four rows are PINNED by live
          regressions that re-measure them every CI run at 10-20 trials each
          (``scanner/tests/test_boolean_inference_check.py``): CRS-942130 both halves, the complete
          folder, the folder blinded to one shape, and the exact-string blocklist. The 2000-,
          600- and 300-trial figures are one-off at-scale runs of those same cells, not CI cells.
          (The 300/300 row was 299/300 as the red-pen first measured it; the one miss was their
          folder's naive OR-split cutting inside a string literal that happened to contain "or" —
          a fixture artefact, and the fixture here masks literals before splitting.)

          WHAT THE CLAUSE SET DOES BUY, precisely and no more: a filter must be COMPLETE over the
          shape set to partition. Blind it to any ONE comparison shape and it blocks only part of
          the TRUE side, within-truth agreement breaks, and the round REFUTES — measured 0 for the
          CRS-942130 rule, for equality-only, lexicographic-only, numeric-direction-only,
          LIKE-prefix-only and generic block-any-OR/quote filters, and 0 in a LEAVE-ONE-SHAPE-OUT
          sweep for every one of the seven shipped shapes blinded. That is a real property and it
          is why the common real-world filter refutes. It is NOT sufficiency, and an earlier
          revision of this docstring that said the set was closed by a "SQL-EVALUATED" pair was
          wrong: the pair is a seventh comparison shape, no more.

          WHAT AN OPERATOR SHOULD CONCLUDE. A boolean_sqli FACT is sound against a page whose body
          varies independently of the input (the bound above) and against every INCOMPLETE
          request-side filter. It is NOT sound against a filter purpose-built to decide this clause
          set, and such a filter is cheap. Where that matters — a target known to sit behind an
          aggressive WAF, or a FACT whose whole weight rests on this one oracle — corroborate with a
          channel that does not live in the response bytes (an OOB/DNS callback, an error-signature
          or a timing arm), or treat it as a LEAD.

          RESIDUAL (a2) — STATUS: OPEN, and out of reach from the response side. An interposer that
          genuinely EVALUATES the injected expression (a WAF embedding a real SQL parser and
          evaluator) can partition the probes by truth value with no database behind it. That is the
          same shape of limit as (b) — such an interposer IS computing the truth function this
          oracle reads — and no clause set defeats it from the response side; it needs an
          out-of-band channel (OOB/DNS, a side effect) to separate. (a) is NOT a special case of
          (a2) and must not be filed under it: (a) needs no evaluator at all, only a folder.

          A caller supplying its own clause sets inherits the shape-diversity obligation and the
          same open residual; see ``scanner.checks.boolean_clause_families``.

      (b) A page that is a DETERMINISTIC but ARBITRARY function of the request — STATUS: OPEN,
          and BOUNDED rather than closed (a CDN caching per exact URL over an origin that picked a
          variant at fill time, a balancer pinning each URL to a replica). There the byte-identical
          repeats are cache HITS, not independent draws, and re-running the SAME clauses in a
          later round returns the SAME bytes — so neither the repeats nor the extra SPRT rounds are
          new evidence, and the per-FINDING bound degrades to the single-draw one:

              SUM over a != b of  p_a**K_T * p_b**K_F   <=  2 * 2**-(K_T + K_F)

          = ``1.2e-4`` at ``K = 7``, and the formula is CALIBRATED, not assumed: over the real
          mint path a uniform 2-variant cached page measures ``1.20e-4`` at ``K = 7``
          (200k trials) against an analytic ``1.22e-4``, and ``7.9e-3`` at ``K = 4`` against an
          analytic ``7.8e-3``. (A
          single-clause-per-truth-value design — what this test replaced — sits at ``~0.5``.)
          Repetition cannot help against a map that is by definition constant in the request, so
          for THIS case more distinct clauses is the lever — and it is the lever that keeps the
          seventh shipped clause (the ``IN (SELECT ...)`` pair) in the set now that its original
          "a folder cannot decide it" justification is retracted: at ``K = 6`` this residual is 4x
          worse (analytic ``2 * 2**-12`` = ``4.9e-4``). It is not free: every extra clause is
          another chance that a real vulnerable target answers ONE of them differently and the
          round refutes, so ``K`` trades this residual against recall. The drivers also BOUND the
          number of independent attempts per URL and state the resulting per-URL figure (see
          ``live/runtime_redrive.py::boolean_redrive``).

    THE TWO DETERMINISM MECHANISMS ARE A CHEAP PRE-FILTER, NOT THE SOUNDNESS CORE:
      1. BASELINE PRE-GATE — ``false_baseline_samples`` is a run of ``>= min_baseline_samples``
         responses to ONE IDENTICAL false-clause request collected up front; not-all-identical
         proves non-determinism → REFUSE. A confirm still REQUIRES it to have passed
         (fail-closed), but it is no longer what makes the oracle sound.
      2. PER-ROUND HARD REFUTE — if ANY clause's byte-identical repeat differs from the clause,
         the WHOLE finding hard-refutes (the page is provably non-deterministic).

    CALLER OBLIGATION (the oracle sees responses, not requests). The ``K_T``/``K_F`` clauses must
    genuinely be DISTINCT requests of a FIXED truth value and must VARY IN COMPARISON SHAPE rather
    than only in their literals — which buys refutation against every INCOMPLETE request-side
    filter and nothing beyond it (residual (a) above stays OPEN whatever the caller ships). The
    oracle cannot check any of that from the bytes. The drivers enforce distinctness where the
    clauses live (``BooleanInferenceCheck`` and ``DifferentialHttpAdapter`` both refuse a duplicate
    or a cross-side clause at the call site) and build their families from
    ``scanner.checks.boolean_clause_families``; the shape property is a review obligation on the
    clause sets, pinned by the live CRS-942130, constant-folder and leave-one-shape-out
    regressions — the folder cell PINS the open class (it must keep minting), not a win.

    WHAT "RE-VERIFIES OFFLINE" DOES AND DOES NOT MEAN. Re-execution over a retained context
    recomputes this whole decision from the retained bytes, so a GROSS edit (a swapped page, a
    dropped arm, a removed baseline, a truncated clause list) is rejected. It is NOT a byte
    integrity check: the comparison is deliberately FUZZY (``length`` 5%, ``lexical`` 10%), so a
    sub-threshold edit inside a retained body — a byte, a word — does not change the verdict.
    Byte integrity comes from the certificate signature and digest binding, not from this oracle.

    FAIL-CLOSED ON SHAPE. A round that does not carry the multi-clause truth-value arms — an
    OLD single-clause retained context ``{"true", "false_a", "false_b", "false_a_repeat"}``
    included — can NEVER be a positive signal: it yields 0 and the SPRT refutes. Old-shape
    evidence can only refute, never mint.

    RECALL COST (honest, and the safe direction). A legitimately noisy-but-vulnerable page
    (per-request ``__VIEWSTATE`` / CSRF token / rotating banner), and a vulnerable page whose
    varied true clauses do not all land on the same response, are REFUSED to a LEAD. That is a
    documented false-LEAD, never a false FACT.
    """
    rounds = [r for r in (probe_rounds or []) if isinstance(r, Mapping)]

    def _nondeterministic(reason: str) -> OracleSignal:
        # A non-deterministic page cannot support boolean inference → LEAD, never a FACT and never a
        # CLEAN (conclusive=False): the page MIGHT be vulnerable but noisy — refusing it is a recall
        # cost, not a proof of safety. decision="refute" (fired=False) so a downstream refute-branch
        # still classifies it as "did not mint", while conclusive=False keeps it out of any CLEAN.
        return OracleSignal(
            kind=OracleKind.BOOLEAN_INFERENCE, fired=False, confidence=0.0, conclusive=False,
            evidence=("boolean inference REFUSED — page is not deterministic to identical input "
                      f"({reason}); boolean-blind inference is unsound on a non-deterministic page → LEAD"),
            observed={"decision": "refute", "nondeterministic": True, "reason": reason},
        )

    # PIN the dimensions (never latency / marker) and force expect="differ" — see _BOOLEAN_DIMENSIONS.
    disc = _boolean_discriminator(discriminator)

    def _same(a: Any, b: Any) -> bool:
        """Do two observed responses AGREE? ``differential_response_oracle`` is the authority; an
        EXACT match short-circuits it (identical bytes + identical status make every dimension
        non-differing, so the oracle provably cannot fire) — a pure speed path, never a
        semantic one.

        Before the discriminator compares them, each response has ITS OWN reflected injected clause
        removed (``_mask_boolean_reflection``): on a page that echoes the distinct clause back into
        its body, two same-truth-value responses only DIFFER in that reflection, so masking is what
        lets a genuine channel behind a reflection attribute. It never manufactures one — a reflect-
        only page masks to the SAME residual on both sides and stays indistinguishable. A response
        with no retained ``clause`` masks to itself, so a non-reflecting target is unchanged."""
        if a == b:
            return True
        return not differential_response_oracle(
            _mask_boolean_reflection(a), _mask_boolean_reflection(b), disc).fired

    # --- PRE-FILTER 1: BASELINE DETERMINISM PRE-GATE ----------------------------------------------
    baseline = list(false_baseline_samples) if false_baseline_samples is not None else None
    baseline_deterministic = False
    if baseline is not None and len(baseline) >= 2:
        ref = baseline[0]
        if any(not _same(ref, s) for s in baseline[1:]):
            return _nondeterministic(
                f"{len(baseline)} identical-request baseline samples are not all identical")
        baseline_deterministic = len(baseline) >= min_baseline_samples

    # --- PRE-FILTER 2: HARD REFUTE on any observed non-determinism (a byte-identical repeat that
    #     came back different). Covers every clause of the new shape AND the legacy false_a pair. ---
    for r in rounds:
        pairs = list(zip(_boolean_round_arm(r, "trues"), _boolean_round_arm(r, "true_repeats")))
        pairs += list(zip(_boolean_round_arm(r, "falses"), _boolean_round_arm(r, "false_repeats")))
        legacy_rep = r.get("false_a_repeat")
        if legacy_rep is not None and "false_a" in r:
            pairs.append((r["false_a"], legacy_rep))
        for clause_resp, repeat_resp in pairs:
            if not _same(clause_resp, repeat_resp):
                return _nondeterministic(
                    "a byte-identical clause repeat returned a different response in a probe round")

    def _truth_value_attributed(r: Mapping[str, Any]) -> bool:
        """THE SOUNDNESS CORE — is this round's response a FUNCTION of the injected truth value?
        One TRUE cluster, one FALSE cluster, and the two disjoint. Short-circuits."""
        trues = _boolean_round_arm(r, "trues")
        falses = _boolean_round_arm(r, "falses")
        t_reps = _boolean_round_arm(r, "true_repeats")
        f_reps = _boolean_round_arm(r, "false_repeats")
        # FAIL-CLOSED on shape: too few DISTINCT clauses per truth value, or a missing repeat, and the
        # round cannot attribute anything → it is not a positive signal (an old-shape round lands here).
        if (len(trues) < min_true_clauses or len(falses) < min_false_clauses
                or len(t_reps) != len(trues) or len(f_reps) != len(falses)):
            return False
        t_cluster = trues + t_reps
        f_cluster = falses + f_reps
        # (2) WITHIN-TRUTH AGREEMENT — all of one truth value land on ONE response.
        for cluster in (t_cluster, f_cluster):
            for i in range(len(cluster)):
                for j in range(i + 1, len(cluster)):
                    if not _same(cluster[i], cluster[j]):
                        return False
        # (3) ACROSS-TRUTH SEPARATION — every TRUE response differs from every FALSE response.
        for t in t_cluster:
            for f in f_cluster:
                if _same(t, f):
                    return False
        return True

    def _round_signals():
        for r in rounds:
            yield _truth_value_attributed(r)

    decided, llr, n_used, signals, upper, lower = _sprt_decision(
        _round_signals(), alpha=alpha, beta=beta, p1=p1, p0=p0)

    observed = {
        "rounds_used": n_used, "signal_rounds": signals, "llr": llr,
        "upper": upper, "lower": lower, "decision": decided or "inconclusive",
        "baseline_samples": (len(baseline) if baseline is not None else 0),
        "baseline_deterministic": baseline_deterministic,
        "min_true_clauses": min_true_clauses, "min_false_clauses": min_false_clauses,
        # the ACTUAL clause counts the judged rounds carried (the analytic bound is a function of THESE,
        # not of the floor) — recorded so an auditor can recompute the bound from the retained evidence.
        "true_clauses_per_round": sorted({len(_boolean_round_arm(r, "trues")) for r in rounds}),
        "false_clauses_per_round": sorted({len(_boolean_round_arm(r, "falses")) for r in rounds}),
    }
    if decided == "confirm":
        # FAIL-CLOSED determinism pre-filter: a FACT also requires the baseline pre-gate to have PASSED
        # (>= min_baseline_samples identical up-front samples). Belt-and-braces on top of the
        # truth-value attribution that carries the soundness — a confirm without a determinism proof is
        # DOWNGRADED to inconclusive (a LEAD, never a FACT).
        if not baseline_deterministic:
            observed["decision"] = "inconclusive"
            observed["confirm_without_baseline_pregate"] = True
            return OracleSignal(
                kind=OracleKind.BOOLEAN_INFERENCE, fired=False, confidence=0.0, conclusive=False,
                evidence=(
                    f"SPRT reached the confirm boundary in {n_used} round(s) but the baseline "
                    f"determinism pre-gate did NOT pass ({observed['baseline_samples']} < "
                    f"{min_baseline_samples} identical up-front samples) — a boolean FACT requires "
                    "proving the page is deterministic to identical input first → LEAD"),
                observed=observed,
            )
        # confidence reflects the controlled type-I error rate of the test
        confidence = min(0.99, 1.0 - alpha)
        return OracleSignal(
            kind=OracleKind.BOOLEAN_INFERENCE, fired=True, confidence=confidence,
            evidence=(
                f"SPRT confirmed boolean inference in {n_used} round(s): {signals} round(s) in which the "
                f"response was a FUNCTION of the injected truth value "
                f"(K_T={observed['true_clauses_per_round']} distinct TRUE clauses all agree, "
                f"K_F={observed['false_clauses_per_round']} distinct FALSE clauses all agree, each also "
                f"stable to a byte-identical repeat, and the two clusters disjoint), behind a passed "
                f"determinism pre-gate ({observed['baseline_samples']} identical baseline samples), "
                f"LLR={llr:.2f} >= {upper:.2f}"
            ),
            observed=observed,
        )
    reason = "refuted (indistinguishable)" if decided == "refute" else "inconclusive (no boundary reached)"
    # A REFUTE decision is a channel-confirmed negative: the SPRT accumulated enough
    # evidence to accept the null (no boolean channel) at the controlled type-II rate,
    # so it is a decisive "provably-tested-clean". Running out of rounds WITHOUT reaching
    # a boundary is genuinely inconclusive (never a clean), so it is NOT conclusive.
    return OracleSignal(
        kind=OracleKind.BOOLEAN_INFERENCE, fired=False, confidence=0.0,
        conclusive=(decided == "refute"),
        evidence=f"SPRT {reason} after {n_used} round(s): LLR={llr:.2f} in ({lower:.2f}, {upper:.2f})",
        observed=observed,
    )


def _searchable(sink: Any) -> str:
    if isinstance(sink, Mapping):
        return "\n".join(f"{k}={_coerce_text(v)}" for k, v in sink.items())
    if isinstance(sink, (list, tuple)):
        return "\n".join(_coerce_text(x) for x in sink)
    return _coerce_text(sink)


def side_effect_oracle(marker: str, observed_sink: Any, control_sink: Any = None) -> OracleSignal:
    """Fire when a unique, attacker-chosen marker appears somewhere it should not.

    WHERE THIS ORACLE IS THE SOLE AUTHORITY (`verifier.BUG_CLASS_ORACLES`):
    ``path_traversal`` and ``lfi``. Nothing else adjudicates those two classes, so
    for them this function's verdict IS the FACT. It is also one of several
    confirmers for ``error_based_sqli`` / ``sqli`` / ``rce`` / ``command_injection``
    / ``ssti`` / ``el_injection`` / ``ssi`` / ``xxe`` / ``websocket_injection``.

    WHERE IT IS **NOT** USED: XSS. A "reflected/stored XSS canary in rendered
    output" is precisely what this oracle must NOT be used for — ``xss`` goes to
    REFLECTION_CONTEXT (a proven breakout) and ``stored_xss``/``dom_xss`` to
    DOM_EXECUTION (proven execution). Marker-in-a-sink is substring XSS detection,
    the false positive both of those exist to refuse.

    The marker must be non-trivial (>= 4 chars) so we do not confirm on incidental
    substrings.

    ``control_sink`` (OPTIONAL — absent ⇒ every existing caller is byte-identical) is the sink
    observed under a BENIGN control on the same insertion point. When it is supplied and ALREADY
    CONTAINS the marker, the marker's presence under the payload is NOT attributable to the payload
    and the oracle REFUSES. That is the offline-re-derivable half of the fix for a measured defect:
    a marker that is not attacker-UNIQUE (a KNOWN-CONTENT file signature such as ``root:x:0:0:``)
    is present in an ordinary security knowledge-base page that merely documents it, and bare
    substring presence minted four ``path_traversal`` FACTs against a site with ZERO file I/O.
    Producers that hold a control must retain it here so re-verification re-derives the refusal.

    KNOWN LIMITATION (RED-PEN), only PARTLY closed by ``control_sink``: a marker's PRESENCE in a
    sink is not proof that the PAYLOAD put it there — an endpoint that echoes its own input into the
    sink produces the same observation. A supplied ``control_sink`` refuses the KNOWN-CONTENT case,
    but where no control is supplied, and for the sole-authority ``path_traversal``/``lfi`` classes,
    a full payload-correlation / content-provenance guard is still owed (its own slice). Until then,
    treat a bare ``path_traversal``/``lfi`` confirmation as needing a human look at the snippet.

    Pure: it decides from the retained sinks alone and sends nothing."""
    marker = (marker or "").strip()
    haystack = _searchable(observed_sink)

    if len(marker) < 4:
        return OracleSignal(
            kind=OracleKind.SIDE_EFFECT, fired=False, confidence=0.0,
            evidence="marker too short to be a reliable canary",
            observed={"marker": marker})

    if control_sink is not None and marker in _searchable(control_sink):
        return OracleSignal(
            kind=OracleKind.SIDE_EFFECT, fired=False, confidence=0.0,
            evidence=(f"marker {marker!r} is ALREADY PRESENT in the benign control response — its "
                      "presence under the payload is not attributable to the payload"),
            observed={"marker": marker, "present_in_control": True})

    idx = haystack.find(marker)
    if idx < 0:
        return OracleSignal(
            kind=OracleKind.SIDE_EFFECT, fired=False, confidence=0.0,
            evidence=f"marker {marker!r} not present in sink",
            observed={"marker": marker})

    start = max(0, idx - 24)
    snippet = haystack[start: idx + len(marker) + 24]
    return OracleSignal(
        kind=OracleKind.SIDE_EFFECT,
        fired=True,
        confidence=0.9,
        evidence=f"marker {marker!r} reached sink: ...{snippet}...",
        observed={"marker": marker, "offset": idx, "snippet": snippet},
    )


_INERT_TEXT_CONTAINERS = frozenset({
    "noscript", "noembed", "noframes", "textarea", "title", "template",
    "iframe", "xmp", "plaintext", "style",
})


_JS_MIME_ESSENCES = frozenset({
    "application/ecmascript", "application/javascript", "application/x-ecmascript",
    "application/x-javascript", "text/ecmascript", "text/javascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
    "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
})


def _script_is_executable(
    type_attr: str | None, has_nomodule: bool
) -> tuple[bool, str]:
    """Decide whether a browser EXECUTES a ``<script>``'s inline text, from its RAW
    ``type`` attribute value and the presence of ``nomodule``.

    Returns ``(executable, reason)``; ``reason`` names the non-executing rule.

    ``type_attr`` is the RAW attribute value (``None`` when the attribute is
    absent) — *not* stripped and *not* lowercased by the caller, because the HTML
    Living Standard's rules distinguish the raw empty string from a whitespace-only
    value. Pure and deterministic. Every branch below is measured against
    /usr/bin/chromium 150 in ``test_script_type_executability_matches_chromium``:

      * attribute ABSENT              -> classic, EXECUTES
      * ``type=""`` (raw empty)       -> classic, EXECUTES  (LS: "if the type
        attribute's value is the empty string, the script block's type is classic")
      * ``type=" "`` / ``type="\\t"``  -> does NOT execute. The empty-string rule is
        about the RAW value; a whitespace-only value strips to ``""``, which is not
        a JavaScript MIME essence and is not ``module``, so the element is a data
        block. (Chromium: measured inert. The old code stripped first and let it in
        through the ``""`` member.)
      * stripped, case-folded value in :data:`_JS_MIME_ESSENCES` -> EXECUTES
      * raw value case-insensitively equal to ``module`` -> EXECUTES.  The match is
        on the UNSTRIPPED value: Chromium runs ``type="MODULE"`` and does NOT run
        ``type=" module "``.  Where Chromium and the LS may differ (the LS strips),
        this oracle takes the NON-FIRING option — a missed detection, never a
        manufactured FACT.
      * ``nomodule`` present on a CLASSIC script -> does NOT execute ("prepare the
        script element" step 13 returns early). Measured: ``<script nomodule>``
        inert, ``<script type="module" nomodule>`` EXECUTES (``nomodule`` is
        ignored for module scripts), ``nomodule="false"`` inert (boolean attribute
        — presence is the test)."""
    if type_attr is None:
        is_module, executable = False, True
    elif type_attr == "":
        is_module, executable = False, True
    else:
        lowered = type_attr.lower()
        is_module = lowered == "module"
        executable = is_module or type_attr.strip().lower() in _JS_MIME_ESSENCES
    if not executable:
        return False, "script_data_block"
    if has_nomodule and not is_module:
        return False, "script_nomodule_ignored"
    return True, ""


_EVENT_HANDLER_ATTRIBUTES = frozenset({
    # AUDIT-B4 (measured in Chromium 150): real handler content attributes this
    # closed set was missing.
    "oncommand", "oncontentvisibilityautostatechange", "onmousewheel",
    "onscrollsnapchange", "onscrollsnapchanging",
    # HTML LS: element / document / window event handlers
    "onabort", "onauxclick", "onbeforeinput", "onbeforematch", "onbeforetoggle",
    "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick",
    "onclose", "oncontextlost", "oncontextmenu", "oncontextrestored", "oncopy",
    "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter",
    "ondragexit", "ondragleave", "ondragover", "ondragstart", "ondrop",
    "ondurationchange", "onemptied", "onended", "onerror", "onfocus", "onformdata",
    "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onload",
    "onloadeddata", "onloadedmetadata", "onloadstart", "onmousedown", "onmouseenter",
    "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup",
    "onpaste", "onpause", "onplay", "onplaying", "onprogress", "onratechange",
    "onreset", "onresize", "onscroll", "onscrollend", "onsecuritypolicyviolation",
    "onseeked", "onseeking", "onselect", "onslotchange", "onstalled", "onsubmit",
    "onsuspend", "ontimeupdate", "ontoggle", "onvolumechange", "onwaiting", "onwheel",
    # HTML LS: Window-reflecting handlers (<body> / <frameset>)
    "onafterprint", "onbeforeprint", "onbeforeunload", "onhashchange",
    "onlanguagechange", "onmessage", "onmessageerror", "onoffline", "ononline",
    "onpagehide", "onpagereveal", "onpageshow", "onpageswap", "onpopstate",
    "onrejectionhandled", "onstorage", "onunhandledrejection", "onunload",
    # CSS animations / transitions
    "onanimationcancel", "onanimationend", "onanimationiteration", "onanimationstart",
    "ontransitioncancel", "ontransitionend", "ontransitionrun", "ontransitionstart",
    "onwebkitanimationend", "onwebkitanimationiteration", "onwebkitanimationstart",
    "onwebkittransitionend",
    # Pointer / touch / gesture
    "ongotpointercapture", "onlostpointercapture", "onpointercancel", "onpointerdown",
    "onpointerenter", "onpointerleave", "onpointermove", "onpointerout",
    "onpointerover", "onpointerrawupdate", "onpointerup", "ontouchcancel",
    "ontouchend", "ontouchmove", "ontouchstart",
    # Misc. widely-implemented content attributes
    "onbeforecopy", "onbeforecut", "onbeforepaste", "onfocusin", "onfocusout",
    "onfullscreenchange", "onfullscreenerror", "oninputsourceschange", "onsearch",
    "onselectionchange", "onselectstart", "onshow", "onwebkitfullscreenchange",
    "onwebkitfullscreenerror",  # ("ontoggle" listed once, with the HTML LS block above)
})


_ON_SHAPED_ATTRIBUTE = re.compile(r"on[a-z]+\Z")


def _rindex(seq: list[str], value: str) -> int:
    """Index of the LAST occurrence of ``value`` in ``seq``. Pure; the caller has
    already checked membership."""
    return len(seq) - 1 - seq[::-1].index(value)


def _js_scan(script_text: str, idx: int) -> tuple[bool, str]:
    """Walk ``script_text`` up to ``idx`` and report
    ``(at_code_position, ambiguity)``.

    ``at_code_position`` is True iff offset ``idx`` is NOT inside a string literal,
    template literal or comment. It is meaningful ONLY when ``ambiguity`` is the
    empty string.

    ``ambiguity`` names the first construct this deliberately-small, pure,
    stdlib-only lexer does NOT model. The caller MUST fail closed on it.

    RED-PEN B1 (the reason this function exists in this shape). The previous
    version claimed "every misparse biases toward NOT-code → NOT-firing. The
    failure direction is a missed detection, never a manufactured FACT". That was
    FALSE, and reproduced in five shapes. The lexer had no regex-literal state, so
    ``/it's/`` opened a PHANTOM single-quote state, and the OPENING quote of the
    NEXT real string CLOSED it — leaving the real string's CONTENTS at apparent
    code position. One quote of desync manufactures a High ``xss`` FACT at 0.90 on
    a CORRECTLY ESCAPED page. The same one-quote desync is reachable through
    Annex B ``<!--`` / ``-->`` (SingleLineHTMLOpenComment / HTMLCloseComment, which
    a browser lexes as line comments inside a classic script) and through a
    template-literal substitution ``${…}`` whose body contains a quote or a nested
    backtick.

    So the lexer no longer guesses. Each unmodelled construct encountered BEFORE
    the marker offset aborts the walk with an ``ambiguity`` name:

      ``regex_literal``          a ``/`` at apparent code position that is not
                                 ``//`` or ``/*`` — a regex literal or a division,
                                 and this lexer cannot tell which;
      ``html_comment``           ``<!--`` or ``-->`` anywhere before the marker;
      ``template_substitution``  a ``${`` inside a template literal;
      ``hashbang``               a ``#!`` at apparent code position that is NOT at
                                 offset 0 (see below).

    AUDIT-B3 — the HashbangComment. ``#!`` at offset 0 of a script's source text is
    a comment running to the end of the first line (ECMA-262 § Hashbang Comments;
    ``node -e`` and Chromium agree). The lexer had no state for it, found no
    ambiguity, and reported the first line as CODE POSITION — measured firing at
    0.90 on ``<script>#! …</script>`` that Chromium does not execute at all. That is
    the same class B1's fail-closed design exists to eliminate, so it is modelled
    here rather than merely refused:

      * at offset 0 the walk skips to the first line terminator — EXACT, so a
        marker on the hashbang line is correctly "not code" and a marker after it
        is still adjudicated normally (no capability lost);
      * anywhere else ``#!`` at code position is a SyntaxError, so the whole script
        fails to parse and NOTHING executes — the lexer refuses rather than
        silently call the surrounding text code.

    A ``#!`` inside a string literal (``var r = "#!/users"`` — the legacy hashbang
    routing shape) is in string state and is not reached by either rule, so this
    costs no real detection; measured.

    A missed detection is an INCONCLUSIVE advisory and recoverable. A manufactured
    FACT is not. Pure and deterministic."""
    n = len(script_text)
    stop = min(idx, n)
    head = script_text[:stop]
    # Annex B HTML-like comments are lexed by a real JS engine as line comments;
    # this lexer does not model them at all, so their mere PRESENCE before the
    # marker is ambiguity. Checked as a substring (not gated on lexer state)
    # because the HTML tokenizer's script-data-escaped states react to ``<!--``
    # irrespective of JS string context.
    if "<!--" in head or "-->" in head:
        return False, "html_comment"

    state: str | None = None   # None | "'" | '"' | "`" | "//" | "/*"
    i = 0
    # AUDIT-B3: a HashbangComment is legal ONLY at offset 0 and runs to the first
    # line terminator. Modelled exactly. (Only \n and \r are treated as
    # terminators, matching the "//" state below: recognising fewer terminators
    # extends the comment, which is the NON-FIRING direction.)
    if script_text.startswith("#!"):
        j = 2
        while j < n and script_text[j] not in ("\n", "\r"):
            j += 1
        if stop <= j:
            return False, ""       # the marker sits INSIDE the hashbang comment
        i = j
    while i < stop:
        c = script_text[i]
        if state is None:
            if c in ("'", '"', "`"):
                state = c
            elif c == "#" and i + 1 < n and script_text[i + 1] == "!":
                # AUDIT-B3: `#!` away from offset 0 is a SyntaxError — the script
                # never runs, so "code position" is not a claim this lexer may
                # make. FAIL CLOSED. (`#x` private names are untouched.)
                return False, "hashbang"
            elif c == "/":
                nxt = script_text[i + 1] if i + 1 < n else ""
                if nxt == "/":
                    state = "//"
                    i += 1
                elif nxt == "*":
                    state = "/*"
                    i += 1
                else:
                    # A regex literal or a division — indistinguishable without a
                    # full token stream. FAIL CLOSED.
                    return False, "regex_literal"
        elif state in ("'", '"'):
            if c == "\\":
                i += 1
            elif c == state:
                state = None
        elif state == "`":
            if c == "\\":
                i += 1
            elif c == "$" and i + 1 < n and script_text[i + 1] == "{":
                # A substitution's body is CODE (it may contain strings, nested
                # template literals and regexes). Not modelled → FAIL CLOSED.
                return False, "template_substitution"
            elif c == "`":
                state = None
        elif state == "//":
            if c in ("\n", "\r"):
                state = None
        elif state == "/*":
            if c == "*" and i + 1 < n and script_text[i + 1] == "/":
                state = None
                i += 1
        i += 1
    return state is None, ""


class _ReflectionScanner(HTMLParser):
    """Locate a marker's parse context with stdlib HTML parsing, and decide whether
    the payload PROVABLY BROKE OUT into that position (see the module note above).

    ``context`` is set only for a proven breakout (``html_tag`` / ``js_attribute:…``
    / ``script``). ``advisory`` records the strongest NON-proving observation — the
    marker was seen in/near an executable position but as escaped DATA the page put
    there, which is not a breakout."""

    def __init__(self, marker_lower: str) -> None:
        super().__init__(convert_charrefs=True)
        self._ml = marker_lower
        self._in_script = False
        self._script_executable = False
        # RED-PEN B2: per the HTML spec a <script> that bears a `src` IGNORES its
        # child text entirely — the element's inline content never runs. The old
        # `_script_executable` looked only at `type`, so
        # `<script src="/app.js">MARKER();</script>` fired at 0.90 on text no
        # browser evaluates.
        self._script_has_src = False
        # AUDIT-B2: `nomodule` makes a CLASSIC script non-executing.
        self._script_nonexec_reason = ""
        # RED-PEN B1: the JS lexer starts from a known state only at the FIRST data
        # chunk of a script element. If HTMLParser ever splits a script's text, a
        # later chunk begins mid-token and "code position" is unknowable — so a
        # continuation chunk is ambiguity, never a breakout.
        self._script_chunk = 0
        self._inert_depth = 0
        # AUDIT-B1: the innermost open inert container, so the advisory can NAME it.
        self._inert_tags: list[str] = []
        self.context: str | None = None
        self.detail: str = ""
        self.advisory: str | None = None
        self.advisory_detail: str = ""

    # -- advisory bookkeeping ------------------------------------------------

    def _note(self, kind: str, detail: str = "") -> None:
        if self.advisory is None:
            self.advisory, self.advisory_detail = kind, detail

    # -- parser callbacks ----------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "script":
            # AUDIT-B2: keep the RAW `type` value — the LS distinguishes the raw
            # empty string (classic) from a whitespace-only one (a data block), and
            # the essence match forbids parameters. No `.split(";")`, no pattern.
            raw_type: str | None = None
            has_src = False
            has_nomodule = False
            # HTML DUPLICATE-ATTRIBUTE FIRST-WINS: the tokenizer keeps the FIRST occurrence of an attribute
            # name and DISCARDS every later one, so `<script type="application/json" type="text/javascript">`
            # is a DATA block to Chromium — the FIRST `type` (a JSON essence) wins, not the executable one.
            # Take the first `type` only (`raw_type is None` == "not yet seen"). `has_src` / `has_nomodule`
            # are presence flags, so which duplicate wins does not change them.
            for name, val in attrs:
                lname = name.lower()
                if lname == "type" and raw_type is None:
                    raw_type = val if val is not None else ""
                elif lname == "src":
                    has_src = True
                elif lname == "nomodule":
                    has_nomodule = True
            self._in_script = True
            executable, reason = _script_is_executable(raw_type, has_nomodule)
            self._script_executable = executable
            self._script_nonexec_reason = reason
            self._script_has_src = has_src
            self._script_chunk = 0
        if t in _INERT_TEXT_CONTAINERS:
            self._inert_depth += 1
            self._inert_tags.append(t)
        if self.context is not None:
            return

        inert = self._inert_depth > 0
        if self._ml in t:
            if inert:
                self._note("inert_text_container", t)
            else:
                self.context, self.detail = "html_tag", tag
            return
        # HTML DUPLICATE-ATTRIBUTE FIRST-WINS (the same tokenizer rule as the <script> `type` above): once an
        # attribute NAME has been seen on this tag the tokenizer discards every later occurrence, so it never
        # reaches Chromium. `<div onclick="void 0" onclick="MARKER">` runs `void 0` (the FIRST onclick) and
        # `<a href="#" href="javascript:MARKER">` navigates `#` (the FIRST href) — the marker in the SECOND
        # occurrence is inert. The name is recorded on first sight, BEFORE the marker filter, so a duplicate
        # is dropped even when the first occurrence carried no marker; refusing it kills FACTs Chromium would
        # never execute.
        seen_attr_names: set[str] = set()
        for name, val in attrs:
            a = name.lower()
            if a in seen_attr_names:
                continue
            seen_attr_names.add(a)
            v = val or ""
            if self._ml not in v.lower():
                continue
            stripped = v.strip()
            # RED-PEN B2: membership of the CLOSED event-handler set, never an
            # `on` prefix (`on-click` / `once` / `online` are not handlers).
            is_handler = a in _EVENT_HANDLER_ATTRIBUTES
            is_js_url = (a in ("href", "src", "action", "formaction")
                         and stripped.lower().startswith("javascript:"))
            if not (is_handler or is_js_url):
                # AUDIT-B4 — a CLOSED-SET MISS MUST NOT FALL THROUGH TO "CLEAN".
                # The comment on `_EVENT_HANDLER_ATTRIBUTES` promises a miss is "a
                # non-firing advisory — recoverable". Without this branch it was
                # not: nothing called `_note`, so the scan reached the terminal
                # `conclusive=True` return and `probe_verdict` certified the probe
                # CLEAN. Measured on `oncontentvisibilityautostatechange`, a real
                # Chromium-executed handler: a true positive became a
                # channel-confirmed clean. Any `on`-SHAPED non-member is therefore
                # an advisory. It still cannot FIRE — firing needs membership.
                if _ON_SHAPED_ATTRIBUTE.match(a):
                    if inert:
                        self._note("inert_text_container", name)
                    else:
                        self._note("unmodelled_handler_shape", name)
                continue
            if inert:
                self._note("inert_text_container", name)
                continue
            # SOUND BREAKOUT (R5): the attacker must own the WHOLE executable value.
            # A marker embedded inside a larger expression the PAGE composed
            # (``onclick="search(&quot;…marker…&quot;)"``) is the page's own handler
            # with the value correctly escaped into it — it did not break out.
            body = stripped
            if is_js_url:
                body = stripped[len("javascript:"):].strip()
            if body.lower() == self._ml:
                self.context, self.detail = f"js_attribute:{name}", name
                return
            self._note("js_attribute_data", name)

    def _close(self, t: str) -> None:
        if t == "script":
            self._in_script = False
            self._script_executable = False
            self._script_nonexec_reason = ""
            self._script_has_src = False
            self._script_chunk = 0
        if t in _INERT_TEXT_CONTAINERS and t in self._inert_tags:
            # AUDIT-B1: close back to the MATCHING open container. An UNMATCHED end
            # tag must be IGNORED, exactly as a browser ignores one — a plain
            # `self._inert_depth -= 1` let the shipped `</title><script>{marker}`
            # payload cancel an enclosing `<noscript>` that was never closed, and
            # the marker was reported live again. Chromium, measured: it is not.
            del self._inert_tags[_rindex(self._inert_tags, t):]
            self._inert_depth = len(self._inert_tags)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        # a self-closing form opens nothing, so undo the container/script bookkeeping
        self._close(tag.lower())

    def handle_endtag(self, tag: str) -> None:
        self._close(tag.lower())

    def handle_data(self, data: str) -> None:
        if not self._in_script:
            return
        chunk = self._script_chunk
        self._script_chunk += 1
        if self.context is not None:
            return
        low = data.lower()
        idx = low.find(self._ml)
        if idx < 0:
            return
        if self._inert_depth > 0:
            # AUDIT-B1 — `_inert_depth` was maintained but READ ONLY in
            # `handle_starttag`. Python's HTMLParser has RCDATA handling for
            # textarea/title/iframe/xmp, so those were ACCIDENTALLY safe — but NOT
            # for <noscript> (with scripting enabled the HTML LS gives its start tag
            # the generic RAW TEXT algorithm) or <template> (whose contents live in
            # an inert DocumentFragment). So a nested <script> inside either was
            # reported live. Measured: `<noscript><script>M</script></noscript>` and
            # the <template> twin both fired 0.90 ctx=script; Chromium executes
            # NEITHER, and six SHIPPED m2 payloads minted a High/0.9 xss FACT
            # end-to-end through `confirm_finding`.
            self._note("inert_text_container",
                       self._inert_tags[-1] if self._inert_tags else "script")
            return
        if not self._script_executable:
            # <script type="application/json"> and friends: a DATA block the browser
            # never executes. Django's json_script emits exactly this. AUDIT-B2 adds
            # the `nomodule` classic script and the whitespace-only `type`.
            self._note(self._script_nonexec_reason or "script_data_block")
            return
        if self._script_has_src:
            # RED-PEN B2: a `src`-bearing <script> never evaluates its child text.
            self._note("script_src_ignored_body")
            return
        if chunk:
            # RED-PEN B1: a continuation chunk starts mid-token — fail closed.
            self._note("script_lexer_ambiguous", "split_script_text")
            return
        code, ambiguity = _js_scan(data, idx)
        if ambiguity:
            # RED-PEN B1 — FAIL CLOSED ON LEXER AMBIGUITY. A regex literal, an
            # Annex B `<!--`/`-->` comment or a template substitution before the
            # marker desyncs this lexer by one quote, which is enough to report a
            # STRING's contents as code. Downgrade to a non-firing, non-conclusive
            # advisory rather than mint a FACT the page does not support.
            self._note("script_lexer_ambiguous", ambiguity)
            return
        if code:
            self.context, self.detail = "script", "script"
        else:
            # F4: inside a string literal / template literal / comment — the value
            # cannot terminate the element or the literal, so no breakout is proven.
            self._note("script_string_literal")


def reflection_context_oracle(marker: str, observed_sink: Any) -> OracleSignal:
    """Fire only when the reflected marker PROVABLY BROKE OUT into a live,
    executable position — never merely because the marker substring is present
    somewhere executable-looking.

    Substring-presence (what ``side_effect_oracle`` and most DAST use for XSS)
    over-reports: a marker reflected inside an HTML-encoded attribute, a comment,
    or plain text is inert. So does "the marker is somewhere inside a ``<script>``"
    or "somewhere inside an ``on*`` value" — the audited F4/R5 false positives,
    which a CORRECTLY escaped page (Django ``json_script``, a ``&quot;``-escaped
    handler) reproduces on demand. The response is PARSED (stdlib, no third-party
    dependency) and a signal fires ONLY for a proven breakout:

      * ``html_tag``     — the marker is (part of) a TAG NAME: the payload created
        an element (0.95);
      * ``js_attribute`` — the marker is the ENTIRE value of an event-handler
        attribute, or the entire body of a ``javascript:`` URL: the attacker owns
        the whole handler (0.90);
      * ``script``       — the marker sits at CODE position (outside every string
        literal, template literal and comment) inside a script the browser actually
        EXECUTES (``type`` absent or a JS MIME) (0.90).

    Anything weaker — a marker inside a JS string literal, inside a handler
    expression the page composed, inside a ``type="application/json"`` data block,
    or inside a raw-text container (``<noscript>``/``<textarea>``/…) — is returned
    as a NON-FIRING, NON-CONCLUSIVE advisory: not a FACT, and not a clean bill of
    health either. A fully encoded / text-only reflection is the one decisive
    negative (``conclusive=True``).

    SCOPE: this oracle proves a reflection reached a LIVE / EXECUTABLE POSITION.
    It does NOT prove EXECUTION — that is the DOM_EXECUTION oracle's claim, and no
    evidence string here may be read as one."""
    marker = (marker or "").strip()
    body = observed_sink if isinstance(observed_sink, str) else _searchable(observed_sink)
    if len(marker) < 4:
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
            evidence="marker too short to be a reliable canary", observed={"marker": marker})
    ml = marker.lower()
    if ml not in body.lower():
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
            evidence=f"marker {marker!r} not reflected", observed={"marker": marker})

    scanner = _ReflectionScanner(ml)
    try:
        scanner.feed(body)
        scanner.close()
    except Exception:
        scanner.context = None

    if scanner.context == "html_tag":
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.95,
            evidence=(f"marker became the TAG NAME of a live element <{scanner.detail}> — the payload "
                      f"broke out into markup (injection into an executable position PROVEN; this "
                      f"oracle does not prove execution)"),
            observed={"marker": marker, "context": "html_tag", "tag": scanner.detail})
    if scanner.context == "script":
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.9,
            evidence=("marker sits at CODE position inside an executable <script> — outside every string "
                      "literal, template literal and comment, so the payload broke out of the data "
                      "position (injection into an executable position PROVEN; this oracle does not "
                      "prove execution)"),
            observed={"marker": marker, "context": "script"})
    if scanner.context and scanner.context.startswith("js_attribute"):
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=True, confidence=0.9,
            evidence=(f"marker is the ENTIRE value of executable attribute {scanner.detail!r} — the "
                      f"attacker supplied the whole handler / javascript: URL body (injection into an "
                      f"executable position PROVEN; this oracle does not prove execution)"),
            observed={"marker": marker, "context": scanner.context})

    if scanner.advisory is not None:
        # AUDIT F4/R5 — NON-FIRING ADVISORY. The marker was seen in or beside an
        # executable position, but as DATA the page itself placed there; no breakout
        # is proven. NOT conclusive either: an escaping bug this parse cannot see
        # could still make it executable, so the honest verdict is "UNRESOLVED —
        # needs an execution-proving oracle, run by an operator" (no automatic
        # handoff exists; see the module note), never "clean" and never a FACT.
        _ADVISORY_EVIDENCE = {
            "script_string_literal":
                "marker is inside a JS STRING LITERAL / template literal / comment in an executable "
                "<script> — it cannot terminate the literal or the element from this parse, so NO "
                "breakout is proven (the Django json_script / Rails json_escape shape). ADVISORY ONLY",
            "script_data_block":
                "marker is inside a <script> the browser does NOT execute (type is a data MIME such as "
                "application/json) — NO breakout is proven. ADVISORY ONLY",
            "js_attribute_data":
                f"marker is EMBEDDED IN a larger expression in attribute {scanner.advisory_detail!r} that "
                "the PAGE composed (e.g. a correctly &quot;-escaped handler argument) — the attacker does "
                "not own the value, so NO breakout is proven. ADVISORY ONLY",
            "inert_text_container":
                f"marker reached {scanner.advisory_detail!r} inside a raw-text container "
                "(<noscript>/<textarea>/<title>/<template>/…) whose content a browser does not parse as "
                "live markup — NO breakout is proven. ADVISORY ONLY",
            "script_src_ignored_body":
                "marker is inside a <script> that bears a `src` attribute — per the HTML spec such an "
                "element IGNORES its child text, so the reflected bytes are never evaluated and NO "
                "breakout is proven. ADVISORY ONLY",
            "script_nomodule_ignored":
                "marker is inside a CLASSIC <script> bearing `nomodule` — 'prepare the script element' "
                "returns early for it, so a module-supporting browser never evaluates the element and NO "
                "breakout is proven (measured inert in Chromium 150). ADVISORY ONLY",
            "unmodelled_handler_shape":
                f"marker is in attribute {scanner.advisory_detail!r}, which has the SHAPE of an HTML "
                "event-handler content attribute but is NOT in this oracle's closed, measured set of "
                "handlers — so whether a browser would execute it is UNKNOWN to this oracle. It does not "
                "fire (firing needs membership) and it is explicitly NOT a clean bill of health. "
                "ADVISORY ONLY",
            "script_lexer_ambiguous":
                f"marker is inside an executable <script> whose text contains "
                f"{scanner.advisory_detail!r} before the marker — a construct this lexer does not model "
                "(regex literal vs division, an Annex B <!-- / --> comment, a template substitution, a "
                "misplaced hashbang, or split script text). The code-vs-string verdict is therefore "
                "UNKNOWN, and this oracle FAILS CLOSED rather than risk reporting a string literal as "
                "code. ADVISORY ONLY — this verdict is UNRESOLVED, not clean. NOTE: nothing in this "
                "engine schedules a follow-up probe on this advisory; resolving it requires an operator "
                "to run an execution-proving oracle by hand (wiring that handoff is tracked, not shipped)",
        }
        return OracleSignal(
            kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
            conclusive=False,
            evidence=_ADVISORY_EVIDENCE.get(
                scanner.advisory, "marker in a non-proving position. ADVISORY ONLY"),
            observed={"marker": marker, "context": scanner.advisory,
                      "detail": scanner.advisory_detail, "advisory": True})

    return OracleSignal(
        kind=OracleKind.REFLECTION_CONTEXT, fired=False, confidence=0.0,
        # CHANNEL-CONFIRMED NEGATIVE: the marker WAS reflected (`ml in body` above),
        # so the payload provably reached the response sink — and it landed only in an
        # inert/encoded position. That is a decisive "reflected-but-neutralised" clean,
        # unlike the "not reflected" branch above (no channel → non-conclusive/inconclusive).
        conclusive=True,
        evidence="marker reflected but NOT in an executable context (encoded/inert)",
        observed={"marker": marker, "context": "inert"})


def evaluation_oracle(
    raw_expr: str,
    expected_result: str,
    observed_body: Any,
    control_body: Any = None,
) -> OracleSignal:
    """Fire when an injected expression was **evaluated** by the server, not
    merely reflected — the signature of server-side template / expression-language
    injection (Jinja2/Twig/Freemarker/Velocity/ERB/Smarty/Mako/Thymeleaf, EL).

    The proof is deliberately strict, because "reflected" and "evaluated" look
    identical unless you separate them:

      1. the ``expected_result`` (what ``raw_expr`` computes to, e.g. ``31337*31337
         -> 981538969``) appears in the response, AND
      2. the ``raw_expr`` itself (``{{31337*31337}}``) does NOT appear — if the
         raw template text survives, the input was reflected verbatim, not
         evaluated, so this is NOT SSTI, AND
      3. when a benign ``control_body`` is supplied, the ``expected_result`` does
         NOT occur in it — so a value that merely happens to be on the page can
         never be mistaken for an evaluation.

    Use a distinctive arithmetic result (a large product, not ``7*7=49``) so the
    expected value cannot coincidentally appear. A reflected-but-unevaluated
    payload, an encoded payload, or a benign page all correctly do NOT fire."""
    raw = (raw_expr or "").strip()
    expected = (expected_result or "").strip()
    body = _coerce_text(observed_body)

    if len(expected) < 2:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence="expected evaluation result too short to be a reliable marker",
            observed={"expected": expected})

    if expected not in body:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"evaluated result {expected!r} not present; expression was not evaluated",
            observed={"expected": expected, "raw_present": raw in body})

    if raw and raw in body:
        # The literal template text survived — reflection, not evaluation.
        # CHANNEL-CONFIRMED NEGATIVE: the raw expression provably reached the response
        # sink and was rendered as inert text (not computed), so this is a decisive
        # "reached-but-not-evaluated" clean — distinct from the "result absent" branch
        # above (a blind/second-order sink where nothing was observed → inconclusive).
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0, conclusive=True,
            evidence=f"raw expression {raw!r} reflected verbatim — reflected, not evaluated",
            observed={"expected": expected, "raw_present": True})

    if control_body is not None and expected in _coerce_text(control_body):
        # The "result" is just part of the page regardless of the payload.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"result {expected!r} also present in the benign control — not attributable to evaluation",
            observed={"expected": expected})

    idx = body.find(expected)
    snippet = body[max(0, idx - 24): idx + len(expected) + 24]
    return OracleSignal(
        kind=OracleKind.EVALUATION,
        fired=True,
        confidence=0.95,
        evidence=f"expression {raw!r} evaluated to {expected!r} server-side: ...{snippet}...",
        observed={"expected": expected, "raw": raw, "snippet": snippet},
    )


_SSI_DIRECTIVE_RE = re.compile(r"<!--#\s*[A-Za-z]+\b[^>]*-->", re.DOTALL)


def ssi_evaluation_oracle(
    raw_directive: str,
    expected_result: str,
    observed_body: Any,
    control_body: Any = None,
) -> OracleSignal:
    """Fire when an injected **Server-Side Include (SSI) directive was EVALUATED** by the
    server — the arithmetic it carries was COMPUTED and its product emitted — not merely
    reflected (CWE-97: Improper Neutralization of Server-Side Includes).

    The same strict computed-product proof the SSTI/EL :func:`evaluation_oracle` uses,
    specialised to SSI so it can never be confused with a template-expression evaluation and so
    a page that merely echoes the directive as an inert HTML comment never fires:

      1. ``raw_directive`` must be a well-formed SSI directive (``<!--#…-->``) — a payload that is
         not an SSI directive is not an SSI probe and never fires here (keeps the class distinct);
      2. the ``expected_result`` — the PER-PROBE product ``N1*N2``, unguessable and unable to
         pre-exist — appears in the response, AND
      3. the raw directive does NOT survive verbatim: if ``<!--#…-->`` is echoed back unchanged the
         include was NOT processed (SSI disabled / reflected as an inert comment), which is the
         honest boundary — reflected, not evaluated — and a CHANNEL-CONFIRMED clean, AND
      4. when a benign ``control_body`` is supplied, the product does NOT occur in it — so a value
         that merely happens to be on the page can never be mistaken for an evaluation.

    Use a distinctive per-probe random product (a large ``N1*N2``, never ``7*7``) so the expected
    value cannot coincidentally appear. A reflected-but-unevaluated directive, an escaped payload,
    or a benign page all correctly do NOT fire."""
    raw = (raw_directive or "").strip()
    expected = (expected_result or "").strip()
    body = _coerce_text(observed_body)

    if len(expected) < 2:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence="expected SSI evaluation result too short to be a reliable marker",
            observed={"expected": expected})

    if not _SSI_DIRECTIVE_RE.search(raw):
        # Not a genuine SSI directive — nothing SSI-specific to adjudicate. NON-conclusive: the
        # probe never carried an include directive, so this says nothing about the target.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"payload {raw!r} is not a well-formed SSI directive (<!--#…-->) — not an SSI probe",
            observed={"raw": raw})

    if expected not in body:
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"computed product {expected!r} not present; the SSI directive was not evaluated",
            observed={"expected": expected, "raw_present": raw in body})

    if raw and raw in body:
        # The literal SSI directive survived verbatim — SSI is disabled and the directive was echoed
        # as an inert HTML comment. CHANNEL-CONFIRMED NEGATIVE: the directive provably reached the
        # response sink and was NOT processed (reflected, not evaluated) — the honest boundary, a
        # decisive "reached-but-not-evaluated" clean, distinct from the "product absent" blind branch.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0, conclusive=True,
            evidence=f"SSI directive {raw!r} reflected verbatim as an inert comment — reflected, not evaluated",
            observed={"expected": expected, "raw_present": True})

    if control_body is not None and expected in _coerce_text(control_body):
        # The "product" is on the page regardless of the directive — not attributable to evaluation.
        return OracleSignal(
            kind=OracleKind.EVALUATION, fired=False, confidence=0.0,
            evidence=f"product {expected!r} also present in the benign control — not attributable to SSI evaluation",
            observed={"expected": expected})

    idx = body.find(expected)
    snippet = body[max(0, idx - 24): idx + len(expected) + 24]
    return OracleSignal(
        kind=OracleKind.EVALUATION,
        fired=True,
        confidence=0.95,
        evidence=f"SSI directive {raw!r} evaluated to {expected!r} server-side: ...{snippet}...",
        observed={"expected": expected, "raw": raw, "snippet": snippet, "ssi": True},
    )


_MIN_CANARY_LEN = 16


_MIN_CANARY_ENTROPY_BITS_PER_CHAR = 2.5


def _shannon_bits_per_char(s: str) -> float:
    """Shannon entropy of ``s`` in bits/char (pure). A random base62/hex sentinel clears
    ~4-6; a repeated char ("aaaa…") is 0; an English phrase is ~1-2."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def system_prompt_disclosure_oracle(canary: str, llm_output: Any) -> OracleSignal:
    """Fire when a PLANTED high-entropy canary sentinel appears VERBATIM in the app's own
    LLM output — proof the secret LEAKED (system-prompt disclosure). The defensive dual of
    ``side_effect_oracle``: the operator plants a random sentinel in the system prompt out
    of band; if the model's response echoes it, the secret provably crossed the boundary.

    Honest scope (doctrine fix P2): this proves DISCLOSURE, not that an *injection* caused
    it — a benign "repeat your instructions" or the app's own debug path echoes the same
    sentinel. ``prompt_injection`` (control-vs-treatment behavior delta) is the separate,
    stronger oracle that earns the adversarial-cause label. The sentinel must be
    >= 16 chars AND >= 2.5 bits/char so a substring match cannot be coincidental."""
    sentinel = (canary or "").strip()
    haystack = llm_output if isinstance(llm_output, str) else _searchable(llm_output)
    if len(sentinel) < _MIN_CANARY_LEN:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence=f"canary too short (< {_MIN_CANARY_LEN} chars) to be collision-resistant",
            observed={"canary_len": len(sentinel)})
    if _shannon_bits_per_char(sentinel) < _MIN_CANARY_ENTROPY_BITS_PER_CHAR:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence="canary entropy too low — not a collision-resistant random sentinel",
            observed={"canary_len": len(sentinel)})
    idx = haystack.find(sentinel)
    if idx < 0:
        return OracleSignal(
            kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=False, confidence=0.0,
            evidence="planted canary not present in LLM output — no disclosure",
            observed={"canary_len": len(sentinel)})
    # Bounded, redacted human-readable span: reveal only a short window around the hit and
    # MASK the sentinel itself in the evidence string. (PR1: the retained oracle_context
    # still holds the verbatim sentinel + output so the certificate re-fires offline — the
    # reverify contract requires verbatim substrings; documented, not hashes-only.)
    start = max(0, idx - 16)
    end = min(len(haystack), idx + len(sentinel) + 16)
    redacted_span = haystack[start:idx] + "<canary>" + haystack[idx + len(sentinel):end]
    return OracleSignal(
        kind=OracleKind.SYSTEM_PROMPT_DISCLOSURE, fired=True, confidence=0.95,
        evidence=f"planted canary disclosed in the app's LLM output: ...{redacted_span}...",
        observed={"offset": idx, "canary_len": len(sentinel), "redacted_span": redacted_span})


def _pi_behavior(obs: Any) -> dict[str, Any]:
    """Normalise one structurally-detectable LLM behavior observation to the three fields
    the control-vs-treatment delta compares. Total + deterministic."""
    if isinstance(obs, Mapping):
        tool = obs.get("tool")
        return {
            "tool": str(tool).strip().lower() if tool not in (None, "") else None,
            "refused": bool(obs.get("refused", False)),
            "boundary_token_echoed": bool(obs.get("boundary_token_echoed", False)),
        }
    return {"tool": None, "refused": False, "boundary_token_echoed": False}


def prompt_injection_oracle(pi_control: Any, pi_treatment: Any) -> OracleSignal:
    """Fire ONLY when an injected directive PROVABLY flipped a structurally-detectable
    behavior in the treatment turn vs a CLEAN control turn — the honest, strong proof of
    prompt injection (doctrine fix P2). Structurally the ``evaluation_oracle``'s control-
    vs-treatment discipline: the effect present in treatment, absent in the control that
    omits the attacker directive (everything else held fixed).

    It fires on a BEHAVIOR DELTA, never on structural-override markers alone (those stay
    LEADs — users legitimately paste "ignore the above"):
      1. refusal flipped — the clean control refused, the attacker turn complied;
      2. coerced tool — treatment selected a sensitive tool the clean control did not;
      3. boundary breakout — the model echoed the instruction/data boundary token only
         under the injected directive.
    Same retained (control, treatment) -> same verdict, re-runnable offline."""
    control = _pi_behavior(pi_control)
    treatment = _pi_behavior(pi_treatment)

    deltas: list[str] = []
    if control["refused"] and not treatment["refused"]:
        deltas.append("refusal flipped to compliance under the injected directive")
    if treatment["tool"] and treatment["tool"] != control["tool"]:
        deltas.append(f"injected directive coerced tool {treatment['tool']!r} the clean control did not select")
    if treatment["boundary_token_echoed"] and not control["boundary_token_echoed"]:
        deltas.append("instruction/data boundary token echoed only under the injected directive")

    if not deltas:
        return OracleSignal(
            kind=OracleKind.PROMPT_INJECTION, fired=False, confidence=0.0,
            evidence="no structurally-detectable behavior change vs the clean control — "
                     "markers alone do not confirm prompt injection",
            observed={"control": control, "treatment": treatment})
    return OracleSignal(
        kind=OracleKind.PROMPT_INJECTION, fired=True, confidence=0.9,
        evidence="prompt injection confirmed by a control-vs-treatment behavior delta: " + "; ".join(deltas),
        observed={"control": control, "treatment": treatment, "deltas": deltas})


_SANITIZER_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"ERROR:\s*AddressSanitizer"), "asan", 0.95),
    (re.compile(r"AddressSanitizer:\s*(DEADLYSIGNAL|SEGV|heap-|stack-|global-)"), "asan", 0.95),
    (re.compile(r"(heap|stack|global)-buffer-overflow"), "asan", 0.9),
    (re.compile(r"heap-use-after-free|use-after-free"), "asan", 0.92),
    (re.compile(r"WARNING:\s*MemorySanitizer"), "msan", 0.9),
    (re.compile(r"WARNING:\s*ThreadSanitizer|data race"), "tsan", 0.88),
    (re.compile(r"runtime error:.*(overflow|out of bounds|null pointer|misaligned)"), "ubsan", 0.85),
    (re.compile(r"UndefinedBehaviorSanitizer"), "ubsan", 0.85),
    (re.compile(r"LeakSanitizer|detected memory leaks"), "lsan", 0.75),
    (re.compile(r"\*\*\* stack smashing detected \*\*\*"), "stack-protector", 0.9),
    (re.compile(r"double free or corruption|malloc\(\): |free\(\): "), "glibc-abort", 0.85),
    (re.compile(r"thread '.*' panicked at"), "rust-panic", 0.85),
    (re.compile(r"^panic:", re.MULTILINE), "go-panic", 0.8),
    (re.compile(r"Segmentation fault|SIGSEGV|SIGABRT|core dumped"), "signal", 0.8),
    (re.compile(r"Traceback \(most recent call last\):"), "py-traceback", 0.65),
]


def sanitizer_signal_oracle(process_output: Any) -> OracleSignal:
    """Scan captured stdout/stderr for sanitizer, panic, abort and traceback
    markers. A single unambiguous crash marker fires; a bare Python traceback
    fires only at moderate confidence (it can be an ordinary handled error)."""
    text = _coerce_text(process_output)
    matches: list[dict[str, Any]] = []
    for pattern, label, conf in _SANITIZER_PATTERNS:
        m = pattern.search(text)
        if m:
            line = _line_of(text, m.start())
            matches.append({"label": label, "confidence": conf,
                            "match": m.group(0), "line": line})

    if not matches:
        return OracleSignal(
            kind=OracleKind.SANITIZER_SIGNAL, fired=False, confidence=0.0,
            evidence="no sanitizer/crash/panic marker in output", observed={})

    best = max(matches, key=lambda x: x["confidence"])
    return OracleSignal(
        kind=OracleKind.SANITIZER_SIGNAL,
        fired=True,
        confidence=best["confidence"],
        evidence=f"{best['label']} marker: {best['line'].strip()[:200]}",
        observed={"matches": matches, "best": best["label"]},
    )


def _line_of(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start: end if end >= 0 else len(text)]


_PP_KEY_RE = re.compile(r"^cpp_[0-9a-f]{8,}$")   # VIGIL per-probe pollution-KEY canary (scanner.proto_pollution mints cpp_<token_hex>)


_PP_VAL_RE = re.compile(r"^ppv_[0-9a-f]{8,}$")   # VIGIL per-probe pollution-VALUE canary (ppv_<token_hex>)


def prototype_pollution_oracle(observed: Any) -> OracleSignal:
    """Fire when a real headless DOM's ACHIEVED runtime state proves client-side prototype
    pollution: ``Object.prototype[uniqKey] === uniqVal`` for the unique per-probe key/value a
    ``__proto__[uniqKey]=uniqVal`` gadget drove in, AND a BENIGN-KEY control (a different key
    that was NEVER injected) stayed ``undefined``.

    ``observed`` is the binding-reported readback a driver captured after rendering the target
    page — a mapping ``{polluted_key, polluted_val, expected_val, benign_key,
    benign_key_undefined}``. The oracle judges the ACHIEVED STATE, never that the payload merely
    appeared: a page that reflects the key into the DOM but does NOT assign it onto
    ``Object.prototype`` reports ``polluted_val`` absent/mismatched and does not fire.

    Near-zero-FP by three independent guards:
      * the key AND value must match VIGIL's own per-probe canary SHAPE (``cpp_<hex>`` /
        ``ppv_<hex>``, minted by ``scanner.proto_pollution`` via ``secrets.token_hex``). This is a
        SELF-CONTAINED guard: the oracle's standalone re-fire (its certificate) can therefore
        NEVER be satisfied by a pre-existing NAMED prototype property (``toString``,
        ``hasOwnProperty``, ``constructor``) or any arbitrary key — a match can only be the
        high-entropy marker VIGIL drove in, so soundness does not depend on the upstream caller;
      * the value must reproduce EXACTLY (``polluted_val == expected_val``) — a truthy-but-
        different value (a page that sets its own default) does not fire;
      * the BENIGN-KEY control must be ``undefined`` — if some ambient gadget polluted the
        prototype independently of this probe, ``benign_key_undefined`` is False and the oracle
        REFUSES to attribute (an ambient-pollution page does not fire).

    This is the client-side ACHIEVED-STATE FACT (CWE-1321), not a posture check: a fire means
    VIGIL observed ``Object.prototype`` actually carry the value it drove in."""
    obs = observed if isinstance(observed, Mapping) else {}
    key = _coerce_text(obs.get("polluted_key")).strip()
    expected = _coerce_text(obs.get("expected_val")).strip()
    got_raw = obs.get("polluted_val")
    got = _coerce_text(got_raw).strip() if got_raw is not None else ""
    benign_key = _coerce_text(obs.get("benign_key")).strip()
    benign_undef = obs.get("benign_key_undefined")

    base = {"polluted_key": key, "benign_key": benign_key}

    # SELF-CONTAINED SOUNDNESS: the key/value must match VIGIL's own per-probe canary SHAPE
    # (scanner.proto_pollution mints ``cpp_<hex>`` / ``ppv_<hex>``). Requiring the shape here — not
    # merely a length floor — means the oracle's STANDALONE re-fire (its certificate) cannot be
    # satisfied by a pre-existing NAMED prototype property (``toString``/``hasOwnProperty``/
    # ``constructor``) or any arbitrary key: a match can ONLY be the high-entropy marker VIGIL drove
    # in, so soundness never depends on the upstream caller being the sole key source.
    if not _PP_KEY_RE.match(key):
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("pollution key is not a VIGIL per-probe canary marker (expected cpp_<hex>) — an "
                      "arbitrary or pre-existing prototype property cannot mint this FACT"),
            observed=base)
    if not _PP_VAL_RE.match(expected):
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence="expected pollution value is not a VIGIL per-probe canary marker (expected ppv_<hex>)",
            observed=base)

    # The BENIGN-KEY control gates attribution: a different key that was NEVER injected MUST be
    # undefined. If it is not (ambient pollution, or a page that pollutes every key), refuse —
    # we cannot attribute the polluted state to THIS probe.
    if benign_undef is not True:
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("benign-key control was not undefined — cannot attribute the polluted state to this "
                      "probe (ambient / indiscriminate pollution); refusing"),
            observed={**base, "benign_key_undefined": benign_undef})

    # The ACHIEVED-STATE test: Object.prototype[key] must reproduce the exact value driven in.
    if got_raw is None or got != expected:
        return OracleSignal(
            kind=OracleKind.PROTOTYPE_POLLUTION, fired=False, confidence=0.0,
            evidence=("Object.prototype was not polluted to the expected value (the payload may have been "
                      "reflected without polluting the prototype); did not fire"),
            observed={**base, "expected_val": expected, "observed_val": got})

    return OracleSignal(
        kind=OracleKind.PROTOTYPE_POLLUTION,
        fired=True,
        confidence=0.96,
        evidence=(f"Object.prototype.{key} was polluted to {expected!r} in a real DOM "
                  f"(benign-key control {benign_key!r} stayed undefined)"),
        observed={"polluted_key": key, "polluted_val": expected, "benign_key": benign_key,
                  "benign_key_undefined": True},
    )


_ERROR_SIGNATURES: list[tuple[re.Pattern[str], str, float]] = [
    # --- SQL: MySQL / MariaDB ---
    (re.compile(r"You have an error in your SQL syntax", re.I), "mysql", 0.95),
    (re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.I), "mysql", 0.95),
    (re.compile(r"\bwarning:\s*mysqli?_", re.I), "mysql", 0.85),
    (re.compile(r"MySQLSyntaxErrorException|com\.mysql\.jdbc", re.I), "mysql", 0.9),
    (re.compile(r"valid MySQL result|Unknown column '[^']+' in 'field list'", re.I), "mysql", 0.85),
    # --- SQL: PostgreSQL ---
    (re.compile(r"PostgreSQL.*ERROR|PG::(Syntax|Undefined)|pg_query\(\)|org\.postgresql", re.I), "postgresql", 0.95),
    (re.compile(r"unterminated quoted string at or near|syntax error at or near", re.I), "postgresql", 0.9),
    # --- SQL: MSSQL ---
    (re.compile(r"Unclosed quotation mark after the character string", re.I), "mssql", 0.95),
    (re.compile(r"Microsoft SQL (Server|Native Client)|System\.Data\.SqlClient\.SqlException", re.I), "mssql", 0.92),
    (re.compile(r"Incorrect syntax near|\[SQL Server\]", re.I), "mssql", 0.9),
    # --- SQL: Oracle ---
    (re.compile(r"\bORA-\d{5}\b", re.I), "oracle", 0.95),
    (re.compile(r"Oracle.*(Driver|Database)|quoted string not properly terminated", re.I), "oracle", 0.9),
    # --- SQL: SQLite ---
    (re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite|sqlite3\.OperationalError", re.I), "sqlite", 0.92),
    (re.compile(r"unrecognized token:|SQL logic error|near \"[^\"]*\": syntax error", re.I), "sqlite", 0.88),
    # --- SQL: generic JDBC/ODBC ---
    (re.compile(r"java\.sql\.SQLException|SQLSTATE\[|ODBC.*Driver.*error", re.I), "sql-generic", 0.8),
    # --- NoSQL ---
    (re.compile(r"MongoError|E11000 duplicate key|BSONError|com\.mongodb", re.I), "mongodb", 0.85),
    # --- LDAP ---
    (re.compile(r"javax\.naming\.directory|LDAPException|Invalid DN syntax|com\.sun\.jndi\.ldap", re.I), "ldap", 0.82),
    # --- XPath ---
    (re.compile(r"XPathException|MS\.Internal\.Xml|Expression must evaluate to a node-set|xmlXPathEval", re.I), "xpath", 0.82),
]


def error_signature_oracle(observed_body: Any, control_body: Any = None) -> OracleSignal:
    """Fire when a response contains a distinctive **datastore/parser error** that
    a malformed injection payload provoked — the signature of error-based injection
    (SQL/NoSQL/LDAP/XPath).

    Two guards keep it precise: the error string must be a known, engine-specific
    signature (not a generic "error" word), AND — when a benign ``control_body`` is
    supplied — the SAME signature must be ABSENT from the control, so a page that
    always shows a stack trace cannot be mistaken for an injection. This is the
    error-based analogue of the sanitizer oracle: a real backend error is strong,
    attributable evidence the input reached and broke the query parser."""
    body = _coerce_text(observed_body)
    control = _coerce_text(control_body) if control_body is not None else ""

    for pattern, engine, conf in _ERROR_SIGNATURES:
        m = pattern.search(body)
        if not m:
            continue
        if control and pattern.search(control):
            # the same error is present without the payload -> not attributable
            continue
        line = _line_of(body, m.start())
        return OracleSignal(
            kind=OracleKind.ERROR_SIGNATURE,
            fired=True,
            confidence=conf,
            evidence=f"{engine} error provoked by the payload: {line.strip()[:200]}",
            observed={"engine": engine, "match": m.group(0)[:200]},
        )

    return OracleSignal(
        kind=OracleKind.ERROR_SIGNATURE, fired=False, confidence=0.0,
        evidence="no datastore/parser error signature in the response",
        observed={})


_WEAK_SIG_HASH_RE = re.compile(r"(?i)(?:md[245]|sha-?1(?![0-9]))")


_WEAK_SIG_OIDS = frozenset({
    "1.2.840.113549.1.1.2",   # md2WithRSAEncryption
    "1.2.840.113549.1.1.3",   # md4WithRSAEncryption
    "1.2.840.113549.1.1.4",   # md5WithRSAEncryption
    "1.2.840.113549.1.1.5",   # sha1WithRSAEncryption
    "1.2.840.10040.4.3",      # dsa-with-sha1
    "1.2.840.10045.4.1",      # ecdsa-with-SHA1
    "1.3.14.3.2.29",          # sha1WithRSASignature (legacy)
    "1.3.14.3.2.27",          # dsaWithSHA1 (legacy)
})


_MIN_RSA_DSA_BITS = 2048


_MIN_EC_BITS = 224


def weak_crypto_artifact_oracle(observed: Any) -> OracleSignal:
    """Fire when a parsed crypto artifact (an X.509 cert) is signed with a BROKEN hash — MD5/MD4/MD2 or
    SHA-1. These are collision-forgeable (MD5 chosen-prefix, SHA-1 SHAttered) with NO benign use for a
    certificate signature, so a benign modern cert (SHA-256+) does NOT fire. The proof is the retained
    signatureAlgorithm OID NAME (or dotted OID) — a pure, deterministic classification that re-verifies
    offline, exactly like ``tls_weakness_oracle`` re-verifies a negotiated cipher name. Emitted under the
    TLS_WEAKNESS kind (a weak-crypto FACT). Never raises."""
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
                            evidence="no crypto-artifact evidence")
    name = _coerce_text(observed.get("signature_algorithm")).strip()
    oid = _coerce_text(observed.get("oid")).strip()
    subject = _coerce_text(observed.get("subject")).strip()
    subj = (" " + subject) if subject else ""
    # (1) BROKEN SIGNATURE HASH — collision-forgeable, no benign use.
    if (name and _WEAK_SIG_HASH_RE.search(name)) or (oid in _WEAK_SIG_OIDS):
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.95,
            evidence=(f"certificate{subj} is signed with the BROKEN hash {name or oid} — collision-forgeable "
                      "(MD5 chosen-prefix / SHA-1 SHAttered), no benign use"),
            observed={"signature_algorithm": name, "oid": oid, "subject": subject, "reason": "broken_sig_hash"})
    # (2) UNDERSIZED PUBLIC KEY — below the ~112-bit-security floor (NIST SP 800-131A, deprecated 2013).
    key_type = _coerce_text(observed.get("key_type")).strip().lower()
    try:
        key_bits = int(observed.get("key_bits"))
    except (TypeError, ValueError):
        key_bits = 0
    if key_bits > 0 and (
            (key_type in ("rsa", "dsa") and key_bits < _MIN_RSA_DSA_BITS)
            or (key_type == "ec" and key_bits < _MIN_EC_BITS)):
        floor = _MIN_RSA_DSA_BITS if key_type in ("rsa", "dsa") else _MIN_EC_BITS
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.9,
            evidence=(f"certificate{subj} uses an UNDERSIZED {key_type.upper()} public key ({key_bits}-bit, "
                      f"below the {floor}-bit floor) — under ~112-bit security (NIST SP 800-131A, deprecated 2013)"),
            observed={"key_type": key_type, "key_bits": key_bits, "subject": subject, "reason": "short_key"})
    return OracleSignal(
        kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
        evidence=f"signature algorithm {name or oid or '?'} is not a broken hash and the key is not undersized")


_SQL_TAUT_RE = re.compile(
    r"""(?i)^(OR|AND|XOR)\b\s*\(?\s*['"]?([A-Za-z0-9_]+)['"]?\s*(?:=|<=>|\bLIKE\b)\s*['"]?([A-Za-z0-9_]+)['"]?""")


_SQL_UNION_RE = re.compile(r"(?i)^UNION\b\s+(?:ALL\s+)?SELECT\b")


_SQL_STACK_RE = re.compile(
    r"(?is)^;\s*(?:"
    r"SELECT\b.{0,120}?\bFROM\b"
    r"|INSERT\b.{0,40}?\bINTO\b"
    r"|UPDATE\b.{0,80}?\bSET\b"
    r"|DELETE\b.{0,40}?\bFROM\b"
    r"|DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER)\b"
    r"|CREATE\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|PROCEDURE)\b"
    r"|ALTER\s+(?:TABLE|DATABASE|USER|SCHEMA)\b"
    r"|TRUNCATE\s+TABLE\b"
    r"|GRANT\b.{0,80}?\bTO\b"
    r"|EXEC(?:UTE)?\b\s+\w"
    r")")


def _sql_breakout_tails(text: str, quote: str):
    """Yield the QUERY-context tail after EACH UNESCAPED `quote` in `text` (the injection point is
    `... WHERE x=<quote>PAYLOAD<quote>`, and any quote in the payload could be the break-out). Honours
    `''` doubling and `\\` escapes so a legitimately-escaped quote stays inside the literal."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            i += 2                                  # backslash-escaped char stays in the literal
            continue
        if c == quote:
            if i + 1 < n and text[i + 1] == quote:
                i += 2                              # doubled quote ('' or "") = an escaped quote
                continue
            yield text[i + 1:]                      # unescaped closing quote -> a candidate tail
        i += 1


def _sql_structure_at_start(tail: str) -> str:
    """The SQL structure PROVEN present at the START of a break-out tail, or "" — the near-zero-FP
    proofs, each ANCHORED immediately after the break-out (leading whitespace/parens skipped): a
    boolean SELF-tautology (`OR 1=1`, `OR 'a'='a'`), a `UNION [ALL] SELECT`, or a stacked statement
    with a full statement shape (`; DROP TABLE`, `; SELECT .. FROM`). A lone comment (`--`/`/*`) is
    DELIBERATELY not a proof — `'Inception' -- best film`, pasted code comments, and prose em-dashes
    after a quoted word produce it, so it was a false positive; an attacker's comment almost always
    follows a tautology/UNION we already catch. Prose after an apostrophe never matches."""
    s = tail.lstrip().lstrip("()").lstrip()
    if not s:
        return ""
    m = _SQL_TAUT_RE.match(s)
    if m and m.group(2).lower() == m.group(3).lower():
        return f"{m.group(1).upper()} tautology ({m.group(2)}={m.group(3)})"
    if _SQL_UNION_RE.match(s):
        return "UNION SELECT"
    if _SQL_STACK_RE.match(s):
        return "stacked statement"
    return ""


def sql_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff `payload`, placed inside a SQL string literal, PROVABLY closes it and introduces query
    STRUCTURE IMMEDIATELY after the break-out (a self-tautology / UNION SELECT / stacked statement /
    terminating comment). Proves a structured SQL injection ATTEMPT — never exploitation. The
    STRUCTURE must be anchored to the break-out quote, so ordinary apostrophe-bearing prose is safe:
    `O'Brien`, `it's fine`, `Don't drop the ball; I'll update you`, `I've got 5 or 6 options`,
    `credit union, please select` all have only text after the apostrophe and never fire.
    Pure/deterministic."""
    kind = OracleKind.SQL_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    if len(text) < 3 or ("'" not in text and '"' not in text):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no string-literal break-out (no quote to close the literal)",
                            observed={"param": param})
    for quote in ("'", '"'):
        for tail in _sql_breakout_tails(text, quote):
            struct = _sql_structure_at_start(tail)
            if struct:
                return OracleSignal(
                    kind=kind, fired=True, confidence=0.92,
                    evidence=(f"payload closes a {quote} SQL string literal and introduces query "
                              f"structure ({struct}) at the break-out — a structured SQL injection attempt"),
                    observed={"param": param, "quote": quote, "structure": struct, "break_out": True})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence="quote present but no SQL structure anchored to a break-out (inert prose, e.g. an apostrophe in text)",
        observed={"param": param})


_SHELL_CMDS = ("cat", "ls", "id", "whoami", "uname", "nc", "ncat", "netcat", "curl", "wget", "bash",
               "sh", "zsh", "ksh", "powershell", "pwsh", "nslookup", "dig", "cmd", "python", "python3",
               "perl", "ruby", "php", "chmod", "chown", "mkfifo", "telnet", "socat", "base64", "xxd",
               "hostname", "ifconfig", "ping", "certutil", "sleep", "rm", "kill", "env")


_CMD_ALT = "|".join(sorted(set(_SHELL_CMDS), key=lambda s: (-len(s), s)))


_SHELL_CMD_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(" + _CMD_ALT + r")(?![A-Za-z0-9_])")


_SHELL_CMD_AT_START_RE = re.compile(r"(?i)^(" + _CMD_ALT + r")(?![A-Za-z0-9_])")


_SHELL_SUBST_RE = re.compile(r"\$\(([^)]{1,300})\)|`([^`]{1,300})`")


_SHELL_SYS_DIRS = ("etc", "bin", "usr", "tmp", "var", "dev", "proc", "root", "sys", "opt", "home",
                   "sbin", "lib", "lib64", "mnt", "srv", "boot", "run", "media")


_SHELL_ARG_RE = re.compile(
    r"(?i)(?:/(?:" + "|".join(_SHELL_SYS_DIRS) + r")\b|\.\.?/|(?<=\s)-[a-z]{1,3}\b"
    r"|https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b)")


def command_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff `payload` contains an OS-command-execution construct PROVEN by a dangerous command
    invoked WITH a shell argument — inside a command substitution (`$(cat /etc/passwd)`, `` `curl
    http://evil/x` ``), or AFTER a command separator (`; cat /etc/passwd`, `| nc 10.0.0.1 4444`).
    Conservative for near-zero FP: (a) a bare command name is not a proof, so a shell argument is
    required; (b) the separator branch SKIPS the first segment (a value that merely BEGINS with a
    command word — `python-requests/2.25.1`, `id > 1000` — had no preceding separator and is benign);
    (c) `>`/`|` and `tool/version` slashes are not arguments. So `$(id)` / `` `code` `` / `dog|cat` /
    `Name | Age | ID` / `id > 1000` / `python-requests/2.25.1` do NOT fire. ReDoS-safe (split on the
    separator class). Pure/deterministic; proves an ATTEMPT, never exploitation."""
    kind = OracleKind.COMMAND_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    if len(text) < 4:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="too short to carry a command-execution construct",
                            observed={"param": param})
    # (1) command substitution wrapping a dangerous command WITH an argument. `$(...)` / backticks are
    # already a strong shell signal, so a whitespace-separated argument also suffices — `$(id)` /
    # `` `code` `` / `$(document)` do NOT fire, but `$(sleep 5)` / `$(cat /etc/passwd)` do.
    for m in _SHELL_SUBST_RE.finditer(text):
        body = m.group(1) or m.group(2) or ""
        cmd = _SHELL_CMD_RE.search(body)
        if not cmd:
            continue
        after = body[cmd.end():]
        # a command immediately followed by `=` is a key=value / assignment / URL query param
        # (`id=https://...`), NOT a command invocation — the review's header/cookie false positive.
        if after[:1] == "=":
            continue
        if _SHELL_ARG_RE.search(after) or re.match(r"\s+\S", after):
            return OracleSignal(
                kind=kind, fired=True, confidence=0.9,
                evidence=(f"shell command substitution invokes {cmd.group(1)!r} with an argument — "
                          f"a structured OS command injection attempt"),
                observed={"param": param, "construct": "substitution", "command": cmd.group(1).lower()})
    # (2) a command SEPARATOR then a dangerous command WITH a shell argument. Split on the separator
    #     class (linear, no backtracking) and inspect each segment AFTER a real separator — segment[0]
    #     had NO preceding separator, so a value that merely starts with a command word is not a proof.
    for seg in re.split(r"[;|&\n\r]", text)[1:]:
        seg = seg.strip()
        cmd = _SHELL_CMD_AT_START_RE.match(seg)
        if not cmd:
            continue
        after = seg[cmd.end():]
        # `id=https://cdn/...` (a `&`-split URL query param in a Referer/cookie) is a key=value, NOT a
        # command invocation — the review's header/cookie command-injection false positive.
        if after[:1] == "=":
            continue
        if _SHELL_ARG_RE.search(after):
            return OracleSignal(
                kind=kind, fired=True, confidence=0.9,
                evidence=(f"a command separator chains to {cmd.group(1)!r} with an argument — "
                          f"a structured OS command injection attempt"),
                observed={"param": param, "construct": "separator+command", "command": cmd.group(1).lower()})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence="no command-execution construct (a bare command name or lone metacharacter is not a proof)",
        observed={"param": param})


_NOSQL_OPERATORS: frozenset[str] = frozenset({
    "ne", "eq", "gt", "gte", "lt", "lte", "in", "nin",     # comparison
    "or", "and", "nor", "not",                              # logical
    "exists",                                              # element
    "where", "expr", "mod", "text", "jsonschema",          # evaluation
    "all", "elemmatch", "size",                            # array
})


_NOSQL_OP_ALT = "|".join(sorted(_NOSQL_OPERATORS, key=lambda s: (-len(s), s)))


_NOSQL_PARAM_OP_RE = re.compile(r"(?i)(?:^|\[)\$(" + _NOSQL_OP_ALT + r")(?=$|\])")


_NOSQL_JSON_CAP = 65536      # bound the JSON parse input on the value path (DoS-safe on adversarial input)


_NOSQL_SCAN_DEPTH = 32       # bound the recursion over a parsed JSON value (stack-safe)


def _nosql_operator_key(obj: Any, depth: int = 0) -> str:
    """The first KNOWN MongoDB operator appearing as an object KEY anywhere in a parsed JSON `obj` (to a
    bounded depth), returned WITH its `$` (e.g. ``"$ne"``), or "". Only a KEY counts — an operator as a
    string VALUE or a list element is inert (that is ordinary data / documentation, not query structure)."""
    if depth > _NOSQL_SCAN_DEPTH:
        return ""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k[:1] == "$" and k[1:].lower() in _NOSQL_OPERATORS:
                return "$" + k[1:].lower()
            hit = _nosql_operator_key(v, depth + 1)
            if hit:
                return hit
    elif isinstance(obj, list):
        for v in obj[:256]:                                 # bounded fan-out
            hit = _nosql_operator_key(v, depth + 1)
            if hit:
                return hit
    return ""


def _nosql_operator_key_in_json_text(text: str) -> str:
    """Parse ``text`` as JSON (only when it looks like a container) and return the first operator-as-key,
    or "". A non-JSON value (a price, an email, a scalar) parses to nothing here and stays inert."""
    s = text.strip()
    if s[:1] not in ("{", "[") or len(s) > _NOSQL_JSON_CAP:
        return ""
    try:
        obj = json.loads(s)
    except (ValueError, TypeError, RecursionError):
        return ""
    return _nosql_operator_key(obj)


def nosql_injection_breakout_oracle(payload: Any, *, param: str = "") -> OracleSignal:
    """Fire iff a request carries a MongoDB QUERY OPERATOR injected as a KEY where a SCALAR was expected —
    either (1) the PARAM NAME has a `$operator` as a whole BRACKET key segment (`user[$ne]`, `q[$gt]`,
    `a[b][$in]`, `$where`), which the framework nests into `{user:{$ne:…}}`; or (2) the VALUE parses to
    JSON with a `$operator` object KEY (`{"$ne":null}`). Proves a STRUCTURED NoSQL operator-injection
    ATTEMPT, never exploitation. Near-zero-FP: the token must be a KNOWN query operator (curated allowlist
    — the EJSON/JSON-Schema/DBRef `$`-keys AND the dual-use `$type`/`$regex` are excluded, since they are
    also legitimate .NET type-discriminators / EJSON regex data) AND a KEY, so a price `$5.00`, `$net`, an
    email, a regex `^admin$`, a mid-word `$` (`pass$word`), an operator as a string VALUE (`["$ne"]`), and
    a plain scalar all stay inert. Pure/deterministic; bounded; ReDoS-safe."""
    kind = OracleKind.NOSQL_INJECTION_BREAKOUT
    text = payload if isinstance(payload, str) else str(payload if payload is not None else "")
    name = param if isinstance(param, str) else str(param if param is not None else "")
    # (1) the PARAM NAME injects an operator as a nested bracket/dot KEY -> a query operator lands where a
    #     scalar param was declared. The strongest proof: it is proven by the request's own key structure.
    m = _NOSQL_PARAM_OP_RE.search(name)
    if m:
        op = "$" + m.group(1).lower()
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"parameter {name!r} injects the MongoDB query operator {op!r} as a nested key where "
                      f"a scalar was expected — a structured NoSQL operator-injection attempt"),
            observed={"param": name, "operator": op, "vector": "operator_as_param_key", "break_out": True})
    # (2) the VALUE is a JSON object literal whose KEY is a known operator (`username={"$ne":null}`).
    op = _nosql_operator_key_in_json_text(text)
    if op:
        return OracleSignal(
            kind=kind, fired=True, confidence=0.9,
            evidence=(f"value parses to JSON carrying the MongoDB query operator {op!r} as an object key "
                      f"where a scalar was expected — a structured NoSQL operator-injection attempt"),
            observed={"param": name, "operator": op, "vector": "operator_as_json_key", "break_out": True})
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=("no NoSQL operator-injection structure (a $-prefixed KNOWN query operator as a KEY where "
                  "a scalar was expected); a $ in text/a price/an operator-shaped string value is inert"),
        observed={"param": name})


# --- the canonical-context reader: dispatch a general oracle_context to its ported oracle(s) ----
# Mirrors ``verify.verifier.OracleVerifier._run`` for the ported kinds EXACTLY: the same ctx keys,
# the same PROTOCOL-CONSTANT pins (the differential discriminator and the timing alpha are chosen by
# the AUTHORITY, never the producer ctx — audit F8 / B3b), and the same baseline-admissibility
# refusal (a ``request_smuggling`` baseline/mutated pair is not admissible — RED-PEN B3). The
# retained ``oracle_context`` is the canonical verifier-context (verify.adapter.FindingContext.
# to_verifier_context), so these keys read identically in a FindingContext dump or that projection.
_GENERAL_HIGH_CONFIDENCE = 0.7  # verify.verifier.HIGH_CONFIDENCE — the confirm threshold
_GENERAL_TIMING_PROTOCOL_ALPHA = 0.01  # verify.verifier._TIMING_PROTOCOL_ALPHA
# verify.verifier._DIFFERENTIAL_CONTENT_DISCRIMINATOR — the default for EVERY class reaching the
# differential arm (the protocol table _DIFFERENTIAL_PROTOCOL_DISCRIMINATORS is deliberately empty).
_GENERAL_DIFFERENTIAL_CONTENT_DISCRIMINATOR: dict = {
    "dimensions": ["status", "length", "lexical"],
    "length_threshold": 0.05,
    "lexical_threshold": 0.10,
    "expect": "differ",
}
# verify.verifier._DIFFERENTIAL_BASELINE_REFUSED. No alias in verify.verifier._ALIASES folds onto
# ``request_smuggling`` (checked against the in-tree table), so the string-normalised class suffices;
# the parity harness pins this dispatch to verifier._run over a request_smuggling context so a future
# alias drift is caught.
_GENERAL_DIFFERENTIAL_BASELINE_REFUSED = frozenset({"request_smuggling"})


def _general_normalize_bug_class(bug_class: Any) -> str:
    """The string normalisation of ``verify.verifier.normalize_bug_class`` (strip / lower / ``-``,
    space -> ``_`` / collapse runs). The alias fold is omitted because no alias maps onto the only
    class this dispatch keys on (``request_smuggling``); see the note above."""
    key = (str(bug_class or "")).strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in key:
        key = key.replace("__", "_")
    return key


def _general_differential_discriminator() -> dict:
    """The discriminator the AUTHORITY re-executes a differential with — a fresh copy, never the
    producer's (audit F8). The protocol table is empty, so it is always the content discriminator."""
    d = _GENERAL_DIFFERENTIAL_CONTENT_DISCRIMINATOR
    return {**d, "dimensions": list(d["dimensions"])}


# ---------------------------------------------------------------------------
# 8c-G1. A-PRIME GENERAL families — the PURE-BUT-DEFERRED set Lane C left unported, now RE-DERIVED
#        standalone. Each *_oracle below is a BYTE-FOR-BYTE copy of the corresponding body in
#        framework.v2.verify.oracles (extracted by AST over its exact source + the transitive closure
#        of its pure module-level helpers; the closure is provably stdlib+cryptography-only — see
#        integration/tests/test_general_reexecutable.py::test_bucket_classification_is_enforced, which
#        pins the import-closure of every ported body and holds the genuinely-irreducible set to EXACTLY
#        version_range (packaging) / saml_forgery (signxml,lxml) / oob_callback (external collector)).
#        Re-execution is over the RETAINED oracle_context (the capture's retained bytes), so a family
#        whose LIVE capture needs a socket/browser/cloud-API is still PURE at re-exec — the socket ran
#        at capture time; here we only re-read what it retained. HONEST BOUND is unchanged: re-firing
#        proves the verdict is the correct FUNCTION of the retained evidence, never that the evidence
#        is live. cryptography is the one non-stdlib dep this file already carries (Ed25519), so the
#        cert/jwt/mobile bodies that parse x509 / verify HMAC remain portable, not irreducible.
# ---------------------------------------------------------------------------
def holm_correction(p_values: Sequence[float], alpha: float = 0.01) -> list[bool]:
    """Holm-Bonferroni step-down over ``m`` simultaneous timing tests (one per
    candidate parameter). Returns, per input p-value, whether it rejects at
    family-wise error rate ``alpha``. Probing many params at once inflates false
    positives; Holm controls that without the raw Bonferroni's loss of power."""
    m = len(p_values)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: p_values[i])
    reject = [False] * m
    for rank, idx in enumerate(order):
        if p_values[idx] <= alpha / (m - rank):
            reject[idx] = True
        else:
            break  # step-down: once one fails to reject, all larger p-values do too
    return reject


def _resolve_operand(operand: Any, observed: Mapping[str, Any]) -> Any:
    """A predicate operand is either a variable reference ``{"var": "name"}``
    (looked up in the observed evidence) or a literal (str/int/list/...)."""
    if isinstance(operand, Mapping) and set(operand.keys()) == {"var"}:
        return observed.get(operand["var"])
    return operand


def _eval_predicate(pred: Any, observed: Mapping[str, Any]) -> tuple[bool, str]:
    """Evaluate one declarative predicate node over the observed evidence and
    return (holds, human-readable evidence). The predicate is a tiny, pure,
    JSON-serialisable AST — no code, so a certificate stays re-verifiable. Ops:
    all/any/not, eq/ieq, contains/icontains, in, min_len, gt/ge."""
    if not isinstance(pred, Mapping) or len(pred) != 1:
        raise ValueError(f"predicate node must be a single-op mapping, got {pred!r}")
    op, args = next(iter(pred.items()))

    if op == "all":
        results = [_eval_predicate(p, observed) for p in args]
        return all(r[0] for r in results), " AND ".join(f"({r[1]})" for r in results)
    if op == "any":
        results = [_eval_predicate(p, observed) for p in args]
        return any(r[0] for r in results), " OR ".join(f"({r[1]})" for r in results)
    if op == "not":
        r = _eval_predicate(args, observed)
        return (not r[0]), f"NOT({r[1]})"

    a = _resolve_operand(args[0], observed)
    if op in ("eq", "ieq", "contains", "icontains", "in", "min_len", "gt", "ge"):
        b = _resolve_operand(args[1], observed) if len(args) > 1 else None
    if op == "eq":
        return a == b, f"{a!r} == {b!r}"
    if op == "ieq":
        return str(a).lower() == str(b).lower(), f"{a!r} =(ci) {b!r}"
    if op == "contains":
        ok = bool(a) and bool(b) and str(b) in str(a)
        return ok, f"{b!r} in <{len(str(a))}b body>"
    if op == "icontains":
        ok = bool(a) and bool(b) and str(b).lower() in str(a).lower()
        return ok, f"{b!r} in(ci) <{len(str(a))}b body>"
    if op == "in":
        return a in (b or []), f"{a!r} in {b!r}"
    if op == "min_len":
        return len(str(a or "")) >= int(b), f"len({a!r})>={b}"
    if op == "gt":
        return (a is not None and b is not None and a > b), f"{a!r} > {b!r}"
    if op == "ge":
        return (a is not None and b is not None and a >= b), f"{a!r} >= {b!r}"
    raise ValueError(f"unknown predicate op {op!r}")


def honeypot_hit_oracle(
    requested_path: Any, honeypot_paths: Any, crawler_allowlisted: bool = False
) -> OracleSignal:
    """Deterministic set-membership: fire (AUTOMATED_ACCESS) iff a client fetched a seeded
    honeypot resource no human UI links AND the client is not an allowlisted known-good
    crawler/monitor.

    Honest scope (doctrine fix P1): this proves AUTOMATED ACCESS — a non-interactive client
    fetched a resource no human UI renders — NOT "scraping". Link-unfurl bots, speculative
    prefetch, AV URL scanners, and uptime monitors also trip it; those are exactly what the
    operator allowlist REFUTES (``crawler_allowlisted=True`` -> a benign, non-firing signal).
    'Adversarial scraping' stays a LEAD unless independently corroborated."""
    path = _coerce_text(requested_path).strip()
    if isinstance(honeypot_paths, str):
        paths = {honeypot_paths.strip()}
    else:
        paths = {_coerce_text(p).strip() for p in (honeypot_paths or [])}

    if crawler_allowlisted:
        return OracleSignal(
            kind=OracleKind.AUTOMATED_ACCESS, fired=False, confidence=0.0,
            evidence="requester is an allowlisted known-good crawler/monitor — benign automation (REFUTES)",
            observed={"path": path, "allowlisted": True})
    if not path or path not in paths:
        return OracleSignal(
            kind=OracleKind.AUTOMATED_ACCESS, fired=False, confidence=0.0,
            evidence="requested path is not a seeded honeypot resource",
            observed={"path": path})
    return OracleSignal(
        kind=OracleKind.AUTOMATED_ACCESS, fired=True, confidence=0.95,
        evidence=f"automated access confirmed: honeypot resource {path!r} (no human UI links it) was fetched",
        observed={"path": path, "matched": True})


_CREDSTUFF_ALPHA = 0.01


_CREDSTUFF_BETA = 0.01


_CREDSTUFF_P1 = 0.8


_CREDSTUFF_P0 = 0.2


_CREDSTUFF_FWER = 0.01


_CREDSTUFF_MAX_EVENTS = 20000


_CREDSTUFF_EXACT_N = 400


def _binomial_upper_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p) — the per-family p-value under H0 (unseen-pair successes
    arise only at the benign rate ``p``). Exact stdlib integer binomials for small n; a bounded,
    continuity-corrected normal approximation beyond ``_CREDSTUFF_EXACT_N`` so the computation
    stays cheap and deterministic on a large (but SPRT-decided, hence realistically small) n."""
    if n <= 0 or k <= 0:
        return 1.0
    if k > n:
        return 0.0
    p = min(1.0, max(0.0, p))
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    if n <= _CREDSTUFF_EXACT_N:
        tail = sum(math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i)) for i in range(k, n + 1))
        return min(1.0, tail)
    mu = n * p
    sigma = math.sqrt(n * p * (1.0 - p))
    if sigma <= 0.0:
        return 1.0 if k <= mu else 0.0
    z = (k - 0.5 - mu) / sigma
    return max(0.0, min(1.0, 1.0 - _normal_cdf(z)))


def credential_stuffing_oracle(
    auth_events: Any,
    *,
    alpha: float = _CREDSTUFF_ALPHA,
    beta: float = _CREDSTUFF_BETA,
    p1: float = _CREDSTUFF_P1,
    p0: float = _CREDSTUFF_P0,
    fwer: float = _CREDSTUFF_FWER,
    benign_sources: Any = None,
) -> OracleSignal:
    """Confirm a credential-stuffing / account-takeover CAMPAIGN by the SAME Wald SPRT
    ``boolean_inference_oracle`` uses (``_sprt_decision``), run over each source's stream of
    UNSEEN-``(account, source)`` auth SUCCESS outcomes, with a Holm-Bonferroni family-wise
    correction across the distinct source identities.

    ``auth_events`` is an ORDERED list of ``{"account", "source", "success"}``. Identifiers are
    already keyed-HMAC pseudonyms (the oracle NEVER sees a raw username/IP). The oracle REPLAYS
    the log deterministically — no wallclock, no rng, bounded to ``_CREDSTUFF_MAX_EVENTS``:

      * Per source, a SUCCESS on an ``(account, source)`` pair not previously seen succeeding is
        the attacker-signature Bernoulli signal (1); a repeat success on an already-owned pair is
        a returning-user control (0). FAILURES produce NO SPRT round — so a failed-only burst (the
        MECE benign twin: NAT/CGNAT bulk) yields zero rounds and can NEVER confirm here.
      * The per-source SPRT CONFIRMS only when the log-likelihood ratio crosses ``log((1-beta)/
        alpha)`` — one new-device login cannot cross it; a run of successes across many unseen
        accounts does. A binomial upper-tail p-value under H0 is derived from the consumed counts.
      * Across the distinct sources (the multiple identities probed at once), ``holm_correction``
        controls the FAMILY-WISE false-positive rate: a source is CONFIRMED only when its SPRT
        crossed AND it survives the family-wise correction at ``fwer`` — so monitoring thousands
        of sources cannot manufacture a confirmation by multiplicity (a marginal single-source
        SPRT hit that fails the family-wise control is honestly withheld).

    ``benign_sources`` (optional) is an operator allowlist of known-good egress identities
    (a documented NAT/CGNAT, an SSO gateway) whose successes REFUTE — they can never confirm,
    mirroring the honeypot crawler allowlist (P1). Pure + deterministic."""
    events = list(auth_events or [])[:_CREDSTUFF_MAX_EVENTS]
    allow = {_coerce_text(s).strip() for s in (benign_sources or [])}

    # group per source in arrival order (deterministic; a dict preserves insertion order).
    by_source: dict[str, list[tuple[str, bool]]] = {}
    order: list[str] = []
    for ev in events:
        if not isinstance(ev, Mapping):
            continue
        source = _coerce_text(ev.get("source")).strip()
        account = _coerce_text(ev.get("account")).strip()
        if not source or not account:
            continue
        if source not in by_source:
            by_source[source] = []
            order.append(source)
        by_source[source].append((account, bool(ev.get("success", False))))

    families: list[dict[str, Any]] = []
    for source in order:
        rows = by_source[source]
        allowlisted = source in allow

        # (a) The SEQUENTIAL decision: the SAME Wald SPRT boolean_inference uses, over the
        #     unseen-(account, source) SUCCESS indicator stream — it stops early at the first
        #     boundary. FAILURES never yield a round (a failed-only burst never crosses).
        seen_sprt: set[str] = set()

        def _sig_seq(_rows=rows, _seen=seen_sprt):
            for account, success in _rows:
                if not success:
                    continue
                unseen = account not in _seen
                _seen.add(account)
                yield unseen

        decided, llr, _n_used, _n_signal, upper, lower = _sprt_decision(
            _sig_seq(), alpha=alpha, beta=beta, p1=p1, p0=p0)

        # (b) The FAMILY-WISE evidence: a FIXED-sample binomial upper-tail p-value over the WHOLE
        #     window (NOT the SPRT-truncated prefix) — so evidence STRENGTH scales with the breadth
        #     of compromise (a 6-account run is stronger than a 4-account run even though the SPRT
        #     halts at the same boundary). This is what Holm ranks across identities.
        seen_full: set[str] = set()
        n_success = 0
        n_unseen = 0
        for account, success in rows:
            if not success:
                continue
            n_success += 1
            if account not in seen_full:
                n_unseen += 1
                seen_full.add(account)
        pval = 1.0 if allowlisted else _binomial_upper_tail(n_unseen, n_success, p0)

        families.append({
            "source": source, "decided": "allowlisted" if allowlisted else (decided or "inconclusive"),
            "llr": round(llr, 4), "n_success": n_success, "n_unseen": n_unseen,
            "distinct_accounts": len(seen_full), "p_value": pval,
        })

    # Holm-Bonferroni across the distinct source identities (the multi-identity family-wise
    # control). A source confirms iff its SPRT crossed AND Holm rejects its p-value at `fwer`.
    pvals = [f["p_value"] for f in families]
    rejects = holm_correction(pvals, alpha=fwer) if pvals else []
    confirmed = [
        f for f, rej in zip(families, rejects)
        if f["decided"] == "confirm" and rej
    ]

    observed = {"families": families, "confirmed_sources": [f["source"] for f in confirmed],
                "n_families": len(families), "fwer": fwer}
    if not confirmed:
        # honest non-fire: name why (no SPRT crossing, or family-wise control withheld it).
        crossed = [f for f in families if f["decided"] == "confirm"]
        if crossed:
            why = (f"{len(crossed)} source(s) crossed the SPRT but did NOT survive the Holm "
                   f"family-wise control at fwer={fwer} over {len(families)} identities")
        else:
            why = "no source's unseen-pair successes crossed the SPRT boundary (failed-only / benign)"
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_STUFFING, fired=False, confidence=0.0,
            evidence=f"no credential stuffing confirmed: {why}", observed=observed)

    confidence = min(0.99, 1.0 - fwer)
    detail = "; ".join(
        f"source {f['source']!r}: {f['n_unseen']} unseen-account successes over "
        f"{f['distinct_accounts']} accounts (LLR={f['llr']:.2f}, p={f['p_value']:.2g})"
        for f in confirmed)
    return OracleSignal(
        kind=OracleKind.CREDENTIAL_STUFFING, fired=True, confidence=confidence,
        evidence=(f"credential stuffing / ATO confirmed for {len(confirmed)} source identity(ies) "
                  f"(SPRT crossed + Holm family-wise control at fwer={fwer}): {detail}"),
        observed=observed)


def dom_execution_oracle(binding_calls: Any, canary: str) -> OracleSignal:
    """Fire when a unique canary appears among the arguments the page passed to a
    CDP binding — proof that injected JavaScript **executed** in a real browser
    DOM, not merely that a marker was reflected.

    This is the strongest possible XSS evidence and is near-unforgeable: the
    binding is a function only the driver registered (Runtime.addBinding), and the
    only way its call carrying the canary appears is if the injected script ran and
    invoked it. A reflected-but-inert payload, an encoded payload, or a page that
    never executes the sink all produce no binding call and correctly do not fire.
    The canary must be non-trivial so an incidental value cannot masquerade as one."""
    canary = (canary or "").strip()
    calls = [_coerce_text(c) for c in (binding_calls or [])]

    if len(canary) < 6:
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
            evidence="execution canary too short to be a reliable, unforgeable marker",
            observed={"canary": canary})

    hit = next((c for c in calls if canary in c), None)
    if hit is None:
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
            evidence="no binding call carried the execution canary; injected script did not run",
            observed={"canary": canary, "call_count": len(calls)})

    return OracleSignal(
        kind=OracleKind.DOM_EXECUTION,
        fired=True,
        confidence=0.97,
        evidence=f"injected script executed in the DOM and invoked the callback with {canary!r}",
        observed={"canary": canary, "call": hit[:200]},
    )


_SFX_SENTINEL_RE = re.compile(r"^sfx_[0-9a-f]{32,}$")


_SFX_MIN_MARKER = 3


_SFX_MIN_BODY = 16


_SFX_MAX_ERROR_BODY = 96


_SFX_DEFAULT_LOGGED_OUT_STATUSES = frozenset({401, 403})


_SFX_TAG_RE = re.compile(r"<[^>]+>")


_SFX_WS_RE = re.compile(r"\s+")


_SFX_ERROR_OPENER_RE = re.compile(r"^(errors?\b|forbidden\b|unauthori[sz]ed\b|denied\b|[45]\d\d\b)")


_SFX_ERROR_SIGNATURES: tuple[str, ...] = (
    "internal server error", "500 internal server error",
    "service unavailable", "service temporarily unavailable", "temporarily unavailable",
    "bad gateway", "gateway timeout", "bad request",
    "not found", "page not found", "404 not found", "403 forbidden",
    "access denied", "access is denied", "access blocked", "request blocked",
    "an error occurred", "an error has occurred", "an unexpected error", "something went wrong",
)


def _sfx_status_set(statuses: Any) -> "frozenset[int]":
    out: set[int] = set()
    if isinstance(statuses, (list, tuple, set, frozenset)):
        for s in statuses:
            try:
                out.add(int(s))
            except (TypeError, ValueError):
                continue
    return frozenset(out) if out else _SFX_DEFAULT_LOGGED_OUT_STATUSES


def _sfx_substantive_body(status: Any, body: str) -> bool:
    """A response usable in the differential — a real 2xx with a non-trivial body that is not itself an
    error/deny page. A response FAILING this proves NOTHING (it can neither score authenticated NOR serve as
    a negative reference whose marker-absence is meaningful), so the caller FAILS CLOSED to a LEAD."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    if not (200 <= code < 300):
        return False
    raw = body or ""
    if len(raw.strip()) < _SFX_MIN_BODY:
        return False
    text = _SFX_WS_RE.sub(" ", _SFX_TAG_RE.sub(" ", raw)).strip().lower()
    if not text:
        return False
    if _SFX_ERROR_OPENER_RE.match(text):
        return False
    if len(text) <= _SFX_MAX_ERROR_BODY and any(sig in text for sig in _SFX_ERROR_SIGNATURES):
        return False
    return True


_SFX_DENIAL_STATUSES = frozenset({401, 403})


_SFX_MIN_DENIAL_BODY = 3


def _sfx_nocred_baseline_valid(status: Any, body: str) -> bool:
    """A no-session (logged-out) gating baseline is a VALID proof the datum is authorization-gated — its
    ``not-contains(D)`` is meaningful — ONLY when it is EITHER a SUBSTANTIVE 2xx read of the resource (the
    datum is gated at the record level) OR a GENUINE 401/403 authorization DENIAL carrying a real (non-empty)
    deny body (access requires credentials). A bare 5xx / empty / 404 / body-less denial proves NOTHING (its
    absent D is vacuous) ⇒ INVALID, and the caller fails closed to a LEAD."""
    if _sfx_substantive_body(status, body):
        return True
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return code in _SFX_DENIAL_STATUSES and len(_coerce_text(body).strip()) >= _SFX_MIN_DENIAL_BODY


def _sfx_private_read_achieved(discriminator: Any, authorized: Any, owner_view: Any, unauth_ref: Any,
                               logged_out_ref: Any, logged_out_markers: Any, logged_out_statuses: Any,
                               *, sentinel_id: str = "") -> "bool | None":
    """Re-derive, from the RETAINED RAW bytes, whether the VIGIL-fixed id S0's post-login read of the
    protected/victim resource ACHIEVED a read of a victim-PRIVATE datum ``D`` — the ONLY SOUND proof of the
    achieved fixation state. An authenticated/accepted state CANNOT be proven from response CONTENT (six
    rounds proved every marker / same-shape / credential-presence heuristic is defeated by a benign app whose
    response merely VARIES by credential presence), so this NEVER scores a body and never trusts a bool.
    TRI-STATE:

      * ``True``  — D is a valid, non-reflected discriminator PRESENT in S0's SUBSTANTIVE read (a), PRESENT in
        the owner's authoritative SUBSTANTIVE read (b), ABSENT from a SUBSTANTIVE SAME-SHAPE 2xx read by an
        OTHER unauthorized identity (c, DECISIVE) AND ABSENT from a VALID no-session gating baseline (c) ⇒ S0
        reached the victim's PRIVATE view ⇒ a live fixed session;
      * ``False`` — S0 is DECISIVELY not authenticated: a logged-out status / operator logged-out marker on
        S0's read, OR — with the full differential validated — D ABSENT from S0's otherwise-substantive read
        (S0 rendered the resource but NOT the victim's private datum, like the unauthorized peer);
      * ``None``  — undecidable ⇒ FAIL CLOSED to a LEAD: no / invalid D; D reflects / straddles the sentinel
        (a cookie echo); S0's read is not a substantive success; NO substantive owner (positive) reference or
        D absent from it (D not proven private); NO substantive SAME-SHAPE other-identity reference (a
        denial / empty / error / different-shape is REFUSED); NO valid no-session baseline; or D PRESENT in a
        negative reference (chrome / shared / public — not victim-private)."""
    s0 = _coerce_text(sentinel_id).strip()
    d = _coerce_text(discriminator).strip()
    if not isinstance(authorized, Mapping):
        return None
    a_status = authorized.get("status")
    a_body = _coerce_text(authorized.get("body"))
    # DECISIVE logged-out signals on S0's read DISPROVE auth (channel-confirmed not-authenticated), no D
    # needed: an explicit logged-out status or an operator-supplied logged_out_marker.
    try:
        a_code = int(a_status)
    except (TypeError, ValueError):
        a_code = 0
    if a_code in _sfx_status_set(logged_out_statuses):
        return False
    lo_markers = [t for t in (_coerce_text(x).strip() for x in (logged_out_markers or ())) if t]
    if any(t in a_body for t in lo_markers):
        return False
    # (d) VALID DISCRIMINATOR. D must be non-trivial and must NOT discriminate VIGIL's OWN injected id: the
    # sentinel S0 is the per-probe nonce, so a D that is a SUBSTRING of it is a reflected cookie echo, not
    # access-gated content (mirrors scanner.session.valid_discriminator(D, nonce=S0)). ⇒ undecidable.
    if len(d) < _SFX_MIN_MARKER:
        return None
    if s0 and d in s0:
        return None
    # S0's read must ITSELF be a SUBSTANTIVE success to carry an achieved private read (empty / too-short /
    # error-or-deny 2xx proves nothing) ⇒ undecidable.
    if not _sfx_substantive_body(a_status, a_body):
        return None
    # STRADDLE / reflected-sentinel guard: even a D not WHOLLY inside S0 is a cookie-echo artifact when it
    # OVERLAPS S0 in the echoed body. Mask every occurrence of the fixed sentinel; if D's presence in S0's
    # body vanishes, its presence was the cookie echo — not access-gated content ⇒ undecidable. (S0's read is
    # the ONLY leg carrying Cookie: <name>=S0, so this is the reflected-from-request guard for (d).)
    if s0 and s0 in a_body and d in a_body and d not in a_body.replace(s0, "\x00"):
        return None
    # (b) POSITIVE reference — the owner's authoritative read MUST be a substantive success and MUST CONTAIN
    # D, proving D is the REAL victim-private content (not chrome that appears whenever a credential is
    # present). No substantive owner read, or D absent from it ⇒ D is not validated as private ⇒ undecidable.
    if not isinstance(owner_view, Mapping):
        return None
    o_body = _coerce_text(owner_view.get("body"))
    if not _sfx_substantive_body(owner_view.get("status"), o_body):
        return None
    if d not in o_body:
        return None
    # (c) DECISIVE SAME-SHAPE negative reference — an OTHER unauthorized identity's read of the SAME resource
    # that MUST be a SUBSTANTIVE SAME-SHAPE 2xx (a real render of the resource, NOT a denial / empty / error /
    # different shape). D MUST be ABSENT. This is the ONLY reference a benign credential-presence-varying app
    # cannot fool: cosmetic chrome shown for ANY credential appears here too (D present ⇒ refused); a real
    # datum gated to the victim identity does not. A non-substantive-same-shape reference is REFUSED (its
    # absent D is vacuous). NO such reference ⇒ undecidable — a no-session-ONLY differential is defeated by a
    # credential-presence-varying app, so it can never mint.
    if not isinstance(unauth_ref, Mapping):
        return None
    u_body = _coerce_text(unauth_ref.get("body"))
    if not _sfx_substantive_body(unauth_ref.get("status"), u_body):
        return None
    if d in u_body:
        return None   # present for another identity ⇒ chrome / shared / not victim-private ⇒ undecidable
    # (c) no-session GATING baseline — a VALID gating proof (a substantive 2xx that lacks D, or a genuine
    # 401/403 denial with a real body). D present in a SUBSTANTIVE no-session read ⇒ D is public ⇒ undecidable.
    if not isinstance(logged_out_ref, Mapping):
        return None
    l_status = logged_out_ref.get("status")
    l_body = _coerce_text(logged_out_ref.get("body"))
    if not _sfx_nocred_baseline_valid(l_status, l_body):
        return None
    if _sfx_substantive_body(l_status, l_body) and d in l_body:
        return None
    # The full SAME-SHAPE private-read differential is established and D is a proven victim-PRIVATE
    # discriminator. POSITIVE achieved read: D present in S0's substantive read ⇒ S0 reached the victim's
    # private view ⇒ True. D ABSENT from S0's otherwise-substantive read ⇒ S0 rendered the resource but did
    # NOT reach the private datum (like the unauthorized peer) ⇒ False (channel-confirmed clean).
    return d in a_body


def _sfx_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.SESSION_FIXATION (held OUT of the frozen _ALL_ORACLES, so
    # oracle_version(ACHIEVED_STATE) is untouched and the unknown-class fallback stays EXACTLY 15). A fire is
    # always decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (a rotated+dead or an
    # unrotated+not-authenticated fixed id) — an undecidable / disqualified-differential / server-set / bare
    # shape non-fire is a LEAD (conclusive=False), never a CLEAN.
    return OracleSignal(kind=OracleKind.SESSION_FIXATION, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def session_fixation_oracle(observed: Any) -> OracleSignal:
    """Fire when a VIGIL-fixed PRE-AUTH session id SURVIVES the operator's login sequence unrotated AND
    achieves a read of a victim-PRIVATE datum — the ACHIEVED-STATE proof of session fixation (CWE-384),
    proven by the PRIVATE-READ REDUCTION (an achieved authenticated state cannot be proven from response
    content; see :func:`_sfx_private_read_achieved`), re-derived from RAW retained bytes (never a bool).

    ``observed`` is the retained record ``scanner.session.SessionFixationCheck`` captured through the gated
    ``send``:

      * ``sentinel_id`` (S0) — the UNIQUE high-entropy id VIGIL chose and set as the session cookie BEFORE
        the login sequence (the attacker-fixed id); MUST match VIGIL's per-run sentinel shape ``sfx_<hex>``;
      * ``post_auth_id`` (S1) — the session-cookie value in effect AFTER login;
      * ``private_discriminator`` (D) — the operator's genuine victim-PRIVATE datum (the achieved-state proof);
      * ``authorized_view`` — ``{status, body}`` of the protected URL fetched carrying the VIGIL-fixed id S0
        AFTER login (S0's read);
      * ``owner_view`` — ``{status, body}`` of the SAME URL read authoritatively as the owner/victim (the
        POSITIVE reference: D must be PRESENT, proving D is real private content);
      * ``unauth_ref`` — ``{status, body}`` of the SAME URL read by an OTHER unauthorized identity (the
        DECISIVE SAME-SHAPE negative reference: a substantive 2xx from which D must be ABSENT);
      * ``logged_out_ref`` — ``{status, body}`` of the SAME URL with NO session cookie (the no-session gating
        baseline: D absent from a valid — substantive-2xx-or-genuine-denial — read);
      * ``logged_out_markers`` / ``logged_out_statuses`` — the operator's decisive not-authenticated signals;
      * ``success_marker`` — LEGACY; a bare success-marker differential is NO LONGER a minting path (six
        rounds proved it is defeated by a benign app whose response varies by credential presence), so it is
        NOT used to prove the achieved state — only ``logged_out_markers`` still drive the not-authenticated
        determination.

    Adjudication (a bare ``authenticated_after_login`` bool, if present, is IGNORED — the oracle re-derives):

      * ``sentinel_id`` not the ``sfx_<hex>`` shape ⇒ a server-issued id cannot mint this FACT — LEAD;
      * ``post_auth_id`` missing ⇒ INCONCLUSIVE;
      * :func:`_sfx_private_read_achieved` is ``None`` (no / invalid / reflected D; a non-substantive S0 read;
        no substantive owner (positive) reference or D absent from it; no substantive SAME-SHAPE other-identity
        reference; no valid no-session baseline; or D present in a negative reference) ⇒ LEAD (never a FACT,
        never a false CLEAN);
      * the id was ROTATED at login (``post_auth_id != sentinel_id``): S0 DEAD ⇒ channel-confirmed CLEAN
        (the correct defense); S0 STILL LIVE ⇒ INCONCLUSIVE (a value rotation alone does not prove S0 was
        invalidated, and a live-S0 rotated record is indistinguishable from a hand-forged rotation — never a
        false CLEAN, never a FACT);
      * survived UNROTATED but S0 did not achieve the private read ⇒ channel-confirmed CLEAN;
      * survived UNROTATED AND the private-read differential proves S0 reached the victim's private view ⇒ FIRE.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    sentinel = _coerce_text(obs.get("sentinel_id")).strip()
    post_auth_raw = obs.get("post_auth_id")
    post_auth = _coerce_text(post_auth_raw).strip() if post_auth_raw is not None else ""
    cookie_name = _coerce_text(obs.get("cookie_name")).strip()
    discriminator = _coerce_text(obs.get("private_discriminator")).strip()
    base = {"cookie_name": cookie_name, "sentinel_id_shape_ok": bool(_SFX_SENTINEL_RE.match(sentinel))}

    # SELF-CONTAINED SOUNDNESS: the fixed id must be VIGIL's own per-run sentinel. A server-issued id can NEVER
    # be the id VIGIL drove in — so this FACT provably rests on an id VIGIL fixed, and a server-set-only id is
    # NOT rounded to a FACT. Non-conclusive (a weaker LEAD, per the plan).
    if not _SFX_SENTINEL_RE.match(sentinel):
        return _sfx_signal(
            False, observed=base,
            evidence=("fixed session id is not a VIGIL per-run sentinel (expected sfx_<hex>) — a server-issued "
                      "id cannot mint this FACT; the app did not honour a client-fixed id (degrades to a LEAD)"))

    # No post-auth id observed ⇒ no channel-confirmed observation of the login's effect ⇒ INCONCLUSIVE.
    if post_auth_raw is None or not post_auth:
        return _sfx_signal(
            False, observed=base,
            evidence="no post-authentication session id was observed — cannot adjudicate fixation (inconclusive)")

    # RE-DERIVE the achieved state from RAW retained bytes via the PRIVATE-READ REDUCTION — never a bool, never
    # a bare success-marker differential. None ⇒ undecidable (no/invalid/reflected D, non-substantive S0 read,
    # missing/failing positive owner reference, missing/non-substantive-same-shape other-identity reference,
    # missing/invalid no-session baseline, or D present in a negative reference) ⇒ LEAD.
    s0_auth = _sfx_private_read_achieved(discriminator, obs.get("authorized_view"), obs.get("owner_view"),
                                         obs.get("unauth_ref"), obs.get("logged_out_ref"),
                                         obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
                                         sentinel_id=sentinel)
    if s0_auth is None:
        return _sfx_signal(
            False, observed={**base, "discriminator_len": len(discriminator)},
            evidence=("the fixed id's achieved state could not be proven by the PRIVATE-READ differential (no "
                      "valid victim-private discriminator D; D reflects/straddles the VIGIL-fixed sentinel — a "
                      "cookie echo, not access-gated content; a non-substantive S0 read; no substantive owner "
                      "positive reference or D absent from it; no substantive SAME-SHAPE other-identity "
                      "reference — a denial/empty/error/different-shape is refused; no valid no-session "
                      "baseline; or D present in a negative reference — chrome/shared/public) — cannot mint (LEAD)"))

    # The session-cookie VALUE was ROTATED at login (S1 != S0). Rotation ALONE is NOT proof of defense: an app
    # can rotate the value yet leave the pre-auth-fixed id S0 valid (a real fixation). Only the differential
    # showing S0 is DEAD is a channel-confirmed clean; a still-LIVE S0 under a rotated value is
    # indistinguishable from a hand-forged rotation in the retained record ⇒ refuse to clear AND to mint.
    if post_auth != sentinel:
        if s0_auth is True:
            return _sfx_signal(
                False, observed={**base, "rotated": True, "s0_authenticated": True},
                evidence=("session-cookie value was ROTATED at login yet the VIGIL-fixed pre-auth id still "
                          "reaches the victim's private view (proven by the private-read differential) — a value "
                          "rotation does not by itself prove the fixed id was invalidated; cannot conclusively "
                          "clear (inconclusive)"))
        return _sfx_signal(
            False, conclusive=True, observed={**base, "rotated": True, "s0_authenticated": False},
            evidence=("session id was ROTATED at login and the VIGIL-fixed pre-auth id no longer reaches the "
                      "victim's private view — the app defends against fixation; did not fire"))

    # The fixed id survived unrotated but did not achieve the private read ⇒ no fixation risk. Confirmed clean.
    if s0_auth is not True:
        return _sfx_signal(
            False, conclusive=True, observed={**base, "s0_authenticated": False},
            evidence=("the VIGIL-fixed id survived login unrotated but did not reach the victim's private view "
                      "(the private datum D is absent from its read, present for the owner) — not a live fixed "
                      "session; did not fire"))

    return _sfx_signal(
        True, conf=0.92,
        evidence=(f"session fixation: the VIGIL-fixed pre-auth id {sentinel!r} SURVIVED the login sequence "
                  f"(post-auth id is identical) AND achieved a read of a victim-PRIVATE datum — the private "
                  f"discriminator D is PRESENT in S0's read AND in the owner's authoritative read yet PROVABLY "
                  f"ABSENT from a SUBSTANTIVE SAME-SHAPE read by an OTHER unauthorized identity and from a "
                  f"no-session baseline (the private-read differential proves S0 reached the victim's gated "
                  f"content) — the app adopted an attacker-fixable session id at authentication"),
        observed={"sentinel_id": sentinel, "post_auth_id": post_auth, "cookie_name": cookie_name,
                  "s0_authenticated": True, "differential": "private_datum_present_in_fixed_session_and_owner_"
                  "reads_absent_in_same_shape_other_identity_and_no_session_references"})


_WORKFLOW_MODES = ("race", "tamper")


def _workflow_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9,
                     conclusive: bool = False) -> OracleSignal:
    # kind is the FROZEN ACHIEVED_STATE (already in _ALL_ORACLES — this adds NO new OracleKind and
    # oracle_version(ACHIEVED_STATE) is byte-identical, mirroring csrf_achieved_oracle): reachable ONLY
    # via the fresh `workflow_abuse` ctx key no benchmark/scan/engage finding carries. A fire is always
    # decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed CLEAN (a properly-locked
    # resource with successes<=max_allowed, or a validating flow whose danger predicate is false). A
    # missing owner attestation / missing semantic predicate / malformed record is a LEAD/INCONCLUSIVE
    # (conclusive=False) — never a CLEAN: absence of a positive channel is not proof the surface is safe.
    return OracleSignal(kind=OracleKind.ACHIEVED_STATE, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


_MFA_ATTESTATION_FIELDS: tuple[str, ...] = (
    "mfa_enrolled_account",         # the account under test genuinely has a second factor ENROLLED
    "factor1_only_presented",       # VIGIL's session completed ONLY factor-1 (no OTP/WebAuthn/push supplied)
    "post_mfa_resource_certified",  # the read resource/datum is genuinely gated BEHIND factor-2 (closes the FP)
)


def _mfa_attested(attestation: Any) -> bool:
    """The FAIL-CLOSED operator attestation — a HARD precondition, re-derived from the retained record at every
    verification. True ONLY when the record carries all three attestation fields set with strict ``is True`` (a
    truthy non-bool does NOT pass). Absent / partial / false ⇒ the oracle refuses to mint (an honest LEAD): an
    intentionally factor-1 page is otherwise indistinguishable from a bypass."""
    if not isinstance(attestation, Mapping):
        return False
    return all(attestation.get(f) is True for f in _MFA_ATTESTATION_FIELDS)


def _mfa_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.MFA_BYPASS (held OUT of the frozen _ALL_ORACLES, so
    # oracle_version(ACHIEVED_STATE) is untouched and the unknown-class fallback stays EXACTLY 15). A fire is
    # always decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (attested AND the
    # factor-1-only session provably did NOT reach the victim's post-MFA private view — the app enforces
    # factor-2). An un-attested / undecidable-differential non-fire is a LEAD (conclusive=False), never a CLEAN.
    return OracleSignal(kind=OracleKind.MFA_BYPASS, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed=observed)


def _workflow_resp_pair(resp: Any) -> dict[str, Any]:
    """Normalise one retained burst response into the ``{status, body}`` the operator's semantic
    success predicate reads. Pure — never fetches anything."""
    if isinstance(resp, Mapping):
        return {"status": resp.get("status"), "body": _coerce_text(resp.get("body"))}
    return {"status": None, "body": _coerce_text(resp)}


def _workflow_race(obs: Mapping[str, Any], base: dict) -> OracleSignal:
    try:
        max_allowed = int(obs.get("max_allowed"))
    except (TypeError, ValueError):
        return _workflow_signal(
            False, observed=base,
            evidence="race: max_allowed is missing or not an integer — cannot adjudicate (inconclusive)")
    if max_allowed < 0:
        return _workflow_signal(
            False, observed=base,
            evidence="race: max_allowed is negative — malformed spec (inconclusive)")

    responses = obs.get("responses")
    if not isinstance(responses, (list, tuple)) or not responses:
        return _workflow_signal(
            False, observed=base,
            evidence="race: no retained burst responses to re-derive the success count over (inconclusive)")

    predicate = obs.get("success_predicate")
    if not isinstance(predicate, Mapping) or not predicate:
        # A12: a bare any-2xx count does not prove a should-be-atomic resource was over-CONSUMED — a
        # benignly-idempotent endpoint returns 2xx to every concurrent request. Without an operator-
        # declared SEMANTIC success predicate proving each COMMIT, the over-count is a LEAD, not a FACT.
        return _workflow_signal(
            False, observed={**base, "n_responses": len(responses), "semantic_predicate": False},
            evidence=("race: no SEMANTIC success predicate supplied — an any-2xx concurrent-success count "
                      "does not prove over-consumption (a benignly-idempotent endpoint returns 2xx to every "
                      "request); this is a LEAD, not a FACT"))

    # RE-DERIVE the success count from the RAW retained responses by re-evaluating the operator's
    # semantic predicate over EACH one (never a trusted pre-computed integer). A malformed predicate over
    # any response ⇒ inconclusive (fail closed, never fabricate a count).
    successes = 0
    try:
        for resp in responses:
            hit, _ = _eval_predicate(predicate, _workflow_resp_pair(resp))
            if hit:
                successes += 1
    except (ValueError, TypeError) as e:
        return _workflow_signal(
            False, observed={**base, "n_responses": len(responses)},
            evidence=f"race: malformed success predicate ({e}) — cannot re-derive the count (inconclusive)")

    detail = {**base, "n_responses": len(responses), "successes": successes,
              "max_allowed": max_allowed, "semantic_predicate": True}
    if successes > max_allowed:
        return _workflow_signal(
            True, conf=0.9, observed=detail,
            evidence=(f"limit-overrun race: a should-be-atomic action committed {successes} time(s) in a "
                      f"single-packet burst — re-derived from the raw responses by the operator's SEMANTIC "
                      f"success predicate — exceeding its permitted maximum of {max_allowed}. The check-then-"
                      f"act window is unguarded (a TOCTOU double-spend / one-time-token reuse race)."))
    return _workflow_signal(
        False, conclusive=True, observed=detail,
        evidence=(f"race: the action committed {successes} time(s) under the burst — within its permitted "
                  f"maximum of {max_allowed} (re-derived by the semantic success predicate) — the resource "
                  f"is properly locked; did not fire"))


def _workflow_tamper(obs: Mapping[str, Any], base: dict) -> OracleSignal:
    danger = obs.get("danger")
    if not isinstance(danger, Mapping) or not danger:
        return _workflow_signal(
            False, observed=base,
            evidence="tamper: no danger predicate supplied — cannot adjudicate the post-state (inconclusive)")
    observed_state = obs.get("observed_state")
    if not isinstance(observed_state, Mapping):
        return _workflow_signal(
            False, observed=base,
            evidence="tamper: no observed post-state supplied — cannot adjudicate (inconclusive)")
    try:
        fired, evidence = _eval_predicate(danger, dict(observed_state))
    except (ValueError, TypeError) as e:
        return _workflow_signal(
            False, observed=base,
            evidence=f"tamper: malformed danger predicate ({e}) — cannot adjudicate (inconclusive)")
    detail = {**base, "danger_eval": evidence, "observed_state": dict(observed_state)}
    if fired:
        return _workflow_signal(
            True, conf=0.9, observed=detail,
            evidence=(f"price/parameter tampering accepted into a dangerous persisted state: the operator's "
                      f"danger predicate holds over the observed post-state ({evidence}). Server-side "
                      f"validation of the price/quantity is missing, so a negative/overflow/tampered value "
                      f"was driven straight into the persisted order/balance."))
    return _workflow_signal(
        False, conclusive=True, observed=detail,
        evidence=(f"tamper: the danger predicate does NOT hold over the observed post-state ({evidence}) — "
                  f"the flow validated/clamped the tampered value; did not fire"))


def workflow_abuse_oracle(observed: Any) -> OracleSignal:
    """Fire on a race limit-overrun (COUNT-based) or an accepted price/parameter tampering — BOTH
    gated behind the OWNER-SIGNED WorkflowSpec attestation (Wave-4.4). ``observed`` is the retained
    record ``scanner.race`` / ``scanner.bizlogic`` (or ``live.race_bizlogic_redrive``) captured:

      * ``mode`` — ``"race"`` or ``"tamper"``;
      * ``owner_signed_spec`` — the runner-attested fact that it cryptographically verified the owner's
        Ed25519 signature over the canonical WorkflowSpec AST BEFORE running any state-changing step
        (the FATAL-2-safe gated-workflow attestation; the certificate binds it);
      * RACE: ``max_allowed`` (int), ``responses`` (the raw ``{status, body}`` burst outcomes), and
        ``success_predicate`` (the operator's SEMANTIC per-response commit predicate — a pure JSON AST);
      * TAMPER: ``observed_state`` (the retained post-state) and ``danger`` (the operator's danger
        predicate — a pure JSON AST).

    Adjudication: an unknown mode, a missing owner attestation, or a malformed record ⇒ INCONCLUSIVE;
    a race with no semantic success predicate ⇒ LEAD (an any-2xx count is not proof of over-consumption);
    a race whose semantic-predicate-re-derived successes exceed max_allowed ⇒ FIRE, else channel-
    confirmed CLEAN (properly locked); a tamper whose danger predicate holds over the post-state ⇒ FIRE,
    else channel-confirmed CLEAN (the flow validated the value). Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    mode = _coerce_text(obs.get("mode")).strip().lower()
    owner_signed = obs.get("owner_signed_spec") is True
    base = {"mode": mode, "owner_signed_spec": owner_signed}

    if mode not in _WORKFLOW_MODES:
        return _workflow_signal(
            False, observed=base,
            evidence=(f"unknown workflow-abuse mode {mode!r} (expected one of {_WORKFLOW_MODES}) — "
                      f"cannot adjudicate (inconclusive)"))

    # FAIL CLOSED behind the owner-signed WorkflowSpec attestation. Without it the WorkflowSpec is not
    # proven operator intent and the state-changing steps were not owner-approved ⇒ INCONCLUSIVE.
    if not owner_signed:
        return _workflow_signal(
            False, observed=base,
            evidence=("no OWNER-SIGNED WorkflowSpec attestation (owner_signed_spec != true) — the spec is "
                      "not proven operator intent and the state-changing steps were not owner-approved; "
                      "cannot mint (inconclusive, never a FACT)"))

    if mode == "race":
        return _workflow_race(obs, base)
    return _workflow_tamper(obs, base)


def mfa_bypass_oracle(observed: Any) -> OracleSignal:
    """Fire when a session that completed ONLY factor-1 achieves a read of a victim-PRIVATE datum the app gates
    BEHIND factor-2 — the ACHIEVED-STATE proof of an MFA bypass (CWE-287 improper authentication / CWE-308
    single-factor-only), under a FAIL-CLOSED operator attestation. An achieved post-MFA state CANNOT be proven
    from response content, and an intentionally factor-1 page is indistinguishable from a bypass without operator
    intent, so this oracle requires BOTH the three-part attestation (LOCK 1) AND the PRIVATE-READ REDUCTION
    (LOCK 2, reusing :func:`_sfx_private_read_achieved`) — re-derived from RAW retained bytes, never a bool.

    ``observed`` is the retained record ``scanner.mfa.MfaBypassCheck`` captured through the gated ``send``:

      * ``operator_attestation`` — ``{mfa_enrolled_account, factor1_only_presented, post_mfa_resource_certified}``
        (each strict ``is True``): the HARD certification gate;
      * ``private_discriminator`` (D) — the operator's genuine victim-PRIVATE post-MFA-gated datum;
      * ``factor1_view``  — ``{status, body}`` of the post-MFA resource read carrying ONLY the factor-1 session;
      * ``owner_view``    — ``{status, body}`` of the SAME resource read by the fully post-MFA-authenticated
        owner (the POSITIVE reference: D must be PRESENT);
      * ``pre_mfa_ref``   — ``{status, body}`` of the SAME resource read by an OTHER not-post-MFA identity (the
        DECISIVE SAME-SHAPE negative reference: a substantive 2xx from which D must be ABSENT);
      * ``logged_out_ref``— ``{status, body}`` of the SAME resource with NO session (the no-session baseline);
      * ``logged_out_markers`` / ``logged_out_statuses`` — the operator's decisive not-authenticated signals.

    Adjudication:

      * attestation NOT fully present (LOCK 1 open) ⇒ NO fire for ANY input — refuse to mint (LEAD); the killer
        FP of an intentionally factor-1 page can never round to a FACT;
      * attested, but :func:`_sfx_private_read_achieved` is ``None`` (no / invalid / reflected D; a
        non-substantive factor-1 read; no substantive owner positive reference or D absent from it; no
        substantive SAME-SHAPE other-identity reference; no valid no-session baseline; or D present in a negative
        reference) ⇒ LEAD (never a FACT, never a false CLEAN);
      * attested, and the factor-1-only session did NOT reach the victim's post-MFA private view (D absent from
        its otherwise-substantive read, present for the owner) ⇒ the app enforces factor-2 — channel-confirmed
        CLEAN (the benign twin);
      * attested, and the factor-1-only session reached the victim's post-MFA private view ⇒ FIRE.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    attested = _mfa_attested(obs.get("operator_attestation"))
    discriminator = _coerce_text(obs.get("private_discriminator")).strip()
    base = {"operator_attested": attested}

    # LOCK 1 — the FAIL-CLOSED operator attestation (Wave-3.4 certification-gate shape), re-derived from the
    # retained record at EVERY verification so a tampered / absent attestation refuses to mint offline. This is
    # the HARD precondition and it is checked FIRST, so NO input — benign or a bypass — mints without it, and an
    # intentionally factor-1 page (the killer FP) can never round to a FACT.
    if not attested:
        return _mfa_signal(
            False, observed=base,
            evidence=("no complete operator MFA attestation (mfa_enrolled_account + factor1_only_presented + "
                      "post_mfa_resource_certified, each strict True) — refuse to mint (LEAD). An intentionally "
                      "factor-1 page is indistinguishable from a bypass without the operator certifying the "
                      "resource is genuinely post-MFA-gated; absent the attestation this class is a rigorous LEAD"))

    # LOCK 2 — RE-DERIVE the achieved post-MFA read from RAW retained bytes via the PRIVATE-READ REDUCTION (the
    # SAME machinery SESSION_FIXATION / Wave-3.1 IDOR use). No VIGIL cookie sentinel here (a real factor-1
    # login), so no per-probe sentinel is passed; the (a)-(c) private-read differential is the load-bearing
    # proof. None ⇒ undecidable (no/invalid/reflected D, non-substantive factor-1 read, missing/failing owner
    # positive reference, missing/non-substantive-same-shape other-identity reference, missing/invalid
    # no-session baseline, or D present in a negative reference) ⇒ LEAD.
    reached = _sfx_private_read_achieved(discriminator, obs.get("factor1_view"), obs.get("owner_view"),
                                         obs.get("pre_mfa_ref"), obs.get("logged_out_ref"),
                                         obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
                                         sentinel_id="")
    if reached is None:
        return _mfa_signal(
            False, observed={**base, "discriminator_len": len(discriminator)},
            evidence=("attested, but the achieved post-MFA state could not be proven by the PRIVATE-READ "
                      "differential (no valid victim-private discriminator D; a non-substantive factor-1 read; no "
                      "substantive post-MFA owner positive reference or D absent from it; no substantive "
                      "SAME-SHAPE other-identity reference — a denial/empty/error/different-shape is refused; no "
                      "valid no-session baseline; or D present in a negative reference — chrome/shared/public) — "
                      "cannot mint (LEAD)"))

    # attested AND the factor-1-only session did NOT reach the victim's post-MFA private view ⇒ the app enforces
    # factor-2 (the benign twin). D absent from the factor-1-only read yet present for the owner — a
    # channel-confirmed CLEAN, never a FACT.
    if reached is not True:
        return _mfa_signal(
            False, conclusive=True, observed={**base, "factor1_reached_private": False},
            evidence=("the factor-1-only session did not reach the victim's post-MFA private view (the private "
                      "datum D is absent from its read, present for the post-MFA owner) — the app enforces the "
                      "second factor; did not fire"))

    return _mfa_signal(
        True, conf=0.92,
        evidence=("MFA bypass: a session that completed ONLY factor-1 achieved a read of a victim-PRIVATE datum "
                  "the app gates behind factor-2 — the private discriminator D is PRESENT in the factor-1-only "
                  "read AND in the fully post-MFA-authenticated owner's read yet PROVABLY ABSENT from a "
                  "SUBSTANTIVE SAME-SHAPE read by an OTHER not-post-MFA identity and from a no-session baseline "
                  "(the private-read differential proves the factor-1-only session reached the victim's "
                  "post-MFA-gated content), under the operator's attestation that the account is MFA-enrolled, "
                  "only factor-1 was presented, and the resource is genuinely post-MFA-gated"),
        observed={"operator_attested": True, "factor1_reached_private": True,
                  "differential": "private_datum_present_in_factor1_only_and_owner_reads_absent_in_same_shape_"
                  "other_identity_and_no_session_references"})


_PRT_MIN_TOKEN = 8


_PRT_MIN_SECRET = 8


_PRT_MIN_COLLISION_SAMPLES = 2


_PRT_MIN_ADJACENCY_SAMPLES = 3


_PRT_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


_PRT_DEC_RE = re.compile(r"^[0-9]+$")


def _prt_signal(fired: bool, *, mode: str, evidence: str, observed: dict, conf: float = 0.92,
                conclusive: bool = False) -> OracleSignal:
    # kind is the DEDICATED OracleKind.PASSWORD_RESET_INVARIANT (held OUT of the frozen _ALL_ORACLES, so the
    # unknown-class fallback stays EXACTLY 15 and oracle_version(ACHIEVED_STATE) is untouched). A fire is always
    # decisive; a NON-fire is ``conclusive`` ONLY for a channel-confirmed clean (a single-use token that
    # correctly expired; a set of distinct high-entropy tokens) — an undecidable/insufficient-sample non-fire is
    # a LEAD (conclusive=False), never a false CLEAN.
    return OracleSignal(kind=OracleKind.PASSWORD_RESET_INVARIANT, fired=fired,
                        confidence=(conf if fired else 0.0),
                        conclusive=(True if fired else conclusive),
                        evidence=evidence, observed={**observed, "mode": mode})


def _prt_parse_counter(tok: str) -> "int | None":
    """A reset token's numeric value if it is a PURE decimal or PURE hex integer, else ``None``. Deterministic;
    used ONLY to test an EXACT arithmetic progression (the deterministic 'adjacent' collision), never entropy."""
    t = _coerce_text(tok).strip()
    if not t:
        return None
    if _PRT_DEC_RE.match(t):
        try:
            return int(t, 10)
        except ValueError:
            return None
    if _PRT_HEX_RE.match(t):
        try:
            return int(t, 16)
        except ValueError:
            return None
    return None


def _prt_normalize_samples(raw: Any) -> "list[tuple[str, str]]":
    """Coerce the retained collision captures into ``(token, account)`` pairs, in request order. Accepts the
    canonical richer form (a list of ``{"token","account"}`` mappings the scanner now records so a CROSS-USER
    identical token can be proven) OR a flat list of token strings (accounts UNKNOWN — a cross-user identity
    cannot be established, so a byte-identical pair fails closed to a LEAD, never a FACT)."""
    out: list[tuple[str, str]] = []
    for item in (raw or []):
        if isinstance(item, Mapping):
            tok = _coerce_text(item.get("token")).strip()
            acct = _coerce_text(item.get("account")).strip()
        else:
            tok, acct = _coerce_text(item).strip(), ""
        if tok:
            out.append((tok, acct))
    return out


def _prt_collision(samples: Any) -> "tuple[bool | None, dict]":
    """Deterministic collision adjudication over reset tokens captured from INDEPENDENT requests (in request
    order), each carrying the account LABEL it was issued for. The ONLY genuinely-EXPLOITABLE predicate provable
    from the token bytes ALONE is a PREDICTABLE COUNTER (an exact arithmetic progression). A BYTE-IDENTICAL token
    — whether it repeats for the SAME account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a
    FACT here: account labels are opaque strings NEVER proven to be distinct PRINCIPALS. A benign per-user-
    DETERMINISTIC, identifier-NORMALIZING generator (case-insensitive email/username) returns byte-identical
    tokens for 'alice' and 'Alice' — ONE principal, not two — so a byte-identical token across labels would mint
    a FALSE cross-user FACT; and a cryptographically-secure DETERMINISTIC generator (stock Django
    default_token_generator within a timestamp bucket, a cache-one-token-per-account app) returns byte-identical
    tokens for one user. Genuine CROSS-PRINCIPAL exploitation is proven ONLY by the EXISTING
    ``password_reset_cross_user`` private-read differential (a token issued to principal A actually authorizes a
    read of principal B's PRIVATE datum), never by label identity here. TRI-STATE:

      * ``True``  — a PREDICTABLE counter: >=3 tokens forming an EXACT arithmetic progression (every token parses
        as a fixed-width integer counter and the step between consecutive values is a single constant nonzero
        delta, reproduced from the observed sequence). Genuinely exploitable regardless of identity: observe one
        token, predict the next. This is the ONLY token-shape provable as a FACT from the captures alone;
      * ``False`` — all tokens DISTINCT with no exact progression ⇒ proper generation ⇒ channel-confirmed clean;
      * ``None``  — fewer than 2 samples, any sample below the minimum length, OR ANY byte-identical repeat (same
        OR cross label) with no exact progression ⇒ undecidable ⇒ LEAD, never a FACT, never a CLEAN. A
        byte-identical repeat across DIFFERENT labels is a LEAD to escalate via the cross-user private-read
        differential — it is NOT proof of a weak generator on its own.

    ENTROPY is never scored here: a set of distinct tokens is CLEAN regardless of apparent randomness — a
    low-entropy-but-distinct token stays a probabilistic LEAD in the scanner, never a FACT."""
    pairs = _prt_normalize_samples(samples)
    toks = [t for t, _ in pairs]
    if len(pairs) < _PRT_MIN_COLLISION_SAMPLES or any(len(t) < _PRT_MIN_TOKEN for t in toks):
        return None, {"n": len(pairs)}
    # (1) EXACT deterministic arithmetic progression (>=3 fixed-width integer counters, constant nonzero step) —
    # a PREDICTABLE counter reproduced from the observed sequence. Sound regardless of account label: a
    # predictable counter is exploitable across principals (observe one token, predict the next). This is the
    # ONLY token-shape a FACT can rest on from the captures alone.
    if len(toks) >= _PRT_MIN_ADJACENCY_SAMPLES and len({len(t) for t in toks}) == 1:
        vals = [_prt_parse_counter(t) for t in toks]
        if all(v is not None for v in vals):
            steps = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]  # type: ignore[operator]
            if steps and steps[0] != 0 and all(s == steps[0] for s in steps):
                return True, {"identical": False, "arithmetic": True, "samples": len(toks), "step": steps[0]}
    # (2) ANY byte-identical repeat — SAME account label OR across DIFFERENT account LABELS — with no exact
    # progression ⇒ UNDECIDABLE ⇒ LEAD, never a FACT: account labels are never proven to be distinct PRINCIPALS
    # (a benign identifier-NORMALIZING generator returns byte-identical tokens for 'alice'/'Alice' = ONE
    # principal), and a deterministic-but-secure generator returns byte-identical tokens for one user. Surface
    # whether the repeat SPANNED distinct labels (a stronger LEAD to escalate via the cross-user private-read
    # differential), but NEVER mint here — genuine cross-principal exploitation is proven only by
    # ``password_reset_cross_user`` (the private-read reduction), never by token identity.
    if len(set(toks)) < len(toks):
        by_token: dict[str, set[str]] = {}
        for tok, acct in pairs:
            by_token.setdefault(tok, set()).add(acct)
        cross_label = any(len({a for a in accts if a}) >= 2 for accts in by_token.values())
        return None, {"identical_lead": True, "cross_label": cross_label, "samples": len(pairs)}
    # (3) all tokens DISTINCT, no exact progression ⇒ proper generation ⇒ clean.
    return False, {"distinct": len(set(toks)), "samples": len(pairs)}


def _prt_reuse_p2_binding(replay_secret: str, consumed_secret: str, authorized_secret: str,
                          discriminator: str, authorized_view: Any) -> "str | None":
    """Bind the achieved token-reuse read to the REPLAY-set secret P2 — mirroring session fixation's
    sentinel-binding discipline. Returns a LEAD reason string if the binding fails (⇒ the oracle degrades to a
    LEAD, never a FACT), or ``None`` when the binding holds. The binding is what makes a reuse FACT sound: a
    single-use / expiring token whose replay set NOTHING could still read the private datum via a leftover
    session established by the FIRST consume; without this binding that would mint a FALSE reuse FACT. So a fire
    requires the achieved read to be provably attributable to the REPLAY (P2), not the consume (P1):

      * ``replay_secret`` (P2) present and non-trivial (a fresh VIGIL secret the replay set);
      * ``consumed_secret`` (P1) present and non-trivial AND DISTINCT from P2 — so a successful authenticated
        read cannot be attributed to the FIRST consume;
      * ``authorized_secret`` == ``replay_secret`` — the authenticated read was EXPLICITLY reached WITH P2 (not
        P1, not a leftover consume-session);
      * D is not an echo of P2 (a substring of, or present only as part of, the reflected secret) — the
        reflected-value / straddle guard, mirroring the sentinel echo guard in ``_sfx_private_read_achieved``."""
    if len(replay_secret) < _PRT_MIN_SECRET:
        return ("the replay-set secret P2 is absent or too short to bind the achieved read to the replayed "
                "token — cannot mint (LEAD)")
    if len(consumed_secret) < _PRT_MIN_SECRET or replay_secret == consumed_secret:
        return ("the replay-set secret P2 is not a distinct, non-trivial secret from the consumed secret P1 — a "
                "successful read cannot be attributed to the REPLAY rather than the first consume (LEAD)")
    if authorized_secret != replay_secret:
        return ("the authenticated read was NOT reached with the replay-set secret P2 (authorized_secret != "
                "replay_secret) — the achieved state is not bound to the replayed token (e.g. a leftover "
                "consume-session or the consumed P1) — cannot mint (LEAD)")
    if discriminator and discriminator in replay_secret:
        return ("the private datum D is a substring of the replay-set secret P2 (a credential echo, not "
                "access-gated content) — cannot mint (LEAD)")
    a_body = _coerce_text(authorized_view.get("body")) if isinstance(authorized_view, Mapping) else ""
    if replay_secret and replay_secret in a_body and discriminator and discriminator in a_body \
            and discriminator not in a_body.replace(replay_secret, "\x00"):
        return ("the private datum D appears in the replay-authenticated read ONLY as part of the echoed secret "
                "P2 — a credential echo, not access-gated content — cannot mint (LEAD)")
    return None


def password_reset_invariant_oracle(observed: Any) -> OracleSignal:
    """Fire on an invariant-FREE password-reset / account-recovery sub-property, proven WITHOUT operator intent
    over VIGIL's OWN retained raw bytes (never a bool, never a bare marker/entropy heuristic). ``observed`` is
    the record ``scanner.reset`` captured through the gated send; ``mode`` selects the sub-property:

      * ``token_reuse`` — a reset token that was CONSUMED (set the account password to a first VIGIL secret P1)
        is REPLAYED to set a SECOND, unique VIGIL secret P2; the runner then AUTHENTICATES with P2 and reads the
        account. The achieved read is first BOUND to P2 (:func:`_prt_reuse_p2_binding` — P2 present + non-trivial
        + DISTINCT from P1, the read explicitly reached WITH P2, D not an echo of P2), mirroring session
        fixation's sentinel-binding so a fire proves the REPLAY re-changed the credential, never a leftover
        consume-session or the consumed P1. It then fires ONLY when the PRIVATE-READ REDUCTION
        (:func:`_sfx_private_read_achieved`) proves that read reached a victim-PRIVATE datum D — D PRESENT in the
        replay-authenticated read AND in the owner's authoritative read yet PROVABLY ABSENT from a SUBSTANTIVE
        SAME-SHAPE unauthorized read and a no-session baseline (so the second submit GENUINELY changed the
        credential, not merely returned 200). A single-use token that correctly expires (the benign twin) leaves
        P2 unset — the replay-authenticated read never reaches D ⇒ channel-confirmed CLEAN. A failed P2-binding
        (P2 absent/short/equal-to-P1, or the read reached with the WRONG secret), no/invalid/reflected D, a
        missing positive or same-shape negative reference, D present in a negative reference, or a non-substantive
        read ⇒ LEAD (never a FACT, never a false CLEAN).
      * ``token_collision`` — ``samples`` are ``{token, account}`` captures from INDEPENDENT reset requests (in
        order); a flat ``tokens`` list is accepted with account labels UNKNOWN. Fires ONLY on a genuinely-
        EXPLOITABLE PREDICTABLE COUNTER (:func:`_prt_collision`): >=3 tokens forming an EXACT arithmetic
        progression (observe one token, predict the next — exploitable regardless of identity). A BYTE-IDENTICAL
        token — same account LABEL or across DIFFERENT account LABELS — is DELIBERATELY NOT a FACT: account labels
        are never proven to be distinct PRINCIPALS (a benign identifier-NORMALIZING generator maps 'alice'/'Alice'
        to ONE principal; a deterministic-but-secure generator repeats for one user) ⇒ LEAD; genuine cross-
        principal exploitation is minted only by the ``password_reset_cross_user`` private-read differential. A
        set of distinct tokens (the benign twin) ⇒ channel-confirmed CLEAN; too few / too-short samples ⇒ LEAD.
        ENTROPY alone is never a FACT here.

    Pure + deterministic; never raises."""
    obs = observed if isinstance(observed, Mapping) else {}
    mode = _coerce_text(obs.get("mode")).strip()

    if mode == "token_reuse":
        reset_token = _coerce_text(obs.get("reset_token")).strip()
        discriminator = _coerce_text(obs.get("private_discriminator")).strip()
        replay_secret = _coerce_text(obs.get("replay_secret")).strip()
        consumed_secret = _coerce_text(obs.get("consumed_secret")).strip()
        authorized_secret = _coerce_text(obs.get("authorized_secret")).strip()
        base = {"reset_token_len": len(reset_token), "discriminator_len": len(discriminator),
                "replay_secret_bound": False}
        # P2-BINDING (mirror session fixation's sentinel-binding): the achieved read MUST be attributable to the
        # REPLAY-set secret P2, not the consumed P1 / a leftover consume-session — else a single-use token whose
        # replay set nothing could still read D via the first consume and mint a FALSE reuse FACT. Fail ⇒ LEAD.
        bind_fail = _prt_reuse_p2_binding(replay_secret, consumed_secret, authorized_secret,
                                          discriminator, obs.get("authorized_view"))
        if bind_fail is not None:
            return _prt_signal(False, mode=mode, observed=base, evidence=bind_fail)
        base["replay_secret_bound"] = True
        # RE-DERIVE the achieved changed state from RAW retained bytes via the PRIVATE-READ REDUCTION — the same
        # same-shape differential Wave-3.1/3.2 use. The consumed-then-replayed token is passed as the sentinel so
        # its reflected-value / straddle guard masks any echo of the token itself (a reset token must never be
        # the datum that satisfies the read). None ⇒ undecidable ⇒ LEAD.
        achieved = _sfx_private_read_achieved(
            discriminator, obs.get("authorized_view"), obs.get("owner_view"),
            obs.get("unauth_ref"), obs.get("logged_out_ref"),
            obs.get("logged_out_markers"), obs.get("logged_out_statuses"),
            sentinel_id=reset_token)
        if achieved is None:
            return _prt_signal(
                False, mode=mode, observed=base,
                evidence=("password-reset token-reuse could not be proven by the PRIVATE-READ differential (no "
                          "valid victim-private datum D; D reflects/straddles the reset token; a non-substantive "
                          "replay-authenticated read; no substantive owner positive reference or D absent from "
                          "it; no substantive SAME-SHAPE unauthorized reference; no valid no-session baseline; or "
                          "D present in a negative reference) — cannot mint (LEAD)"))
        if achieved is not True:
            return _prt_signal(
                False, mode=mode, conclusive=True, observed=base,
                evidence=("the reset token, once consumed, no longer set a new credential on replay — the "
                          "replay-set secret does not reach the victim's private view (single-use / expiring "
                          "token, the correct defense); did not fire"))
        return _prt_signal(
            True, mode=mode, conf=0.92, observed={**base, "reset_token": reset_token,
                                                  "differential": "replay_set_credential_reaches_private_datum_"
                                                  "absent_in_same_shape_unauthorized_and_no_session_reads"},
            evidence=("password-reset token REUSE / NON-EXPIRY: a reset token that was already CONSUMED was "
                      "REPLAYED to set a SECOND unique VIGIL secret P2 (distinct from the consumed P1) and the "
                      "second submit GENUINELY changed the credential — authenticating WITH P2 reaches a "
                      "victim-PRIVATE datum D that is PRESENT in the owner's authoritative read yet PROVABLY "
                      "ABSENT from a SUBSTANTIVE SAME-SHAPE unauthorized read and a no-session baseline (the "
                      "P2-bound private-read reduction proves the REPLAY re-changed the credential, not a bare "
                      "200 nor a leftover consume-session) — the recovery token is reusable / does not expire"))

    if mode == "token_collision":
        fired, detail = _prt_collision(obs.get("samples") if obs.get("samples") is not None else obs.get("tokens"))
        if fired is None:
            return _prt_signal(
                False, mode=mode, observed=detail,
                evidence=("no genuinely-exploitable reset-token collision could be adjudicated from the tokens "
                          "alone: too few / too-short samples (need >=2 captures of length >= 8), OR a "
                          "BYTE-IDENTICAL token that repeats — whether for the SAME account LABEL or across "
                          "DIFFERENT account LABELS. A byte-identical repeat is NOT an exploitable collision here: "
                          "account labels are never proven to be distinct PRINCIPALS (a benign identifier-"
                          "NORMALIZING generator returns identical tokens for 'alice'/'Alice' = ONE principal) and "
                          "a cryptographically-secure DETERMINISTIC generator (e.g. Django default_token_generator "
                          "within a timestamp bucket, or a cache-one-token-per-account app) returns identical "
                          "tokens for one user — a LEAD to escalate via the password_reset_cross_user private-read "
                          "differential, never a FACT here"))
        if fired is False:
            return _prt_signal(
                False, mode=mode, conclusive=True, observed=detail,
                evidence=("the independent reset requests returned DISTINCT tokens with no exact arithmetic "
                          "progression — proper generation (entropy is not scored here); did not fire"))
        # A fire here is EXCLUSIVELY the PREDICTABLE-COUNTER shape (an exact arithmetic progression). The
        # byte-identical cross-label 'collision' FACT path is RETIRED (⇒ LEAD): account-label identity never
        # proves distinct PRINCIPALS, so genuine cross-principal exploitation is minted only by the
        # password_reset_cross_user private-read differential, never from token identity.
        return _prt_signal(
            True, mode=mode, conf=0.95, observed=detail,
            evidence=(f"deterministic password-reset token COLLISION: {detail.get('samples')} independent reset "
                      f"requests returned tokens forming an EXACT arithmetic progression (constant step "
                      f"{detail.get('step')!r}) — the recovery token is a predictable counter, not a random value; "
                      f"observe one token and the victim's is predictable (exploitable regardless of identity)"))

    return _prt_signal(
        False, mode=(mode or "unknown"), observed={},
        evidence="unknown/absent password-reset invariant mode — cannot adjudicate (inconclusive)")


def service_reachability_oracle(observed_handshake: Any) -> OracleSignal:
    """Fire when a REAL transport handshake to a service reproduced — a completed TCP connect to the
    claimed host:port (optionally corroborated by a service banner the endpoint sent). This is what
    promotes a scanner's "open 443" OBSERVATION (Nmap et al.) into a reachability FACT: the port is
    open iff a live handshake actually connected, judged here over the RETAINED connect evidence —
    pure, deterministic, and re-runnable offline, so a scanner's say-so alone never confirms.

    ``observed_handshake`` is the JSON-safe evidence a reachability probe captured::

        {"connected": bool, "host": str, "port": int, "protocol": "tcp"|"udp",
         "peer": "ip:port"?, "banner": str?, "error": str?}

    Fires only when ``connected is True`` AND the evidence names the concrete host+port the connect
    resolved to. A completed TCP three-way handshake IS the proof of reachability, so a bare connect
    confirms at 0.90; a captured service BANNER — raw application-layer bytes the endpoint actually
    sent, a genuine re-derivable artifact — raises it to 0.97. (The captured ``peer`` is retained for
    the audit trail but does NOT raise confidence: ``getpeername`` returns the very port we dialled,
    so a "peer port matches" check is self-referential and would over-state a bare connect.) A refused
    / timed-out / UDP-without-a-banner / malformed handshake does not fire — an absent or negative
    signal is never an assumed pass.

    GROUNDING is procedural, exactly as for every oracle: the handshake MUST originate from a real
    gated capture (``verify.reachability.capture_handshake``), never a scanner's parsed "open" row —
    that is what keeps this a re-verification rather than a rubber-stamp of the scanner's say-so."""
    if not isinstance(observed_handshake, Mapping):
        return OracleSignal(kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
                            evidence="no handshake evidence")
    hs = observed_handshake
    connected = hs.get("connected")
    host = _coerce_text(hs.get("host")).strip()
    protocol = (_coerce_text(hs.get("protocol")).strip().lower() or "tcp")
    try:
        port_i = int(hs["port"]) if hs.get("port") is not None else None
    except (TypeError, ValueError, KeyError):
        port_i = None

    if connected is not True or not host or port_i is None:
        reason = _coerce_text(hs.get("error")).strip() or "no completed handshake to a concrete host:port"
        return OracleSignal(
            kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
            evidence=f"not reachable: {reason}",
            observed={"host": host, "port": port_i, "connected": connected})

    banner = _coerce_text(hs.get("banner")).strip()
    peer = _coerce_text(hs.get("peer")).strip()
    # UDP has no connection handshake — only an application-layer response proves reachability.
    if protocol == "udp" and not banner:
        return OracleSignal(
            kind=OracleKind.SERVICE_REACHABILITY, fired=False, confidence=0.0,
            evidence="udp reachability needs a service response (no banner)",
            observed={"host": host, "port": port_i, "protocol": protocol})

    # Only a real service banner corroborates beyond the bare handshake — the captured peer port is
    # definitionally the one we dialled, so it carries no independent signal.
    confidence = 0.97 if banner else 0.90
    detail = f"banner {banner[:48]!r}" if banner else (f"peer {peer}" if peer else "tcp connect")
    return OracleSignal(
        kind=OracleKind.SERVICE_REACHABILITY, fired=True, confidence=confidence,
        evidence=f"{protocol} handshake reproduced to {host}:{port_i} ({detail})",
        observed={"host": host, "port": port_i, "protocol": protocol,
                  "peer": peer, "banner": banner[:96]})


def anonymous_reachable_oracle(observed_capture: Any) -> OracleSignal:
    """Fire when a bounded, UNAUTHENTICATED HTTP GET actually reached a resource anonymously — the
    endpoint answered a credential-free request with an HTTP 2xx and a non-empty body. This is what
    promotes a cloud POSTURE fact ("this bucket is public" — an anonymous grant path the POLICY_PATH
    oracle re-derived over the retained export) into an ACTIVE-EXPOSURE FACT: the resource is not merely
    *configured* public, it is *provably* fetchable by anyone, judged here over the RETAINED capture
    ALONE — pure, deterministic, re-runnable offline, so a posture heuristic alone never confirms it.

    ``observed_capture`` is the JSON-safe evidence a gated anonymous GET captured
    (``verify.reachability_cloud.capture_anonymous_get``)::

        {"url": str, "status": int|None, "body_len": int, "snippet": str,
         "content_type": str, "authenticated": bool, "error": str?}

    Fires iff (a) the request was UNAUTHENTICATED — the capture does NOT record credentials
    (``authenticated`` is not ``True``): this oracle proves ANONYMOUS reachability, so a capture that
    admits it carried auth must NOT confirm; AND (b) ``status`` is an integer in 200..299 — a real
    success, so a 3xx redirect, a 401/403 (present-but-protected — the OPPOSITE of the claim), a 404
    (absent), or a ``None`` (gate refusal / connect failure) does NOT fire; AND (c) ``body_len`` > 0 —
    the endpoint actually returned content, not an empty 204/200. A completed anonymous 2xx-with-body IS
    the proof of public reachability. An absent or negative signal is never an assumed pass.

    GROUNDING is procedural, exactly as for ``service_reachability_oracle``: the capture MUST originate
    from a real gated GET (``capture_anonymous_get``: kill-switch -> single-host -> ACTIVE_RECON ->
    charter scope, credential-free), never a posture tool's "public=true" say-so — that is what keeps
    this a re-verification of *reachability* rather than a rubber-stamp of the *configuration*."""
    if not isinstance(observed_capture, Mapping):
        return OracleSignal(kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
                            evidence="no capture evidence")
    cap = observed_capture
    url = _coerce_text(cap.get("url")).strip()
    # status is the AUTHORITY's input — accept ONLY a real int (a bool or a "200" string is NOT a status);
    # anything else is UNKNOWN → no fact (C3 red-pen LOW-1: the sole oracle must not coerce a non-int).
    raw_status = cap.get("status")
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else None
    try:
        body_len = int(cap.get("body_len") or 0)
    except (TypeError, ValueError):
        body_len = 0

    # (a) an anonymous proof must not have carried credentials — refuse ANY truthy `authenticated` (a
    # string "true" must not evade a strict `is True`; C3 red-pen LOW-1).
    if bool(cap.get("authenticated")):
        return OracleSignal(
            kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
            evidence="capture carried credentials — cannot prove ANONYMOUS reachability",
            observed={"url": url, "status": status, "authenticated": True})
    # (b)/(c) an unauthenticated 2xx with a present body, judged over the retained response alone.
    if status is None or not (200 <= status <= 299) or body_len <= 0:
        reason = _coerce_text(cap.get("error")).strip() or (
            f"status {status}, body_len {body_len} — not an unauthenticated 2xx with a present body")
        return OracleSignal(
            kind=OracleKind.ACTIVE_EXPOSURE, fired=False, confidence=0.0,
            evidence=f"not anonymously reachable: {reason}",
            observed={"url": url, "status": status, "body_len": body_len})

    content_type = _coerce_text(cap.get("content_type")).strip()
    return OracleSignal(
        kind=OracleKind.ACTIVE_EXPOSURE, fired=True, confidence=0.95,
        evidence=(f"unauthenticated GET reached {url or 'the resource'} — HTTP {status} with a "
                  f"{body_len}-byte body (content-type {content_type or 'unknown'})"),
        observed={"url": url, "status": status, "body_len": body_len,
                  "content_type": content_type[:96], "authenticated": False})


_DEPRECATED_TLS_VERSIONS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"})


_WEAK_CIPHER_TOKENS: tuple[tuple[str, str], ...] = (
    ("RC4", "RC4 keystream biases"),
    ("RC2", "RC2 is broken"),
    ("3DES", "3DES/Sweet32 (64-bit block)"),
    ("DES-CBC3", "3DES/Sweet32 (64-bit block)"),
    ("DES-CBC", "single-DES 56-bit key"),
    ("EXPORT", "export-grade (deliberately weakened) crypto"),
    ("EXP-", "export-grade (deliberately weakened) crypto"),
    ("NULL", "NULL cipher — no encryption"),
    ("ADH", "anonymous DH — no authentication"),
    ("AECDH", "anonymous ECDH — no authentication"),
    ("ANON", "anonymous key exchange — no authentication"),
    ("MD5", "MD5 MAC is broken"),
    ("IDEA", "IDEA is deprecated"),
    ("SEED", "SEED is deprecated"),
)


def tls_weakness_oracle(observed_tls: Any) -> OracleSignal:
    """Fire when a REAL TLS handshake negotiated a DEPRECATED protocol or a WEAK cipher suite — the
    server actually agreed to it, so it is a re-verifiable FACT about the endpoint's crypto posture,
    not a config guess. Judges the retained handshake (``verify.tls.capture_tls_handshake`` captured it
    over a live connection); a strong TLS1.2/1.3 handshake with a modern suite does NOT fire (good
    posture is not a finding), and an absent/failed handshake does not fire.

    ``observed_tls`` is JSON-safe evidence::

        {"connected": bool, "host": str, "port": int, "tls_version": "TLSv1"|"TLSv1.2"|...,
         "cipher": "ECDHE-RSA-AES128-GCM-SHA256"|..., "cipher_bits": int?, "error": str?}

    A deprecated protocol confirms at 0.95; a weak cipher at 0.92. Pure and deterministic, so the same
    verdict re-verifies offline from the retained context — an absent signal is never an assumed pass."""
    if not isinstance(observed_tls, Mapping):
        return OracleSignal(kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
                            evidence="no tls handshake evidence")
    tls = observed_tls
    if tls.get("connected") is not True:
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
            evidence=f"no completed tls handshake: {_coerce_text(tls.get('error')).strip() or 'not connected'}")
    host = _coerce_text(tls.get("host")).strip()
    version_raw = _coerce_text(tls.get("tls_version")).strip()
    cipher_raw = _coerce_text(tls.get("cipher")).strip()
    version_u = version_raw.upper()
    cipher_u = cipher_raw.upper()

    if version_u in _DEPRECATED_TLS_VERSIONS:
        return OracleSignal(
            kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.95,
            evidence=f"{host or 'endpoint'} negotiated deprecated protocol {version_raw}",
            observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw,
                      "reason": "deprecated_protocol"})
    for token, why in _WEAK_CIPHER_TOKENS:
        if token in cipher_u:
            return OracleSignal(
                kind=OracleKind.TLS_WEAKNESS, fired=True, confidence=0.92,
                evidence=f"{host or 'endpoint'} negotiated weak cipher {cipher_raw or '?'} — {why}",
                observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw,
                          "reason": "weak_cipher", "token": token})
    return OracleSignal(
        kind=OracleKind.TLS_WEAKNESS, fired=False, confidence=0.0,
        evidence=f"no TLS weakness: negotiated {version_raw or '?'} / {cipher_raw or '?'}",
        observed={"host": host, "tls_version": version_raw, "cipher": cipher_raw})


_CERT_VALIDITY_DEFECTS: tuple[str, ...] = ("expired", "not_yet_valid", "hostname_mismatch", "self_signed")


def _cert_validity_epochs(cert: Any) -> "tuple[int, int]":
    """(not_before, not_after) as UTC epochs, preferring the timezone-aware accessors so the comparison is
    unambiguous on every ``cryptography`` version."""
    import datetime

    def _epoch(aware_attr: str, naive_attr: str) -> int:
        dt = getattr(cert, aware_attr, None)
        if dt is None:
            dt = getattr(cert, naive_attr)
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())

    return (_epoch("not_valid_before_utc", "not_valid_before"),
            _epoch("not_valid_after_utc", "not_valid_after"))


def _cert_validity_identity_matches(cert: Any, host: str) -> "tuple[bool, list[str]]":
    """(matched, presented_identities) for ``host`` against the leaf's SAN dNSName / iPAddress entries,
    falling back to the subject CN only when the cert presents no SAN at all (RFC 6125 §6.4.4). Wildcards
    match ONE left-most label, as a browser does. Deterministic: no DNS, no clock, no network."""
    import ipaddress

    from cryptography import x509

    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.extend(str(n) for n in san.get_values_for_type(x509.DNSName))
        names.extend(str(n) for n in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    if not names:
        try:
            from cryptography.x509.oid import NameOID
            names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        except Exception:  # noqa: BLE001
            names = []
    target = (host or "").strip().strip("[]").lower()
    try:
        target_ip: "ipaddress._BaseAddress | None" = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None
    for raw in names:
        cand = str(raw).strip().lower()
        if target_ip is not None:
            try:
                if ipaddress.ip_address(cand) == target_ip:
                    return True, [str(n) for n in names]
            except ValueError:
                continue
            continue
        if cand == target:
            return True, [str(n) for n in names]
        if cand.startswith("*.") and "." in target and target.split(".", 1)[1] == cand[2:]:
            return True, [str(n) for n in names]
    return False, [str(n) for n in names]


def _cert_validity_self_signed(cert: Any) -> bool:
    """True iff issuer == subject AND the certificate's signature verifies under its OWN public key. The
    second half matters: a name collision alone is not self-issuance. Fail-closed — any verification error
    returns False rather than asserting self-signature."""
    try:
        if cert.issuer != cert.subject:
            return False
    except Exception:  # noqa: BLE001
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001
        return False


def certificate_validity_oracle(observed: Any) -> OracleSignal:
    """Fire when the presented leaf has a VALIDITY defect — expired / not-yet-valid (against the RETAINED
    capture instant), hostname-mismatch (SAN/CN vs the captured host), or self-signed (structural). The proof
    is the retained DER bytes + the retained instant + its provenance — a pure, deterministic re-derivation
    that re-verifies OFFLINE, exactly like ``weak_crypto_artifact_oracle`` re-derives the signature hash.

    REFUSES (a non-fire, never a raise) when there is nothing it may soundly judge:
      * no mapping / no ``cert_der_b64`` / unparseable DER — nothing to judge;
      * ``captured_at_epoch`` missing or not an int — no retained instant to compare against;
      * ``capture_time_source`` missing/empty — the instant has no provenance, so the oracle will NOT assume
        one (the WIRING TRAP: a trusted timestamp the evidence never earned). The capture must stamp it.

    A non-fire over a LEAF cert is NOT a clean certificate — the branch is clean_incapable (leaf-only, no
    chain), so admission maps a conclusive non-fire to INCONCLUSIVE, never CLEAN."""
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="no certificate-validity evidence")
    b64 = _coerce_text(observed.get("cert_der_b64")).strip()
    if not b64:
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="no retained certificate (cert_der_b64 absent)")
    at = observed.get("captured_at_epoch")
    if not isinstance(at, int) or isinstance(at, bool):
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="no retained capture instant (captured_at_epoch absent/non-int) — nothing to judge")
    source = _coerce_text(observed.get("capture_time_source")).strip()
    if not source:
        # REFUSE rather than assume a source: an instant with no retained provenance cannot ground an
        # expiry claim. Do not default it to 'runner_clock' — that is a label the evidence never earned.
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="REFUSED: captured_at_epoch carries no capture_time_source provenance — "
                                     "the oracle will not assume a timestamp source it was not given")
    try:
        der = base64.b64decode(b64)
    except Exception:  # noqa: BLE001
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="retained cert_der_b64 is not valid base64")
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        not_before, not_after = _cert_validity_epochs(cert)
    except Exception:  # noqa: BLE001 — unparseable DER judges nothing
        return OracleSignal(kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
                            evidence="retained DER did not parse as an X.509 certificate")

    host = _coerce_text(observed.get("host")).strip()
    defects: list[str] = []
    if at > not_after:
        defects.append("expired")
    if at < not_before:
        defects.append("not_yet_valid")
    matched, presented = _cert_validity_identity_matches(cert, host)
    if not matched:
        defects.append("hostname_mismatch")
    if _cert_validity_self_signed(cert):
        defects.append("self_signed")
    defects = [d for d in _CERT_VALIDITY_DEFECTS if d in defects]

    base_obs = {
        "host": host,
        "at_epoch": at,
        "at_epoch_source": source,
        "not_before_epoch": not_before,
        "not_after_epoch": not_after,
        "presented_identities": presented,
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "defects": defects,
    }
    if defects:
        return OracleSignal(
            kind=OracleKind.CERTIFICATE_VALIDITY, fired=True, confidence=0.95,
            evidence=("the presented leaf certificate has validity defect(s) "
                      f"{defects} at the retained capture instant {at} (source={source}; the runner's own "
                      "clock, so an expiry conclusion is scoped to the instant of capture, not a trusted "
                      f"timestamp) — subject {base_obs['subject']!r}, issuer {base_obs['issuer']!r}"),
            observed=base_obs)
    return OracleSignal(
        kind=OracleKind.CERTIFICATE_VALIDITY, fired=False, confidence=0.0,
        evidence=("the presented leaf certificate shows no validity defect over the retained leaf at the "
                  f"capture instant {at} — this is a LEAF-only observation, not a chain-anchored clean"),
        observed=base_obs)


_STATIC_RULE_IDS = frozenset({
    "broken-crypto-invocation",   # (a) FACT: a broken/risky primitive is CONSTRUCTED or CALLED here
    "insecure-randomness-sink",   # (b) LEAD-only: a recognised pointer, NEVER a FACT (needs provenance dataflow)
    "insecure-flag-literal",      # (c) FACT: a security flag is EXPLICITLY disabled as a LITERAL
    "direct-taint",               # (d) LEAD-only: a recognised pointer, NEVER a FACT (needs sound taint SOURCES)
})


_LEAD_ONLY_RULE_IDS = frozenset({"insecure-randomness-sink", "direct-taint"})


_BROKEN_HASH_NAMES = frozenset({"md5", "sha1", "md4", "md2"})


_BROKEN_CIPHER_NAMES = frozenset({"des", "des3", "tripledes", "arc4", "rc4", "blowfish", "idea"})


_CRYPTO_MODULE_ROOTS = frozenset({"hashlib", "hmac", "crypto", "cryptodome", "cryptography"})


def _attr_or_name(node: Any) -> str:
    """The short callee identifier of a Call target: an ``ast.Name`` id or an ``ast.Attribute`` attr; else ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted_parts(node: Any) -> "list[str]":
    """The dotted identifier chain of a pure Name/Attribute expression, root-first: ``hashlib.md5`` ->
    ['hashlib', 'md5']; ``Crypto.Cipher.DES.new`` -> ['Crypto', 'Cipher', 'DES', 'new']; a bare ``md5`` ->
    ['md5']. Returns [] when the base is not a plain Name (a subscript / call / literal in the chain — an
    UNRESOLVABLE base, so a LEAD)."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return []
    parts.append(cur.id)
    parts.reverse()
    return parts


def _is_crypto_module(dotted: str) -> bool:
    """True iff a dotted module path's ROOT segment is a cryptographic package (the provenance test)."""
    return bool(dotted) and dotted.split(".")[0].strip().lower() in _CRYPTO_MODULE_ROOTS


def _collect_crypto_imports(tree: ast.AST) -> "tuple[set[str], dict[str, tuple[str, str]]]":
    """RESOLVE PROVENANCE for tier (a). Returns ``(crypto_module_locals, from_crypto)``:
      * ``crypto_module_locals`` — local names bound to a CRYPTO MODULE (``import hashlib`` /
        ``import hashlib as h`` / ``import Crypto.Cipher.DES`` binds the root ``Crypto``).
      * ``from_crypto`` — ``local -> (module, original)`` for ``from <crypto-module> import X [as local]``.
    Only crypto-namespace imports are recorded; a name with no crypto provenance is never resolvable to a
    broken primitive (a LEAD)."""
    crypto_locals: set[str] = set()
    from_crypto: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name or ""
                if _is_crypto_module(mod):
                    crypto_locals.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if not mod or not _is_crypto_module(mod):
                continue   # a bare relative import / non-crypto module — unresolved provenance (LEAD).
            for alias in node.names:
                if alias.name != "*":
                    from_crypto[alias.asname or alias.name] = (mod, alias.name)
    return crypto_locals, from_crypto


def _collect_local_shadows(tree: ast.AST) -> "set[str]":
    """Names DEFINED locally in the retained region (``def`` / ``async def`` / ``class`` / a simple
    assignment target). A call to such a name is the LOCAL definition, not an imported primitive, so it is
    never minted (e.g. a locally-shadowed ``def md5(): ...``)."""
    shadows: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadows.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            shadows.update(_assign_targets(node))
    return shadows


def _base_is_crypto(name: str, crypto_locals: "set[str]", from_crypto: "dict[str, tuple[str, str]]",
                    shadows: "set[str]") -> bool:
    """A base identifier resolves to a crypto module (import provenance) and is not locally shadowed."""
    if name in shadows and name not in crypto_locals and name not in from_crypto:
        return False
    return name in crypto_locals or name in from_crypto


def _has_usedforsecurity_false(node: ast.Call) -> bool:
    """True iff the call carries the EXPLICIT ``usedforsecurity=False`` opt-out — Python's hashlib flag
    declaring this hash is NOT used for security (a checksum / cache key / non-cryptographic digest). It is a
    keyword-only, hashlib-specific argument; a broken CIPHER never carries it, so the carve-out only ever
    silences a hash the author has deliberately marked non-security."""
    return any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
               for kw in node.keywords)


def _broken_crypto_call_detail(node: ast.Call, crypto_locals: "set[str]",
                               from_crypto: "dict[str, tuple[str, str]]",
                               shadows: "set[str]") -> "str | None":
    """A Call RESOLVES to a genuinely-invoked broken primitive (returns a detail) or does not (``None`` ->
    a LEAD). A bare/unimported name and a locally-shadowed def never mint; the provenance MUST resolve to a
    crypto module."""
    # CARVE-OUT (noise): an EXPLICIT ``usedforsecurity=False`` is Python's opt-out declaring this hash is NOT
    # for security (e.g. ``hashlib.md5(x, usedforsecurity=False)`` for a checksum). A genuine broken hash
    # WITHOUT the opt-out still mints; WITH it we REFUSE (a LEAD) — we do not flag a hash the author has
    # explicitly marked non-security. See the ``static_broken_crypto`` evidence-branch limitation.
    if _has_usedforsecurity_false(node):
        return None
    parts = _dotted_parts(node.func)
    if not parts:
        return None
    root = parts[0]
    if len(parts) == 1:
        # BARE name call: md5(...) — mints ONLY as a from-import of a broken primitive, never unimported.
        if root in shadows:
            return None
        if root in from_crypto:
            orig = from_crypto[root][1].lower()
            if orig in _BROKEN_HASH_NAMES:
                return f"{orig.upper()} (broken hash) imported from {from_crypto[root][0]} and invoked"
            if orig in _BROKEN_CIPHER_NAMES or orig.replace("_", "") in _BROKEN_CIPHER_NAMES:
                return f"{orig.upper()} (broken cipher) imported from {from_crypto[root][0]} and invoked"
        return None   # bare unimported name — provenance unresolved (LEAD).
    # ATTRIBUTE call: hashlib.md5(...) / DES.new(...) / algorithms.TripleDES(...) / hashlib.new("md5").
    if not _base_is_crypto(root, crypto_locals, from_crypto, shadows):
        return None   # base is a local binding or has no crypto provenance (LEAD).
    if root in crypto_locals:
        segs = [p.lower() for p in parts[1:]]
    else:
        segs = [from_crypto[root][1].lower()] + [p.lower() for p in parts[1:]]
    # <crypto-module>.new("md5") — a `.new` with a broken-hash NAME constant.
    if parts[-1] == "new" and node.args and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str) \
            and node.args[0].value.strip().lower().replace("-", "") in _BROKEN_HASH_NAMES:
        return f"{node.args[0].value.strip().upper()} (broken hash) via .new({node.args[0].value!r})"
    for seg in segs:
        if seg in _BROKEN_HASH_NAMES:
            return f"{seg.upper()} (broken hash) invoked from a resolved crypto module"
        if seg in _BROKEN_CIPHER_NAMES or seg.replace("_", "") in _BROKEN_CIPHER_NAMES:
            return f"{seg.upper()} (broken/risky cipher) invoked from a resolved crypto module"
    return None


def _ecb_construction_detail(tree: ast.AST, crypto_locals: "set[str]",
                             from_crypto: "dict[str, tuple[str, str]]",
                             shadows: "set[str]") -> "str | None":
    """ECB is a WEAK MODE, not a primitive: mint ONLY when it is CONSTRUCTED into a cipher (passed as an
    argument to a ``.new(...)`` / ``Cipher(...)`` call), NEVER when it is merely COMPARED against — a
    defensive ``if mode == AES.MODE_ECB: raise`` is a REJECTION of ECB, not a use of it."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        # (1) pycryptodome: <Cipher>.new(key, <X>.MODE_ECB) — MODE_ECB passed as an argument to a `.new`.
        if _attr_or_name(callee) == "new" and isinstance(callee, ast.Attribute) \
                and _base_is_crypto(_attr_or_name(callee.value), crypto_locals, from_crypto, shadows):
            for arg in node.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Attribute) and sub.attr == "MODE_ECB":
                        return (f"ECB block mode (MODE_ECB) constructed into a cipher via "
                                f"`{_attr_or_name(callee.value)}.new(...)` — deterministic, a broken usage")
        # (2) cryptography: Cipher(algorithms.AES(key), modes.ECB()) — modes.ECB() constructed as an arg.
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr == "ECB" \
                        and _attr_or_name(sub.func.value).lower() == "modes" \
                        and _base_is_crypto(_attr_or_name(sub.func.value), crypto_locals, from_crypto, shadows):
                    return "ECB block mode (modes.ECB) constructed into a Cipher(...) — deterministic, a broken usage"
    return None


def _broken_crypto_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (a): a broken/risky crypto primitive is GENUINELY INVOKED/CONSTRUCTED here, with its
    provenance RESOLVED to a real crypto module. Pure AST — no execution, no import. A bare/unimported name,
    a locally-shadowed def, a mere reference / comparison / defensive guard, or a hash carrying the explicit
    ``usedforsecurity=False`` opt-out does NOT mint (a LEAD — soundness over recall). Returns (fired, detail)."""
    crypto_locals, from_crypto = _collect_crypto_imports(tree)
    shadows = _collect_local_shadows(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            detail = _broken_crypto_call_detail(node, crypto_locals, from_crypto, shadows)
            if detail:
                return True, detail
    ecb = _ecb_construction_detail(tree, crypto_locals, from_crypto, shadows)
    if ecb:
        return True, ecb
    return False, ""


def _assign_targets(node: Any) -> "list[str]":
    """The simple target NAMES of an Assign / AnnAssign (Name or Attribute leaf), for sink-name matching."""
    names: list[str] = []
    targets = list(getattr(node, "targets", [])) or ([node.target] if getattr(node, "target", None) else [])
    for t in targets:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                names.append(n.id)
            elif isinstance(n, ast.Attribute):
                names.append(n.attr)
    return names


_INSECURE_FLAG_FALSE = frozenset({"verify", "secure", "check_hostname", "verify_mode", "validate_certs"})


_HTTP_TLS_MODULE_ROOTS = frozenset({"requests", "httpx", "urllib", "urllib3", "aiohttp", "ssl"})


_HTTP_SESSION_CTORS = frozenset({"session", "client", "clientsession", "asyncclient"})


_SECURITY_RELEVANT_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options", "request", "send",
    "session", "client", "clientsession", "asyncclient",
    "wrapsocket", "createdefaultcontext", "sslcontext", "wrapbio", "setcookie", "createconnection",
})


def _collect_http_imports(tree: ast.AST) -> "tuple[set[str], dict[str, tuple[str, str]]]":
    """RESOLVE import PROVENANCE for tier (c). Returns ``(http_locals, from_http)``: names bound to an
    HTTP/TLS MODULE and ``from``-imported HTTP/TLS symbols. Session/client VARIABLES are NOT collected here —
    they are resolved FLOW-SENSITIVELY by the shared straight-line binding tracker (``_advance_binding``), so
    a variable that is REASSIGNED to a non-session before its use no longer resolves to a session."""
    http_locals: set[str] = set()
    from_http: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name or ""
                if mod.split(".")[0].strip().lower() in _HTTP_TLS_MODULE_ROOTS:
                    http_locals.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod and mod.split(".")[0].strip().lower() in _HTTP_TLS_MODULE_ROOTS:
                for alias in node.names:
                    if alias.name != "*":
                        from_http[alias.asname or alias.name] = (mod, alias.name)
    return http_locals, from_http


def _is_session_ctor(call: ast.Call, http_ctx: "tuple[set[str], dict[str, tuple[str, str]]]") -> bool:
    """True iff ``call`` constructs an HTTP session/client that RESOLVES to an imported HTTP/TLS module or a
    from-imported constructor (``requests.Session()`` / ``from requests import Session; Session()``). This is
    the ONE modeled RHS form the binding tracker maps to a SESSION binding for tier (c)."""
    http_locals, from_http = http_ctx
    ctor = re.sub(r"[^a-z0-9]", "", _attr_or_name(call.func).lower())
    if ctor not in _HTTP_SESSION_CTORS:
        return False
    parts = _dotted_parts(call.func)
    base_ok = len(parts) >= 2 and parts[0] in http_locals          # requests.Session()
    imported_ctor = len(parts) == 1 and parts[0] in from_http      # from requests import Session; Session()
    return base_ok or imported_ctor


def _insecure_flag_on(call: ast.Call) -> str:
    """The evidence detail if ``call`` EXPLICITLY sets a known security flag to its insecure LITERAL —
    ``verify/secure/check_hostname/verify_mode/validate_certs=False`` or ``cert_reqs/verify_mode=
    ssl.CERT_NONE`` — else ``""``. Purely local to the one call; it decides nothing about the callee."""
    for kw in call.keywords:
        if kw.arg is None:
            continue
        if kw.arg in _INSECURE_FLAG_FALSE and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return f"the security flag `{kw.arg}=False`"
        # cert_reqs / verify_mode = ssl.CERT_NONE (TLS certificate verification explicitly disabled).
        if kw.arg in ("cert_reqs", "verify_mode") and isinstance(kw.value, ast.Attribute) \
                and kw.value.attr == "CERT_NONE":
            return f"the TLS flag `{kw.arg}=ssl.CERT_NONE`"
    return ""


def _resolves_http_tls_direct(callee: Any, http_locals: "set[str]",
                              from_http: "dict[str, tuple[str, str]]") -> bool:
    """True iff ``callee`` resolves to a security-relevant HTTP/TLS API WITHIN THE CALL ITSELF — a request /
    TLS wrap / cookie set on a RESOLVED HTTP/TLS module or from-imported symbol — needing NO cross-statement
    variable. A callee that merely happens to accept a ``verify=`` / ``secure=`` kwarg (``chart.render`` /
    ``widget.build``) does not resolve and stays a LEAD."""
    if isinstance(callee, ast.Attribute):
        method = re.sub(r"[^a-z0-9]", "", callee.attr.lower())
        parts = _dotted_parts(callee.value)
        base_is_http = bool(parts) and (parts[0] in http_locals or parts[0] in from_http)
        return base_is_http and method in _SECURITY_RELEVANT_METHODS
    if isinstance(callee, ast.Name):
        return callee.id in from_http and re.sub(r"[^a-z0-9]", "", callee.id.lower()) in _SECURITY_RELEVANT_METHODS
    return False


def _callee_is_session_method(callee: Any, sessions: "set[str]") -> bool:
    """True iff ``callee`` is ``<var>.<security-method>`` where ``<var>`` is CURRENTLY a resolved HTTP session
    in the straight-line binding map (a reassignment of ``<var>`` to a non-session, in ANY form, has already
    removed it from ``sessions`` => this returns False and the call is a LEAD)."""
    return (isinstance(callee, ast.Attribute)
            and _attr_or_name(callee.value) in sessions
            and re.sub(r"[^a-z0-9]", "", callee.attr.lower()) in _SECURITY_RELEVANT_METHODS)


def _insecure_flag_hit(tree: ast.AST) -> "tuple[bool, str]":
    """RE-DERIVE tier (c): a KNOWN security flag is EXPLICITLY set to its insecure LITERAL AND reaches a
    RESOLVED security-relevant HTTP/TLS callee, under TWO sound resolution paths:

      (1) CALL-SITE-DIRECT — the callee resolves within the call itself from import provenance
          (``requests.get(..., verify=False)`` / ``ssl.wrap_socket(..., cert_reqs=ssl.CERT_NONE)`` / a
          from-imported request callable). Flow-INDEPENDENT: it holds no matter what earlier statements did.

      (2) SESSION-VARIABLE — ``s = requests.Session(); s.get(..., verify=False)``. RESOLVED FLOW-SENSITIVELY
          by the SHARED straight-line binding tracker: ``s`` fires only if it is CURRENTLY a session at the
          call. A reassignment of ``s`` to a non-session (``s = 123``) — or ANY unmodeled statement form
          between the constructor and the use — removes/loses the binding, so the call is a LEAD, never a FACT.

    An ABSENT flag, or an insecure flag on an UNRESOLVED / non-security callee (``chart.render(verify=False)``),
    never mints (a LEAD)."""
    http_ctx = _collect_http_imports(tree)
    http_locals, from_http = http_ctx
    # (1) call-site-direct — flow-independent, resolves purely from imports + the call.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            hit = _insecure_flag_on(node)
            if hit and _resolves_http_tls_direct(node.func, http_locals, from_http):
                return True, f"{hit} is explicitly disabled on a resolved security-relevant HTTP/TLS API"
    # (2) session-variable — flow-sensitive via the shared straight-line tracker (soundness over recall).
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for stmt, bindings in _walk_straight_line(fn, http_ctx):
            sessions = {name for name, status in bindings.items() if status == _HTTP_SESSION}
            if not sessions:
                continue
            for call in ast.walk(stmt):
                if isinstance(call, ast.Call):
                    hit = _insecure_flag_on(call)
                    if hit and _callee_is_session_method(call.func, sessions):
                        return True, (f"{hit} is explicitly disabled on a resolved security-relevant HTTP "
                                      f"session variable in function `{fn.name}`")
    return False, ""


_HTTP_SESSION = "session"


def _advance_binding(stmt: ast.stmt, bindings: "dict[str, str]",
                     http_ctx: "tuple[set[str], dict[str, tuple[str, str]]]") -> bool:
    """Advance the SHARED straight-line binding map past ONE statement, for tier (c) session-variable
    resolution. This is the INVERTED core the sound tier (c) turns on: the map advances ONLY through an
    EXPLICIT CLOSED ALLOWLIST of FULLY-MODELED statement forms, and the DEFAULT for anything else is to END the
    straight-line region. So no unmodeled form can ever leave a stale session binding that mints a false FACT.

    The allowlisted forms are a simple ``<Name> = <modeled-expr>`` assignment (a single ``Name`` target) whose
    RHS the tracker FULLY understands:

      * a RESOLVED HTTP session/client constructor (``requests.Session()``): SESSION (tier c);
      * a bare ``Name`` (a copy of another variable) or a literal ``Constant``: KILL the target — plainly not a
        session, so its binding is dropped while the region continues.

    For LITERALLY ANY OTHER statement form — a walrus / ``NamedExpr`` anywhere, ``Import`` / ``ImportFrom``,
    ``AugAssign``, an annotated / tuple / attribute / subscript assignment target, a ``for`` / ``with`` target,
    ``del``, a nested ``def`` / ``class``, ``global`` / ``nonlocal``, any compound / control-flow statement,
    or an assignment whose RHS the tracker does NOT fully model (a non-session call, a subscript / attribute
    read, an ``IfExp`` / ``BoolOp`` / comprehension, …) — return ``False`` to END the straight-line region.
    From that point the caller treats every construct as a LEAD. Returns ``True`` iff the region continues.

    (Wave-5.1 round-8: tier (d) direct-taint is now LEAD-only, so the tracker no longer computes taint
    SOURCE/ALIAS statuses — it tracks ONLY the session status the sound tier (c) needs.)"""
    if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)):
        return False                                             # any non-'simple Name = ...' form ends it
    name = stmt.targets[0].id
    value = stmt.value
    if isinstance(value, ast.Call) and _is_session_ctor(value, http_ctx):
        bindings[name] = _HTTP_SESSION                          # a resolved HTTP session/client constructor
        return True
    if isinstance(value, (ast.Name, ast.Constant)):            # a bare-Name copy or a literal — fully understood
        bindings.pop(name, None)                                 # plainly not a session: KILL, region continues
        return True
    return False


def _walk_straight_line(fn: "ast.FunctionDef | ast.AsyncFunctionDef",
                        http_ctx: "tuple[set[str], dict[str, tuple[str, str]]]"):
    """The flow-sensitive straight-line walker for tier (c) session-variable resolution. Yield
    ``(stmt, bindings)`` for each TOP-LEVEL statement of ``fn.body`` while the straight-line assumption still
    holds, where ``bindings`` maps a variable to its CURRENT status (``_HTTP_SESSION``) AS OF that statement
    (before it executes). The map advances ONLY through ``_advance_binding``'s closed allowlist; the FIRST
    statement of any other form ends the region (nothing further is yielded), so from that point every construct
    the caller checks is a LEAD. The map is shared by reference — a caller must not mutate it.

    (Wave-5.1 round-8: this was shared with tier (d) direct-taint, which is now LEAD-only; the tracker tracks
    only the session status the sound tier (c) needs.)"""
    bindings: dict[str, str] = {}
    for stmt in fn.body:
        yield stmt, bindings
        if not _advance_binding(stmt, bindings, http_ctx):
            return


_STATIC_TIER_CONF: dict[str, float] = {
    "broken-crypto-invocation": 0.9,
    "insecure-flag-literal": 0.9,
}


def _static_tier_hit(rule_id: str, tree: ast.AST) -> "tuple[bool, str]":
    """Dispatch a re-parsed AST to the tier helper for a FACT-capable ``rule_id`` (each helper referenced BY
    NAME so its source is captured in ``oracle_version``'s transitive closure). insecure-randomness-sink and
    direct-taint have NO branch here — both are LEAD-only and never reach this dispatch (fail-closed in
    ``static_rule_oracle``)."""
    if rule_id == "broken-crypto-invocation":
        return _broken_crypto_hit(tree)
    if rule_id == "insecure-flag-literal":
        return _insecure_flag_hit(tree)
    return False, ""


def static_rule_oracle(observed: Any) -> OracleSignal:
    """Fire when a CLOSED-vocabulary static rule holds over RETAINED SOURCE-CODE BYTES that the oracle
    RE-PARSES ITSELF (Python `ast`). The tool (semgrep/joern/pattern) output is only the LEAD saying WHERE to
    look — this oracle re-derives the CODE PROPERTY from the retained bytes, exactly like
    ``weak_crypto_artifact_oracle`` re-derives a broken hash from a retained artifact. Each FACT is honestly
    scoped to the proven CODE PROPERTY, NEVER runtime exploitability.

    Only the TWO FACT-capable tiers (``_FACT_RULE_IDS``: broken-crypto-invocation, insecure-flag-literal) can
    ever mint a STATIC_RULE FACT. ``insecure-randomness-sink`` AND ``direct-taint`` are recognised DETECTION
    POINTERS but are LEAD-only (``_LEAD_ONLY_RULE_IDS``) and are FAIL-CLOSED here: each returns a non-firing LEAD
    for ANY input, before any re-parse or tier dispatch, so neither can EVER become a FACT (a sound version of
    insecure-randomness needs crypto-provenance dataflow; a sound version of direct-taint needs framework-aware,
    provenance-resolved taint SOURCES — see docs/capability-matrix blocking_work for
    ``static_insecure_randomness`` / ``static_taint``).

    ``observed`` is JSON-safe evidence::

        {"rule_id": "broken-crypto-invocation" | "insecure-flag-literal"  (FACT-capable)
                    | "insecure-randomness-sink" | "direct-taint"  (recognised but LEAD-only — never mints),
         "source": "<the retained source region bytes>", "language": "python",
         "path": "<file>", "line": <int>}

    REFUSES (non-firing) — never asserts — when: the evidence is malformed, the rule_id is out of the closed
    vocabulary, the rule_id is LEAD-only (insecure-randomness or direct-taint), the language is not Python, or
    the retained source cannot be re-parsed (a tamper that removes the property no longer re-fires, so the
    retained proof is rejected at re-verify). Pure + deterministic, so the same verdict re-verifies offline from
    the retained context. Never raises."""
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence="no static-rule evidence")
    rule_id = _coerce_text(observed.get("rule_id")).strip()
    source = _coerce_text(observed.get("source"))
    language = _coerce_text(observed.get("language")).strip().lower() or "python"
    path = _coerce_text(observed.get("path")).strip()
    try:
        line = int(observed.get("line"))
    except (TypeError, ValueError):
        line = 0
    where = f"{path}:{line}" if path else "the retained region"

    if rule_id not in _STATIC_RULE_IDS:
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence=f"rule_id {rule_id!r} is out of the closed static-rule vocabulary")
    if rule_id in _LEAD_ONLY_RULE_IDS:
        # FAIL CLOSED: a LEAD-only rule_id is a recognised detection pointer but is NOT FACT-capable. A sound
        # FACT is out of scope for this single-region offline re-parse:
        #   * insecure-randomness needs crypto-provenance-resolved PRNG sourcing (exclude SystemRandom/secrets/
        #     os.urandom by RESOLUTION, not by name) + FLOW-SENSITIVE dataflow (the value reaching the sink is
        #     the PRNG value, not a later secure reassignment) + a RESOLVED secret-material sink;
        #   * direct-taint needs framework-aware, provenance-resolved taint SOURCE identification (a resolved
        #     request/input OBJECT across many frameworks — NOT self./req. attributes or name-matched functions
        #     like input/getenv/get_json with no receiver provenance) + a resolved sink set, on top of the
        #     now-sound inverted straight-line flow tracker.
        # So for ANY input a LEAD-only rule_id returns a non-firing LEAD, BEFORE any parse or tier dispatch: it
        # can never mint a STATIC_RULE FACT (live or offline). See docs/capability-matrix blocking_work for
        # ``static_insecure_randomness`` / ``static_taint``.
        _lead_reason = (
            "insecure randomness: a sound FACT needs crypto-provenance-resolved PRNG sourcing + "
            "flow-sensitive dataflow + a resolved secret-material sink"
            if rule_id == "insecure-randomness-sink"
            else "direct taint: a sound FACT needs framework-aware, provenance-resolved taint SOURCES "
                 "(a resolved request/input object, not self./req. attributes or name-matched functions) + "
                 "a resolved sink set")
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
            evidence=(f"rule_id {rule_id!r} is a LEAD-only static-rule class ({_lead_reason}), out of scope for "
                      f"the offline re-parse — REFUSE (never mint), a LEAD"),
            observed={"rule_id": rule_id, "reason": "lead_only_not_fact_capable"})
    if language not in ("python", "py"):
        # A sound offline re-parse is implemented for Python only; other languages REFUSE (a lead), never assert.
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
            evidence=f"language {language!r} is not re-parseable by this oracle (Python-only) — REFUSE (lead)",
            observed={"rule_id": rule_id, "language": language, "reason": "unsupported_language"})
    if not source.strip():
        return OracleSignal(kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
                            evidence="no retained source bytes to re-parse — REFUSE (lead)")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        # The retained source cannot be re-parsed (tampered / truncated / not a full statement) — REFUSE.
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
            evidence=f"retained source at {where} cannot be re-parsed as Python — REFUSE (never mint)",
            observed={"rule_id": rule_id, "reason": "unparseable"})

    confidence = _STATIC_TIER_CONF[rule_id]
    fired, detail = _static_tier_hit(rule_id, tree)
    if fired:
        return OracleSignal(
            kind=OracleKind.STATIC_RULE, fired=True, confidence=confidence,
            evidence=(f"static rule {rule_id} holds at {where}: {detail} — a re-verifiable CODE PROPERTY over "
                      f"the retained source, NOT proof of runtime exploitability"),
            observed={"rule_id": rule_id, "path": path, "line": line, "detail": detail, "language": "python"})
    return OracleSignal(
        kind=OracleKind.STATIC_RULE, fired=False, confidence=0.0,
        evidence=f"static rule {rule_id} does NOT hold over the retained source at {where}",
        observed={"rule_id": rule_id, "path": path, "line": line})


_ACCESS_LEVEL: dict[str, int] = {
    "list": 1, "read": 2, "get": 2, "describe": 2, "readonly": 2, "read_only": 2, "view": 2,
    "write": 3, "put": 3, "modify": 3, "update": 3, "delete": 3, "create": 3,
    "read_write": 3, "readwrite": 3,
    "admin": 4, "owner": 4, "full": 4, "root": 4, "all": 4, "*": 4, "manage": 4,
}


def _access_level(access: Any) -> int:
    """The lattice level of an access token. Empty/None -> 1 (minimum); an unrecognised non-empty
    token -> 2 (read-tier, never assumed admin); a known token -> its level."""
    a = str(access or "").strip().lower().replace("-", "_")
    if not a:
        return 1
    return _ACCESS_LEVEL.get(a, 2)


def _access_grants(granted: Any, requested: Any) -> bool:
    """True iff a grant of ``granted`` access authorises a request for ``requested`` access. An empty
    request ("any access path") is satisfied by any grant; otherwise the granted level must dominate."""
    if not str(requested or "").strip():
        return True
    return _access_level(granted) >= _access_level(requested)


def _norm_id(value: Any) -> str:
    """Canonical (lowercased, stripped) node key — matches ``intel.from_cloud``'s key normalisation so
    the retained graph and the query agree on identity."""
    return str(value or "").strip().lower()


_K8S_WL_STR_CAP = 4096


_K8S_ANON_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})


_K8S_RBAC_APIGROUP = "rbac.authorization.k8s.io"


def _k8s_norm(value: Any) -> str:
    return _coerce_text(value)[:_K8S_WL_STR_CAP].strip().lower()


def _k8s_subject_is_anon(s: Any) -> bool:
    """A subject is an ANONYMOUS principal when its k8s TYPE matches, not merely its name.

    TYPED subject ``{kind, name, api_group}`` (the declared-manifest reducer, reviewer BLOCK #3): only a
    ``User`` named ``system:anonymous`` or a ``Group`` named ``system:unauthenticated`` — and the RBAC
    apiGroup is REQUIRED (an unapplied manifest that omits it is not API-validated, so it cannot mint a FACT;
    a ServiceAccount, or any other kind, merely NAMED "system:anonymous" is a DIFFERENT principal). Kind, name
    AND apiGroup are compared EXACTLY (case- and whitespace-sensitive, as k8s validates them).

    Legacy STRING subject (a live-read RBAC sensor reads the cluster and emits the reserved name directly, so
    the cluster itself is authority): the bare reserved name IS the anonymous principal.
    """
    if isinstance(s, Mapping):
        # k8s subject kind / name / apiGroup are case- AND whitespace-SENSITIVE — a padded or case-variant
        # value is a DIFFERENT principal (red-pen: a "system:anonymous\n" name, or a "USER"/" User " kind, must
        # NOT match the reserved principal). Compare EXACTLY against the canonical k8s spellings; the RBAC
        # apiGroup is required (an unapplied manifest that omits it is not API-validated).
        if _coerce_text(s.get("api_group") or s.get("apiGroup")) != _K8S_RBAC_APIGROUP:
            return False
        kind = _coerce_text(s.get("kind"))
        name = _coerce_text(s.get("name"))
        return (kind == "User" and name == "system:anonymous") or \
               (kind == "Group" and name == "system:unauthenticated")
    # Legacy STRING subject (a live-read RBAC sensor emits the reserved name directly). Match EXACTLY too — the
    # reserved principals are always lowercase "system:anonymous" / "system:unauthenticated"; a case/whitespace
    # variant ("System:Anonymous", "system:anonymous ") is a DIFFERENT principal and must NOT match (red-pen
    # re-attack: the typed path was made exact but the string path still .strip().lower()'d via _k8s_norm).
    return _coerce_text(s) in _K8S_ANON_SUBJECTS


def _k8s_subject_display(s: Any) -> str:
    """A human name for a subject (typed or string) for the evidence string."""
    if isinstance(s, Mapping):
        return _coerce_text(s.get("name"))[:_K8S_WL_STR_CAP].strip()
    return _coerce_text(s)[:_K8S_WL_STR_CAP].strip()


def _mobile_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.MOBILE_POSTURE, fired=fired, confidence=(conf if fired else 0.0),
                        evidence=evidence, observed=observed)


def mobile_posture_oracle(observed_control: Any) -> OracleSignal:
    """Promote a retained MobSF mobile-posture control to a FACT ONLY when the weakness is offline-
    RE-DERIVABLE from the control's literal evidence — never trusting the scanner's label. This slice
    proves ONE rule: ``private_key_material`` — an embedded PEM private-key block is a FACT iff the
    retained ``pem`` string LOADS as an UNENCRYPTED, structurally-valid private key (re-executed via
    ``cryptography``). An encrypted key (needs a passphrase we cannot prove), a public key, a certificate,
    a masked/partial blob, or an unparseable string do NOT fire — the oracle REFUSES rather than assert a
    weakness it cannot reconstruct. Pure, offline, deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _mobile_signal(False, evidence="no mobile control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()

    if rule == "private_key_material":
        pem = _coerce_text(observed_control.get("pem"))
        if "PRIVATE KEY-----" not in pem:
            return _mobile_signal(False, evidence="no PEM private-key block in the retained evidence",
                                  observed={"rule": rule})
        try:
            from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
                load_pem_private_key,
            )
        except Exception:
            # the crypto lib is absent → we cannot RE-DERIVE, so we REFUSE (never assert on trust).
            return _mobile_signal(False, evidence="cannot re-derive: cryptography unavailable",
                                  observed={"rule": rule})
        try:  # the OpenSSH container (ssh-keygen's default since 7.8) needs a distinct loader
            from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
                load_ssh_private_key,
            )
        except Exception:  # very old cryptography — the PKCS1/8/SEC1 path below still works
            load_ssh_private_key = None
        data = pem.encode("utf-8", "replace")
        loaders = [load_pem_private_key] + ([load_ssh_private_key] if load_ssh_private_key else [])
        key = None
        for loader in loaders:
            try:
                key = loader(data, password=None)
                break
            except TypeError:
                # an ENCRYPTED private key (needs a passphrase we do not have) — real key material, but
                # its usability is unproven, so it stays a LEAD, not a fact.
                return _mobile_signal(False, evidence="an encrypted private key (passphrase-protected) — a lead, not a proven-usable key",
                                      observed={"rule": rule, "encrypted": True})
            except Exception:
                # this container did not parse it — try the next loader (PEM vs OpenSSH), else REFUSE.
                continue
        if key is None:
            # not a loadable key in any container (a public key, a cert, a masked/partial blob, garbage).
            return _mobile_signal(False, evidence="the PEM block does not load as a private key",
                                  observed={"rule": rule})
        key_kind = type(key).__name__
        return _mobile_signal(True, conf=0.95,
                              evidence=("an UNENCRYPTED, structurally-valid private key "
                                        f"({key_kind}) is embedded in the distributed client — extractable "
                                        "by anyone with the APK; not a secret"),
                              observed={"rule": rule, "key_type": key_kind})

    if rule == "exported_content_provider":
        # SOUND only on an EXPLICIT android:exported="true" with ZERO permission guards. We deliberately
        # REFUSE the default-export gating chain (a provider's export default depends on min/targetSdk —
        # a semantic layer the manifest fragment may not resolve): an absent/other `exported` is a LEAD,
        # never asserted. A provider carrying ANY of android:permission / readPermission / writePermission
        # / a <path-permission> child is guarded → NO fire (conservative: a set permission of any level
        # means the claim "unguarded" would be false).
        exported = _coerce_text(observed_control.get("exported")).strip().lower()
        if exported != "true":
            return _mobile_signal(False, observed={"rule": rule, "exported": exported},
                                  evidence="content provider is not EXPLICITLY exported=true (default-export unresolved — a lead)")
        guarded = any(_coerce_text(observed_control.get(k)).strip()
                      for k in ("permission", "read_permission", "write_permission"))
        if guarded or bool(observed_control.get("has_path_permission")):
            return _mobile_signal(False, observed={"rule": rule},
                                  evidence="the exported content provider carries a permission guard (not unguarded)")
        name = _coerce_text(observed_control.get("name")).strip()
        return _mobile_signal(True, conf=0.9,
                              evidence=(f"content provider{(' ' + name) if name else ''} is EXPORTED with no "
                                        "permission/readPermission/writePermission/path-permission guard — any "
                                        "installed app can read/write its content:// data"),
                              observed={"rule": rule, "name": name})

    return _mobile_signal(False, evidence=f"unrecognised/lead-only mobile rule {rule!r} (stays a lead)",
                          observed={"rule": rule})


_DMARC_P_RE = re.compile(r"(?i)(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)")


_DMARC_SP_RE = re.compile(r"(?i)(?:^|;)\s*sp\s*=\s*(none|quarantine|reject)\s*(?:;|$)")


_DMARC_SP_PRESENT_RE = re.compile(r"(?i)(?:^|;)\s*sp\s*=")


_TXT_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _decode_txt_escapes(s: str) -> str:
    """RFC 1035 §5.1: ONE captured character-string's PRESENTATION bytes -> the octets it actually encodes.

    ``\\DDD`` (a backslash + exactly three decimal digits, value 0-255) is the octet with that decimal value;
    ``\\c`` (a backslash + any other single char) is the literal ``c`` with the backslash dropped. This is
    LOAD-BEARING and must run BEFORE any tag regex: a spec-legal separator octet <0x20 (RFC 7489 §6.4
    ``dmarc-sep = *WSP %x3b *WSP``, WSP∋HTAB) is rendered by real ``dig +short``/BIND as the escape
    ``\\009`` — a literal backslash that breaks a tag's ``(?:^|;)\\s*`` anchor and would HIDE a protective
    ``sp=`` behind a visible ``p=none``. Decoding to wire bytes makes the TAB a real separator again.
    Faithful by construction: it only ever yields exactly what the publisher encoded, so it can never
    fabricate a protective tag the record does not carry (it removes FP risk, never adds it). Pure + total;
    a malformed trailing backslash is preserved verbatim, never raises."""
    if "\\" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        # a backslash: \DDD (three decimal digits, an octet 0-255) else \c (literal next char)
        if i + 4 <= n and s[i + 1:i + 4].isdigit() and int(s[i + 1:i + 4]) <= 255:
            out.append(chr(int(s[i + 1:i + 4])))
            i += 4
        elif i + 1 < n:
            out.append(s[i + 1])                 # \c -> literal c (covers \" \\ \; and malformed \9)
            i += 2
        else:
            out.append(c)                        # a lone trailing backslash: preserve, do not raise
            i += 1
    return "".join(out)


_ZONE_RR_HEADER_RE = re.compile(r"(?i)^[^\s\"=]+(?:\s+(?:(?:\d+[smhdw]?)+|IN|CH|CS|HS))*\s+TXT$")


_DMARC_VERSION_RE = re.compile(r"(?i)v\s*=\s*DMARC1\s*(?:;|$)")


_SPF_VERSION_RE = re.compile(r"(?i)v=spf1(?:\s|$)")


def _resolve_txt_record(line: str) -> str | None:
    """ONE record's presentation form -> the character-string it encodes; ``None`` if it does not
    unambiguously encode one.

    RFC 1035 §3.3.14 concatenates ADJACENT character-strings *within a single record*, and §5.1 escape
    sequences inside each string are decoded to wire octets FIRST (`_decode_txt_escapes`). Anything else
    outside the strings is content this cannot faithfully resolve — and silently DISCARDING it is how a
    protective tag disappears (`'"v=DMARC1; p=none;" sp=reject'` -> a `sp=reject` that never reaches the
    parser). Unquoted content mixed among character-strings is REFUSED, never dropped."""
    if '"' not in line:
        bare = line.strip()
        # A BARE (unquoted) record is the operator's already-decoded wire octets — and the wire form of a
        # valid DMARC/SPF record never contains a backslash. So a backslash here is UNRESOLVABLE: it is
        # either an undecoded RFC 1035 §5.1 presentation escape (a quote-stripping export left `\009` for a
        # separator octet, which would HIDE a protective tag behind the literal backslash) or malformed
        # content. We cannot tell which without guessing, and guessing is the fault line — so REFUSE. (The
        # QUOTED branch below decodes, because there a backslash is unambiguously a §5.1 escape.)
        return None if "\\" in bare else bare
    spans = list(_TXT_STRING_RE.finditer(line))
    if not spans:
        return None                             # a quote opens a string that never closes
    head = line[: spans[0].start()].strip()
    if head and not _ZONE_RR_HEADER_RE.match(head):
        return None                             # unquoted content ahead of the record
    prev = spans[0].end()
    for span in spans[1:]:
        if line[prev : span.start()].strip():
            return None                         # unquoted content BETWEEN character-strings
        prev = span.end()
    if line[prev:].strip():
        return None                             # unquoted content trailing the record
    # §5.1 decode each string to wire octets, THEN §3.3.14 concatenate — so every tag regex reads wire bytes
    return "".join(_decode_txt_escapes(span.group(1)) for span in spans).strip()


def _txt_records(raw: Any) -> list[str] | None:
    """A retained DNS TXT blob -> the list of RECORDS it encodes; ``None`` if it cannot be resolved.

    Load-bearing: concatenation is defined WITHIN one record — separate records are NEVER joined, and
    ``dig +short`` prints one record per line. Joining across record boundaries both FABRICATES policy
    (two DMARC records -> one spliced record asserting a `p=` no record published, its verdict decided by
    RRset return order) and DESTROYS it. Records are split here on newlines outside quotes and outside
    zone-file `( )` continuation; an unbalanced quote or paren is unresolvable input, not a record."""
    s = _coerce_text(raw)
    if not s.strip():
        return []
    lines: list[str] = []
    buf: list[str] = []
    in_quote = False
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if in_quote:
            if c == "\\" and i + 1 < len(s):     # an escaped char never closes the string
                buf.append(c)
                buf.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_quote = False
            buf.append(c)
        elif c == '"':
            in_quote = True
            buf.append(c)
        elif c == "(" or c == ")":               # zone-file grouping: a newline inside is NOT a boundary
            depth += 1 if c == "(" else -1
            if depth < 0:
                return None
            buf.append(" ")
        elif c in "\r\n" and depth == 0:         # CR, LF or CRLF: an empty chunk between them is dropped below
            lines.append("".join(buf))
            buf = []
        else:
            buf.append(" " if c in "\r\n" else c)
        i += 1
    if in_quote or depth != 0:
        return None
    lines.append("".join(buf))
    out: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        record = _resolve_txt_record(line)
        if record is None:
            return None
        # An EMPTY record (`""`) is retained, not dropped: a record that exists but carries no policy is
        # not the same thing as a producer that retained nothing, and only the latter may be read as
        # absence. Dropping it here would make `_select_txt` report absence and mint evidence reading
        # "no DMARC record is published" about a domain that published one.
        out.append(record)
    return out


def _select_txt(raw: Any, version: "re.Pattern[str]") -> str | None:
    """The ONE policy record a receiver would act on; ``""`` only when the producer retained NOTHING;
    ``None`` when the blob is unresolvable, carries no policy record, or carries more than one.

    A real apex TXT set is normally MULTI-record (SPF alongside site-verification tokens), so selecting the
    version-tagged record — RFC 7489 §6.6.3 / RFC 7208 §4.5 — is what makes a real export readable at all.
    Duplicate policy records are refused rather than resolved: both RFCs make a duplicate set apply NO
    policy, and picking one of them would be asserting from an ambiguity.

    Load-bearing, and the reason absence is read from the EMPTY blob and not from a failed selection: "no
    record here matched the version tag" is NOT proof that the domain publishes no policy — it is equally
    what a record this cannot canonicalise looks like (a presentation form outside RFC 1035's grammar, say),
    and reading that as absence would fire `dmarc_missing` at a domain whose record is right there in the
    evidence. Absence is only ever asserted from a producer that retained NOTHING and attested it OBSERVED
    the lookup; a non-empty blob that yields no policy record is unresolved input, so REFUSE."""
    records = _txt_records(raw)
    if records is None:
        return None
    if not records:
        return ""                               # the producer retained nothing — absence, gated on *_observed
    hits = [r for r in records if version.match(r)]
    if len(hits) != 1:
        return None
    if len(version.findall(hits[0])) != 1:
        # TWO version tags inside ONE record: RFC 1035 §3.3.14 faithfully concatenated adjacent strings a
        # publisher meant as separate records, yielding a syntactically invalid policy string. Reading a
        # tag out of it names a policy that is not in effect — refuse rather than pick.
        return None
    return hits[0]


_SPF_ALL_RE = re.compile(r"(?i)(?:^|\s)([-~?+]?)all(?:\s|$)")


def _email_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.EMAIL_AUTH_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def email_auth_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a domain's RETAINED, PUBLISHED email-authentication policy provably permits spoofing — a
    pure re-derivation over the DNS TXT records themselves, never a receiving MTA's ``Authentication-Results``
    say-so (that would be string trust). Three rules, each unconditional and re-verifiable offline:

      * ``dmarc_missing``  — the domain publishes NO DMARC record: receivers are given no policy, so
        header-From spoofing is unmitigated (SPF alone does not protect the header-From a user sees).
      * ``dmarc_none``     — DMARC ``p=none``: the domain explicitly instructs receivers to take NO action.
      * ``spf_permissive`` — SPF ends in ``+all``/``all``: ANY host on the internet passes SPF for the domain.

    A hardened domain (``p=reject``/``p=quarantine``, SPF ``-all``) does NOT fire. DELIBERATELY out of scope
    (REFUSE, never assert): message-level SPF/DKIM/DMARC verification — DKIM canonicalisation and SPF
    include/macro chains are a semantic layer this cannot soundly re-derive offline; and ``spf_missing`` alone
    (DKIM+DMARC may still protect the domain — a gating chain). Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _email_signal(False, evidence="no email-auth control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    domain = _coerce_text(observed_control.get("domain")).strip()
    where = f" for {domain}" if domain else ""

    if rule == "dmarc_missing":
        rec = _select_txt(observed_control.get("dmarc_record"), _DMARC_VERSION_RE)
        org_rec = _select_txt(observed_control.get("org_dmarc_record"), _DMARC_VERSION_RE)
        if rec is None or org_rec is None:
            # The blob does not resolve to one policy record (duplicate records, or unquoted content mixed
            # among character-strings). Reading a spliced or truncated record would assert a policy NO
            # record published: absence is UNRESOLVED here, so refuse.
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("a retained DMARC record set does not resolve to a single policy "
                                           "record — the published policy is UNRESOLVED (REFUSE)"))
        # only assert absence when the producer OBSERVED the lookup and recorded no record (never assume)
        if rec:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="a DMARC record is present — not missing")
        if observed_control.get("dmarc_observed") is not True:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="DMARC lookup not observed — absence unproven (REFUSE)")
        # self-contradictory evidence (attested an org domain AND handed an org-domain policy to inherit)
        # is refused rather than resolved down whichever branch happens to fire.
        if observed_control.get("is_org_domain") is True and (
                org_rec or observed_control.get("org_dmarc_observed") is True):
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("contradictory evidence: attested an ORGANIZATIONAL domain yet "
                                           "carries an organizational-domain policy to inherit (REFUSE)"))
        # RFC 7489 §6.6.3: an ABSENT record at the From-domain does NOT mean "no policy" — receivers then
        # query the ORGANIZATIONAL domain, and §6.3 applies its `sp=` (else `p=`) to the subdomain. So a
        # subdomain that correctly publishes nothing is FULLY protected by an org `p=reject`. Absence alone
        # therefore proves NOTHING; the EFFECTIVE policy must be resolved from the RETAINED evidence, or we
        # REFUSE (the same discipline that already refuses `spf_missing` as a gating chain).
        if observed_control.get("is_org_domain") is True:
            return _email_signal(True, conf=0.9,
                                 evidence=(f"no DMARC record is published for the ORGANIZATIONAL domain"
                                           f"{where or ' (unnamed)'} — there is no parent policy to inherit, "
                                           "so receivers are given no policy for it or its subdomains"),
                                 observed={"rule": rule, "domain": domain, "scope": "organizational"})
        if observed_control.get("org_dmarc_observed") is not True:
            return _email_signal(False, observed={"rule": rule, "domain": domain},
                                 evidence=("no DMARC here, but this is not attested an organizational domain "
                                           "and the organizational-domain lookup was not observed — the RFC 7489 "
                                           "§6.6.3 inheritance chain is UNRESOLVED (REFUSE)"))
        org = _coerce_text(observed_control.get("org_domain")).strip()
        if not org:
            # a fired certificate must NAME the domain whose policy was looked up, or a third party
            # re-running it cannot audit the inheritance claim.
            return _email_signal(False, observed={"rule": rule, "domain": domain},
                                 evidence=("the organizational domain is not named — the inheritance claim "
                                           "would not be auditable from the certificate (REFUSE)"))
        if not org_rec:
            return _email_signal(True, conf=0.9,
                                 evidence=(f"neither{where} nor its organizational domain {org} publishes "
                                           "DMARC — no policy exists anywhere in the chain to inherit"),
                                 observed={"rule": rule, "domain": domain, "org_domain": org})
        # §6.3: the subdomain inherits `sp=` when present, else the org domain's `p=`.
        m = _DMARC_SP_RE.search(org_rec)
        if m is None and _DMARC_SP_PRESENT_RE.search(org_rec):
            # An `sp=` tag IS present but its value did not parse. Falling through to `p=` would read the
            # WRONG tag and assert the negative from a failed parse — the same error class as assuming
            # absence. The SUBDOMAIN policy is unresolved: REFUSE.
            return _email_signal(False, observed={"rule": rule, "org_domain": org},
                                 evidence=("the organizational record carries an sp= tag whose value did not "
                                           "parse — the subdomain policy is UNRESOLVED (REFUSE)"))
        if m is None:
            m = _DMARC_P_RE.search(org_rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="the organizational DMARC record has no parseable policy (REFUSE)")
        eff = m.group(1).lower()
        if eff != "none":
            return _email_signal(False, observed={"rule": rule, "inherited_policy": eff},
                                 evidence=(f"publishes no DMARC of its own but INHERITS the organizational "
                                           f"domain's effective subdomain policy p={eff} — protected"))
        return _email_signal(True, conf=0.9,
                             evidence=(f"no DMARC is published{where} and the organizational domain"
                                       f"{(' ' + org) if org else ''} resolves to an effective subdomain "
                                       "policy of none — receivers are told to take no action"),
                             observed={"rule": rule, "domain": domain, "org_domain": org,
                                       "inherited_policy": eff})

    if rule == "dmarc_none":
        rec = _select_txt(observed_control.get("dmarc_record"), _DMARC_VERSION_RE)
        if rec is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("the retained DMARC record set does not resolve to a single "
                                           "policy record — the published policy is UNRESOLVED (REFUSE)"))
        m = _DMARC_P_RE.search(rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="no parseable DMARC policy (p=) in the retained record (REFUSE)")
        policy = m.group(1).lower()
        if policy != "none":
            return _email_signal(False, observed={"rule": rule, "policy": policy},
                                 evidence=f"DMARC policy is p={policy} — receivers are told to act")
        return _email_signal(True, conf=0.9,
                             evidence=(f"DMARC policy{where} is p=none — the domain explicitly instructs "
                                       "receivers to take NO action on spoofed mail (monitoring only)"),
                             observed={"rule": rule, "domain": domain, "policy": policy})

    if rule == "spf_permissive":
        rec = _select_txt(observed_control.get("spf_record"), _SPF_VERSION_RE)
        if rec is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence=("the retained SPF record set does not resolve to a single policy "
                                           "record — the sender policy is UNRESOLVED (REFUSE)"))
        if not rec:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="no SPF record retained (REFUSE — absence is a gating chain)")
        m = _SPF_ALL_RE.search(rec)
        if m is None:
            return _email_signal(False, observed={"rule": rule},
                                 evidence="the SPF record has no `all` mechanism (REFUSE)")
        qual = m.group(1) or "+"          # a bare `all` means `+all` (SPF default qualifier is pass)
        if qual != "+":
            return _email_signal(False, observed={"rule": rule, "qualifier": qual},
                                 evidence=f"SPF ends in {qual}all — not a pass-all policy")
        return _email_signal(True, conf=0.9,
                             evidence=(f"SPF{where} ends in +all — ANY host on the internet passes SPF for "
                                       "this domain (an unconditionally permissive sender policy)"),
                             observed={"rule": rule, "domain": domain, "qualifier": qual})

    return _email_signal(False, evidence=f"unrecognised/lead-only email-auth rule {rule!r} (stays a lead)",
                         observed={"rule": rule})


def _identity_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.IDENTITY_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def _as_nonneg_int(v: Any) -> "int | None":
    """A retained value as a non-negative int, else ``None``. STRICT: a bool is NOT an int here (``True``
    must never be read as age 1), and a numeric STRING is NOT coerced (a retained age/threshold must be a
    real integer the producer computed, not a parse of presentation text — the fault line that cost Domain
    10 eight defects). Only a genuine ``int >= 0`` qualifies."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and v >= 0:
        return v
    return None


def _is_universal_grant(grant: str) -> bool:
    """A grant string that provably confers EVERYTHING-ON-EVERYTHING (FORGE Domain 7 slice 2). Universal iff
    every ``:``/``/``-separated segment is a bare ``*`` (a bare ``*``, ``*:*``, ``*/*``, ``*:*:*`` …). A
    scoped or PARTIAL wildcard — ``read:*`` (action scoped), ``*:invoices`` (resource scoped), ``*:`` (empty
    segment) — is NOT universal and must NOT fire: partial wildcards are common and legitimate, and firing on
    them is exactly where the false positives would live (the charter's near-zero-FP scoping)."""
    s = (grant or "").strip()
    if not s:
        return False
    parts = re.split(r"[:/]", s)
    return bool(parts) and all(p.strip() == "*" for p in parts)


def identity_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED identity-provider export provably carries an identity-posture weakness — a pure
    re-derivation over STRICT-TYPED literal fields, never an IdP's or scanner's say-so. Two rules (FORGE
    Domain 7, slice 1), each unconditional and re-verifiable offline:

      * ``privileged_without_mfa`` — a producer-attested privileged identity with MFA PROVABLY absent:
        ``privileged is True`` AND ``mfa_enrolled is False``. An ABSENT/unknown ``mfa_enrolled`` REFUSES —
        a missing field is NOT proof MFA is absent (absence must be OBSERVED, never assumed).
      * ``stale_credential`` — ``never_rotated is True`` (a producer attestation that the credential is
        configured NEVER to expire/rotate — a permanent secret), OR two retained integers
        ``age_days >= max_age_days`` (the operator's rotation policy). A missing/non-integer age or
        threshold REFUSES.

    A compliant identity (``mfa_enrolled is True``; ``age_days < max_age_days``) does NOT fire. DELIBERATELY
    out of scope (REFUSE, never assert): anomaly/behavioral detection (probabilistic); cloud-resource IAM
    (POLICY_PATH/CLOUD_POSTURE own that); privilege INFERENCE — the ``privileged`` attestation is REQUIRED,
    never guessed from a role name. Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _identity_signal(False, evidence="no identity control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    subject = _coerce_text(observed_control.get("subject")).strip()
    where = f" for {subject}" if subject else ""

    if rule == "privileged_without_mfa":
        # privilege is a PRODUCER ATTESTATION, never inferred; without it there is no privileged-account
        # weakness to assert.
        if observed_control.get("privileged") is not True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("identity is not attested privileged — no privileged-account "
                                              "weakness to assert (REFUSE)"))
        mfa = observed_control.get("mfa_enrolled")
        if mfa is True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="MFA is enrolled — compliant")
        if mfa is not False:
            # a MISSING/unknown mfa flag is NOT proof MFA is absent (the failed-parse≠absence discipline).
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="MFA status not observed — absence unproven (REFUSE)")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a privileged identity{where or ' (unnamed)'} has MFA provably "
                                          "disabled (mfa_enrolled=false) — a single stolen password fully "
                                          "compromises a privileged account"),
                                observed={"rule": rule, "subject": subject, "privileged": True,
                                          "mfa_enrolled": False})

    if rule == "stale_credential":
        if observed_control.get("never_rotated") is True:
            return _identity_signal(True, conf=0.9,
                                    evidence=(f"a credential{where or ' (unnamed)'} is attested configured "
                                              "never to expire/rotate — a permanent, non-expiring secret"),
                                    observed={"rule": rule, "subject": subject, "never_rotated": True})
        age = _as_nonneg_int(observed_control.get("age_days"))
        maxa = _as_nonneg_int(observed_control.get("max_age_days"))
        if age is None or maxa is None:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("credential age or its rotation-policy threshold is missing or "
                                              "not an integer — staleness UNRESOLVED (REFUSE)"))
        if maxa < 1:
            # a rotation policy of 0 (or less) days is not a real policy — it is almost always a "no policy"
            # sentinel, against which EVERY credential (age >= 0) would fire. Refuse rather than assert.
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("the rotation-policy threshold is 0 days — not a real policy "
                                              "(a likely 'no policy' sentinel); staleness UNRESOLVED (REFUSE)"))
        if age < maxa:
            return _identity_signal(False, observed={"rule": rule, "age_days": age, "max_age_days": maxa},
                                    evidence=(f"credential age {age}d is within the {maxa}d rotation policy "
                                              "— compliant"))
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a credential{where or ' (unnamed)'} is {age} days old, at or past "
                                          f"its {maxa}-day rotation policy — a stale long-lived secret"),
                                observed={"rule": rule, "subject": subject, "age_days": age,
                                          "max_age_days": maxa})

    if rule == "wildcard_grant":
        # an explicit unrestricted-admin attestation is the strongest form
        if observed_control.get("admin_all") is True:
            return _identity_signal(True, conf=0.9,
                                    evidence=(f"identity{where or ' (unnamed)'} is attested admin_all — "
                                              "unrestricted everything-on-everything access"),
                                    observed={"rule": rule, "subject": subject, "admin_all": True})
        # else a single retained grant that is provably UNIVERSAL (everything on everything). A scoped or
        # partial wildcard does NOT fire (near-zero-FP: only the universal grant is a weakness).
        grant = _coerce_text(observed_control.get("grant")).strip()
        if not grant:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence="no admin_all attestation and no retained grant — nothing to assert (REFUSE)")
        if not _is_universal_grant(grant):
            return _identity_signal(False, observed={"rule": rule, "grant": grant},
                                    evidence=f"grant {grant!r} is scoped or partially-wildcarded — not universal, compliant")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"identity{where or ' (unnamed)'} holds a UNIVERSAL wildcard grant "
                                          f"{grant!r} — everything-on-everything access"),
                                observed={"rule": rule, "subject": subject, "grant": grant})

    if rule == "dormant_privileged":
        if observed_control.get("privileged") is not True:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("identity is not attested privileged — no privileged-account "
                                              "weakness to assert (REFUSE)"))
        days = _as_nonneg_int(observed_control.get("days_since_login"))
        thresh = _as_nonneg_int(observed_control.get("dormancy_threshold_days"))
        if days is None or thresh is None:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("days-since-login or the dormancy threshold is missing or not an "
                                              "integer — dormancy UNRESOLVED (REFUSE)"))
        if thresh < 1:
            return _identity_signal(False, observed={"rule": rule},
                                    evidence=("the dormancy threshold is 0 days — not a real policy (a likely "
                                              "sentinel); dormancy UNRESOLVED (REFUSE)"))
        if days < thresh:
            return _identity_signal(False, observed={"rule": rule, "days_since_login": days,
                                                     "dormancy_threshold_days": thresh},
                                    evidence=f"last authenticated {days}d ago, within the {thresh}d dormancy policy — compliant")
        return _identity_signal(True, conf=0.9,
                                evidence=(f"a privileged identity{where or ' (unnamed)'} last authenticated "
                                          f"{days} days ago, at or past the {thresh}-day dormancy threshold — a "
                                          "stale privileged account an attacker can seize unnoticed"),
                                observed={"rule": rule, "subject": subject, "days_since_login": days,
                                          "dormancy_threshold_days": thresh})

    return _identity_signal(False, evidence=f"unrecognised/lead-only identity rule {rule!r} (stays a lead)",
                            observed={"rule": rule})


def _clickjacking_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CLICKJACKING_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def _normalize_headers(raw: Any) -> "dict[str, str] | None":
    """A retained response's headers as a lowercase-keyed dict of joined values, or ``None`` if the shape
    is not a recognisable header collection. Accepts a Mapping ``{name: value}`` or a sequence of
    ``[name, value]`` pairs — the two JSON-safe shapes a captured response retains. Duplicate header names
    are joined with ``', '`` (RFC 7230 §3.2.2 field-combining). The consumers below read the COMBINED
    value TOKEN-AWARE — ``_xfo_declares_framing`` splits it on ``,`` and ``_CSP_FRAME_ANCESTORS_RE``
    treats ``,`` as a policy separator — so a doubled/comma-combined ``X-Frame-Options`` (proxy+app) and
    two ``Content-Security-Policy`` headers (one carrying ``frame-ancestors``) are correctly read as
    PROTECTED, never mis-read as unprotected."""
    if isinstance(raw, Mapping):
        items: list[tuple[Any, Any]] = list(raw.items())
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        items = []
        for pair in raw:
            if (isinstance(pair, Sequence) and not isinstance(pair, (str, bytes))
                    and len(pair) == 2):
                items.append((pair[0], pair[1]))
            else:
                return None
    else:
        return None
    out: dict[str, str] = {}
    for name, value in items:
        key = _coerce_text(name).strip().lower()
        if not key:
            continue
        val = _coerce_text(value).strip()
        out[key] = f"{out[key]}, {val}" if key in out else val
    return out


_CSP_FRAME_ANCESTORS_RE = re.compile(r"(?i)(?:^|[;,])\s*frame-ancestors\b")


_XFO_TOKEN_RE = re.compile(r"(?i)^(?:deny|sameorigin|allow-from\b.*)$")


def _xfo_declares_framing(value: str) -> bool:
    """True iff ANY comma-separated ``X-Frame-Options`` TOKEN declares a framing policy. Because duplicate
    XFO headers are field-combined into one value (RFC 7230 §3.2.2), a doubled/comma-combined header
    (``SAMEORIGIN, SAMEORIGIN`` from a proxy + app, ``DENY, DENY``) carries MULTIPLE tokens — and a browser
    enforces framing when ANY of them is DENY/SAMEORIGIN. So we split on ``,`` and test each token, rather
    than anchor-matching the whole combined value (which would MISS the multi-token case and mint a FALSE
    "unprotected" fact — the exact multi-header-XFO false positive that got the achieved-state oracle
    reverted, see docs/DELIBERATE-REFUSALS.md refusal 8). XFO's own values never contain a legitimate comma
    (ALLOW-FROM takes a single origin), so splitting on ``,`` is sound."""
    return any(_XFO_TOKEN_RE.match(tok.strip()) for tok in value.split(","))


def clickjacking_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED response provably ships NO framing protection — a pure header check over the
    OBSERVED headers, exactly the two defenses a browser enforces. One rule, ``framing_unprotected``:

      * fires (0.9) ONLY when the response carries NEITHER a framing ``X-Frame-Options`` (DENY /
        SAMEORIGIN / the deprecated ALLOW-FROM) NOR a CSP ``frame-ancestors`` directive — both framing
        defenses are absent, so ANY origin can frame the page and mount a UI-redress (clickjacking) attack.

    A response that declares EITHER defense does NOT fire — a present ``frame-ancestors`` directive (even a
    permissive one) is a deliberate framing policy, and firing on it would be exactly the FP a permissive
    value invites (that stays a LEAD, never an oracle FACT). Two further near-zero-FP gates: (1) the
    response must be a FRAMABLE DOCUMENT — its ``Content-Type`` declares ``text/html`` (or
    ``application/xhtml+xml``); a JSON/image/API response cannot be meaningfully clickjacked, so a missing
    or non-document content-type REFUSES. (2) Absence must be OBSERVED: the control MUST carry a
    ``headers`` collection (a captured response's complete header set); an unretained header set REFUSES.
    DELIBERATELY NOT an achieved-state oracle — a "the page WAS framed" signal cannot be near-zero-FP
    (legitimate framing exists). Never raises."""
    if not isinstance(observed_control, Mapping):
        return _clickjacking_signal(False, evidence="no clickjacking control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "framing_unprotected"
    if rule != "framing_unprotected":
        return _clickjacking_signal(
            False, observed={"rule": rule},
            evidence=f"unrecognised/lead-only clickjacking rule {rule!r} (stays a lead)")
    url = _coerce_text(observed_control.get("url")).strip()
    where = f" for {url}" if url else ""
    headers = _normalize_headers(observed_control.get("headers"))
    if headers is None:
        return _clickjacking_signal(
            False, observed={"rule": rule},
            evidence=("no retained response headers to judge — framing posture UNOBSERVED "
                      "(REFUSE: absence must be observed, never assumed)"))
    ctype = headers.get("content-type", "").lower()
    if not ("text/html" in ctype or "application/xhtml+xml" in ctype):
        return _clickjacking_signal(
            False, observed={"rule": rule, "content_type": ctype or None},
            evidence=("the response is not a framable HTML document (Content-Type "
                      f"{ctype or 'absent'!r}) — clickjacking does not apply (REFUSE)"))
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    xfo_protects = _xfo_declares_framing(xfo)
    csp_protects = bool(_CSP_FRAME_ANCESTORS_RE.search(csp))
    if xfo_protects or csp_protects:
        which = ("X-Frame-Options=" + xfo) if xfo_protects else "CSP frame-ancestors"
        return _clickjacking_signal(
            False, observed={"rule": rule, "x_frame_options": xfo or None, "csp": csp or None},
            evidence=f"a framing defense is declared ({which}) — not unprotected")
    return _clickjacking_signal(
        True, conf=0.9,
        evidence=(f"the response{where} ships NO framing defense — neither an X-Frame-Options "
                  "(DENY/SAMEORIGIN) header nor a CSP frame-ancestors directive is present, so any "
                  "origin can frame it (clickjacking / UI-redress is unmitigated)"),
        observed={"rule": rule, "url": url or None, "x_frame_options": xfo or None, "csp": csp or None})


def _csrf_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CSRF_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


_STATE_CHANGING_METHODS = frozenset({"post", "put", "patch", "delete"})


def _is_2xx(status: Any) -> bool:
    return isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300


def csrf_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire on a control-DIFFERENTIAL proving an anti-CSRF (synchronizer) token is NOT ENFORCED on a
    state-changing endpoint — a re-derivation over TWO retained responses, never a scanner's say-so. One
    rule, ``token_not_enforced``, fires (0.9) ONLY when ALL hold:

      * the method is state-changing (POST/PUT/PATCH/DELETE);
      * the CONTROL request (a valid anti-CSRF token present) was ACCEPTED — a retained 2xx
        ``token_present_status`` (the baseline works);
      * the TREATMENT request (the SAME request with the token REMOVED or FORGED) was ACCEPTED — a
        retained 2xx ``token_absent_status``.

    A valid-token request and a stripped/forged-token request BOTH accepted proves the token is not
    validated — no synchronizer-token CSRF defense (a posture weakness). If stripping/forging the token
    changes acceptance (a non-2xx reject / redirect / status divergence), the token IS enforced and it
    does NOT fire. A safe method (GET/HEAD), a control that did not itself succeed, or a missing/non-int
    status REFUSES. Proves ONLY that the token is not enforced — NEVER that a cross-site attack succeeded
    (SameSite cookies / Origin checks are a separate defense layer this does not adjudicate). Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csrf_signal(False, evidence="no CSRF control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "token_not_enforced"
    if rule != "token_not_enforced":
        return _csrf_signal(False, observed={"rule": rule},
                            evidence=f"unrecognised/lead-only CSRF rule {rule!r} (stays a lead)")
    method = _coerce_text(observed_control.get("method")).strip().lower()
    endpoint = _coerce_text(observed_control.get("endpoint")).strip()
    where = (f" {method.upper()} {endpoint}").rstrip() if (method or endpoint) else ""
    if method not in _STATE_CHANGING_METHODS:
        return _csrf_signal(False, observed={"rule": rule, "method": method or None},
                            evidence=(f"method {method!r} is not state-changing — anti-CSRF token enforcement "
                                      "is not applicable (REFUSE)"))
    present = observed_control.get("token_present_status")
    absent = observed_control.get("token_absent_status")
    if (not isinstance(present, int) or isinstance(present, bool)
            or not isinstance(absent, int) or isinstance(absent, bool)):
        return _csrf_signal(False, observed={"rule": rule},
                            evidence=("both the token-present and token-absent/forged response statuses must be "
                                      "retained integers — the control-differential is UNRESOLVED (REFUSE)"))
    if not _is_2xx(present):
        return _csrf_signal(False, observed={"rule": rule, "token_present_status": present},
                            evidence=(f"the valid-token control was not accepted (status {present}) — there is no "
                                      "working baseline to differentiate against (REFUSE)"))
    if not _is_2xx(absent):
        return _csrf_signal(False, observed={"rule": rule, "token_present_status": present,
                                             "token_absent_status": absent},
                            evidence=(f"removing/forging the anti-CSRF token changed acceptance (status {absent} vs "
                                      f"{present}) — the token IS enforced (protected)"))
    return _csrf_signal(True, conf=0.9,
                        evidence=(f"a state-changing request{where} was accepted with a valid anti-CSRF token "
                                  f"(status {present}) AND accepted with the token removed/forged (status {absent}) "
                                  "— the synchronizer token is NOT enforced (no token-based CSRF defense)"),
                        observed={"rule": rule, "method": method, "endpoint": endpoint or None,
                                  "token_present_status": present, "token_absent_status": absent})


def _csrf_achieved_signal(fired: bool, *, evidence: str, observed: dict,
                          conf: float = 0.9) -> OracleSignal:
    # kind is the FROZEN ACHIEVED_STATE (never a new OracleKind — _ALL_ORACLES stays 15); reachable ONLY
    # via the `csrf_achieved` BUG_CLASS_ORACLES row keyed on a fresh ctx key. `conclusive` is True ONLY on a
    # fire: a fire is a decisive, channel-confirmed achieved cross-site state change; a NON-fire is
    # UNINFORMATIVE here (no channel / a SameSite-protected cookie / an enforced token) — never a CLEAN, so
    # this branch is positive-only (clean_capable:false), unlike the predicate/achieved_state modes.
    return OracleSignal(kind=OracleKind.ACHIEVED_STATE, fired=fired,
                        confidence=(conf if fired else 0.0), conclusive=fired,
                        evidence=evidence, observed=observed)


_CSRF_MARKER_MIN_LEN = 8


_CSRF_TOKEN_INDICATORS = (
    "csrf", "xsrf", "authenticity_token", "csrfmiddlewaretoken", "requestverificationtoken",
    "antiforgery", "anti_forgery", "anti-forgery", "_token", "nonce", "verification_token",
)


def _csrf_origin_parts(origin: Any) -> "tuple[str, str] | None":
    """(scheme, host) of a web origin, lowercased, or None when it is not a parseable http(s) origin.
    The host is what the SameSite ``site`` boundary is derived from below."""
    text = _coerce_text(origin).strip()
    if not text:
        return None
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    return scheme, host


def _csrf_registrable(host: str) -> str:
    """A conservative registrable-site key for ``host``. An IP literal is its own site (the whole IP);
    a single-label host (``localhost``) is itself; otherwise the last two labels (eTLD+1 heuristic — no
    PSL, deliberately coarse: it only ever makes the cross-site test STRICTER / more likely to refuse)."""
    h = (host or "").strip(".").lower()
    if not h:
        return ""
    # IPv4/IPv6 literal → the literal is the site (127.0.0.1 and localhost are DIFFERENT sites).
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    return ".".join(labels[-2:])


def _csrf_cross_site(initiator: Any, target: Any) -> bool:
    """Whether ``initiator`` and ``target`` are genuinely CROSS-SITE (schemeful-same-site is False):
    both parse as http(s) origins, and either the scheme differs or their registrable sites differ.
    A same-origin / same-site pair (or an unparseable origin) is NOT cross-site — so a same-origin
    OBSERVATION can never satisfy the topology this class proves."""
    a = _csrf_origin_parts(initiator)
    b = _csrf_origin_parts(target)
    if a is None or b is None:
        return False
    if a[1] == b[1]:                       # same host ⇒ same site (ports are NOT part of the site)
        return False
    if a[0] != b[0]:                       # schemeful same-site: a scheme mismatch is cross-site
        return True
    return _csrf_registrable(a[1]) != _csrf_registrable(b[1])


def _csrf_ambient_cookie_attached(observed_control: Mapping, cookie_name: str) -> bool:
    """Whether the SameSite-honoring browser ACTUALLY attached the ambient session cookie to the
    cross-site write — the load-bearing SameSite-dissolution evidence, re-derived from the CDP-observed
    ``associated_cookies`` (each ``{name, blocked_reasons}``) and corroborated by the observed ``Cookie``
    request header. True ONLY when an entry named ``cookie_name`` has an EMPTY ``blocked_reasons`` list
    (the browser sent it) AND that name appears in the observed Cookie header. A ``Lax``/``Strict`` cookie
    carries a ``SameSite*`` blocked reason (or is simply absent) ⇒ False ⇒ the oracle REFUSES."""
    name = (cookie_name or "").strip()
    if not name:
        return False
    assoc = observed_control.get("associated_cookies")
    if not isinstance(assoc, Sequence) or isinstance(assoc, (str, bytes)):
        return False
    attached = False
    for entry in assoc:
        if not isinstance(entry, Mapping):
            continue
        if _coerce_text(entry.get("name")).strip() != name:
            continue
        reasons = entry.get("blocked_reasons")
        blocked = bool(reasons) if isinstance(reasons, Sequence) and not isinstance(reasons, (str, bytes)) else bool(_coerce_text(reasons).strip())
        if not blocked:
            attached = True
    # Corroborate against the actual Cookie header the browser sent on the cross-site request.
    cookie_header = _coerce_text(observed_control.get("observed_cookie_header"))
    return attached and (f"{name}=" in cookie_header)


def _csrf_anti_token_present(observed_control: Mapping) -> bool:
    """Whether the OBSERVED cross-site write carried an anti-CSRF token in its body fields or request
    headers (⇒ NOT ambient-cookie-only). Re-derived from the retained observed field / header names."""
    names: list[str] = []
    for key in ("observed_request_fields", "observed_request_header_names"):
        seq = observed_control.get(key)
        if isinstance(seq, Sequence) and not isinstance(seq, (str, bytes)):
            names.extend(_coerce_text(n).strip().lower() for n in seq)
    return any(ind in n for n in names for ind in _CSRF_TOKEN_INDICATORS)


def csrf_achieved_oracle(observed_control: Any) -> OracleSignal:
    """Fire on browser-OBSERVED evidence proving an ACHIEVED cross-site state change — a re-derivation
    over evidence a real SameSite-honoring headless browser produced, NEVER a scanner's bare-bool say-so.
    ONE rule, ``cross_site_state_change``, fires (0.9) ONLY when ALL hold:

      * the method is state-changing (POST/PUT/PATCH/DELETE);
      * ``cross_origin`` is DERIVED, not attested: the retained ``initiator_origin`` (the browser-attested
        ``Origin`` of the page that issued the write) and ``target_origin`` are genuinely CROSS-SITE
        (:func:`_csrf_cross_site` — different registrable sites / schemeful-same-site is False). A
        same-origin observation can never satisfy this;
      * the ambient session cookie was ACTUALLY ATTACHED cross-site by the browser: the CDP-observed
        ``associated_cookies`` shows the ``ambient_cookie_name`` cookie with an EMPTY ``blocked_reasons``
        AND it appears in the observed ``Cookie`` header (:func:`_csrf_ambient_cookie_attached`). This is
        the SameSite-dissolution proof — a ``Lax``/``Strict`` cookie is NOT sent cross-site (it carries a
        ``SameSite*`` blocked reason), so this REFUSES against a SameSite-defended target;
      * ``ambient_only`` is DERIVED, not attested: the observed write carried NO anti-CSRF token in its
        body fields or request headers (:func:`_csrf_anti_token_present` is False) — the cookie is the
        sole credential;
      * a VIGIL-chosen UNIQUE per-probe ``marker`` (>= 8 chars, so it cannot pre-exist) appears in the
        AUTHORITATIVE post-state readback taken AFTER the ambient-cookie cross-site request
        (``with_cookie_state``);
      * that SAME marker is ABSENT from the readback of the NO-COOKIE control (``no_cookie_state``) — the
        identical cross-site request issued FIRST WITHOUT the ambient cookie, so a marker already present
        there attributes the change to something other than the cookie and REFUSES.

    A state change reached WITH the browser-attached ambient cookie but NOT without it, from a genuinely
    cross-site initiator, with no anti-CSRF token, proves the write was authorized SOLELY by the ambient
    session cookie riding cross-site — an achieved CSRF. This DISSOLVES the SameSite objection that got
    the naive version refused: against a target defended by ``SameSite=Strict``/``Lax`` ALONE the browser
    does NOT attach the cookie (``blocked_reasons`` carries ``SameSiteStrict``/``SameSiteLax`` and no state
    change is reached), so BOTH the attachment check AND the with-cookie readback fail → NO fire (correct).
    An enforced anti-CSRF token rejects the token-less write (no state change) AND, if VIGIL had supplied
    one, would trip the anti-token derivation → no fire. An endpoint that accepts the write with NO cookie
    (merely unauthenticated, not CSRF) leaves the marker in ``no_cookie_state`` → no fire. A urllib /
    same-origin / bare-bool context that lacks the browser-observed ``associated_cookies`` /
    ``initiator_origin`` evidence can NEVER fire — the oracle refuses to mint without it. Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csrf_achieved_signal(False, evidence="no CSRF achieved-state evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "cross_site_state_change"
    if rule != "cross_site_state_change":
        return _csrf_achieved_signal(
            False, observed={"rule": rule},
            evidence=f"unrecognised/lead-only CSRF-achieved rule {rule!r} (stays a lead)")
    method = _coerce_text(observed_control.get("method")).strip().lower()
    endpoint = _coerce_text(observed_control.get("endpoint")).strip()
    where = (f" {method.upper()} {endpoint}").rstrip() if (method or endpoint) else ""
    if method not in _STATE_CHANGING_METHODS:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "method": method or None},
            evidence=(f"method {method!r} is not state-changing — an achieved CSRF is not applicable "
                      "(REFUSE)"))
    # DERIVE cross_origin from the OBSERVED origins (browser-attested Origin vs the target) — never a bool.
    initiator_origin = _coerce_text(observed_control.get("initiator_origin")).strip()
    target_origin = _coerce_text(observed_control.get("target_origin")).strip()
    if not _csrf_cross_site(initiator_origin, target_origin):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "initiator_origin": initiator_origin or None,
                             "target_origin": target_origin or None},
            evidence=("the write's OBSERVED initiator origin is not genuinely CROSS-SITE from the target "
                      "(a same-origin / same-site / unparseable observation, or a bare-bool context with no "
                      "observed origins) — the cross-origin topology is UNPROVEN (REFUSE)"))
    # DERIVE the SameSite-dissolution fact from the CDP-observed associated cookies — never a bool. This
    # is what refuses a SameSite=Strict/Lax target: the browser did not attach the cookie cross-site.
    ambient_cookie_name = _coerce_text(observed_control.get("ambient_cookie_name")).strip()
    if not _csrf_ambient_cookie_attached(observed_control, ambient_cookie_name):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "ambient_cookie_name": ambient_cookie_name or None,
                             "associated_cookies": observed_control.get("associated_cookies")},
            evidence=("the SameSite-honoring browser did NOT attach the ambient session cookie to the "
                      "cross-site write (no observed associated-cookie with empty blocked_reasons + a "
                      "matching Cookie header) — a SameSite=Strict/Lax cookie, or the absence of the "
                      "browser-observed cookie-attachment evidence, lands here (REFUSE)"))
    # DERIVE ambient_only from the OBSERVED request — an anti-CSRF token defeats the ambient-cookie-only
    # topology (and a bare-bool context with no observed request evidence stays safe: no fire above).
    if _csrf_anti_token_present(observed_control):
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "observed_request_fields": observed_control.get("observed_request_fields"),
                             "observed_request_header_names": observed_control.get("observed_request_header_names")},
            evidence=("the OBSERVED cross-site write carried an anti-CSRF token (body field or request "
                      "header) — the write was NOT authorized by the ambient cookie ALONE (REFUSE)"))
    marker = _coerce_text(observed_control.get("marker")).strip()
    if len(marker) < _CSRF_MARKER_MIN_LEN:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker_len": len(marker)},
            evidence=(f"the per-probe marker must be a VIGIL-chosen token of >= {_CSRF_MARKER_MIN_LEN} "
                      "chars so it cannot pre-exist in the readback (REFUSE)"))
    with_cookie = _coerce_text(observed_control.get("with_cookie_state"))
    no_cookie = _coerce_text(observed_control.get("no_cookie_state"))
    in_with = marker in with_cookie
    in_no = marker in no_cookie
    if not in_with:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker": marker, "in_with_cookie": in_with,
                             "in_no_cookie": in_no},
            evidence=(f"the marker does NOT appear in the authoritative post-state after the ambient-cookie "
                      f"cross-site request{where} — no cross-site state change was reached (a SameSite "
                      "cookie not sent cross-site, or an enforced token, would land here — correct non-fire)"))
    if in_no:
        return _csrf_achieved_signal(
            False, observed={"rule": rule, "marker": marker, "in_with_cookie": in_with,
                             "in_no_cookie": in_no},
            evidence=("the marker ALSO appears in the NO-COOKIE control's post-state — the state change is "
                      "NOT attributable to the ambient cookie (a merely-unauthenticated write, not CSRF) "
                      "(REFUSE)"))
    return _csrf_achieved_signal(
        True, conf=0.9,
        evidence=(f"a VIGIL-chosen unique marker reached the authoritative post-state after a cross-site "
                  f"state-changing request{where}: the browser ATTACHED the ambient session cookie cross-site "
                  "(observed, no SameSite block), carried NO anti-CSRF token, and the marker is ABSENT from "
                  "the no-cookie control — the write was authorized solely by the ambient cookie riding "
                  "cross-site (an achieved CSRF)"),
        observed={"rule": rule, "method": method, "endpoint": endpoint or None, "marker": marker,
                  "initiator_origin": initiator_origin, "target_origin": target_origin,
                  "ambient_cookie_name": ambient_cookie_name, "in_with_cookie": in_with,
                  "in_no_cookie": in_no})


def _postmessage_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.POSTMESSAGE_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


_POSTMESSAGE_WILDCARD_RE = re.compile(
    r"""(?is)postMessage\s*\((?:[^()]|\([^()]*\))*,\s*(['"])\*\1\s*\)""")


_ORIGIN_REF_RE = re.compile(r"(?i)\borigin\b")


_USES_MESSAGE_DATA_RE = re.compile(r"(?i)\.\s*data\b")


def postmessage_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when a RETAINED postMessage handler source re-derives a wildcard cross-origin weakness — a
    sound STATIC check over the source ALONE, never a scanner's say-so. Two rules:

      * ``wildcard_target`` — a ``postMessage(<data>, "*")`` send whose targetOrigin literal is ``*`` (in
        the retained source), OR a retained ``target_origin`` field equal to ``*``. A ``*`` targetOrigin
        broadcasts the message to ANY origin (data exfiltration to a hostile frame). A send to a SPECIFIC
        origin does NOT fire.
      * ``no_origin_check`` — a ``message``-event handler that CONSUMES the untrusted payload
        (``event.data``) yet references ``origin`` NOWHERE in its source: there is provably no
        ``event.origin`` validation, so the handler acts on messages from ANY origin. A handler that
        references ``origin`` ANYWHERE (an origin check — even in a helper/guard) does NOT fire
        (near-zero-FP: a present ``origin`` reference safely SUPPRESSES).

    Proves the MISSING/WEAK origin restriction (a posture weakness), NEVER a proven cross-origin exploit.
    ReDoS-safe (length-capped source, bounded alternation). Pure + deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return _postmessage_signal(False, evidence="no postMessage control evidence", observed={})
    source = _coerce_text(observed_control.get("handler_source") or observed_control.get("source"))[:20000]
    target_origin = _coerce_text(observed_control.get("target_origin")).strip()
    rule = _coerce_text(observed_control.get("rule")).strip().lower()
    if not rule:
        rule = ("wildcard_target" if (target_origin or "postmessage" in source.lower())
                else ("no_origin_check" if source else ""))

    if rule == "wildcard_target":
        if target_origin == "*":
            return _postmessage_signal(
                True, conf=0.9,
                evidence=("a postMessage send uses targetOrigin '*' (retained literal) — the message is "
                          "broadcast to ANY origin"),
                observed={"rule": rule, "target_origin": "*"})
        if source and _POSTMESSAGE_WILDCARD_RE.search(source):
            return _postmessage_signal(
                True, conf=0.9,
                evidence=("the handler source calls postMessage(<data>, '*') — a wildcard targetOrigin "
                          "broadcasts the message to ANY origin"),
                observed={"rule": rule, "wildcard_send": True})
        return _postmessage_signal(
            False, observed={"rule": rule, "target_origin": target_origin or None},
            evidence="no wildcard '*' targetOrigin in the retained send/source — a specific-origin send is not a weakness (no fire)")

    if rule == "no_origin_check":
        if not source:
            return _postmessage_signal(False, observed={"rule": rule},
                                       evidence="no retained handler source to judge (REFUSE)")
        if not _USES_MESSAGE_DATA_RE.search(source):
            return _postmessage_signal(
                False, observed={"rule": rule},
                evidence="the handler does not consume event.data — no untrusted cross-origin payload is acted on (no fire)")
        if _ORIGIN_REF_RE.search(source):
            return _postmessage_signal(
                False, observed={"rule": rule},
                evidence="the handler references `origin` — an origin check is present (protected; no fire)")
        return _postmessage_signal(
            True, conf=0.9,
            evidence=("a message-event handler consumes event.data yet references `origin` NOWHERE — it "
                      "validates no sender origin and acts on messages from ANY origin"),
            observed={"rule": rule, "uses_data": True, "checks_origin": False})

    return _postmessage_signal(False, observed={"rule": rule},
                               evidence=f"unrecognised/lead-only postMessage rule {rule!r} (stays a lead)")


_CSP_NONCE_HASH_RE = re.compile(r"(?i)^'(?:nonce-|sha256-|sha384-|sha512-)")


def _parse_csp(header: Any) -> "dict[str, list[str]]":
    """Parse a CSP header value into ``{directive_lower: [source_tokens]}``. First occurrence of a
    directive wins (CSP spec); source tokens are kept verbatim (keyword comparisons lowercase a copy).
    Length-capped + split-based (ReDoS-safe). Never raises."""
    directives: dict[str, list[str]] = {}
    for part in _coerce_text(header)[:8000].split(";"):
        toks = part.split()
        if not toks:
            continue
        name = toks[0].lower()
        if name not in directives:
            directives[name] = toks[1:]
    return directives


def _effective_script_src(directives: "dict[str, list[str]]") -> "list[str] | None":
    """The effective script-source directive tokens a browser applies to ``<script>`` execution:
    ``script-src`` if present, else the ``default-src`` fallback, else ``None`` (no script restriction)."""
    if "script-src" in directives:
        return directives["script-src"]
    if "default-src" in directives:
        return directives["default-src"]
    return None


def _csp_signal(fired: bool, *, evidence: str, observed: dict, conf: float = 0.9) -> OracleSignal:
    return OracleSignal(kind=OracleKind.CSP_POSTURE, fired=fired,
                        confidence=(conf if fired else 0.0), evidence=evidence, observed=observed)


def csp_posture_oracle(observed_control: Any) -> OracleSignal:
    """Fire when the RETAINED enforced CSP header's effective ``script-src`` carries a real permissive
    weakness — a sound parse over the header ALONE, no browser, offline. One rule,
    ``permissive_script_src``, fires (0.9) when the effective script-src (``script-src`` else the
    ``default-src`` fallback) of the ENFORCED (non-report-only) policy contains ANY of:

      * ``'unsafe-inline'`` WITHOUT a neutralizing nonce-/hash- companion (a nonce/hash makes the browser
        IGNORE ``'unsafe-inline'`` — CSP3 — so ``'unsafe-inline'`` beside a nonce/hash is NOT flagged);
      * a wildcard ``*`` source (any host may serve script);
      * an ``http:`` or ``data:`` scheme source (any http origin / inline data URI may serve script);
      * ``'unsafe-eval'`` (``eval``/``Function`` are enabled).

    Proves the PARSED policy weakness (a posture-FACT), NEVER an achieved exploit — the achieved bypass is
    the strictly-stronger ``csp_bypass`` class (DOM_EXECUTION + the ``csp_purports_to_block`` guard). A
    well-formed policy (nonce-based, no permissive token), a REPORT-ONLY header (it enforces nothing, so a
    permissive report-only is not judged here), or a policy with no effective script-src do NOT fire
    (near-zero-FP). Pure + deterministic; ReDoS-safe; never raises."""
    if not isinstance(observed_control, Mapping):
        return _csp_signal(False, evidence="no CSP control evidence", observed={})
    rule = _coerce_text(observed_control.get("rule")).strip().lower() or "permissive_script_src"
    if rule != "permissive_script_src":
        return _csp_signal(False, observed={"rule": rule},
                           evidence=f"unrecognised/lead-only CSP rule {rule!r} (stays a lead)")
    url = _coerce_text(observed_control.get("url")).strip()
    where = f" for {url}" if url else ""
    if bool(observed_control.get("report_only")):
        return _csp_signal(
            False, observed={"rule": rule, "report_only": True},
            evidence=("the retained CSP is REPORT-ONLY (Content-Security-Policy-Report-Only) — it enforces "
                      "nothing, so a permissive value here is not an enforced weakness (stays a lead)"))
    header = _coerce_text(observed_control.get("header"))
    if not header.strip():
        return _csp_signal(
            False, observed={"rule": rule},
            evidence="no retained enforced CSP header to judge — CSP posture UNOBSERVED (REFUSE)")
    directives = _parse_csp(header)
    eff = _effective_script_src(directives)
    if eff is None:
        return _csp_signal(
            False, observed={"rule": rule},
            evidence=("the retained CSP declares neither script-src nor default-src — no effective "
                      "script restriction to judge for THIS oracle (stays a lead; a scriptless-CSP "
                      "weakness is a distinct claim)"))
    src_dir = "script-src" if "script-src" in directives else "default-src"
    lower = [t.lower() for t in eff]
    has_nonce_or_hash = any(_CSP_NONCE_HASH_RE.match(t) for t in eff)
    # CSP3: 'strict-dynamic' makes conformant browsers IGNORE host-source and scheme-source expressions
    # ('*', http:, https:, 'self', specific hosts) AND 'unsafe-inline'. Beside 'strict-dynamic' those are
    # therefore NOT weaknesses — flagging them false-flags the Google/OWASP-canonical hardened policy
    # (`'nonce-r' 'strict-dynamic' https: http: 'unsafe-inline'`). 'unsafe-eval' is NOT neutralized by
    # 'strict-dynamic' (eval stays enabled), so it is still flagged.
    has_strict_dynamic = "'strict-dynamic'" in lower
    weaknesses: list[str] = []
    if "'unsafe-inline'" in lower and not has_nonce_or_hash and not has_strict_dynamic:
        weaknesses.append("'unsafe-inline' with no neutralizing nonce/hash")
    if "'unsafe-eval'" in lower:
        weaknesses.append("'unsafe-eval'")
    if "*" in lower and not has_strict_dynamic:
        weaknesses.append("wildcard '*' source")
    if "http:" in lower and not has_strict_dynamic:
        weaknesses.append("'http:' scheme source")
    if "data:" in lower and not has_strict_dynamic:
        weaknesses.append("'data:' scheme source")
    if not weaknesses:
        note = (" ('strict-dynamic' present — host/scheme sources and 'unsafe-inline' are ignored by the "
                "browser per CSP3, not a weakness)" if has_strict_dynamic else
                (" ('unsafe-inline' is present but NEUTRALIZED by a nonce/hash — not a weakness)"
                 if ("'unsafe-inline'" in lower and has_nonce_or_hash) else ""))
        return _csp_signal(
            False, observed={"rule": rule, "effective_directive": src_dir, "script_src": eff},
            evidence=(f"the effective {src_dir} carries no permissive weakness — a well-formed policy"
                      f"{note} (no fire)"))
    return _csp_signal(
        True, conf=0.9,
        evidence=(f"the enforced CSP's effective {src_dir}{where} is permissive: "
                  + "; ".join(weaknesses)
                  + " — script execution is not effectively restricted (a real CSP weakness)"),
        observed={"rule": rule, "url": url or None, "effective_directive": src_dir,
                  "script_src": eff, "weaknesses": weaknesses})


def csp_purports_to_block(observed_control: Any) -> bool:
    """The achieved-CSP-bypass guard: True iff a RETAINED, ENFORCED (non-report-only) CSP whose effective
    ``script-src`` is RESTRICTIVE — it purported to block an arbitrary injected script — was present, so a
    canary that NONETHELESS EXECUTED is a genuine BYPASS. False when the CSP is absent, report-only, has no
    effective script-src, or is PERMISSIVE (``'unsafe-inline'`` unneutralized, a wildcard ``*``, or an
    ``http:``/``data:`` scheme source) — under a permissive/absent policy the execution was permitted /
    unrestricted, so it is plain DOM-XSS, never a bypass. Conservative by design (a permissive policy's
    gadget bypass stays a LEAD): the FACT mints ONLY when a restrictive policy was defeated. Pure +
    deterministic; never raises."""
    if not isinstance(observed_control, Mapping):
        return False
    if bool(observed_control.get("report_only")):
        return False
    header = _coerce_text(observed_control.get("header"))
    if not header.strip():
        return False
    eff = _effective_script_src(_parse_csp(header))
    if eff is None:
        return False
    lower = [t.lower() for t in eff]
    has_nonce_or_hash = any(_CSP_NONCE_HASH_RE.match(t) for t in eff)
    # 'strict-dynamic' (CSP3) makes the browser IGNORE host/scheme sources AND 'unsafe-inline', so a
    # strict-dynamic policy IS restrictive (it blocks an arbitrary injected script) — a canary that
    # nonetheless executes under it is a genuine bypass. Do not treat those tokens as permissive then.
    has_strict_dynamic = "'strict-dynamic'" in lower
    inline_allowed = ("'unsafe-inline'" in lower) and not has_nonce_or_hash and not has_strict_dynamic
    permissive = inline_allowed or (not has_strict_dynamic and ("*" in lower or "http:" in lower or "data:" in lower))
    return not permissive


def dom_execution_csp_bypass_oracle(binding_calls: Any, canary: str, csp_control: Any) -> OracleSignal:
    """The achieved-CSP-bypass adjudication: the DOM_EXECUTION oracle, additionally GUARDED so it fires
    ONLY when the injected canary EXECUTED (``dom_execution_oracle`` fires) AND the RETAINED enforced CSP
    purported to block that execution (``csp_purports_to_block``). If execution occurred but the CSP did
    NOT purport to block (absent / report-only / permissive), it is plain DOM-XSS, NOT a bypass — the
    signal is returned NON-firing so a no-CSP (or permissive-CSP) execution can never be relabelled a
    bypass and a tampered (permissive) CSP cannot mint the FACT offline. Reuses OracleKind.DOM_EXECUTION
    (no new kind). Pure + deterministic; never raises."""
    sig = dom_execution_oracle(binding_calls, canary)
    if not sig.fired:
        return sig
    if csp_purports_to_block(csp_control):
        obs = dict(sig.observed)
        obs["csp_bypassed"] = True
        return OracleSignal(
            kind=OracleKind.DOM_EXECUTION, fired=True, confidence=sig.confidence,
            evidence=(sig.evidence + " — DESPITE a retained enforced CSP whose script-src purported to "
                      "block it (a genuine CSP bypass, not DOM-XSS on a permissive/absent policy)"),
            observed=obs)
    obs = dict(sig.observed)
    obs["csp_bypassed"] = False
    return OracleSignal(
        kind=OracleKind.DOM_EXECUTION, fired=False, confidence=0.0,
        evidence=("injected script executed, but no retained ENFORCED CSP purported to block it "
                  "(absent / report-only / permissive script-src) — this is plain DOM-XSS, NOT a CSP "
                  "bypass (the csp_bypass FACT refuses)"),
        observed=obs)


_WEAK_HS_SECRETS: tuple[str, ...] = (
    "secret", "secretkey", "secret_key", "password", "changeme", "admin", "test", "jwt",
    "jwtsecret", "jwt_secret", "jwt-secret", "key", "private", "your-256-bit-secret",
    "your_jwt_secret", "supersecret", "s3cr3t", "1234567890", "qwerty", "0000000000000000",
)


_JWT_HMAC_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


_JWT_SEG_CAP = 8192


_JWT_SIGNING_INPUT_CAP = 65536


def _jwt_b64url_decode(seg: str) -> bytes:
    """base64url-decode one JWT segment (padding restored). Raises on malformed input."""
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _looks_like_public_key(candidate: str) -> bool:
    """True iff the candidate is PEM public-key material (an RSA/EC public key). Used ONLY to LABEL a
    confirmed HMAC reproduction as algorithm confusion vs a plain weak secret — never to gate firing."""
    return "PUBLIC KEY" in candidate


def jwt_forgery_oracle(token: Any, *, candidate_keys: Sequence[str | bytes] = ()) -> OracleSignal:
    """Fire (SSO_ASSERTION_FORGERY) iff the captured JWT ``token`` is STRUCTURALLY FORGEABLE by a proof
    re-runnable from the token alone: (a) ``alg=none``/``None``; (b) an HS* signature RECOMPUTABLE from a
    supplied/weak candidate secret; or (c) an RS256->HS256 confusion (the HS* signature reproduces with a
    supplied RSA/EC PUBLIC key as the HMAC secret). A normal RS256 token with an unknown key, an HS*
    token whose secret is not recoverable, and a malformed token DO NOT fire (near-zero-FP). Pure +
    deterministic — the verdict re-verifies offline from the token + retained candidate keys."""
    kind = OracleKind.SSO_ASSERTION_FORGERY
    text = token if isinstance(token, str) else _coerce_text(token)
    parts = text.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="not a well-formed three-part JWT — nothing to adjudicate")
    try:
        header = json.loads(_jwt_b64url_decode(parts[0][:_JWT_SEG_CAP]))
    except (ValueError, binascii.Error):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="JWT header is not valid base64url JSON — cannot adjudicate")
    if not isinstance(header, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="JWT header is not a JSON object — cannot adjudicate")
    alg = _coerce_text(header.get("alg")).strip()

    # (a) alg=none — a valid token needs NO secret; anyone can mint one. Structural forgery by
    #     construction. (All case variants: none / None / NONE / nOnE.)
    if alg.lower() == "none":
        return OracleSignal(
            kind=kind, fired=True, confidence=0.95,
            evidence=(f"alg={alg!r}: the token is UNSIGNED — a valid token needs no secret, so anyone "
                      f"can forge one with an arbitrary payload (re-verify: header.alg lowercases to 'none')"),
            observed={"proof": "alg_none", "alg": alg, "header": dict(header)})

    # (b)/(c) HS* — try to REPRODUCE the exact signature by HMAC over `header.payload`. An exact match
    #     is a deterministic proof the token is forgeable by whoever holds that secret. If the matching
    #     secret is a PUBLIC key, it is the RS256->HS256 confusion (public material => anyone forges).
    if alg.upper() in _JWT_HMAC_HASH:
        hasher = _JWT_HMAC_HASH[alg.upper()]
        # bound the HMAC signing input before spending work per candidate key (DoS-safe on an
        # attacker-sized token — an oversized "token" is not a real JWT, so we stay a lead).
        if len(parts[0]) + 1 + len(parts[1]) > _JWT_SIGNING_INPUT_CAP:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"{alg} signing input exceeds {_JWT_SIGNING_INPUT_CAP} bytes — not a plausible "
                          f"JWT; declining the HMAC recompute (stays a lead)"),
                observed={"alg": alg, "signing_input_len": len(parts[0]) + 1 + len(parts[1])})
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii", "ignore")
        target_sig = parts[2]
        for cand in (*candidate_keys, *_WEAK_HS_SECRETS):
            secret = cand if isinstance(cand, bytes) else _coerce_text(cand).encode("utf-8")
            recomputed = base64.urlsafe_b64encode(
                hmac.new(secret, signing_input, hasher).digest()).rstrip(b"=").decode("ascii")
            if hmac.compare_digest(recomputed, target_sig):
                cand_text = cand.decode("utf-8", "replace") if isinstance(cand, bytes) else _coerce_text(cand)
                if _looks_like_public_key(cand_text):
                    return OracleSignal(
                        kind=kind, fired=True, confidence=0.99,
                        evidence=(f"RS256->HS256 algorithm confusion: the {alg} signature reproduces with "
                                  f"the supplied RSA/EC PUBLIC key as the HMAC secret — public material "
                                  f"anyone holds forges accepted tokens (re-verify: "
                                  f"HMAC-{alg}(pubkey, header.payload) == signature)"),
                        observed={"proof": "rs256_hs256_confusion", "alg": alg,
                                  "hmac_key_is_public_key": True})
                return OracleSignal(
                    kind=kind, fired=True, confidence=0.99,
                    evidence=(f"{alg} signature RECOMPUTABLE from a weak/known secret {cand_text!r} — the "
                              f"exact HMAC reproduces, so whoever holds this secret forges arbitrary "
                              f"tokens (re-verify: HMAC-{alg}({cand_text!r}, header.payload) == signature)"),
                    observed={"proof": "hs256_weak_key", "alg": alg, "recovered_key": cand_text})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"{alg} signature not reproducible from any supplied/weak candidate key — the secret "
                      f"is not recoverable, so no structural-forgery proof (stays a lead)"),
            observed={"alg": alg, "candidates_tried": len(candidate_keys) + len(_WEAK_HS_SECRETS)})

    # A normal RS256/ES256/... token (an asymmetric signature, never an HMAC) — forging it needs the
    # PRIVATE key, which the token alone cannot yield. Correctly NOT a structural-forgery proof.
    #
    # DELIBERATELY NOT a fire path: an EMBEDDED verification key (a `jwk` or `x5c` header whose key
    # verifies the token). It is tempting to call that "self-signed, forgeable" (RFC 8725 §3.5), but an
    # adversarial review proved it is NOT offline-provable as a forgery: a legitimate CA-chained `x5c`
    # (the RFC 7515 §4.1.6 norm — the leaf IS the cert whose key signed the JWS) verifies identically to
    # a self-signed one, and legitimate flows embed a self-verifying `jwk` by design (DPoP proofs,
    # SIOP id_tokens). Whether the relying party WRONGLY trusts the embedded key over a proper trust
    # anchor is unknowable from the token alone — so firing here would false-positive on real Azure/
    # enterprise/DPoP tokens. It is a belief-raising RISK INDICATOR at most (a future AEGIS lead), never
    # a confirmed FACT. (`jku`/`x5u` URL-fetch headers are likewise leads — an offline oracle can't fetch.)
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=(f"alg={alg or '?'!r}: an asymmetric signature requires the private key to forge — not "
                  f"structurally forgeable from the token alone (stays a lead)"),
        observed={"alg": alg})


_IMDS_STR_CAP = 8192


_IMDS_OBS_CAP = 512


_IMDS_AWS_AKID = re.compile(r"^ASIA[0-9A-Z]{16}$")


_IMDS_AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")


_IMDS_AWS_IP = "169.254.169.254"


_IMDS_METADATA_IP = ipaddress.ip_address(_IMDS_AWS_IP)


_IMDS_AWS_METADATA_IPS = frozenset({_IMDS_METADATA_IP, ipaddress.ip_address("fd00:ec2::254")})


_IMDS_GCP_METADATA_IPS = frozenset({_IMDS_METADATA_IP, ipaddress.ip_address("fd20:ce::254")})


_IMDS_AWS_CRED_PATH = "iam/security-credentials"


_IMDS_URL_SCHEMES = frozenset({"http", "https"})


_IMDS_OK_PORTS = frozenset({None, 80, 443})


_IMDS_GCP_HOSTS = frozenset({"metadata.google.internal"})


_IMDS_GCP_PATH_RE = re.compile(r"(^|/)computemetadata/v1/(?:[^/]+/)*service-accounts/[^/]+/token(/|$)")


_IMDS_AWS_ACTIONS = frozenset({"sts:getcalleridentity", "getcalleridentity"})


_IMDS_GCP_ACTIONS = frozenset({"tokeninfo", "userinfo", "oauth2/v3/tokeninfo", "oauth2/v1/tokeninfo"})


_IMDS_AWS_PROVIDERS = frozenset({"aws", "amazon", "ec2", "amazon web services"})


_IMDS_GCP_PROVIDERS = frozenset({"gcp", "google", "gce", "google cloud", "googlecloud"})


_IMDS_ERROR_KEYS = frozenset({
    "error", "errors", "errormessage", "error_message", "errorcode", "error_code",
    "message", "code", "__type", "fault", "error_description",
})


_IMDS_FAIL_STATUS = frozenset({
    "error", "fail", "failed", "failure", "forbidden", "unauthorized", "denied", "timeout", "timed out",
    "timed_out", "timedout", "connection refused", "connrefused", "conn refused", "refused", "reset",
    "connreset", "unreachable", "no route to host", "econnrefused", "etimedout",
})


_IMDS_AWS_CONFIRM_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")


_IMDS_GCP_CONFIRM_HOSTS = frozenset({
    "oauth2.googleapis.com", "www.googleapis.com", "openidconnect.googleapis.com", "accounts.google.com",
})


def _imds_text(value: Any) -> str:
    return _coerce_text(value)[:_IMDS_STR_CAP]


def _imds_obs_source(source: str) -> str:
    """The source shown in the oracle's ``observed`` evidence: query + fragment STRIPPED (they carry no part
    of the metadata-endpoint discriminator and could hold a secret, audit B5) and length-capped."""
    return source.split("?", 1)[0].split("#", 1)[0][:_IMDS_OBS_CAP]


def _imds_credential_obj(capture: Mapping[str, Any]) -> Mapping[str, Any]:
    """The credential sub-object: a nested ``credential``/``creds``/``credentials`` mapping, or the
    capture itself (a flat record). Never raises."""
    for k in ("credential", "creds", "credentials"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            return v
    return capture


def _imds_source(capture: Mapping[str, Any], cred: Mapping[str, Any]) -> str:
    """The retained SOURCE url/endpoint of the credential — the load-bearing discriminator that a
    credential came from the metadata endpoint (not an env var / a creds file). Read from the credential
    first, then the capture."""
    for obj in (cred, capture):
        if not isinstance(obj, Mapping):
            continue
        for k in ("source", "url", "metadata_url", "endpoint", "uri"):
            v = obj.get(k)
            if v not in (None, ""):
                return _imds_text(v)
    return ""


def _imds_host_to_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Canonicalize a URL host to an IP address if it DENOTES one — a textual IPv4/IPv6 literal, a 32-bit
    decimal (``2852039166``), a hex literal (``0xA9FEA9FE``), or an IPv6-mapped literal
    (``::ffff:a9fe:a9fe``) — else None. These SSRF IP encodings all denote the same host, so an IMDS reach
    via any of them is still a reach (S1 recall). A DNS name (``metadata.google.internal``,
    ``169.254.169.254.attacker.com``) is NOT an IP -> None. Never raises."""
    # Do NOT strip whitespace: urlsplit already yields a clean hostname, and stripping would let a crafted
    # trailing/leading-whitespace host (``169.254.169.254 ``) — which glibc inet_aton accepts but getaddrinfo
    # rejects, a client-dependent reach — canonicalize to the metadata IP (red-pen whitespace vector). A host
    # with whitespace now falls through ipaddress + the strict numeric regex to None.
    if host.startswith("[") and host.endswith("]"):     # a bracketed IPv6 literal
        host = host[1:-1]
    if not host:
        return None
    if not host.isascii():
        # A non-ASCII host denotes no real IP: str.isdigit()/int() parse Unicode decimal digits
        # (e.g. Arabic-Indic ``٢٨٥٢٠٣٩١٦٦``) to the metadata IP, but no OS resolver / inet_aton / IDNA path
        # does — so accepting it would fire on a host that reaches nothing (red-pen BLOCK-A). ASCII decimal
        # (``2852039166``) and hex (``0xA9FEA9FE``) are ``.isascii()`` and still accepted (S1 recall).
        return None
    try:
        return ipaddress.ip_address(host)               # textual IPv4 / IPv6 literal
    except ValueError:
        pass
    # A 32-bit integer host (decimal ``2852039166`` / hex ``0xA9FEA9FE``) denotes an IPv4 address. Parse it
    # ONLY from a STRICT form: bare ASCII digits, or ``0x`` + bare ASCII hex — NO underscores (Python's
    # ``int()`` accepts ``0xa9_fe_a9_fe`` / ``2_852_039_166``), NO sign, NO whitespace. A host string no OS
    # resolver / inet_aton would accept must not canonicalize to the metadata IP (red-pen BLOCK-A + the
    # hex-underscore vector). ``isascii()`` above already rejects Unicode-digit hosts.
    low = host.lower()
    # Decimal: NO leading zero. Python's int() reads ``02852039166`` as decimal (== the metadata IP), but
    # every resolver / inet_aton reads a leading-zero token as OCTAL (``02852039166`` is invalid octal -> no
    # reach) — so a leading-zero decimal denotes nothing and must not canonicalize to the metadata IP
    # (red-pen octal/leading-zero vector). ``[1-9][0-9]*`` also rejects a bare ``0`` (== 0.0.0.0, not metadata).
    if re.fullmatch(r"[1-9][0-9]*", host):
        n = int(host)
    elif re.fullmatch(r"0x[0-9a-f]+", low):
        n = int(low, 16)
    else:
        return None
    if not (0 <= n <= 0xFFFFFFFF):
        return None
    return ipaddress.ip_address(n)


def _imds_ip_in(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
                allowed: frozenset) -> bool:
    """True iff ``ip`` is one of the ``allowed`` metadata IPs (unwrapping an IPv4-mapped IPv6 address first,
    so ``::ffff:a9fe:a9fe`` matches the IPv4 metadata IP). Native IPv6 endpoints (fd00:ec2::254 /
    fd20:ce::254) are matched directly (audit B6)."""
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip in allowed


def _imds_path_has(path: str, marker: str) -> bool:
    """True iff ``marker`` (which may itself contain ``/``) appears in ``path`` as a bounded run of whole
    PATH SEGMENTS — i.e. delimited by ``/`` or a path boundary — never as a mid-segment substring. So
    ``iam/security-credentials`` matches ``/latest/meta-data/iam/security-credentials/role`` but NOT the
    forged sibling ``/iam/security-credentials-evil/x`` (audit B4). Both are already lower-cased."""
    return re.search(r"(^|/)" + re.escape(marker) + r"(/|$)", path) is not None


def _imds_url_host_path(source: str) -> tuple[str, str] | None:
    """Parse ``source`` as a URL and return ``(host_lower, path_lower)``, or None when it is NOT a URL with
    a host — a file path, a bare string, or a URL carrying USERINFO (an ``@``: the real host is after the
    ``@``, never IMDS). Uses ``urllib.parse.urlsplit`` (a real parser, not a substring scan over the whole
    string), so the credential-path marker is checked ONLY in the PATH — never in the query, userinfo,
    fragment, or the host's own text (CLAIM-DISCIPLINE rule 4). Never raises."""
    try:
        parts = urlsplit(source)
        if parts.scheme not in _IMDS_URL_SCHEMES:       # file:// / scheme-relative / opaque -> not a reach
            return None
        if parts.username or parts.password:            # userinfo present -> the host is not IMDS
            return None
        host = parts.hostname
        path = parts.path or ""
        port = parts.port                               # ValueError here (bad port) -> not a URL we accept
    except ValueError:
        return None
    if not host or port not in _IMDS_OK_PORTS:          # an unexpected/invalid port is not an IMDS reach
        return None
    return host.lower(), path.lower()


def _imds_source_is_aws_metadata(source: str) -> bool:
    """The AWS discriminator: ``source`` is an http(s) URL on a default port whose HOST canonicalizes to an
    AWS metadata IP (169.254.169.254 incl. the decimal/hex/IPv6-mapped SSRF encodings, or native
    fd00:ec2::254) AND whose PATH carries ``iam/security-credentials`` as a bounded segment."""
    parsed = _imds_url_host_path(source)
    if parsed is None:
        return False
    host, path = parsed
    return _imds_ip_in(_imds_host_to_ip(host), _IMDS_AWS_METADATA_IPS) and _imds_path_has(path, _IMDS_AWS_CRED_PATH)


def _imds_source_is_gcp_metadata(source: str) -> bool:
    """The GCP discriminator: ``source`` is an http(s) URL on a default port whose HOST is the compute-
    metadata host (or a GCP metadata IP incl. native fd20:ce::254) AND whose PATH carries
    ``computeMetadata/v1`` + ``service-accounts`` + ``token`` as bounded segments."""
    parsed = _imds_url_host_path(source)
    if parsed is None:
        return False
    host, path = parsed
    host_ok = host in _IMDS_GCP_HOSTS or _imds_ip_in(_imds_host_to_ip(host), _IMDS_GCP_METADATA_IPS)
    return host_ok and _IMDS_GCP_PATH_RE.search(path) is not None


def _imds_confirming_call(capture: Mapping[str, Any]) -> tuple[Mapping[str, Any], Any, Any, Mapping[str, Any], bool]:
    """Return (identity_body, raw_status, action, raw_call, present). The confirming call is a nested
    ``confirming_call``/``confirmation``/… mapping; its identity payload is a nested
    ``response``/``body``/``identity``/``result``/``json`` mapping, or the call mapping itself. The declared
    ``action`` is surfaced so the oracle can require it agree with the branch's provider (audit B1); the raw
    call is surfaced so the oracle can check the binding/transport-provenance fields (E1-complete)."""
    call: Mapping[str, Any] | None = None
    for k in ("confirming_call", "confirmation", "confirm_call", "verify_call", "caller_identity"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            call = v
            break
    if call is None:
        return {}, None, None, {}, False
    status = call.get("status", call.get("status_code"))
    action = call.get("action", call.get("method"))
    for k in ("response", "body", "identity", "result", "json"):
        v = call.get(k)
        if isinstance(v, Mapping):
            return v, status, action, call, True
    return call, status, action, call, True


def _imds_status_ok(status: Any) -> bool | None:
    """True = an explicit 2xx / ok success, False = an explicit failure (incl. a timeout / connection
    error, audit B1), None = absent/unparseable. Positive-evidence-only: an ambiguous status never asserts
    success, and a FAILURE token never masquerades as absent."""
    if status is None:
        return None
    try:
        code = int(status)
        return 200 <= code < 300
    except (TypeError, ValueError):
        s = _coerce_text(status).strip().lower()
        if s in ("ok", "success", "succeeded", "200"):
            return True
        if s in _IMDS_FAIL_STATUS:
            return False
        return None


def _imds_body_has_error(obj: Any, depth: int = 0) -> bool:
    """True iff a FAILURE marker (an ``_IMDS_ERROR_KEYS`` key with a truthy value) appears at ANY bounded
    depth of ``obj`` — a nested error the top-level scan would miss (audit B4). Bounded to avoid pathological
    recursion; scans mapping values and lists/tuples of mappings only."""
    if depth > 4 or not isinstance(obj, Mapping):
        return False
    for k, val in obj.items():
        if not val:
            continue
        if _coerce_text(k).strip().lower() in _IMDS_ERROR_KEYS:
            return True
        if isinstance(val, Mapping) and _imds_body_has_error(val, depth + 1):
            return True
        if isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, Mapping) and _imds_body_has_error(item, depth + 1):
                    return True
    return False


def _imds_call_ok(body: Mapping[str, Any], status: Any) -> bool:
    """POSITIVE proof the confirming call SUCCEEDED: an EXPLICIT 2xx/ok status (audit B1 — a
    missing/ambiguous/timeout status is NOT a success and must not fall back to identity-presence) AND no
    failure marker at ANY depth of the body (audit B4). The identity-field checks in the caller then prove
    WHICH identity authenticated."""
    if _imds_status_ok(status) is not True:
        return False
    return not _imds_body_has_error(body)


def _imds_aws_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether an sts:GetCallerIdentity response echoes a CONSISTENT, valid identity: an Arn (``arn:``…), a
    12-digit Account, a non-empty UserId, AND the Arn's embedded account component EQUALS the returned
    Account (round-2 — an internally-inconsistent identity, e.g. a fabricated Arn/Account pair, does not
    prove a real authenticated call)."""
    arn = _imds_text(body.get("Arn") or body.get("arn")).strip()
    account = _imds_text(body.get("Account") or body.get("account")).strip()
    user_id = _imds_text(body.get("UserId") or body.get("user_id") or body.get("userId")).strip()
    arn_parts = arn.split(":")                       # arn:aws:sts::<account>:<resource>
    arn_account = arn_parts[4] if len(arn_parts) >= 5 else ""
    ok = (arn.startswith("arn:") and _IMDS_AWS_ACCOUNT.match(account) is not None and bool(user_id)
          and arn_account == account)
    return ok, {"arn": arn, "account": account, "user_id": user_id}


def _imds_gcp_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a tokeninfo/userinfo response proves the token authenticated: an email or sub echo — the
    field only a SUCCESSFUL introspection carries. The expiry (exp/expires_in/…) is OPTIONAL (S3): a
    ``tokeninfo`` response carries one but a ``userinfo`` response omits it, and the identity echo alone is
    positive proof the token authenticated. When present the expiry is retained for the evidence."""
    email = _imds_text(body.get("email") or body.get("email_address")).strip()
    sub = _imds_text(body.get("sub") or body.get("subject")).strip()
    expiry: Any = ""
    for k in ("exp", "expires_in", "expires_at", "expiry", "expireTime", "expire_time"):
        if body.get(k) not in (None, ""):
            expiry = body.get(k)
            break
    # A real tokeninfo/userinfo identity is an email (an SA address) OR a long numeric subject id — never a
    # 1-character ``sub`` (audit B4). A malformed/degenerate identity does not prove the token authenticated.
    email_ok = "@" in email and "." in email.rsplit("@", 1)[-1]
    sub_ok = sub.isdigit() and len(sub) >= 6
    ok = email_ok or sub_ok
    return ok, {"email": email, "sub": sub, "expiry": _imds_text(expiry)}


def _imds_truthy(value: Any) -> bool:
    """A runner-set boolean provenance flag: Python ``True``, ``1``, or a truthy token
    ('true'/'yes'/'1'/'verified'/'ok'). A missing or false-y flag is NOT trusted (fail-closed)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return _coerce_text(value).strip().lower() in ("true", "yes", "1", "verified", "ok")


def _imds_confirm_host(endpoint: str) -> str | None:
    """The lower-cased HOST of a confirming-call endpoint, ONLY when it is an https URL (a validated TLS peer
    requires https). None otherwise (fail-closed)."""
    try:
        p = urlsplit(endpoint)
        if p.scheme != "https" or not p.hostname:
            return None
        return p.hostname.lower()
    except ValueError:
        return None


def _imds_binding_provenance_ok(cred: Mapping[str, Any], call: Mapping[str, Any],
                                provider: str) -> tuple[bool, str]:
    """E1-complete FACT-capability gate (operator round-2 requirement). True ONLY when the retained capture
    carries the runner-produced proof that (a) the confirming call used the EXACT captured credential — a
    domain-separated credential fingerprint present in BOTH the credential and the confirming call, and EQUAL
    — AND (b) BOTH network calls used a trusted transport: the IMDS GET resolved to a metadata peer with no
    proxy/redirect, and the confirming call used https to an ALLOW-LISTED endpoint with a validated TLS peer,
    no proxy/redirect, a recorded resolved peer, and a bounded response digest. The oracle never sees
    plaintext — it checks fingerprint EQUALITY. A structurally-consistent capture WITHOUT this proof is a
    LEAD, not a FACT. Returns (ok, reason)."""
    cred_fp = _imds_text(cred.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not cred_fp or not call_fp or cred_fp != call_fp:
        return False, "credential_not_bound_to_confirming_call"
    imds_peer = _imds_text(cred.get("resolved_peer")).strip().lower()
    if not _imds_ip_in(_imds_host_to_ip(imds_peer), _IMDS_AWS_METADATA_IPS | _IMDS_GCP_METADATA_IPS):
        return False, "imds_resolved_peer_not_metadata"
    if not (_imds_truthy(cred.get("no_proxy")) and _imds_truthy(cred.get("no_redirect"))):
        return False, "imds_transport_not_direct"

    def _host_allowed(host: str) -> bool:
        return (_IMDS_AWS_CONFIRM_HOST_RE.match(host) is not None if provider == "aws"
                else host in _IMDS_GCP_CONFIRM_HOSTS)

    return _confirming_call_trusted(call, _host_allowed)


def _confirming_call_trusted(call: Mapping[str, Any], host_allowed) -> tuple[bool, str]:
    """The SHARED confirming-side trust gate (E1 IMDS + E5 exposed-secret validity). True ONLY when the
    confirming call used a TRUSTED transport: a validated TLS peer, no proxy, no redirect, an https endpoint
    whose host passes ``host_allowed`` (the per-provider / per-secret-type ANTI-LAUNDERING allow-list — an
    attacker-controlled 'confirming' endpoint can never mint a FACT), a recorded resolved peer, and a bounded
    response digest. The credential<->call fingerprint binding is checked by each CALLER, because it differs:
    E1 binds the metadata-endpoint credential; E5 binds the exposed secret. Returns (ok, reason)."""
    if not _imds_truthy(call.get("tls_verified")):
        return False, "confirming_call_tls_unverified"
    if not (_imds_truthy(call.get("no_proxy")) and _imds_truthy(call.get("no_redirect"))):
        return False, "confirming_call_transport_not_direct"
    host = _imds_confirm_host(_imds_text(call.get("endpoint")))
    if host is None or not host_allowed(host):
        return False, "confirming_endpoint_not_allowlisted"
    if not _imds_text(call.get("resolved_peer")).strip():
        return False, "confirming_call_peer_unrecorded"
    if not _imds_text(call.get("response_digest")).strip():
        return False, "confirming_call_response_undigested"
    return True, "bound_and_trusted"


def imds_credential_capture_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED capture PROVES an IMDS/metadata credential-capture achieved effect — the E1
    (BUILD-PLAN §E1) exploitation-chain confirmation. The DEFENSIVE dual of an attack: it re-derives,
    over the JSON-safe retained evidence ALONE (offline, ZERO network, NO exploitation code), that role/SA
    credentials were actually retrieved from the instance metadata endpoint AND are usable. It NEVER
    performs the attack — the live reach-IMDS/use-token action is a separate WARDEN-A2-gated runner; this
    pure oracle judges what that runner captured, so a confirmed FACT re-verifies offline from its
    certificate.

    STATUS (E1-Slice3) — **OFFLINE-WIRED; real-transport LIVE-FIRE deferred.** The capability is now wired
    end-to-end OFFLINE: the WARDEN-A2- + D5-scope-gated runner
    (``integration/vigil_integration/live/imds_runner.py``), the ``cloud_exploit.imds.credential_capture``
    evidence branch (``docs/capability-matrix/evidence-branches.json``), the admission/verdict route + D2
    certificate mint (``integration/vigil_integration/live/imds_verify.py`` →
    ``verdict.admit`` → ``oracle_adapter.certify_admitted``), and the attack-path/world-model projection
    (``scanner/orchestrator.py:_establish_imds_capture`` — a HELD credential chaining via
    OWN_VIA_HELD_CREDENTIAL) are all built and fixture-proven; the D2 cert binding and the veracity-firewall
    re-execution engage automatically (both are generic over any finding carrying an ``oracle_context``, so a
    minted FACT re-verifies OFFLINE from its certificate). The oracle stays deliberately OUT of the frozen
    ``_ALL_ORACLES`` fallback, so nothing on the scan/engage/benchmark path ever mints this finding — the
    capability fires ONLY when the producer is called explicitly over a runner capture. **Still deferred:**
    real-transport LIVE-FIRE (running the runner with a real httpx transport against an authorized lab
    metadata endpoint) is credential-gated (an operator-provisioned lab credential); there is no live FACT
    yet. This pure oracle itself never reaches a metadata endpoint — it re-derives over a retained capture.

    ``observed`` is the JSON-safe retained capture::

        {"provider": "aws"?,
         "credential": {"AccessKeyId": "ASIA…", "SecretAccessKey": "…", "Token": "…",
                        "source": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"},
         "confirming_call": {"action": "sts:GetCallerIdentity", "status": 200,
                             "response": {"Arn": "arn:aws:sts::123456789012:assumed-role/role/i-0",
                                          "Account": "123456789012", "UserId": "AROA…:i-0"}}}
        # or GCP:
        {"credential": {"access_token": "ya29.…", "token_type": "Bearer",
                        "source": "http://metadata.google.internal/computeMetadata/v1/instance/"
                                  "service-accounts/default/token"},
         "confirming_call": {"action": "tokeninfo", "status": 200,
                             "response": {"email": "svc@p.iam.gserviceaccount.com", "expires_in": 3599}}}

    Fires (0.95) ONLY when BOTH halves hold (near-zero-FP by construction). NOTE (round-2): firing proves
    the capture is STRUCTURALLY CONSISTENT (a real metadata-endpoint credential + a matching successful
    identity echo); it does NOT prove the exact captured credential produced the confirming call — that
    binding + a trusted-endpoint/transport provenance are the WARDEN-gated runner's job (blocking work),
    which is what makes E1 FACT-capable.
      (a) a STRUCTURALLY-VALID credential whose source is a URL that HOST-IDENTIFIES the metadata endpoint
          — the source is parsed with ``urllib.parse.urlsplit`` and its HOST (not a substring of the raw
          string) must be the metadata endpoint on an http(s) default port, with the credential-path marker
          as a bounded PATH SEGMENT —
          AWS: ``AccessKeyId`` matches ``^ASIA[0-9A-Z]{16}$`` (temporary STS shape only) AND a non-empty
               ``SecretAccessKey`` AND a non-empty ``Token``, AND the source URL's HOST canonicalizes to an
               AWS metadata IP (169.254.169.254 incl. the decimal/hex/IPv6-mapped SSRF encodings, or native
               fd00:ec2::254) AND its PATH carries ``iam/security-credentials`` as a segment; OR
          GCP: a non-empty ``access_token`` AND ``token_type`` == ``bearer`` (case-insensitive), AND the
               source URL's HOST is ``metadata.google.internal`` (or a GCP metadata IP incl. native
               fd20:ce::254) AND its PATH matches the ordered ``computeMetadata/v1/…/service-accounts/<sa>/
               token`` grammar; AND
      (b) a retained CONFIRMING-CALL response proving the credential AUTHENTICATED, with NO failure signal
          (no 4xx/5xx status, no truthy error/errors/message/code/__type/Fault field) —
          AWS: an sts:GetCallerIdentity response echoing an Arn (``arn:``…) + a 12-digit Account + a
               UserId; OR
          GCP: a tokeninfo/userinfo success echoing an email/sub (expiry optional — userinfo omits it).
    The credential's provider and the confirming call's provider MUST agree (an AWS credential needs an
    AWS confirming call; a GCP token needs a GCP one).

    Because the source is HOST-checked with a real URL parser (not substring containment), a userinfo-@
    host (``http://169.254.169.254@evil.com/…``), a query-param IP (``http://evil.com/?u=…169.254.169.254…``),
    a rebind host that merely CONTAINS the IP (``169.254.169.254.attacker.com``), a creds FILE path
    (``/home/user/.aws/169.254.169.254-iam/…``), and a bare non-URL string are all correctly NOT an IMDS
    reach.

    Does NOT fire (stays an honest LEAD / INCONCLUSIVE downstream): a credential retrieved from IMDS but
    with NO confirming call (retrieved-but-unconfirmed = LEAD); a credential + a FAILED confirming call
    (error / 4xx / an error-shaped 200 body); a 401/timeout metadata response (no valid credential); a
    credential whose source does NOT host-identify the metadata endpoint (a normal env-var key, a creds
    file, a proxied/rebind/userinfo host — never mistaken for an IMDS capture); a random JSON blob;
    malformed/absent evidence (never raises). Positive-evidence-only: an absent/unknown signal never fires.
    Pure + deterministic, so the same verdict re-verifies offline from the retained context. GROUNDING is
    procedural exactly as for every oracle: the capture MUST be the runner's RETAINED evidence, never a
    re-run of a live IMDS/STS call laundered as a fact."""
    kind = OracleKind.IMDS_CREDENTIAL_CAPTURE
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no IMDS credential-capture evidence")
    capture = observed
    cred = _imds_credential_obj(capture)
    source = _imds_source(capture, cred)
    body, status, action, call, call_present = _imds_confirming_call(capture)
    # B1: a DECLARED provider must agree with the matched credential shape, and the confirming call's action
    # must be the provider's identity check — a mismatch is a fabricated/laundered capture, not a FACT.
    declared_provider = _imds_text(capture.get("provider")).strip().lower()
    action_norm = _imds_text(action).strip().lower()

    # -- AWS: an STS-temporary instance-role credential from the IMDS security-credentials path --------
    akid = _imds_text(cred.get("AccessKeyId") or cred.get("access_key_id")).strip()
    aws_cred_valid = (
        _IMDS_AWS_AKID.match(akid) is not None
        and bool(_imds_text(cred.get("SecretAccessKey") or cred.get("secret_access_key")).strip())
        and bool(_imds_text(cred.get("Token") or cred.get("SessionToken")
                            or cred.get("session_token")).strip())
    )
    aws_from_imds = aws_cred_valid and _imds_source_is_aws_metadata(source)
    if aws_from_imds:
        if not call_present:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=("AWS instance-role credential retrieved from the IMDS security-credentials path "
                          "but NO confirming sts:GetCallerIdentity call is retained — retrieved-but-"
                          "unconfirmed (stays a LEAD; a credential alone does not prove it is usable)"),
                observed={"provider": "aws", "reason": "no_confirming_call", "access_key_id": akid})
        if declared_provider and declared_provider not in _IMDS_AWS_PROVIDERS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"AWS-shaped instance-role credential from the IMDS path, but the capture DECLARES "
                          f"provider={declared_provider!r} — the declared provider disagrees with the "
                          f"credential shape; a mismatched/fabricated capture is NOT confirmed (stays a LEAD)"),
                observed={"provider": "aws", "reason": "provider_mismatch",
                          "declared_provider": declared_provider, "access_key_id": akid})
        if action_norm not in _IMDS_AWS_ACTIONS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"AWS instance-role credential from IMDS, but the confirming call's action "
                          f"({action_norm or 'ABSENT'!r}) is not the required AWS identity check "
                          f"(sts:GetCallerIdentity) — an absent/mismatched confirming action does NOT prove "
                          f"the AWS credential usable (stays a LEAD)"),
                observed={"provider": "aws", "reason": "confirming_action_mismatch",
                          "action": action_norm, "access_key_id": akid})
        ok, ident = _imds_aws_identity(body)
        if _imds_call_ok(body, status) and ok:
            bound_ok, bound_reason = _imds_binding_provenance_ok(cred, call, "aws")
            if not bound_ok:
                return OracleSignal(
                    kind=kind, fired=False, confidence=0.0,
                    evidence=(f"AWS IMDS credential + a structurally-valid sts:GetCallerIdentity, but the "
                              f"capture is NOT FACT-capable ({bound_reason}): the runner-produced exact "
                              f"credential->call binding + trusted-transport provenance is REQUIRED to prove "
                              f"the SAME credential authenticated over a trusted path — retained as a "
                              f"structural LEAD, not a signed FACT."),
                    observed={"provider": "aws", "reason": "structural_only_not_bound",
                              "detail": bound_reason, "access_key_id": akid,
                              "source": _imds_obs_source(source)})
            return OracleSignal(
                kind=kind, fired=True, confidence=0.95,
                evidence=(f"IMDS credential capture (AWS): a structurally-valid instance-role credential "
                          f"(AccessKeyId {akid!r}) was retrieved from the metadata endpoint ({source!r}) "
                          f"AND sts:GetCallerIdentity authenticated with it (Arn={ident['arn']!r}, "
                          f"Account={ident['account']!r}, UserId={ident['user_id']!r}), and the runner bound "
                          f"the exact credential to that call over a trusted transport (fingerprint match + "
                          f"metadata/STS peers, no proxy/redirect, validated TLS) — the credential is proven "
                          f"usable. SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL "
                          f"re-derives the achieved effect over the retained evidence offline (no network)."),
                observed={"provider": "aws", "reason": "imds_credential_authenticated",
                          "access_key_id": akid, "account": ident["account"], "arn": ident["arn"],
                          "user_id": ident["user_id"], "source": _imds_obs_source(source),
                          "bound": True, "confirming_call": "sts:GetCallerIdentity"})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("AWS instance-role credential retrieved from IMDS but the confirming "
                      "sts:GetCallerIdentity call FAILED or did not echo a valid identity (Arn + 12-digit "
                      "Account + UserId) — not proven usable (stays a LEAD)"),
            observed={"provider": "aws", "reason": "confirming_call_failed", "access_key_id": akid})

    # -- GCP: an OAuth access token from the compute-metadata service-account token path ---------------
    gcp_access_token = _imds_text(cred.get("access_token") or cred.get("accessToken")).strip()
    gcp_token_type = _imds_text(cred.get("token_type") or cred.get("tokenType")).strip()
    gcp_cred_valid = bool(gcp_access_token) and gcp_token_type.lower() == "bearer"
    gcp_from_metadata = gcp_cred_valid and _imds_source_is_gcp_metadata(source)
    if gcp_from_metadata:
        if not call_present:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=("GCP service-account access token retrieved from the compute metadata token path "
                          "but NO confirming tokeninfo/userinfo call is retained — retrieved-but-"
                          "unconfirmed (stays a LEAD)"),
                observed={"provider": "gcp", "reason": "no_confirming_call"})
        if declared_provider and declared_provider not in _IMDS_GCP_PROVIDERS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"GCP-shaped service-account token from the compute-metadata path, but the capture "
                          f"DECLARES provider={declared_provider!r} — the declared provider disagrees with "
                          f"the credential shape; a mismatched/fabricated capture is NOT confirmed (LEAD)"),
                observed={"provider": "gcp", "reason": "provider_mismatch",
                          "declared_provider": declared_provider})
        if action_norm not in _IMDS_GCP_ACTIONS:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"GCP access token from compute metadata, but the confirming call's action "
                          f"({action_norm or 'ABSENT'!r}) is not a required GCP token introspection "
                          f"(tokeninfo/userinfo) — an absent/mismatched action does NOT prove the token "
                          f"usable (stays a LEAD)"),
                observed={"provider": "gcp", "reason": "confirming_action_mismatch", "action": action_norm})
        ok, ident = _imds_gcp_identity(body)
        if _imds_call_ok(body, status) and ok:
            who = ident["email"] or ident["sub"]
            bound_ok, bound_reason = _imds_binding_provenance_ok(cred, call, "gcp")
            if not bound_ok:
                return OracleSignal(
                    kind=kind, fired=False, confidence=0.0,
                    evidence=(f"GCP metadata token + a structurally-valid tokeninfo/userinfo, but the capture "
                              f"is NOT FACT-capable ({bound_reason}): the runner-produced exact "
                              f"credential->call binding + trusted-transport provenance is REQUIRED to prove "
                              f"the SAME token authenticated over a trusted path — retained as a structural "
                              f"LEAD, not a signed FACT."),
                    observed={"provider": "gcp", "reason": "structural_only_not_bound",
                              "detail": bound_reason, "source": _imds_obs_source(source)})
            return OracleSignal(
                kind=kind, fired=True, confidence=0.95,
                evidence=(f"IMDS credential capture (GCP): a structurally-valid service-account access "
                          f"token (token_type=Bearer) was retrieved from the compute metadata token "
                          f"endpoint ({source!r}) AND tokeninfo/userinfo authenticated with it "
                          f"(identity={who!r}, expiry={ident['expiry']!r}), and the runner bound the exact "
                          f"token to that call over a trusted transport (fingerprint match + metadata/"
                          f"googleapis peers, no proxy/redirect, validated TLS) — the token is proven usable. "
                          f"SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL "
                          f"re-derives the achieved effect over the retained evidence offline (no network)."),
                observed={"provider": "gcp", "reason": "imds_credential_authenticated",
                          "identity": who, "email": ident["email"], "sub": ident["sub"],
                          "expiry": ident["expiry"], "source": _imds_obs_source(source),
                          "bound": True, "confirming_call": "tokeninfo"})
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("GCP access token retrieved from compute metadata but the confirming "
                      "tokeninfo/userinfo call FAILED or did not echo an identity (email/sub) + expiry — "
                      "not proven usable (stays a LEAD)"),
            observed={"provider": "gcp", "reason": "confirming_call_failed"})

    # -- neither: no structurally-valid credential FROM the metadata endpoint -------------------------
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=("no structurally-valid cloud credential sourced from the instance metadata endpoint in "
                  "the retained capture (AWS AccessKeyId+SecretAccessKey+Token from "
                  "169.254.169.254/iam/security-credentials, or a GCP Bearer access_token from "
                  "computeMetadata/v1/.../service-accounts/.../token) — not an IMDS credential capture "
                  "(stays a LEAD; a credential not from IMDS, a 401/timeout, or a random blob never fires)"),
        observed={"reason": "no_imds_credential",
                  "aws_akid_shape": _IMDS_AWS_AKID.match(akid) is not None,
                  "source": _imds_obs_source(source)})


_SECRET_AWS_KEY_ID_RE = re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")


_SECRET_GITHUB_PREFIX_RE = re.compile(r"^(gh[posru]_|github_pat_)")


_SECRET_GITLAB_PREFIX_RE = re.compile(r"^glpat-")


_SECRET_SLACK_PREFIX_RE = re.compile(r"^xox[baprse]-")


_SECRET_AWS_STS_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")


def _github_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a GitHub ``GET /user`` response proves the token authenticated: a non-empty ``login`` AND a
    positive numeric ``id`` — the fields only an authenticated /user carries. A degenerate / absent identity
    does not prove authentication (positive-evidence-only)."""
    login = _imds_text(body.get("login")).strip()
    raw_id = body.get("id")
    if isinstance(raw_id, bool):
        id_ok = False
    elif isinstance(raw_id, (int, float)):
        id_ok = raw_id > 0
    else:
        t = _imds_text(raw_id).strip()
        id_ok = t.isdigit() and int(t) > 0
    return (bool(login) and id_ok), {"login": login, "id": _imds_text(raw_id).strip()}


def _gitlab_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a GitLab ``GET /api/v4/user`` response proves the token authenticated: a non-empty
    ``username`` AND a positive numeric ``id`` — the fields only an authenticated /user carries. Mirrors
    ``_github_identity`` (positive-evidence-only; a degenerate/absent identity does not prove auth)."""
    username = _imds_text(body.get("username")).strip()
    raw_id = body.get("id")
    if isinstance(raw_id, bool):
        id_ok = False
    elif isinstance(raw_id, (int, float)):
        id_ok = raw_id > 0
    else:
        t = _imds_text(raw_id).strip()
        id_ok = t.isdigit() and int(t) > 0
    return (bool(username) and id_ok), {"username": username, "id": _imds_text(raw_id).strip()}


def _slack_identity(body: Mapping[str, Any]) -> tuple[bool, dict[str, str]]:
    """Whether a Slack ``auth.test`` response proves the token authenticated: the API-level ``ok`` flag is
    literally ``true`` (Slack answers HTTP 200 with ``ok:false`` for an invalid token, so the boolean, NOT the
    status, is the success signal) AND a non-empty ``user_id`` is echoed. Positive-evidence-only."""
    ok_flag = body.get("ok")
    user_id = _imds_text(body.get("user_id")).strip()
    authenticated = (ok_flag is True) and bool(user_id)
    return authenticated, {"ok": "true" if ok_flag is True else _imds_text(ok_flag),
                           "user_id": user_id, "team_id": _imds_text(body.get("team_id")).strip(),
                           "user": _imds_text(body.get("user")).strip()}


_SECRET_RECOGNIZERS: "dict[str, dict[str, Any]]" = {
    "aws_access_key": {
        "id_ok": lambda s: _SECRET_AWS_KEY_ID_RE.match(s) is not None,
        "action": "sts:getcalleridentity",
        "identity": _imds_aws_identity,
        "host_ok": lambda h: _SECRET_AWS_STS_HOST_RE.match(h) is not None,
    },
    "github_pat": {
        "id_ok": lambda s: _SECRET_GITHUB_PREFIX_RE.match(s) is not None,
        "action": "github:get /user",
        "identity": _github_identity,
        "host_ok": lambda h: h == "api.github.com",
    },
    "gitlab_pat": {
        "id_ok": lambda s: _SECRET_GITLAB_PREFIX_RE.match(s) is not None,
        "action": "gitlab:get /api/v4/user",
        "identity": _gitlab_identity,
        "host_ok": lambda h: h == "gitlab.com",
    },
    "slack_token": {
        "id_ok": lambda s: _SECRET_SLACK_PREFIX_RE.match(s) is not None,
        "action": "slack:auth.test",
        "identity": _slack_identity,
        "host_ok": lambda h: h == "slack.com",
    },
}


def exposed_secret_validity_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED, secret-safe capture PROVES an EXPOSED secret is VALID — the E5 achieved-effect
    confirmation. The DEFENSIVE dual of an attack: it re-derives, over the retained evidence ALONE (offline,
    no network, no attack), that a structurally-recognized leaked credential AUTHENTICATED as a real identity
    via a confirming call BOUND to it over a trusted, allow-listed transport. It never validates the secret's
    content (the secret is a ``[REDACTED]`` presence marker); it proves VALIDITY via the confirming call.

    SOURCE-SEMANTICS INVERSION vs the IMDS oracle: the exposure ``source`` (a JS literal, a git blob, a config
    path, a SecretsManager ARN) is RETAINED as evidence but is NOT a firing gate — E5 asserts VALIDITY, not
    provenance. The ANTI-LAUNDERING gate is on the CONFIRMING-CALL side: the confirming endpoint must be on
    the per-TYPE host allow-list (an AWS key confirmed ONLY against ``sts:GetCallerIdentity`` at
    ``sts[.<region>].amazonaws.com``; a GitHub PAT ONLY against ``api.github.com`` ``GET /user``; a GitLab PAT
    ONLY against ``gitlab.com`` ``GET /api/v4/user``; a Slack token ONLY against ``slack.com`` ``auth.test``),
    and the
    secret must be fingerprint-BOUND to that call over a validated-TLS, no-proxy, no-redirect transport — so
    an attacker-controlled 'confirming' endpoint can never launder an arbitrary string into a FACT.

    ``observed`` is the JSON-safe, SECRET-SAFE retained capture::

        {"secret_type": "aws_access_key" | "github_pat" | "gitlab_pat" | "slack_token",
         "credential": {"identifier": "AKIA…" | "ghp_…" (non-secret id/prefix), "secret": "[REDACTED]",
                        "credential_fingerprint": "…", "source": "js:app.min.js:1024" (evidence only)},
         "confirming_call": {"action": "sts:GetCallerIdentity" | "github:GET /user", "status": 200,
                             "credential_fingerprint": "…" (== credential's), "endpoint": "https://sts…/",
                             "tls_verified": true, "no_proxy": true, "no_redirect": true,
                             "resolved_peer": "…", "response_digest": "…", "response": {…identity echo…}}}

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction). Does NOT fire (stays an honest LEAD): an
    unrecognized secret type; a recognized-but-unconfirmed secret (no confirming call); a failed / 4xx /
    error-shaped-200 confirming call; a confirming action that does not match the type; an identity echo the
    type's extractor rejects; a fingerprint that does not bind the secret to the call; a confirming endpoint
    NOT on the type's allow-list (a laundering attempt); an unverified / proxied / redirected transport;
    malformed / absent evidence (never raises). Pure + deterministic, so the same verdict re-verifies offline
    from the retained context."""
    kind = OracleKind.SECRET_CREDENTIAL_VALIDITY
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no exposed-secret validity evidence",
                            observed={"reason": "malformed_capture"})
    secret_type = _imds_text(observed.get("secret_type")).strip().lower()
    cred = observed.get("credential") if isinstance(observed.get("credential"), Mapping) else {}
    call = observed.get("confirming_call") if isinstance(observed.get("confirming_call"), Mapping) else {}
    resp = call.get("response") if isinstance(call.get("response"), Mapping) else {}

    recog = _SECRET_RECOGNIZERS.get(secret_type)
    if recog is None:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"secret_type {secret_type!r} is not in the closed recognizer set "
                                      f"{sorted(_SECRET_RECOGNIZERS)} — cannot structurally recognize it "
                                      f"(stays a LEAD)"),
                            observed={"reason": "unrecognized_secret_type", "secret_type": secret_type})

    identifier = _imds_text(cred.get("identifier")).strip()
    if not recog["id_ok"](identifier):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the retained {secret_type} identifier {identifier!r} does not match "
                                      f"the recognized non-secret shape — not a structurally-valid secret of "
                                      f"this type (stays a LEAD)"),
                            observed={"reason": "secret_identifier_malformed", "secret_type": secret_type})

    if not call:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"a structurally-recognized {secret_type} secret but NO confirming call "
                                      f"is retained — recognized-but-unconfirmed (a regex match is not proof "
                                      f"the secret is VALID; stays a LEAD)"),
                            observed={"reason": "no_confirming_call", "secret_type": secret_type})

    if not _imds_call_ok(resp, call.get("status")):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret did NOT succeed (no "
                                      f"explicit 2xx, or a failure marker in the body) — the secret is not "
                                      f"proven usable (stays a LEAD)"),
                            observed={"reason": "confirming_call_failed", "secret_type": secret_type})

    action = _imds_text(call.get("action")).strip().lower()
    if action != recog["action"]:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call's action {action!r} is not the expected "
                                      f"{recog['action']!r} for a {secret_type} secret — a mismatched / "
                                      f"wrong-endpoint confirmation is NOT accepted (stays a LEAD)"),
                            observed={"reason": "confirming_action_mismatch", "secret_type": secret_type,
                                      "action": action})

    id_ok, identity = recog["identity"](resp)
    if not id_ok:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret returned no valid "
                                      f"identity echo — cannot prove WHICH identity authenticated (stays a "
                                      f"LEAD)"),
                            observed={"reason": "identity_echo_absent", "secret_type": secret_type})

    secret_fp = _imds_text(cred.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not secret_fp or not call_fp or secret_fp != call_fp:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call is not fingerprint-BOUND to the captured "
                                      f"{secret_type} secret (a domain-separated fingerprint present in BOTH "
                                      f"and EQUAL) — the call may have used a DIFFERENT secret; not a bound "
                                      f"FACT (stays a LEAD)"),
                            observed={"reason": "secret_not_bound_to_confirming_call",
                                      "secret_type": secret_type})

    ok, reason = _confirming_call_trusted(call, recog["host_ok"])
    if not ok:
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence=(f"the confirming call for the {secret_type} secret is not over a "
                                      f"trusted, allow-listed transport ({reason}) — an un-allow-listed / "
                                      f"proxied / redirected / TLS-unverified confirmation cannot mint a FACT "
                                      f"(anti-laundering; stays a LEAD)"),
                            observed={"reason": reason, "secret_type": secret_type})

    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"Exposed-secret validity ({secret_type}): a structurally-recognized secret (identifier "
                  f"{identifier!r}, exposed at {_imds_text(cred.get('source'))!r}) AUTHENTICATED via "
                  f"{recog['action']} as identity {identity!r}, and the runner bound the exact secret to that "
                  f"call over a trusted, allow-listed transport (fingerprint match + per-type endpoint "
                  f"allow-list, no proxy/redirect, validated TLS) — the exposed secret is PROVEN valid. "
                  f"SUBJECT = the retained capture the WARDEN-gated runner produced; VIGIL re-derives the "
                  f"achieved effect over the retained evidence offline (no network)."),
        observed={"reason": "exposed_secret_validated", "secret_type": secret_type,
                  "identity": identity, "source": _imds_text(cred.get("source"))})


_GCP_SA_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,62}@([a-z0-9-]+\.)+gserviceaccount\.com$")


_GCP_MINT_VERBS = frozenset({
    "generateaccesstoken", "getaccesstoken", "generateidtoken", "signjwt", "signblob",
})


_GCP_ACTAS_TOKENS = ("actas", "serviceaccounttokencreator")


_GCP_IMPERSONATION_ACTIONS = frozenset({
    "tokeninfo", "userinfo", "oauth2/v3/tokeninfo", "oauth2/v1/tokeninfo",
    "oauth2/v3/userinfo", "oauth2/v2/userinfo", "getuserinfo",
})


_GCP_IMPERSONATION_CONFIRM_HOSTS = frozenset({
    "oauth2.googleapis.com", "www.googleapis.com", "iamcredentials.googleapis.com",
    "openidconnect.googleapis.com",
})


def _gcp_mint_obj(capture: Mapping[str, Any]) -> Mapping[str, Any]:
    """The mint sub-object: a nested ``mint``/``impersonation``/… mapping, or the capture itself (a flat
    record). Never raises."""
    for k in ("mint", "impersonation", "token_mint", "mint_call"):
        v = capture.get(k)
        if isinstance(v, Mapping):
            return v
    return capture


def _gcp_mint_method_is_impersonation(method: str) -> bool:
    """True iff ``method`` denotes an iamcredentials impersonation mint (getAccessToken / generateAccessToken /
    generateIdToken / signJwt / signBlob — matched on the method's VERB, the last `[:./]`-delimited token, so a
    fully-qualified resource URL or an ``iamcredentials:``-prefixed method resolves) OR an actAs /
    serviceAccountTokenCreator flow (matched as a DELIMITED token — ``iam.serviceAccounts.actAs`` /
    ``roles/iam.serviceAccountTokenCreator`` — never as a mid-word substring, so a benign method that merely
    CONTAINS the letters cannot match). Never raises."""
    m = _coerce_text(method).strip().lower()
    tokens = [t for t in re.split(r"[:./]", m) if t]
    if not tokens:
        return False
    if tokens[-1] in _GCP_MINT_VERBS:
        return True
    return any(t in _GCP_ACTAS_TOKENS for t in tokens)


def _gcp_minted_token_present(mint: Mapping[str, Any]) -> bool:
    """A minted impersonation token was PRESENT at capture time — its presence is the structural fact (the
    binding fingerprint is its secret-safe proxy; the oracle never sees the token). Reads the redacted
    presence marker the reducer leaves, or any non-empty raw token field."""
    for k in ("token", "access_token", "accessToken", "id_token", "idToken", "signed_jwt", "signedJwt",
              "signed_blob", "signedBlob"):
        if _imds_text(mint.get(k)).strip():
            return True
    return False


def _gcp_sa_uid_ok(uid: str) -> bool:
    """A GCP unique-id (the SA's numeric ``unique_id`` / OIDC ``sub``) — a bounded numeric id. Mirrors the
    IMDS ``sub`` shape gate (>= 6 digits) so a degenerate 1-char id is never a valid target/echo."""
    return uid.isdigit() and len(uid) >= 6


def _gcp_target_identity(capture: Mapping[str, Any], mint: Mapping[str, Any]) -> tuple[str, str]:
    """The NAMED impersonation target B as ``(email, uid)`` — an SA email OR a numeric unique-id. Read from
    the mint's ``target``/``target_service_account``/… first, then the top-level capture. A malformed value
    is returned in the ``email`` slot (lower-cased) so it fails the ``_GCP_SA_EMAIL_RE`` gate downstream.
    Never raises."""
    val = ""
    for obj in (mint, capture):
        if not isinstance(obj, Mapping):
            continue
        for k in ("target_service_account", "target", "target_sa", "target_email", "target_principal",
                  "service_account", "sa"):
            v = obj.get(k)
            if v not in (None, ""):
                val = _imds_text(v).strip()
                break
        if val:
            break
    if val.isdigit():
        return "", val
    return val.lower(), ""


def gcp_sa_impersonation_oracle(observed: Any) -> OracleSignal:
    """Fire when a RETAINED, secret-safe capture PROVES a GCP service-account IMPERSONATION achieved effect —
    the E3 (BUILD-PLAN §E3) confirmation. The DEFENSIVE dual of an attack: it re-derives, over the retained
    evidence ALONE (offline, ZERO network, NO exploitation code), that a principal minted a short-lived token
    AS a named target service-account B (via iamcredentials getAccessToken / generateAccessToken / signJwt /
    an actAs / roles/iam.serviceAccountTokenCreator flow) AND that a confirming call ECHOED B's identity at a
    TRUSTED, allow-listed Google introspection endpoint, bound to the mint by a shared token fingerprint. It
    NEVER performs the impersonation — the live mint/introspect action is a separate WARDEN-gated runner; this
    pure oracle judges what that runner retained, so a confirmed FACT re-verifies OFFLINE from its certificate.

    E3 is the OPPOSITE shape to E1: E1 requires the credential SOURCE host to be the metadata endpoint; E3
    makes no claim about a source — it proves an impersonation TOKEN-MINT was confirmed by an identity echo of
    the TARGET SA. The ANTI-LAUNDERING gate (like E5) is entirely on the CONFIRMING-CALL side: the tokeninfo/
    userinfo call must resolve at a Google introspection host on the per-type allow-list, over a validated-TLS,
    no-proxy, no-redirect transport, so an attacker-controlled 'tokeninfo' endpoint can never launder a FACT.

    STATUS (E3) — **OFFLINE-WIRED; real-transport LIVE-FIRE deferred** on operator-provisioned GCP creds. The
    oracle stays OUT of the frozen ``_ALL_ORACLES`` fallback and fires ONLY when the ctx carries
    ``gcp_impersonation_capture`` (no benchmark/scan/engage finding does), so nothing on the scan path mints
    it — the capability fires ONLY when the producer is called explicitly over a runner capture.

    ``observed`` is the JSON-safe, SECRET-SAFE retained capture::

        {"mint": {"method": "generateAccessToken", "target": "svc-b@proj.iam.gserviceaccount.com",
                  "token": "[REDACTED]", "credential_fingerprint": "…"},
         "confirming_call": {"action": "tokeninfo", "status": 200, "credential_fingerprint": "…" (== mint's),
                             "endpoint": "https://oauth2.googleapis.com/tokeninfo", "tls_verified": true,
                             "no_proxy": true, "no_redirect": true, "resolved_peer": "…",
                             "response_digest": "…",
                             "response": {"email": "svc-b@proj.iam.gserviceaccount.com", "sub": "1029…",
                                          "expires_in": 3599}}}

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction):
      (1) the mint is an impersonation token-mint (an iamcredentials verb / an actAs/tokenCreator flow) that
          minted a token targeting a NAMED, well-formed target SA B (a ``*.gserviceaccount.com`` email or a
          numeric unique-id);
      (2) a confirming tokeninfo/userinfo call SUCCEEDED (explicit 2xx, no failure marker at any depth) and
          its identity echo (email/sub) EQUALS the named target SA B — an echo of a DIFFERENT SA does not
          prove B was impersonated;
      (3) the minted token is fingerprint-BOUND to that confirming call (a domain-separated fingerprint in
          BOTH and EQUAL — the token itself is never retained), AND the confirming call used a TRUSTED,
          allow-listed Google endpoint over a validated-TLS, no-proxy, no-redirect transport.

    Does NOT fire (stays an honest LEAD): a mint that is not an impersonation call; no minted token; a
    malformed target SA; no confirming call; a failed / 4xx / error-shaped confirming call; a confirming
    action that is not a token introspection; an echo that resolves a DIFFERENT SA than the target; a
    fingerprint that does not bind the mint to the call; a confirming endpoint NOT on the allow-list (a
    laundering attempt); an unverified / proxied / redirected transport; malformed / absent evidence (never
    raises). Pure + deterministic, so the same verdict re-verifies offline from the retained context."""
    kind = OracleKind.GCP_SA_IMPERSONATION
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no GCP SA-impersonation evidence",
                            observed={"reason": "malformed_capture"})
    capture = observed
    mint = _gcp_mint_obj(capture)
    call = capture.get("confirming_call") if isinstance(capture.get("confirming_call"), Mapping) else {}
    resp = call.get("response") if isinstance(call.get("response"), Mapping) else {}

    # (1) a mint of an impersonation token targeting a NAMED, well-formed target SA B ---------------------
    method = _imds_text(mint.get("method") or mint.get("action"))
    if not _gcp_mint_method_is_impersonation(method):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the mint method {method.strip()!r} is not a GCP service-account impersonation call "
                      f"(iamcredentials getAccessToken/generateAccessToken/generateIdToken/signJwt/signBlob, "
                      f"or an actAs / serviceAccountTokenCreator flow) — not an impersonation (stays a LEAD)"),
            observed={"reason": "mint_method_not_impersonation", "method": method.strip()})
    if not _gcp_minted_token_present(mint):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("an impersonation mint method but NO minted token is retained — a mint attempt without a "
                      "captured token does not prove impersonation (stays a LEAD)"),
            observed={"reason": "no_minted_token"})
    target_email, target_uid = _gcp_target_identity(capture, mint)
    email_target_ok = bool(target_email) and _GCP_SA_EMAIL_RE.match(target_email) is not None
    uid_target_ok = bool(target_uid) and _gcp_sa_uid_ok(target_uid)
    if not (email_target_ok or uid_target_ok):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the impersonation mint names no well-formed target service-account "
                      f"(target={ (target_email or target_uid) or 'ABSENT'!r}) — a target that is not a "
                      f"*.gserviceaccount.com email or a numeric unique-id is not a named SA (stays a LEAD)"),
            observed={"reason": "target_sa_malformed", "target": target_email or target_uid})

    # (2) a confirming tokeninfo/userinfo call that ECHOES the SAME target SA B --------------------------
    if not call:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("an impersonation token minted for the target SA but NO confirming tokeninfo/userinfo "
                      "call is retained — minted-but-unconfirmed (a mint alone does not prove the token "
                      "authenticates as B; stays a LEAD)"),
            observed={"reason": "no_confirming_call", "target": target_email or target_uid})
    action = _imds_text(call.get("action")).strip().lower()
    if action not in _GCP_IMPERSONATION_ACTIONS:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming call's action ({action or 'ABSENT'!r}) is not a GCP token introspection "
                      f"(tokeninfo/userinfo) — an absent/mismatched action does NOT prove the minted token "
                      f"authenticates as B (stays a LEAD)"),
            observed={"reason": "confirming_action_mismatch", "action": action})
    if not _imds_call_ok(resp, call.get("status")):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming tokeninfo/userinfo call did NOT succeed (no explicit 2xx, or a failure "
                      "marker in the body) — the minted token is not proven usable as B (stays a LEAD)"),
            observed={"reason": "confirming_call_failed", "target": target_email or target_uid})
    id_ok, ident = _imds_gcp_identity(resp)
    if not id_ok:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming call returned no valid identity echo (email / numeric sub) — cannot "
                      "prove WHICH service-account the minted token resolves to (stays a LEAD)"),
            observed={"reason": "identity_echo_absent"})
    echo_email = ident["email"].strip().lower()
    echo_sub = ident["sub"].strip()
    if email_target_ok:
        matched = bool(echo_email) and echo_email == target_email
    else:
        matched = bool(echo_sub) and echo_sub == target_uid
    if not matched:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming identity echo (email={echo_email or '∅'!r}, sub={echo_sub or '∅'!r}) "
                      f"does NOT resolve the named target SA "
                      f"({(target_email or target_uid)!r}) — the minted token authenticates as a DIFFERENT "
                      f"principal, so it does not prove impersonation OF B (stays a LEAD)"),
            observed={"reason": "identity_echo_mismatch", "target": target_email or target_uid,
                      "echo_email": echo_email, "echo_sub": echo_sub})

    # (3) the minted token is fingerprint-BOUND to the confirming call, over a TRUSTED endpoint -----------
    mint_fp = _imds_text(mint.get("credential_fingerprint")).strip()
    call_fp = _imds_text(call.get("credential_fingerprint")).strip()
    if not mint_fp or not call_fp or mint_fp != call_fp:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=("the confirming call is not fingerprint-BOUND to the minted impersonation token (a "
                      "domain-separated fingerprint present in BOTH the mint and the confirming call and "
                      "EQUAL) — the call may have introspected a DIFFERENT token; not a bound FACT (LEAD)"),
            observed={"reason": "token_not_bound_to_confirming_call", "target": target_email or target_uid})
    ok, reason = _confirming_call_trusted(call, lambda h: h in _GCP_IMPERSONATION_CONFIRM_HOSTS)
    if not ok:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the confirming tokeninfo/userinfo call is not over a trusted, allow-listed Google "
                      f"endpoint ({reason}) — an un-allow-listed / proxied / redirected / TLS-unverified "
                      f"confirmation cannot mint a FACT (anti-laundering; stays a LEAD)"),
            observed={"reason": reason, "target": target_email or target_uid})

    who = target_email or target_uid
    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"GCP service-account impersonation: an impersonation token was minted via {method.strip()!r} "
                  f"targeting service-account {who!r}, and a confirming {action} call authenticated with it "
                  f"and echoed that exact identity (email={ident['email']!r}, sub={ident['sub']!r}), with the "
                  f"runner binding the exact token to that call over a trusted, allow-listed Google endpoint "
                  f"(fingerprint match + introspection-host allow-list, no proxy/redirect, validated TLS) — a "
                  f"short-lived token valid AS {who!r} was proven minted. SUBJECT = the retained capture the "
                  f"WARDEN-gated runner produced; VIGIL re-derives the achieved effect over the retained "
                  f"evidence offline (no network)."),
        observed={"reason": "gcp_sa_impersonation_confirmed", "impersonated_sa": who, "method": method.strip(),
                  "confirming_call": action, "echo_email": ident["email"], "echo_sub": ident["sub"]})


_IAM_COMPUTE_RUN_ACTIONS: "tuple[str, ...]" = (
    "cloudformation:createstack", "datapipeline:activatepipeline", "datapipeline:createpipeline",
    "ec2:runinstances", "ecs:runtask", "glue:createdevendpoint", "lambda:createfunction",
    "lambda:invokefunction", "sagemaker:createnotebookinstance",
)


_IAM_ESCALATION_PRIMITIVES: "dict[str, dict[str, Any]]" = {
    "assume_role_trust_rewrite": {
        "all": ("sts:assumerole", "iam:updateassumerolepolicy"), "any": (), "any_scope": "cover",
        "edge": "assume", "cover": "via", "family": "grant_gain",
        "label": "trust-policy rewrite (sts:AssumeRole + iam:UpdateAssumeRolePolicy)",
    },
    "pass_role_to_compute": {
        "all": ("iam:passrole",), "any": _IAM_COMPUTE_RUN_ACTIONS, "any_scope": "anywhere",
        "edge": "assume", "cover": "via", "family": "grant_gain",
        "label": "iam:PassRole to a compute service (a run/create action)",
    },
    "attach_user_policy": {
        "all": (), "any": ("iam:attachuserpolicy", "iam:putuserpolicy"), "any_scope": "cover",
        "edge": "grant_admin", "cover": "base", "family": "grant_gain",
        "label": "self policy-attach (iam:AttachUserPolicy / iam:PutUserPolicy)",
    },
    "add_user_to_group": {
        "all": ("iam:addusertogroup",), "any": (), "any_scope": "cover",
        "edge": "member_of", "cover": "via", "family": "grant_gain",
        "label": "add-to-privileged-group (iam:AddUserToGroup)",
    },
    "create_access_key": {
        "all": (), "any": ("iam:createaccesskey", "iam:createloginprofile"), "any_scope": "cover",
        "edge": "assume", "cover": "via", "family": "credential_mint",
        "label": "create-credential-for-target (iam:CreateAccessKey / iam:CreateLoginProfile)",
    },
}


def _iam_norm_action(value: Any) -> str:
    """Canonical (lower-cased, stripped) IAM action token."""
    return _imds_text(value).strip().lower()


def _iam_as_list(value: Any) -> "list[str]":
    """Normalize an IAM Action/Resource field (a single string OR a list of strings) to a list of strings.
    A string is a single-element list (NOT iterated char-by-char); anything else is dropped. Never raises."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [x for x in value if isinstance(x, str)]
    return []


def _iam_glob_matches(pattern: str, target: str) -> bool:
    """True iff an IAM glob ``pattern`` (``*`` any run, ``?`` one char — the only wildcards IAM uses) matches
    the whole lower-cased ``target``. ``*`` alone matches everything; a wildcard that EXCLUDES the target
    (``role/dev-*`` vs ``role/admin``) does NOT match. Both are already lower-cased. Anchored, non-backtracking
    over fixed alternations, ReDoS-safe."""
    if not pattern or not target:
        return False
    if pattern == "*":
        return True
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, target) is not None


def _iam_action_matches(action_pattern: Any, required: str) -> bool:
    """True iff an IAM action PATTERN (which may wildcard: ``*``, ``iam:*``, ``iam:Attach*``) matches the
    lower-cased ``required`` action."""
    return _iam_glob_matches(_iam_norm_action(action_pattern), required)


def _iam_resource_covers(resource_pattern: Any, target: str) -> bool:
    """True iff an IAM resource PATTERN covers the lower-cased ``target`` id (the graph/via/base id space —
    the capture uses CONSISTENT ids exactly like ``policy_path``). ``*`` covers everything; a wildcard that
    excludes the target does NOT cover it (the FP trap)."""
    return _iam_glob_matches(_imds_text(resource_pattern).strip().lower(), _norm_id(target))


def _iam_stmt_allows(stmt: Any, action: str, target: str) -> bool:
    """A single statement UNCONDITIONALLY Allows ``action`` over ``target``: Effect==Allow, NO Condition (a
    conditional grant is not unconditional), NO NotAction (an inverted action set is ambiguous), some Action
    pattern matches, some Resource pattern covers the target. Condition / NotAction / a non-covering resource
    all return False — the fail-closed FP traps."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "allow":
        return False
    if stmt.get("condition") or stmt.get("Condition"):
        return False
    if stmt.get("not_action") or stmt.get("NotAction"):
        return False
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    if not any(_iam_action_matches(a, action) for a in actions):
        return False
    return any(_iam_resource_covers(r, target) for r in resources)


def _iam_stmt_allows_somewhere(stmt: Any, action: str) -> bool:
    """A statement UNCONDITIONALLY Allows ``action`` over SOME (any) resource — the PassRole run-action leg,
    whose compute resource (an instance/function) is not the passed role. Same unconditional guards
    (Effect==Allow, no Condition, no NotAction, an action match, at least one Resource present)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "allow":
        return False
    if stmt.get("condition") or stmt.get("Condition"):
        return False
    if stmt.get("not_action") or stmt.get("NotAction"):
        return False
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    return bool(resources) and any(_iam_action_matches(a, action) for a in actions)


def _iam_stmt_denies(stmt: Any, action: str, target: str) -> bool:
    """A statement DENIES ``action`` over ``target`` (deny-precedence, fail-closed). A ``Deny NotAction=[X]``
    denies everything EXCEPT X, so it denies ``action`` UNLESS ``action`` matches a NotAction pattern. A plain
    ``Deny Action=… Resource=…`` denies on an action+resource match. A Deny with no Resource is treated as
    covering the target (IAM requires a Resource; absent -> fail-closed to blocking)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "deny":
        return False
    resources = _iam_as_list(stmt.get("resource") or stmt.get("Resource"))
    covers = (not resources) or any(_iam_resource_covers(r, target) for r in resources)
    if not covers:
        return False
    not_action = _iam_as_list(stmt.get("not_action") or stmt.get("NotAction"))
    if not_action:
        return not any(_iam_action_matches(na, action) for na in not_action)
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    return any(_iam_action_matches(a, action) for a in actions)


def _iam_stmt_denies_anywhere(stmt: Any, action: str) -> bool:
    """A Deny that could block ``action`` over SOME resource — the fail-closed dual of the ``anywhere`` ALLOW
    leg (the PassRole run-action's compute resource, e.g. an instance/function, is NOT the passed role, so its
    id is unknown to the capture). Since the specific resource cannot be known, ANY Deny on the action is
    treated as potentially blocking: over-approximating denies is the SAFE direction (fewer escalation FACTs).
    A ``Deny NotAction=[X]`` denies everything except X; a plain ``Deny Action=…`` denies on an action match.
    Resource is IGNORED here (a resource-scoped run-action Deny — e.g. ``Deny ec2:RunInstances
    Resource=instance/*`` — really does block the launch, so it must suppress the FACT even though it does not
    cover the passed role)."""
    if not isinstance(stmt, Mapping):
        return False
    if _imds_text(stmt.get("effect") or stmt.get("Effect")).strip().lower() != "deny":
        return False
    not_action = _iam_as_list(stmt.get("not_action") or stmt.get("NotAction"))
    if not_action:
        return not any(_iam_action_matches(na, action) for na in not_action)
    actions = _iam_as_list(stmt.get("action") or stmt.get("Action"))
    return any(_iam_action_matches(a, action) for a in actions)


def _iam_effective_allow(action: str, target: str, id_stmts: "list", boundary_stmts: "list | None",
                         scp_stmts: "list | None", *, anywhere: bool = False) -> bool:
    """UNCONDITIONAL effective allow of ``action`` over ``target`` (or, with ``anywhere``, over ANY resource):
    allowed by the IDENTITY policy AND — when present — by the permissions BOUNDARY AND by the SCP, with NO
    Deny at ANY layer. A permissions boundary / SCP that is PRESENT but does NOT allow the action RESTRICTS
    it -> not allowed (the boundary/SCP FP trap, fail-closed). ``boundary_stmts``/``scp_stmts`` are None when
    ABSENT (no restriction) and a (possibly empty) list when present (empty -> denies all). With ``anywhere``
    the DENY check is resource-agnostic too (``_iam_stmt_denies_anywhere``): a Deny on the run action at ANY
    scope suppresses the FACT, because the run leg's compute resource is unknown and a resource-scoped Deny
    (e.g. ``Deny ec2:RunInstances Resource=instance/*``) genuinely blocks the launch."""
    def allows(s: Any) -> bool:
        return _iam_stmt_allows_somewhere(s, action) if anywhere else _iam_stmt_allows(s, action, target)

    def denies(s: Any) -> bool:
        return _iam_stmt_denies_anywhere(s, action) if anywhere else _iam_stmt_denies(s, action, target)

    for layer in (id_stmts, boundary_stmts or [], scp_stmts or []):
        if any(denies(s) for s in layer):
            return False
    if not any(allows(s) for s in id_stmts):
        return False
    if boundary_stmts is not None and not any(allows(s) for s in boundary_stmts):
        return False
    if scp_stmts is not None and not any(allows(s) for s in scp_stmts):
        return False
    return True


def _iam_build_adj_grants(graph: Mapping[str, Any]) -> "tuple[dict, dict]":
    """Build the principal->principal adjacency (assume/member closure) and principal->[(resource, access)]
    grants from a retained policy graph — the SAME model ``policy_path_oracle`` searches. Deterministic;
    malformed entries are skipped, never raised."""
    adj: "dict[str, list[str]]" = {}
    for rel_key in ("assume", "member_of"):
        for e in graph.get(rel_key) or []:
            if not isinstance(e, Mapping):
                continue
            src, dst = _norm_id(e.get("src")), _norm_id(e.get("dst"))
            if src and dst:
                adj.setdefault(src, []).append(dst)
    grants: "dict[str, list[tuple[str, str]]]" = {}
    for g in graph.get("grants") or []:
        if not isinstance(g, Mapping):
            continue
        p, r = _norm_id(g.get("principal")), _norm_id(g.get("resource"))
        if p and r:
            grants.setdefault(p, []).append((r, str(g.get("access") or "")))
    return adj, grants


def _iam_reaches(adj: Mapping[str, "list[str]"], grants: Mapping[str, "list[tuple[str, str]]"],
                 start: str, target: str, requested: str) -> bool:
    """BFS: does ``start`` reach the resource ``target`` with ``requested`` access over the assume/member
    closure? Mirrors ``policy_path_oracle``'s search (sorted adjacency -> deterministic)."""
    order, seen = [start], {start}
    i = 0
    while i < len(order):
        cur = order[i]
        i += 1
        for res, acc in grants.get(cur, ()):
            if res == target and _access_grants(acc, requested):
                return True
        for nxt in sorted(adj.get(cur, ())):
            if nxt not in seen:
                seen.add(nxt)
                order.append(nxt)
    return False


_IAM_WRITE_VERB_PREFIXES: "tuple[str, ...]" = (
    "create", "put", "delete", "update", "modify", "write", "attach", "detach", "add", "remove", "set",
    "replace", "assume", "pass", "enable", "disable", "authorize", "revoke", "associate", "disassociate",
    "start", "stop", "run", "invoke", "import", "restore", "reset",
)


_IAM_READ_VERB_PREFIXES: "tuple[str, ...]" = (
    "get", "list", "describe", "read", "view", "lookup", "head", "select", "query", "scan", "batchget",
    "generate", "decrypt", "search",
)


_IAM_ACCESS_RANK: "dict[str, int]" = {"read": 2, "write": 3, "admin": 4}


def _iam_action_service(action: Any) -> str:
    """The AWS service prefix of an IAM action (``s3:GetObject`` -> ``s3``); ``*`` -> ``*`` (any service)."""
    a = _iam_norm_action(action)
    if a == "*":
        return "*"
    return a.split(":", 1)[0] if ":" in a else a


def _iam_target_service(target: Any) -> str:
    """The service of a target resource id (``s3/crown-jewels`` -> ``s3``, ``arn:aws:kms:…`` -> ``arn`` —
    keep capture ids in the ``service/name`` space, exactly as ``policy_path`` uses canonical ids)."""
    t = _norm_id(target)
    if "/" in t:
        return t.split("/", 1)[0]
    if ":" in t:
        return t.split(":", 1)[0]
    return t


def _iam_action_access_token(action: Any) -> str:
    """The access-lattice token an IAM action grants: ``*`` / ``svc:*`` -> admin; a write-verb -> write; a
    read-verb (or an unknown named action, conservatively) -> read."""
    a = _iam_norm_action(action)
    if a == "*":
        return "admin"
    verb = a.split(":", 1)[1] if ":" in a else a
    if verb in ("", "*"):
        return "admin"
    for p in _IAM_WRITE_VERB_PREFIXES:
        if verb.startswith(p):
            return "write"
    for p in _IAM_READ_VERB_PREFIXES:
        if verb.startswith(p):
            return "read"
    return "read"


def _iam_identity_target_access(target: str, id_stmts: "list") -> "str | None":
    """The access token at which the base principal's OWN identity policy DIRECTLY reaches ``target`` — the
    SYMMETRIC base fold that makes the base closure see the SAME action-level evidence the escalation side
    does (defect #1: base asymmetry). Considers only UNCONDITIONAL Allows (no Condition, no NotAction) whose
    Resource covers ``target`` AND whose action's SERVICE matches the target's service (or ``*``), so an
    ``iam:*`` grant does NOT fold as reach over an ``s3`` target. Returns the HIGHEST such access token, or
    None. Over-approximating base reach is the FAIL-CLOSED direction (a larger base closure = fewer escalation
    FACTs); denies are deliberately NOT subtracted here (subtracting them would SHRINK the base closure and
    make escalation EASIER to claim — the unsafe direction)."""
    tsvc = _iam_target_service(target)
    best: "str | None" = None
    for s in id_stmts:
        if not isinstance(s, Mapping):
            continue
        if _imds_text(s.get("effect") or s.get("Effect")).strip().lower() != "allow":
            continue
        if s.get("condition") or s.get("Condition") or s.get("not_action") or s.get("NotAction"):
            continue
        resources = _iam_as_list(s.get("resource") or s.get("Resource"))
        if not any(_iam_resource_covers(r, target) for r in resources):
            continue
        for a in _iam_as_list(s.get("action") or s.get("Action")):
            asvc = _iam_action_service(a)
            if asvc != "*" and asvc != tsvc:
                continue   # a cross-service action does not grant reach over this target
            tok = _iam_action_access_token(a)
            if best is None or _IAM_ACCESS_RANK[tok] > _IAM_ACCESS_RANK[best]:
                best = tok
    return best


def iam_escalation_oracle(observed: Any) -> OracleSignal:
    """Fire when RETAINED IAM statements grant a principal an UNCONDITIONAL escalation PRIMITIVE that
    STRICTLY increases what it can reach — the E2 (BUILD-PLAN §E2) achieved-escalation confirmation, the
    stronger dual of ``policy_path_oracle`` (mere reachability). Pure + deterministic, re-verifies OFFLINE.

    ``observed`` is the JSON-safe retained capture::

        {"base_principal": "role/dev",
         "target_resource": "s3/crown-jewels", "target_access": "admin"?,   # "" = any grant path
         "graph": { "grants":[{principal,resource,access}], "assume":[{src,dst}], "member_of":[{src,dst}] },
         "escalation": {
             "primitive": "assume_role_trust_rewrite" | "pass_role_to_compute" | "attach_user_policy"
                        | "add_user_to_group" | "create_access_key",
             "via": "role/admin",                       # the principal the primitive lets base ACT AS
             "statements": [ {effect, action, resource, condition?, not_action?} ],   # base identity policy
             "boundary": {"statements":[…]}?,           # optional permissions boundary (restrictive)
             "scp":      {"statements":[…]}? } }        # optional SCP (restrictive)

    Fires (0.95) ONLY when ALL hold (near-zero-FP by construction):
      (1) STRICT-GAIN precondition — ``base_principal`` does NOT already reach ``target_resource`` in the
          BASE closure (else it is plain reachability, not escalation — the central anti-overclaim guard);
      (2) some primitive from the FIXED set is UNCONDITIONALLY granted (every FP trap fail-closed: a
          Condition, NotAction, explicit Deny / deny-precedence, restricting boundary/SCP, or a Resource
          wildcard that does not cover the target contributes NO edge);
      (3) the ONE edge the primitive synthesizes makes ``base_principal`` reach ``target_resource`` in the
          ESCALATION-CLOSED closure. (2)+(3) over (1) = a strict differential gain.

    Does NOT fire (stays an honest LEAD): a target already reachable in the base closure; an unknown /
    unparseable primitive; a primitive whose required actions are not unconditionally allowed; a synthesized
    edge that still does not reach the target; malformed / absent evidence (never raises)."""
    kind = OracleKind.IAM_ESCALATION_PRIMITIVE
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no IAM escalation evidence", observed={"reason": "malformed_capture"})

    base = _norm_id(observed.get("base_principal"))
    target = _norm_id(observed.get("target_resource"))
    requested = str(observed.get("target_access") or "").strip()
    graph = observed.get("graph") if isinstance(observed.get("graph"), Mapping) else {}
    esc = observed.get("escalation") if isinstance(observed.get("escalation"), Mapping) else {}
    if not base or not target:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence="escalation query needs both a base_principal and a target_resource",
            observed={"reason": "incomplete_query", "base_principal": base, "target": target})

    # Parse the escalation statements EARLY — the base fold (defect #1) needs them BEFORE the strict-gain
    # differential, so the base and escalation closures are computed over the SAME action-level evidence.
    id_stmts = [s for s in (esc.get("statements") or []) if isinstance(s, Mapping)]
    boundary = esc.get("boundary")
    scp = esc.get("scp")
    boundary_stmts = ([s for s in (boundary.get("statements") or []) if isinstance(s, Mapping)]
                      if isinstance(boundary, Mapping) else None)
    scp_stmts = ([s for s in (scp.get("statements") or []) if isinstance(s, Mapping)]
                 if isinstance(scp, Mapping) else None)

    adj, grants = _iam_build_adj_grants(graph)
    # SYMMETRIC BASE FOLD (defect #1: base asymmetry). Fold the base principal's OWN unconditional identity-
    # policy Allows that DIRECTLY reach `target` (same service, resource covers target) into base_grants, so
    # the base closure sees the SAME action-level evidence the escalation side does — an attacker who already
    # reaches the target via a direct Allow (not represented as a coarse resource-grant edge) is NOT counted
    # as a strict gain. base_grants is the SHARED base for BOTH closures; the ONLY delta is the ONE
    # synthesized primitive edge, so strict-gain is an honest differential (esc_closure \ base_closure).
    base_grants = {k: list(v) for k, v in grants.items()}
    folded = _iam_identity_target_access(target, id_stmts)
    if folded is not None:
        base_grants.setdefault(base, []).append((target, folded))

    # (1) STRICT-GAIN precondition — base must NOT already reach the target over the FOLDED base closure
    #     (else it is plain reachability, not escalation). The central anti-overclaim guard.
    if _iam_reaches(adj, base_grants, base, target, requested):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"{base!r} ALREADY reaches {target!r} in the base closure (a direct identity-policy Allow "
                      f"or an existing grant path) without escalating — this is reachability (policy_path), "
                      f"NOT a strict escalation gain (stays a LEAD)"),
            observed={"reason": "no_strict_gain_already_reachable", "base_principal": base, "target": target})

    primitive = _imds_text(esc.get("primitive")).strip().lower()
    spec = _IAM_ESCALATION_PRIMITIVES.get(primitive)
    if spec is None:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"escalation primitive {primitive!r} is not in the fixed auditable set "
                      f"{sorted(_IAM_ESCALATION_PRIMITIVES)} — no edge is synthesized (stays a LEAD)"),
            observed={"reason": "unknown_primitive", "primitive": primitive})

    via = _norm_id(esc.get("via"))
    cover = via if spec["cover"] == "via" else base
    if spec["cover"] == "via" and not via:
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the {primitive!r} primitive names no `via` principal to escalate to — no edge can be "
                      f"synthesized (stays a LEAD)"),
            observed={"reason": "no_via_principal", "primitive": primitive})

    # (2) every REQUIRED action UNCONDITIONALLY allowed over `cover`; and, when the primitive has an
    #     alternative set, at least ONE of it (over `cover`, or over ANY resource for the PassRole run leg).
    for action in spec["all"]:
        if not _iam_effective_allow(action, cover, id_stmts, boundary_stmts, scp_stmts):
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"the {primitive!r} primitive requires an UNCONDITIONAL Allow of {action!r} over "
                          f"{cover!r}, but the retained statements do not grant it (a Condition, NotAction, "
                          f"Deny, restricting boundary/SCP, or a resource wildcard that excludes the target "
                          f"— stays a LEAD)"),
                observed={"reason": "action_not_unconditionally_allowed", "primitive": primitive,
                          "action": action, "cover": cover})
    if spec["any"]:
        anywhere = spec["any_scope"] == "anywhere"
        matched = [a for a in spec["any"]
                   if _iam_effective_allow(a, cover, id_stmts, boundary_stmts, scp_stmts, anywhere=anywhere)]
        if not matched:
            return OracleSignal(
                kind=kind, fired=False, confidence=0.0,
                evidence=(f"the {primitive!r} primitive requires at least one of {list(spec['any'])} "
                          f"{'over any resource' if anywhere else f'over {cover!r}'}, but none is "
                          f"unconditionally allowed (stays a LEAD)"),
                observed={"reason": "no_alternative_action_allowed", "primitive": primitive, "cover": cover})

    # (3) synthesize the ONE new capability edge and re-run the differential over the escalation-closed graph
    #     (a COPY of the FOLDED base closure — base_grants — plus the ONE new edge, so the ONLY delta vs the
    #     base closure is the primitive edge).
    esc_adj = {k: list(v) for k, v in adj.items()}
    esc_grants = {k: list(v) for k, v in base_grants.items()}
    if spec["edge"] in ("assume", "member_of"):
        esc_adj.setdefault(base, []).append(via)
        new_edge = f"{base} -[{spec['edge']}]-> {via}"
    else:   # grant_admin — self policy-attach grants base a direct admin grant over the target resource
        esc_grants.setdefault(base, []).append((target, "admin"))
        new_edge = f"{base} -[has_grant admin]-> {target}"

    if not _iam_reaches(esc_adj, esc_grants, base, target, requested):
        return OracleSignal(
            kind=kind, fired=False, confidence=0.0,
            evidence=(f"the {primitive!r} primitive synthesizes {new_edge}, but {base!r} STILL does not reach "
                      f"{target!r} in the escalation-closed closure — no strict gain (stays a LEAD)"),
            observed={"reason": "edge_does_not_reach_target", "primitive": primitive,
                      "synthesized_edge": new_edge, "target": target})

    return OracleSignal(
        kind=kind, fired=True, confidence=0.95,
        evidence=(f"IAM privilege-escalation PRIMITIVE ({spec['label']}): the RETAINED IAM configuration "
                  f"PERMITS {base!r} this escalation primitive UNCONDITIONALLY, synthesizing {new_edge}, which "
                  f"lets {base!r} reach {target!r}{(' with access '+requested) if requested else ''} — a STRICT "
                  f"gain (unreachable in the base closure, reachable in the escalation-closed closure). This is "
                  f"a CAPABILITY over the retained config: the identity policy + boundary + SCP permit it, but "
                  f"a resource-based policy (a KMS key policy, an S3 bucket policy, the target role's trust "
                  f"Deny) NOT present in the capture could still nullify it. SUBJECT = the retained IAM policy "
                  f"statements; VIGIL re-derives the permitted escalation over the retained evidence offline "
                  f"(no cloud, no attack)."),
        observed={"reason": "iam_escalation_permitted", "primitive": primitive, "family": spec["family"],
                  "base_principal": base, "via": via, "target": target, "requested_access": requested,
                  "synthesized_edge": new_edge})


_K8S_RBAC_GRANT_STR_CAP = 4096


_K8S_CORE_OR_WILDCARD_GROUPS = frozenset({"", "*"})


_K8S_PRIVESC_GROUPS = frozenset({"", "*", "rbac.authorization.k8s.io"})


_K8S_SECRET_READ_VERBS = frozenset({"get", "list", "watch", "*"})


_K8S_LIST_WATCH_STAR = frozenset({"list", "watch", "*"})


_K8S_SECRET_RESOURCES = frozenset({"secrets", "*"})


_K8S_ESCALATE_RESOURCES = frozenset({"roles", "clusterroles", "*"})


_K8S_BIND_RESOURCES = frozenset({"rolebindings", "clusterrolebindings", "*"})


_K8S_IMPERSONATE_RESOURCES = frozenset({"users", "groups", "serviceaccounts", "*"})


_K8S_LIVE_RULE_SOURCES = frozenset({"live_clusterrole_get", "live_role_get"})


_K8S_GRANT_SHAPE_EFFECT = {
    "full_wildcard": "exercise ALL verbs on ALL resources (cluster-admin-equivalent)",
    "secret_read": "read (get/list/watch) Secrets",
    "priv_esc": "escalate privilege via escalate/bind/impersonate on RBAC objects",
}


def _k8s_grant_token_set(values: Any) -> "frozenset[str]":
    """A NORMALIZED (lower+strip, capped) token SET from a PolicyRule field (verbs/resources/apiGroups). A
    non-list yields the empty set; unknown tokens are retained but only ever SUPPRESS a match."""
    if not isinstance(values, (list, tuple)):
        return frozenset()
    return frozenset(_k8s_norm(v) for v in values)


def _k8s_rule_has_resource_names(rule: Mapping[str, Any]) -> bool:
    """True IFF the rule carries a NON-EMPTY ``resourceNames`` constraint (a per-object scoping that limits
    get/delete/update to named objects; list/watch/* ignore it, so a wildcard/list rule is NOT so constrained)."""
    rn = rule.get("resourceNames")
    if rn is None:
        rn = rule.get("resource_names")
    return isinstance(rn, (list, tuple)) and any(_coerce_text(x).strip() for x in rn)


def _k8s_rule_shapes(rule: Any) -> "set[str]":
    """The set of dangerous shapes a SINGLE PolicyRule exhibits — a subset of {full_wildcard, secret_read,
    priv_esc}. All over NORMALIZED tokens with EXACT membership; an unknown token can only suppress."""
    if not isinstance(rule, Mapping):
        return set()
    verbs = _k8s_grant_token_set(rule.get("verbs"))
    resources = _k8s_grant_token_set(rule.get("resources") if rule.get("resources") is not None
                                     else rule.get("resource"))
    groups = _k8s_grant_token_set(rule.get("apiGroups") if rule.get("apiGroups") is not None
                                  else rule.get("api_groups"))
    shapes: set[str] = set()
    # (a) FULL WILDCARD — cluster-admin-equivalent: * verbs AND * resources in the core/wildcard apiGroup.
    if "*" in verbs and "*" in resources and (groups & _K8S_CORE_OR_WILDCARD_GROUPS):
        shapes.add("full_wildcard")
    # (b) SECRET READ — get/list/watch/* on secrets in the core/wildcard apiGroup. A get-only rule constrained
    #     by a NON-EMPTY resourceNames is EXCLUDED (a single named secret); list/watch/* IGNORE resourceNames.
    if (verbs & _K8S_SECRET_READ_VERBS) and (resources & _K8S_SECRET_RESOURCES) \
            and (groups & _K8S_CORE_OR_WILDCARD_GROUPS):
        if not (_k8s_rule_has_resource_names(rule) and not (verbs & _K8S_LIST_WATCH_STAR)):
            shapes.add("secret_read")
    # (c) PRIV-ESC verbs in the RBAC/core apiGroups: escalate on roles/clusterroles/*, bind on
    #     rolebindings/clusterrolebindings/*, impersonate on users/groups/serviceaccounts/*.
    if groups & _K8S_PRIVESC_GROUPS:
        if ("escalate" in verbs and (resources & _K8S_ESCALATE_RESOURCES)) \
                or ("bind" in verbs and (resources & _K8S_BIND_RESOURCES)) \
                or ("impersonate" in verbs and (resources & _K8S_IMPERSONATE_RESOURCES)):
            shapes.add("priv_esc")
    return shapes


def _k8s_subject_class(s: Any) -> str:
    """Classify a binding subject into the FIXED attacker-occupiable set S, or ``""`` (a NAMED subject, not in
    S). Comparisons are EXACT (case- and whitespace-sensitive), like ``_k8s_subject_is_anon``.
      ``anon``       — User system:anonymous / Group system:unauthenticated (reuse ``_k8s_subject_is_anon``);
      ``default_sa`` — the typed namespace-``default`` ServiceAccount ``default`` (kind/namespace/name EXACT,
                       core/empty apiGroup — a ServiceAccount is not in the RBAC apiGroup);
      ``all_auth``   — the Group ``system:authenticated`` (Groups carry the RBAC apiGroup, like anon).
    Any NAMED user/group/SA (including ``default/<named-app>``) returns ``""`` and is NOT in S."""
    if _k8s_subject_is_anon(s):
        return "anon"
    if isinstance(s, Mapping):
        kind = _coerce_text(s.get("kind"))
        name = _coerce_text(s.get("name"))
        ns = _coerce_text(s.get("namespace") if s.get("namespace") is not None else s.get("ns"))
        api_group = _coerce_text(s.get("api_group") or s.get("apiGroup"))
        if kind == "ServiceAccount" and ns == "default" and name == "default" and api_group == "":
            return "default_sa"
        if kind == "Group" and name == "system:authenticated" and api_group == _K8S_RBAC_APIGROUP:
            return "all_auth"
        return ""
    # legacy STRING subject (a live-read RBAC sensor may emit a reserved name directly): only the
    # all-authenticated pseudo-group is representable as a bare string here (anon is handled above).
    return "all_auth" if _coerce_text(s) == "system:authenticated" else ""


def _k8s_roleref_role_object_linked(binding: Mapping[str, Any],
                                    role_obj: Mapping[str, Any]) -> "tuple[bool, str]":
    """(I) IDENTITY LINKAGE — re-check the roleRef->role_object JOIN over the retained evidence, NEVER trust
    the runner's say-so. ALL comparisons EXACT (case/whitespace-sensitive). roleRef.name==role_object.name;
    roleRef.kind==role_object.kind∈{ClusterRole,Role}; roleRef.apiGroup==role_object.apiGroup==the RBAC group
    (NO empty-string tolerance — a stronger claim than TIER-1). Role => the binding is a RoleBinding AND the
    role_object.namespace==binding.namespace; ClusterRole => role_object.namespace is empty. Returns
    ``(linked, reason)``."""
    ref = binding.get("role_ref")
    if not isinstance(ref, Mapping):
        ref = binding.get("roleRef") if isinstance(binding.get("roleRef"), Mapping) else {}
    cap = _K8S_RBAC_GRANT_STR_CAP
    ref_name = _coerce_text(ref.get("name"))[:cap]
    ref_kind = _coerce_text(ref.get("kind"))[:cap]
    ref_group = _coerce_text(ref.get("api_group") or ref.get("apiGroup"))[:cap]
    ro_name = _coerce_text(role_obj.get("name"))[:cap]
    ro_kind = _coerce_text(role_obj.get("kind"))[:cap]
    ro_group = _coerce_text(role_obj.get("api_group") or role_obj.get("apiGroup"))[:cap]
    ro_ns = _coerce_text(role_obj.get("namespace") if role_obj.get("namespace") is not None
                         else role_obj.get("ns"))[:cap]
    if not ref_name or ref_name != ro_name:
        return False, "roleRef.name != role_object.name"
    if ref_kind not in ("ClusterRole", "Role") or ref_kind != ro_kind:
        return False, "roleRef.kind != role_object.kind (or not exactly ClusterRole|Role)"
    if not (ref_group == ro_group == _K8S_RBAC_APIGROUP):
        return False, "roleRef.apiGroup/role_object.apiGroup not exactly rbac.authorization.k8s.io"
    bind_kind = _coerce_text(binding.get("kind"))[:cap]
    bind_ns = _coerce_text(binding.get("namespace") if binding.get("namespace") is not None
                           else binding.get("ns"))[:cap]
    if ref_kind == "Role":
        if bind_kind != "RoleBinding":
            return False, "a namespaced Role roleRef requires a RoleBinding"
        if not ro_ns or ro_ns != bind_ns:
            return False, "the namespaced Role's namespace must equal the RoleBinding's namespace"
    else:  # ClusterRole
        if ro_ns != "":
            return False, "a ClusterRole role_object must have an empty namespace"
    return True, "linked"


def _k8s_grant_lead(kind: "OracleKind", label: str, reason: str, claim_scope: str) -> OracleSignal:
    return OracleSignal(
        kind=kind, fired=False, confidence=0.0,
        evidence=(f"k8s RBAC verb-grant control {label} is not a provable dangerous (verb,resource) grant to "
                  f"an attacker-occupiable subject: {reason} — not provably critical (stays a lead)"),
        observed={"check_id": label, "reason": "no_dangerous_verb_grant", "claim_scope": claim_scope})


def _k8s_grant_fact(kind: "OracleKind", label: str, subj_class: str, who: str, shapes: "set[str]",
                    claim_scope: str, role_obj: Mapping[str, Any]) -> OracleSignal:
    ro_name = _coerce_text(role_obj.get("name"))[:_K8S_RBAC_GRANT_STR_CAP]
    ro_kind = _coerce_text(role_obj.get("kind"))[:_K8S_RBAC_GRANT_STR_CAP]
    effects = "; ".join(_K8S_GRANT_SHAPE_EFFECT[s] for s in sorted(shapes) if s in _K8S_GRANT_SHAPE_EFFECT)
    subj_desc = {
        "anon": "an UNAUTHENTICATED principal",
        "default_sa": "the namespace-default ServiceAccount (default:default)",
        "all_auth": "ANY authenticated principal (the system:authenticated group)",
    }.get(subj_class, subj_class)
    occ = ""
    if subj_class == "default_sa":
        occ = (" NOTE: this asserts the BINDING GRANT (any principal that IS default:default is so authorized); "
               "the binding's existence is NOT proof a pod runs as that ServiceAccount — occupancy of the "
               "default SA is an ASSUMPTION stated here, not proven by the binding.")
    return OracleSignal(
        kind=kind, fired=True, confidence=0.9,
        evidence=(f"k8s RBAC verb-grant FACT: binding {label} binds {subj_desc} ({who!r}) to {ro_kind} "
                  f"{ro_name!r}, whose PARSED rules authorize {effects} ({claim_scope} scope). Any principal "
                  f"that IS {who!r} is authorized to {effects}. Re-derived over the retained binding + "
                  f"role_object rules (offline, ZERO cluster calls), the roleRef->role join re-checked, not "
                  f"trusted." + occ),
        observed={"check_id": label, "rule": "dangerous_verb_grant", "subject_class": subj_class,
                  "subject": who, "role": ro_name, "role_kind": ro_kind,
                  "dangerous_shapes": sorted(shapes), "claim_scope": claim_scope})


def k8s_rbac_verb_grant_oracle(observed_control: Any) -> OracleSignal:
    """Fire (0.9) when a RETAINED RBAC ``binding`` + its SEPARATELY-retained ``role_object`` PROVABLY grant a
    DANGEROUS (verb,resource) capability to an ATTACKER-OCCUPIABLE subject — the E4 TIER-2 achieved-effect
    confirmation. The oracle PARSES the role's ``rules`` (TIER-1 only name-matched a built-in role) and
    re-derives the judgment over the retained set ALONE (offline, ZERO cluster calls), so a confirmed FACT
    re-verifies offline from its certificate.

    ``observed_control`` is the JSON-safe retained control::

        {"check_id": "binding:ns/name"?,
         "binding": {"kind": "ClusterRoleBinding"|"RoleBinding", "namespace": str?, "name": str?,
                     "subjects": [{"kind","name","namespace","api_group"} | "system:…"],
                     "role_ref": {"name", "kind": "ClusterRole"|"Role", "api_group": "rbac.authorization.k8s.io"}},
         "role_object": {"name", "kind", "api_group", "namespace",
                         "rules": [{"verbs":[…],"resources":[…],"apiGroups":[…],"resourceNames":[…]?}, …],
                         "rules_source": "live_clusterrole_get"|"live_role_get"|"static_manifest",
                         "aggregationRule": {...}?}}

    Fires iff ALL hold — (I) identity linkage re-checked; (IV) rules AUTHORITATIVE (a live API GET, or a
    static manifest with NO aggregationRule); (III) the role's rules contain a dangerous shape; (II) an
    attacker-occupiable subject is bound — under the SUBJECT-GATED eligibility that is the near-zero-FP fix:
      * an ANONYMOUS subject MAY FACT on ANY dangerous shape — full-wildcard, secret-read, OR priv-esc;
      * the DEFAULT ServiceAccount / system:authenticated MAY FACT ONLY on a FULL-WILDCARD (*/*/*) grant AND
        ONLY via a ClusterRoleBinding — NEVER secret-read, NEVER priv-esc, NEVER a namespaced RoleBinding
        (the built-in ``admin`` legitimately grants Secrets get/list/watch, and cluster-read backup/monitoring
        roles legitimately grant */* get/list/watch, so those MOST-COMMON legitimate delegations stay LEAD).
    Everything else — a NAMED subject; a resourceNames-scoped single-secret get; default-SA×secret-read;
    authenticated×broad-read; a linkage break; non-authoritative (aggregated static) rules; malformed/absent
    evidence — stays an honest LEAD (never raises). Pure + deterministic (re-verifies offline)."""
    kind = OracleKind.K8S_RBAC_VERB_GRANT
    if not isinstance(observed_control, Mapping):
        return OracleSignal(kind=kind, fired=False, confidence=0.0,
                            evidence="no k8s RBAC verb-grant control evidence",
                            observed={"reason": "malformed_capture", "claim_scope": "?"})
    ctl = observed_control
    binding = ctl.get("binding") if isinstance(ctl.get("binding"), Mapping) else {}
    role_obj = ctl.get("role_object") if isinstance(ctl.get("role_object"), Mapping) else {}
    cap = _K8S_RBAC_GRANT_STR_CAP
    cid = _coerce_text(ctl.get("check_id") or binding.get("name") or ctl.get("name"))[:cap].strip()
    label = cid or "?"

    bind_kind = _coerce_text(binding.get("kind"))[:cap]
    bind_ns = _coerce_text(binding.get("namespace") if binding.get("namespace") is not None
                           else binding.get("ns"))[:cap]
    is_crb = bind_kind == "ClusterRoleBinding"
    claim_scope = "cluster" if is_crb else (f"namespace:{bind_ns}" if bind_ns else "namespace:?")

    # (I) identity linkage — re-derived over the retained roleRef + role_object, never trusted.
    linked, link_reason = _k8s_roleref_role_object_linked(binding, role_obj)
    if not linked:
        return _k8s_grant_lead(kind, label, f"identity linkage not proven ({link_reason})", claim_scope)

    # (IV) rules AUTHORITATIVE: a live API GET, or a static manifest with NO aggregationRule.
    rules_source = _k8s_norm(role_obj.get("rules_source") or role_obj.get("rulesSource"))
    has_agg = bool(role_obj.get("aggregationRule")) or bool(role_obj.get("aggregation_rule"))
    authoritative = (rules_source in _K8S_LIVE_RULE_SOURCES) or (rules_source == "static_manifest" and not has_agg)
    if not authoritative:
        why = (", aggregationRule present" if has_agg and rules_source == "static_manifest" else "")
        return _k8s_grant_lead(kind, label,
                               f"role rules are not authoritative (rules_source={rules_source or 'ABSENT'!r}{why})",
                               claim_scope)

    # (III) dangerous shapes over the role's PARSED rules.
    raw_rules = role_obj.get("rules")
    rules = raw_rules if isinstance(raw_rules, (list, tuple)) else []
    shapes: set[str] = set()
    for r in rules:
        shapes |= _k8s_rule_shapes(r)

    # (II) attacker-occupiable subjects, classified.
    raw_subjects = binding.get("subjects")
    subjects = raw_subjects if isinstance(raw_subjects, (list, tuple)) else []
    classified = [(_k8s_subject_class(s), s) for s in subjects]
    anon_subj = next((s for c, s in classified if c == "anon"), None)
    priv_subj = next(((c, s) for c, s in classified if c in ("default_sa", "all_auth")), None)

    # SUBJECT-GATED FACT ELIGIBILITY (the mandatory near-zero-FP fix) --------------------------------------
    # ANON is inherently attacker-occupiable: MAY FACT on (a) OR (b) OR (c) — TIER-2's genuine anon delta is a
    # CUSTOM role whose RULES are dangerous (which TIER-1's built-in-name match missed).
    if anon_subj is not None and shapes:
        return _k8s_grant_fact(kind, label, "anon", _k8s_subject_display(anon_subj), shapes, claim_scope, role_obj)
    # DEFAULT_SA / ALL_AUTH: ONLY a genuine */*/* full-wildcard grant via a ClusterRoleBinding is an
    # unambiguous FACT — NOT secret-read (built-in admin), NOT a namespaced RoleBinding, NOT priv-esc.
    if priv_subj is not None and "full_wildcard" in shapes and is_crb:
        return _k8s_grant_fact(kind, label, priv_subj[0], _k8s_subject_display(priv_subj[1]),
                               {"full_wildcard"}, claim_scope, role_obj)

    in_s = sum(1 for c, _ in classified if c)
    return _k8s_grant_lead(
        kind, label,
        (f"no attacker-occupiable subject is bound to a FACT-eligible dangerous grant (subjects in S: {in_s}; "
         f"dangerous rule shapes: {sorted(shapes) or 'none'}; scope: {claim_scope}) — a default/authenticated "
         f"subject may FACT only on a */*/* ClusterRoleBinding"),
        claim_scope)


# --- credential_acceptance_oracle (M-11.3) — the A-prime family Lane C left untracked; its
#     import-closure is stdlib-only (closure=12), so it is PORTABLE and re-derived here. ---
_CRED_SIGNAL_MIN_LEN = 12


_CRED_SIGNAL_MIN_ENTROPY = 2.5


_CRED_DENIAL_STATUSES = frozenset({401, 403})


_CRED_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _cred_status_int(status: Any) -> "int | None":
    """Coerce a captured status to an int, or None (a non-int / bool / unparseable status). Pure."""
    if isinstance(status, bool):
        return None
    if isinstance(status, int):
        return status
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _cred_access_fields(resp: Any) -> "tuple[int | None, str, str, str, str, str]":
    """Coerce one captured PROTECTED-RESOURCE access leg to
    ``(status, body, header_blob, location, url, method)`` (pure). Reads ONLY the response's status / body /
    header values and the request's url / method — never any credential or secret field. ``location`` is the
    (case-insensitive) Location header, used to adjudicate a redirect-to-login denial; ``url`` / ``method`` carry
    the request provenance used to prove the two legs are the SAME protected-resource request (same-shape)."""
    body = ""
    header_blob = ""
    location = ""
    url = ""
    method = ""
    status: Any = None
    if isinstance(resp, Mapping):
        body = _coerce_text(resp.get("body", resp.get("text", resp.get("content", ""))))
        status = resp.get("status", resp.get("status_code"))
        headers = resp.get("headers")
        if isinstance(headers, Mapping):
            parts = []
            for k, v in headers.items():
                ks = _coerce_text(k)
                vs = _coerce_text(v)
                parts.append(f"{ks}: {vs}")
                if ks.strip().lower() == "location":
                    location = vs.strip()
            header_blob = " ".join(parts)
        url = _coerce_text(resp.get("url", resp.get("request_url", ""))).strip()
        method = _coerce_text(resp.get("method", resp.get("request_method", ""))).strip().upper()
        req = resp.get("request")
        if isinstance(req, Mapping):
            url = url or _coerce_text(req.get("url", "")).strip()
            method = method or _coerce_text(req.get("method", "")).strip().upper()
    else:
        body = _coerce_text(resp)
    return _cred_status_int(status), body, header_blob, location, url, method


def _cred_leg_has_capture(status: "int | None", body: str, header_blob: str) -> bool:
    """True iff a leg actually captured a response (a status, a body, or headers) — a leg that captured
    nothing is INCONCLUSIVE, never half of a sound differential. Pure."""
    return status is not None or bool(body) or bool(header_blob)


def _cred_descriptor_denial_model(descriptor: Mapping[str, Any]) -> "tuple[frozenset[int], list[str], str]":
    """Extract the operator-attested denial model from the protected-resource descriptor:
    ``(denial_statuses, login_redirect_locations, denial_body_signature)``. ``denial_statuses`` ALWAYS includes
    the universal {401,403}; the operator may attest additional mechanisms. Pure.

    H1 coherence guard: a 2xx (200-299) is this oracle's definition of an authenticated SUCCESS, so an
    operator-attested denial_status that intersects [200,299] is INCOHERENT — it would let a 2xx baseline count
    as "denied" while a DIFFERENT 2xx weak leg fires. Such entries are DROPPED here (never let the success code
    mean "denied"); a genuine soft-200 denial must be attested via ``denial_body_signature`` (which is sound in
    both directions). A baseline whose only "denial" was a dropped 2xx then correctly falls through to the
    "baseline is NOT a denial" REFUSE, surfacing the misconfiguration instead of manufacturing a differential."""
    statuses: set[int] = set(_CRED_DENIAL_STATUSES)
    raw_statuses = descriptor.get("denial_statuses")
    if isinstance(raw_statuses, (list, tuple, set, frozenset)):
        for s in raw_statuses:
            si = _cred_status_int(s)
            if si is not None and not (200 <= si < 300):   # H1: a 2xx is SUCCESS, never a denial
                statuses.add(si)
    raw_loc = descriptor.get("login_redirect_locations")
    locations = ([t for t in (_coerce_text(x).strip() for x in raw_loc) if t]
                 if isinstance(raw_loc, (list, tuple, set, frozenset)) else [])
    body_sig = _coerce_text(descriptor.get("denial_body_signature")).strip()
    return frozenset(statuses), locations, body_sig


def _cred_access_is_denial(status: "int | None", body: str, header_blob: str, location: str,
                           denial_statuses: "frozenset[int]", login_locations: "list[str]",
                           body_sig: str) -> bool:
    """True iff a protected-resource access is a DENIAL that matches the operator-attested denial model:
    (a) ``status`` in the attested denial statuses (default {401,403}); OR
    (b) a 3xx redirect whose Location targets one of the attested login/SSO prefixes; OR
    (c) the attested ``denial_body_signature`` is present in the body or header blob.
    Pure — the denial model is the operator's attestation, re-derived offline from the retained bytes."""
    if status is not None and status in denial_statuses:
        return True
    if status is not None and status in _CRED_REDIRECT_STATUSES and location and login_locations:
        # H2: PREFIX match only. A removed ``loc in location`` substring arm could mis-classify a non-login
        # redirect that merely EMBEDS the attested login url (an open-redirect to ``evil?next=.../login``) as a
        # denial. A real "unauthenticated => redirect to login" gate puts the login url at the START of Location
        # (optionally with a ``?return=`` suffix), which startswith captures; a login url buried mid-string is not.
        if any(loc and location.startswith(loc) for loc in login_locations):
            return True
    if body_sig and (body_sig in body or (bool(header_blob) and body_sig in header_blob)):
        return True
    return False


def credential_acceptance_oracle(observed: Any) -> OracleSignal:
    """Fire when a target's auth ACCEPTED a credential the operator-planted TEST policy marks
    should-be-REJECTED, proven by an UNFORGEABLE ACHIEVED EFFECT: the weak-credential session SUCCESSFULLY
    ACCESSES an AUTHENTICATED PROTECTED RESOURCE that a KNOWN-BAD (or no) session is DENIED. The discriminator is
    the PROTECTED-RESOURCE ACCESS OUTCOME, re-derived offline from the retained record — NEVER the login response
    (three prior login-byte-marker versions failed the red-pen). Pure + offline-re-derivable.

    Expected ``observed`` mapping::

        {
          "corpus_id":     "<operator-planted test-identity corpus id>",   # REQUIRED — refuse without it
          "credential_id": "<identifier of the attempted WEAK credential>",# an IDENTIFIER, never the secret
          "policy": {
            "corpus_id":     "<must equal the record's corpus_id>",        # the corpus binds itself
            "should_reject": ["<cred id>", ...]                            # the planted must-be-REJECTED set
          },
          "protected_resource": {                                          # the operator-attested descriptor
            "url":    "<the auth-gated protected resource url>",           # REQUIRED — refuse without it
            "method": "GET",                                              # optional (default GET)
            "authenticated_signal": "<text present ONLY in an authenticated view>",  # REQUIRED
            # how the resource DENIES unauthenticated access (401/403 always apply):
            "denial_statuses":          [401, 403],                        # optional (added to the default set)
            "login_redirect_locations": ["https://app/login", "https://sso/..."],   # optional
            "denial_body_signature":    "<attested denial-body text>"      # optional
          },
          # the SAME protected-resource request (same url+method), differing ONLY in the session:
          "weak_access":     {"status": <int>, "body": "...", "headers": {...}, "url": "...", "method": "GET"},
          "baseline_access": {"status": <int>, "body": "...", "headers": {...}, "url": "...", "method": "GET"}
        }

    REFUSES (a non-fire, never a raise) when there is nothing it may soundly judge:
      * no mapping / no ``corpus_id`` — no planted corpus;
      * no ``policy`` mapping, or ``policy['corpus_id']`` != the record's ``corpus_id`` — the corpus does not bind;
      * an empty / missing ``should_reject`` set, or no ``credential_id``;
      * no ``protected_resource`` descriptor, or it carries no ``url`` or no ``authenticated_signal`` — without the
        attestation a bare 2xx is not acceptance;
      * no ``weak_access`` / ``baseline_access`` capture, or a leg captured nothing;
      * the two legs are NOT same-shape — a leg's provenance (url/method) is missing or does not equal the attested
        resource (not the SAME protected-resource request); or
      * ``baseline_access`` is NOT a denial — the resource is not auth-gating (it serves the known-bad/no session
        too), so there is no differential.

    LEAD (a non-fire that is NOT a sound negative — just undecidable from this input):
      * a short / low-entropy ``authenticated_signal`` cannot reliably tell an authenticated view from an inlined
        login page — downgraded to a LEAD, never a FACT;
      * the ``authenticated_signal`` appears in BOTH legs — a coincidental substring, not a differential.

    NON-FIRE (safe) — a sound judgement that did NOT confirm acceptance:
      * the attempted ``credential_id`` is NOT in ``should_reject`` (not a planted weak credential); or
      * ``weak_access`` is itself a DENIAL — the weak credential yielded no session (a rejecting login), so the
        target DENIED it the SAME protected resource as the baseline; or
      * ``weak_access`` is not a 2xx authenticated success carrying the attested signal (the weak session did not
        reach an authenticated view of the resource).

    FIRES (ACCEPTED) IFF the legs are same-shape AND ``baseline_access`` is denied AND ``weak_access`` is an
    authenticated success (2xx + the attested signal, absent from the denied baseline): the weak-credential
    session reached an authenticated state the denied session could not.
    """
    if not isinstance(observed, Mapping):
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="no credential-acceptance evidence")
    corpus_id = _coerce_text(observed.get("corpus_id")).strip()
    if not corpus_id:
        # HARD PRECONDITION: without the operator-planted TEST corpus there is no sound FACT — REFUSE.
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="REFUSED: no operator-planted test-identity corpus (corpus_id absent) — "
                                     "a credential-acceptance FACT requires the planted TEST corpus; this is a "
                                     "LEAD/INCONCLUSIVE, never a FACT")
    policy = observed.get("policy")
    if not isinstance(policy, Mapping):
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="REFUSED: no planted policy (policy absent) — nothing marks a credential "
                                     "should-be-rejected")
    policy_corpus = _coerce_text(policy.get("corpus_id")).strip()
    if policy_corpus != corpus_id:
        # The planted corpus must bind itself: a policy that does not name THIS corpus cannot authorise a verdict
        # over this record (defeats re-aiming a policy at an unrelated capture — the relabelled-certificate case).
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="REFUSED: the planted policy's corpus_id does not bind this record's "
                                     "corpus_id — the planted corpus does not authorise this capture")
    should_reject = policy.get("should_reject")
    reject_set = {_coerce_text(c).strip() for c in should_reject if _coerce_text(c).strip()} \
        if isinstance(should_reject, (list, tuple, set, frozenset)) else set()
    if not reject_set:
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="REFUSED: the planted policy carries no should_reject set — no credential "
                                     "is marked should-be-rejected, so nothing can be judged")
    credential_id = _coerce_text(observed.get("credential_id")).strip()
    if not credential_id:
        return OracleSignal(kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
                            evidence="REFUSED: no credential_id on the record — nothing to test for membership")

    base_obs = {
        "corpus_id": corpus_id,
        "credential_id": credential_id,
        "credential_in_should_reject": credential_id in reject_set,
    }
    if credential_id not in reject_set:
        # SAFE / sound non-fire: the attempted credential is not a planted must-be-rejected one. (Could be a
        # legitimate credential; this oracle only speaks to planted weak credentials.)
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=(f"credential {credential_id!r} is not in the planted should-be-rejected set — the oracle "
                      "only confirms acceptance of a planted weak credential"),
            observed=base_obs)

    # HARD PRECONDITION — the operator-attested PROTECTED-RESOURCE descriptor. Acceptance is an achieved READ of
    # an auth-gated resource, so without the descriptor (its url + the authenticated_signal) a bare 2xx is not
    # acceptance => REFUSE (a LEAD/INCONCLUSIVE, never a FACT).
    descriptor = observed.get("protected_resource")
    if not isinstance(descriptor, Mapping):
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: no protected-resource attestation (protected_resource absent) — acceptance is an "
                      "ACHIEVED read of an auth-gated resource; without the descriptor this is a LEAD, never a FACT"),
            observed=base_obs)
    resource_url = _coerce_text(descriptor.get("url")).strip()
    if not resource_url:
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: the protected-resource descriptor carries no url — the attested auth-gated "
                      "resource is unidentified, so the SAME-SHAPE access differential cannot be established"),
            observed=base_obs)
    authed_signal = _coerce_text(descriptor.get("authenticated_signal"))
    if not authed_signal.strip():
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: the protected-resource descriptor carries no authenticated_signal — a bare 2xx "
                      "is not acceptance; the operator-attested signal that marks a genuinely authenticated view "
                      "is required to tell an authenticated read from an inlined login page"),
            observed=base_obs)
    resource_method = (_coerce_text(descriptor.get("method")).strip().upper() or "GET")
    base_obs = {**base_obs, "resource_url": resource_url, "resource_method": resource_method}

    # The authenticated-content-signal discriminator floor (the smuggling-canary treatment). A too-short /
    # low-entropy signal cannot reliably tell an authenticated view from an inlined login page (a coincidental
    # substring could manufacture an authenticated-looking read) — so it is a LEAD, never a FACT.
    signal = authed_signal.strip()
    signal_entropy = _shannon_bits_per_char(signal)
    if len(signal) < _CRED_SIGNAL_MIN_LEN or signal_entropy < _CRED_SIGNAL_MIN_ENTROPY:
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=(f"LEAD: the attested authenticated_signal is too weak to be a reliable discriminator "
                      f"(needs >= {_CRED_SIGNAL_MIN_LEN} chars AND >= {_CRED_SIGNAL_MIN_ENTROPY} bits/char; got "
                      f"{len(signal)} chars, {signal_entropy:.2f} bits/char) — a coincidental substring could "
                      "manufacture an authenticated-looking read, so this is a LEAD, never a FACT"),
            observed={**base_obs, "signal_len": len(signal),
                      "signal_entropy_bits_per_char": round(signal_entropy, 3)})

    # HARD PRECONDITION — both captured PROTECTED-RESOURCE reads. The differential is over the SAME resource
    # request with the weak session vs a known-bad/no session; without BOTH legs there is nothing to adjudicate.
    weak_resp = observed.get("weak_access")
    baseline_resp = observed.get("baseline_access")
    if not isinstance(weak_resp, (Mapping, str, bytes)) or not isinstance(baseline_resp, (Mapping, str, bytes)):
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: a protected-resource access capture is missing (need BOTH weak_access AND "
                      "baseline_access) — the achieved-access differential cannot be adjudicated, a LEAD never "
                      "a FACT"),
            observed=base_obs)

    weak_status, weak_body, weak_hdr, weak_loc, weak_url, weak_method = _cred_access_fields(weak_resp)
    base_status, base_body, base_hdr, base_loc, base_url, base_method = _cred_access_fields(baseline_resp)
    if not _cred_leg_has_capture(weak_status, weak_body, weak_hdr) \
            or not _cred_leg_has_capture(base_status, base_body, base_hdr):
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: a protected-resource access leg captured no response (no status, no body, no "
                      "headers) — there is no sound differential to adjudicate"),
            observed=base_obs)

    # (1) SAME-SHAPE — both legs must be reads of the SAME attested resource url with the SAME method, differing
    # ONLY in the session. Missing provenance or a mismatch is not a differential => REFUSE (this disarms the
    # mis-shaped / different-endpoint baseline red-pen shape — the legs must be the SAME request).
    weak_m = weak_method or resource_method
    base_m = base_method or resource_method
    same_shape = (weak_url == resource_url and base_url == resource_url
                  and weak_m == resource_method and base_m == resource_method)
    shape_obs = {"weak_url": weak_url, "baseline_url": base_url, "weak_method": weak_m,
                 "baseline_method": base_m, "same_shape": same_shape}
    if not same_shape:
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=("REFUSED: the two protected-resource legs are NOT the same request — weak_access "
                      f"({weak_m or '?'} {weak_url!r}) and baseline_access ({base_m or '?'} {base_url!r}) must "
                      f"both read the attested resource ({resource_method} {resource_url!r}), differing ONLY in "
                      "the session; a mis-shaped / different-endpoint / provenance-less leg is not a differential"),
            observed={**base_obs, **shape_obs})

    denial_statuses, login_locations, body_sig = _cred_descriptor_denial_model(descriptor)
    weak_denial = _cred_access_is_denial(weak_status, weak_body, weak_hdr, weak_loc,
                                         denial_statuses, login_locations, body_sig)
    base_denial = _cred_access_is_denial(base_status, base_body, base_hdr, base_loc,
                                         denial_statuses, login_locations, body_sig)
    outcome_obs = {**base_obs, **shape_obs, "weak_status": weak_status, "baseline_status": base_status,
                   "baseline_is_denial": base_denial, "weak_is_denial": weak_denial}

    # (2) BASELINE DENIED — the known-bad/no session MUST be DENIED the resource, else it is not auth-gating and
    # there is no differential (a resource that serves everyone proves nothing) => REFUSE.
    if not base_denial:
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
            evidence=(f"REFUSED: baseline_access is NOT a denial (status {base_status}) — the known-bad/no "
                      "session was SERVED the resource, so it is not actually auth-gating; without a denied "
                      "baseline there is no differential (a resource that serves everyone proves nothing), a "
                      "LEAD never a FACT"),
            observed=outcome_obs)

    # (3) WEAK AUTHENTICATED — weak_access must be a 2xx authenticated SUCCESS carrying the attested signal, which
    # must be ABSENT from the denied baseline (a TRUE differential, not a coincidental substring present on both
    # legs). A rejecting login makes weak_access itself a denial => (3) fails => NO fire (the SAFE negative).
    signal_in_weak = (signal in weak_body) or (bool(weak_hdr) and signal in weak_hdr)
    signal_in_base = (signal in base_body) or (bool(base_hdr) and signal in base_hdr)
    weak_2xx = weak_status is not None and 200 <= weak_status < 300
    weak_authenticated = weak_2xx and (not weak_denial) and signal_in_weak and (not signal_in_base)
    fire_obs = {**outcome_obs, "weak_is_2xx": weak_2xx, "signal_in_weak": signal_in_weak,
                "signal_in_baseline": signal_in_base, "weak_is_authenticated_success": weak_authenticated}

    # (4) FIRE — the weak-credential session reached an authenticated state the denied session could not.
    if weak_authenticated:
        return OracleSignal(
            kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=True, confidence=0.95,
            evidence=(f"the target auth ACCEPTED credential {credential_id!r}, which the operator-planted TEST "
                      f"policy for corpus {corpus_id!r} marks should-be-REJECTED — ACHIEVED STATE: the weak-"
                      f"credential session SUCCESSFULLY read the auth-gated resource {resource_method} "
                      f"{resource_url!r} (a 2xx carrying the attested authenticated signal) while a known-bad/no "
                      f"session was DENIED the SAME request (baseline status {base_status}). The weak session "
                      "reached an authenticated state the denied session could not; a planted TEST identity, "
                      "no real-user secret is read or retained."),
            observed=fire_obs)

    if weak_denial:
        reason = ("weak_access is itself a DENIAL — the weak credential yielded no session (a rejecting login), "
                  "so the target DENIED it the SAME protected resource as the known-bad/no baseline; the "
                  "credential was NOT accepted (the SAFE negative)")
    elif not weak_2xx:
        reason = (f"weak_access is not a 2xx authenticated success (status {weak_status}) — the weak session did "
                  "not reach an authenticated read of the protected resource; did not fire")
    elif not signal_in_weak:
        reason = ("the attested authenticated_signal is ABSENT from weak_access — a 2xx that is not an "
                  "authenticated view (e.g. an inlined login page); the weak session did not reach an "
                  "authenticated state; did not fire")
    else:  # signal_in_base
        reason = ("the attested authenticated_signal appears in BOTH the weak read AND the denied baseline — a "
                  "coincidental substring that CANCELS (not a differential); did not fire (a LEAD, never a FACT)")
    return OracleSignal(
        kind=OracleKind.CREDENTIAL_ACCEPTANCE, fired=False, confidence=0.0,
        evidence=reason, observed=fire_obs)


# --- G1: A-prime family re-fire closures (mirror verifier._run's per-kind ctx-key dispatch) -------
def _gen_service_reachability(ctx: Mapping) -> "OracleSignal | None":
    if "handshake" in ctx:
        return service_reachability_oracle(ctx["handshake"])
    return None


def _gen_active_exposure(ctx: Mapping) -> "OracleSignal | None":
    if "anon_get" in ctx:
        return anonymous_reachable_oracle(ctx["anon_get"])
    return None


def _gen_tls_live(ctx: Mapping) -> "OracleSignal | None":
    # The LIVE tls handshake path (``tls`` key) — re-executed over the RETAINED handshake record (the
    # socket ran at capture time; here we only re-read its retained negotiated protocol/cipher). The
    # crypto_artifact path is handled by _gen_weak_crypto; both stamp OracleKind.TLS_WEAKNESS.
    if "tls" in ctx:
        return tls_weakness_oracle(ctx["tls"])
    return None


def _gen_certificate_validity(ctx: Mapping) -> "OracleSignal | None":
    if "cert_validity" in ctx:
        return certificate_validity_oracle(ctx["cert_validity"])
    return None


def _gen_credential_acceptance(ctx: Mapping) -> "OracleSignal | None":
    if "credential_acceptance" in ctx:
        return credential_acceptance_oracle(ctx["credential_acceptance"])
    return None


def _gen_automated_access(ctx: Mapping) -> "OracleSignal | None":
    if "requested_path" in ctx and "honeypot_paths" in ctx:
        return honeypot_hit_oracle(
            ctx["requested_path"], ctx["honeypot_paths"],
            crawler_allowlisted=bool(ctx.get("crawler_allowlisted", False)))
    return None


def _gen_credential_stuffing(ctx: Mapping) -> "OracleSignal | None":
    if "auth_events" in ctx:
        return credential_stuffing_oracle(
            ctx["auth_events"], benign_sources=ctx.get("benign_sources"),
            **{k: ctx[f"credstuff_{k}"] for k in ("alpha", "beta", "p1", "p0", "fwer")
               if f"credstuff_{k}" in ctx})
    return None


def _gen_dom_execution(ctx: Mapping) -> "OracleSignal | None":
    # Mirrors verifier._run's DOM_EXECUTION guard: a retained ENFORCED blocking CSP (csp_block_control)
    # routes to the csp_bypass oracle; a csp_bypass finding with NO blocking control fails closed
    # (``_require_csp_block_control``), never falling through to plain dom_execution; otherwise plain
    # DOM-XSS.
    if "dom_binding_calls" in ctx and "dom_canary" in ctx:
        if "csp_block_control" in ctx:
            return dom_execution_csp_bypass_oracle(
                ctx["dom_binding_calls"], ctx["dom_canary"], ctx["csp_block_control"])
        if ctx.get("_require_csp_block_control"):
            return None
        return dom_execution_oracle(ctx["dom_binding_calls"], ctx["dom_canary"])
    return None


def _gen_csp_posture(ctx: Mapping) -> "OracleSignal | None":
    if "csp_control" in ctx:
        return csp_posture_oracle(ctx["csp_control"])
    return None


def _gen_mobile_posture(ctx: Mapping) -> "OracleSignal | None":
    if "mobile_control" in ctx:
        return mobile_posture_oracle(ctx["mobile_control"])
    return None


def _gen_email_auth_posture(ctx: Mapping) -> "OracleSignal | None":
    if "email_auth_control" in ctx:
        return email_auth_posture_oracle(ctx["email_auth_control"])
    return None


def _gen_identity_posture(ctx: Mapping) -> "OracleSignal | None":
    if "identity_control" in ctx:
        return identity_posture_oracle(ctx["identity_control"])
    return None


def _gen_sso_jwt(ctx: Mapping) -> "OracleSignal | None":
    # Only the jwt HS/structural path is ported here; the SAML path (saml_xml -> signxml/lxml) is
    # IRREDUCIBLE and reported via _GENERAL_UNPORTED_CONTEXT_KEYS.
    if "jwt_token" in ctx:
        return jwt_forgery_oracle(ctx["jwt_token"], candidate_keys=ctx.get("jwt_candidate_keys", ()))
    return None


def _gen_imds(ctx: Mapping) -> "OracleSignal | None":
    if "imds_capture" in ctx:
        return imds_credential_capture_oracle(ctx["imds_capture"])
    return None


def _gen_secret_validity(ctx: Mapping) -> "OracleSignal | None":
    if "secret_capture" in ctx:
        return exposed_secret_validity_oracle(ctx["secret_capture"])
    return None


def _gen_gcp_impersonation(ctx: Mapping) -> "OracleSignal | None":
    if "gcp_impersonation_capture" in ctx:
        return gcp_sa_impersonation_oracle(ctx["gcp_impersonation_capture"])
    return None


def _gen_iam_escalation(ctx: Mapping) -> "OracleSignal | None":
    if "iam_escalation_capture" in ctx:
        return iam_escalation_oracle(ctx["iam_escalation_capture"])
    return None


def _gen_k8s_rbac(ctx: Mapping) -> "OracleSignal | None":
    if "k8s_rbac_grant_control" in ctx:
        return k8s_rbac_verb_grant_oracle(ctx["k8s_rbac_grant_control"])
    return None


def _gen_clickjacking(ctx: Mapping) -> "OracleSignal | None":
    if "clickjacking_control" in ctx:
        return clickjacking_posture_oracle(ctx["clickjacking_control"])
    return None


def _gen_csrf_posture(ctx: Mapping) -> "OracleSignal | None":
    if "csrf_control" in ctx:
        return csrf_posture_oracle(ctx["csrf_control"])
    return None


def _gen_postmessage(ctx: Mapping) -> "OracleSignal | None":
    if "postmessage_control" in ctx:
        return postmessage_posture_oracle(ctx["postmessage_control"])
    return None


def _gen_static_rule(ctx: Mapping) -> "OracleSignal | None":
    # NOTE: the in-tree verifier.confirm applies an ADDITIONAL anti-relabel gate for STATIC_RULE (it
    # only confirms when the retained rule_id derives EXACTLY the claimed bug_class). That gate is the
    # verifier's mint-choke, not re-derived by this any-high-confidence-fire combine; the standalone
    # re-derivation proves only that the retained source region re-parses to the code property.
    if "static_rule" in ctx:
        return static_rule_oracle(ctx["static_rule"])
    return None


def _gen_session_fixation(ctx: Mapping) -> "OracleSignal | None":
    if "session_fixation" in ctx:
        return session_fixation_oracle(ctx["session_fixation"])
    return None


def _gen_mfa_bypass(ctx: Mapping) -> "OracleSignal | None":
    if "mfa_bypass" in ctx:
        return mfa_bypass_oracle(ctx["mfa_bypass"])
    return None


def _gen_password_reset(ctx: Mapping) -> "OracleSignal | None":
    if "password_reset_invariant" in ctx:
        return password_reset_invariant_oracle(ctx["password_reset_invariant"])
    return None


def _gen_csrf_achieved(ctx: Mapping) -> "OracleSignal | None":
    if "csrf_achieved" in ctx:
        return csrf_achieved_oracle(ctx["csrf_achieved"])
    return None


def _gen_workflow_abuse(ctx: Mapping) -> "OracleSignal | None":
    if "workflow_abuse" in ctx:
        return workflow_abuse_oracle(ctx["workflow_abuse"])
    return None


# (ctx-key predicate, re-fire closure, kind label). One entry per ported OracleKind, in the same
# order verifier._run checks them. Each closure takes the whole verifier-context and returns an
# ``OracleSignal`` (or ``None`` when the keys are present but the AUTHORITY refuses, e.g. a
# request_smuggling baseline/mutated pair). ``reexecute_general_oracle`` runs every ported oracle
# whose keys are present and combines exactly as verifier.confirm does (any high-confidence fire).
def _gen_differential(ctx: Mapping) -> "OracleSignal | None":
    if "smuggling_desync" in ctx:
        return smuggling_desync_oracle(ctx["smuggling_desync"])
    if "baseline" in ctx and "mutated" in ctx:
        if _general_normalize_bug_class(ctx.get("bug_class", "")) in _GENERAL_DIFFERENTIAL_BASELINE_REFUSED:
            return None
        return differential_response_oracle(ctx["baseline"], ctx["mutated"],
                                            _general_differential_discriminator())
    return None


def _gen_timing(ctx: Mapping) -> "OracleSignal | None":
    if "baseline_latencies" in ctx and "treatment_latencies" in ctx:
        return timing_oracle(ctx["baseline_latencies"], ctx["treatment_latencies"],
                             injected_ms=ctx.get("timing_injected_ms"),
                             alpha=_GENERAL_TIMING_PROTOCOL_ALPHA, dose=ctx.get("timing_dose"))
    return None


def _gen_boolean(ctx: Mapping) -> "OracleSignal | None":
    if "probe_rounds" in ctx:
        return boolean_inference_oracle(ctx["probe_rounds"],
                                        false_baseline_samples=ctx.get("false_baseline_samples"))
    return None


def _gen_side_effect(ctx: Mapping) -> "OracleSignal | None":
    if "marker" in ctx and "observed_sink" in ctx:
        return side_effect_oracle(ctx["marker"], ctx["observed_sink"], ctx.get("observed_sink_control"))
    return None


def _gen_reflection(ctx: Mapping) -> "OracleSignal | None":
    if "marker" in ctx and "observed_sink" in ctx:
        return reflection_context_oracle(ctx["marker"], ctx["observed_sink"])
    return None


def _gen_evaluation(ctx: Mapping) -> "OracleSignal | None":
    if "ssi_expected" in ctx and "ssi_observed" in ctx:
        return ssi_evaluation_oracle(ctx.get("ssi_raw", ""), ctx["ssi_expected"],
                                     ctx["ssi_observed"], ctx.get("ssi_control"))
    if "eval_expected" in ctx and "eval_observed" in ctx:
        return evaluation_oracle(ctx.get("eval_raw", ""), ctx["eval_expected"],
                                 ctx["eval_observed"], ctx.get("eval_control"))
    return None


def _gen_error_signature(ctx: Mapping) -> "OracleSignal | None":
    if "error_observed" in ctx:
        return error_signature_oracle(ctx["error_observed"], ctx.get("error_control"))
    return None


def _gen_sanitizer(ctx: Mapping) -> "OracleSignal | None":
    if "process_output" in ctx:
        return sanitizer_signal_oracle(ctx["process_output"])
    return None


def _gen_system_prompt_disclosure(ctx: Mapping) -> "OracleSignal | None":
    if "canary" in ctx and "llm_output" in ctx:
        return system_prompt_disclosure_oracle(ctx["canary"], ctx["llm_output"])
    return None


def _gen_prompt_injection(ctx: Mapping) -> "OracleSignal | None":
    if "pi_control" in ctx and "pi_treatment" in ctx:
        return prompt_injection_oracle(ctx["pi_control"], ctx["pi_treatment"])
    return None


def _gen_sql_breakout(ctx: Mapping) -> "OracleSignal | None":
    if "request_payload" in ctx:
        return sql_injection_breakout_oracle(ctx["request_payload"], param=str(ctx.get("payload_param", "")))
    return None


def _gen_command_breakout(ctx: Mapping) -> "OracleSignal | None":
    if "request_payload" in ctx:
        return command_injection_breakout_oracle(ctx["request_payload"], param=str(ctx.get("payload_param", "")))
    return None


def _gen_nosql_breakout(ctx: Mapping) -> "OracleSignal | None":
    if "request_payload" in ctx:
        return nosql_injection_breakout_oracle(ctx["request_payload"], param=str(ctx.get("payload_param", "")))
    return None


def _gen_weak_crypto(ctx: Mapping) -> "OracleSignal | None":
    if "crypto_artifact" in ctx:
        return weak_crypto_artifact_oracle(ctx["crypto_artifact"])
    return None


def _gen_prototype_pollution(ctx: Mapping) -> "OracleSignal | None":
    if "proto_pollution" in ctx:
        return prototype_pollution_oracle(ctx["proto_pollution"])
    return None


# One entry per ported family (kind label -> re-fire closure). The breakout entries dispatch on the
# SAME ``request_payload`` key but are mutually exclusive by the finding's bug_class in-tree; a
# retained context carries at most one request-payload oracle's finding, so running the matching one
# is faithful — the dispatch keys the breakout on the declared class to avoid re-firing all three.
_GENERAL_ORACLE_DISPATCH: tuple = (
    ("differential_response", _gen_differential),
    ("timing", _gen_timing),
    ("boolean_inference", _gen_boolean),
    ("side_effect", _gen_side_effect),
    ("reflection_context", _gen_reflection),
    ("evaluation", _gen_evaluation),
    ("error_signature", _gen_error_signature),
    ("sanitizer_signal", _gen_sanitizer),
    ("system_prompt_disclosure", _gen_system_prompt_disclosure),
    ("prompt_injection", _gen_prompt_injection),
    ("prototype_pollution", _gen_prototype_pollution),
    # --- G1 A-prime families (same per-kind ctx-key dispatch verifier._run uses) ---
    ("service_reachability", _gen_service_reachability),
    ("active_exposure", _gen_active_exposure),
    ("tls_weakness", _gen_tls_live),
    ("certificate_validity", _gen_certificate_validity),
    ("credential_acceptance", _gen_credential_acceptance),
    ("automated_access", _gen_automated_access),
    ("credential_stuffing", _gen_credential_stuffing),
    ("dom_execution", _gen_dom_execution),
    ("csp_posture", _gen_csp_posture),
    ("mobile_posture", _gen_mobile_posture),
    ("email_auth_posture", _gen_email_auth_posture),
    ("identity_posture", _gen_identity_posture),
    ("sso_assertion_forgery", _gen_sso_jwt),
    ("imds_credential_capture", _gen_imds),
    ("secret_credential_validity", _gen_secret_validity),
    ("gcp_sa_impersonation", _gen_gcp_impersonation),
    ("iam_escalation_primitive", _gen_iam_escalation),
    ("k8s_rbac_verb_grant", _gen_k8s_rbac),
    ("clickjacking_posture", _gen_clickjacking),
    ("csrf_posture", _gen_csrf_posture),
    ("postmessage_posture", _gen_postmessage),
    ("static_rule", _gen_static_rule),
    ("session_fixation", _gen_session_fixation),
    ("mfa_bypass", _gen_mfa_bypass),
    ("password_reset_invariant", _gen_password_reset),
    ("achieved_state", _gen_csrf_achieved),
    ("achieved_state", _gen_workflow_abuse),
)
# request_payload breakout families, keyed on the declared bug_class so only the matching parse-proof
# oracle re-fires (mirrors verifier._run, where the class selects exactly one breakout kind).
_GENERAL_BREAKOUT_BY_CLASS: dict = {
    "sqli_attempt": ("sql_injection_breakout", _gen_sql_breakout),
    "command_injection_attempt": ("command_injection_breakout", _gen_command_breakout),
    "nosql_injection_attempt": ("nosql_injection_breakout", _gen_nosql_breakout),
}
# TLS_WEAKNESS kind is shared: the LIVE tls handshake path (tls key) is IRREDUCIBLE and NOT ported;
# only the PURE weak-crypto-artifact path (crypto_artifact key) is re-derived here.
_GENERAL_WEAK_CRYPTO = ("tls_weakness", _gen_weak_crypto)


def reexecute_general_oracle(oracle_context: Any) -> dict:
    """VIGIL-FREE re-execution of a general FACT's retained ``oracle_context`` (Step 2 of the audit
    package for the PURE, stdlib-only oracle families). Re-fires every PORTED oracle whose retained
    keys are present and reproduces the in-tree ``verifier.confirm`` combine (any high-confidence
    fire) over the ported signals.

    Returns ``{"signals": [{kind, fired, conclusive, confidence}, ...], "fired": bool,
    "reproduced": bool, "unported_keys": [...]}`` where ``fired`` is the re-derived positive verdict
    (a ported oracle fired at or above the confirm threshold) and ``reproduced`` is True iff at least
    one ported oracle had keys present to re-fire. ``unported_keys`` names any IRREDUCIBLE oracle key
    present in the context whose re-execution this file cannot perform standalone (so the caller is
    told, honestly, that the FACT also rests on an in-VIGIL re-run — never that it was reproduced).

    HONEST BOUND: re-firing proves the verdict is the correct FUNCTION of the retained evidence, NOT
    that the evidence is live. See the section header."""
    if not isinstance(oracle_context, Mapping):
        return {"signals": [], "fired": False, "reproduced": False, "unported_keys": []}
    ctx = oracle_context
    bug_class = _general_normalize_bug_class(ctx.get("bug_class", ""))
    signals: list = []

    def _record(kind: str, sig: "OracleSignal | None") -> None:
        if sig is not None:
            signals.append({"kind": kind, "fired": bool(sig.fired), "conclusive": bool(sig.conclusive),
                            "confidence": float(sig.confidence)})

    for kind, fn in _GENERAL_ORACLE_DISPATCH:
        _record(kind, fn(ctx))
    # the request_payload breakout — only the family the declared class selects (faithful to _run)
    if "request_payload" in ctx:
        entry = _GENERAL_BREAKOUT_BY_CLASS.get(bug_class)
        if entry is not None:
            kind, fn = entry
            _record(kind, fn(ctx))
    _record(*(_GENERAL_WEAK_CRYPTO[0], _GENERAL_WEAK_CRYPTO[1](ctx)))

    # Oracle keys present but NOT re-derived standalone HERE (a genuinely-irreducible oracle, or a
    # pure-but-not-yet-ported one) — REPORT them so the caller is told the FACT also rests on an
    # in-VIGIL re-run; never fake them as reproduced.
    unported = [k for k in _GENERAL_UNPORTED_CONTEXT_KEYS if k in ctx]
    fired = any(s["fired"] and s["confidence"] >= _GENERAL_HIGH_CONFIDENCE for s in signals)
    return {"signals": signals, "fired": fired, "reproduced": bool(signals), "unported_keys": unported}


# The oracle_context keys whose oracle this file does NOT re-derive standalone — either genuinely
# IRREDUCIBLE (version_advisory -> packaging, saml_xml -> signxml/lxml, oob_hits -> external collector)
# or PURE-BUT-NOT-YET-PORTED (the live-capture / browser / subprocess / cloud-API families; re-fireable
# with stdlib+cryptography, port is follow-up). Presence is REPORTED by reexecute_general_oracle, never
# re-derived here — see LIMIT-audit-package-reproduction + test_bucket_classification_is_enforced.
_GENERAL_UNPORTED_CONTEXT_KEYS = frozenset({
    # The ONLY three general oracles whose re-fire import-closure needs a module OUTSIDE
    # stdlib+cryptography (enforced by test_bucket_classification_is_enforced): version_advisory ->
    # packaging; saml_xml -> signxml/lxml; oob_hits -> the framework collector-receipt crypto backing
    # an EXTERNAL out-of-band collector. Every other formerly-deferred A-prime key is now re-derived
    # standalone by the closures above. Presence of one of these is REPORTED (never faked reproduced).
    "oob_hits", "version_advisory", "saml_xml",
})

# ---------------------------------------------------------------------------
# 9. Authority-Envelope certificate (the accountability twin) — standalone, VIGIL-free.
#    Re-checks: the m-of-n governance signature + the out-of-band pin; the owner-signed envelope; and
#    re-derives CONFORMANCE (every EXECUTED action inside the envelope) — a forged "conformant" verdict,
#    or an executed action that left the envelope, is refused. Mirrors posture.authority byte-for-byte.
# ---------------------------------------------------------------------------
_AUTH_ENVELOPE_DOMAIN = b"vigil-authority-envelope-v1\x00"


def _auth_envelope_core(env: dict) -> dict:
    return {
        "schema_version": env.get("schema_version", 1),
        "owner_pubkey": env.get("owner_pubkey"),
        "engagement": env.get("engagement"),
        "scope_hosts": sorted(str(h) for h in (env.get("scope_hosts") or [])),
        "action_allowlist": sorted(str(a) for a in (env.get("action_allowlist") or [])),
        "not_before": int(env.get("not_before", 0)),
        "not_after": int(env.get("not_after", 0)),
    }


def _verify_auth_envelope(env: dict, owner_pubkey: str, engagement: str) -> tuple[bool, str]:
    if not isinstance(env, dict) or env.get("owner_pubkey") != owner_pubkey:
        return False, "authority envelope is not by the pinned owner key"
    if env.get("engagement") != engagement:
        return False, f"envelope engagement {env.get('engagement')!r} != required {engagement!r}"
    sig = env.get("sig")
    if not sig or not verify_one(str(owner_pubkey), _AUTH_ENVELOPE_DOMAIN + canonical_json(_auth_envelope_core(env)), str(sig)):
        return False, "authority envelope signature does not verify against the owner key"
    return True, "envelope OK"


def _auth_host(target: str) -> str:
    return urlsplit(str(target)).hostname or (str(target) or "")


def _derive_conformance(env: dict, actions: list) -> dict:
    scope = set(env.get("scope_hosts") or [])
    allow = set(env.get("action_allowlist") or [])
    nb, na = int(env.get("not_before", 0)), int(env.get("not_after", 0))
    violations, n_exec = [], 0
    for a in actions:
        executed = bool(a.get("executed")) or str(a.get("gate_outcome", "")).lower() in ("allow", "auto", "executed")
        if not executed:
            continue
        n_exec += 1
        reasons = []
        if _auth_host(a.get("target", "")) not in scope:
            reasons.append("target out of scope")
        if str(a.get("action_kind", "")) not in allow:
            reasons.append("action kind not permitted")
        at = int(a.get("at", 0))
        if na and not (nb <= at <= na):
            reasons.append("outside the authority window")
        if reasons:
            violations.append({"seq": a.get("seq"), "action_kind": a.get("action_kind"),
                               "target": a.get("target"), "reasons": reasons})
    return {"conformant": not violations, "violations": violations,
            "n_actions": len(actions), "n_executed": n_exec}


def verify_authority(authority: dict, *, pin: str, owner_pubkey: str, engagement: str) -> tuple[bool, str]:
    """Standalone-verify an Authority-Envelope certificate. ``authority`` = {"certificate": {...},
    "signature": {...}}. Fail-closed: pin, m-of-n signature, owner envelope, re-derived conformance."""
    cert = authority.get("certificate") or {}
    sig_env = authority.get("signature") or {}
    tr = sig_env.get("trust_root") or {}
    fp = _authorizer_fingerprint(tr.get("authorizers") or [])
    pin_s = (pin or "").strip()
    if not pin_s:
        return False, f"UNPINNED — supply the out-of-band authority fingerprint ({fp})"
    want = pin_s if pin_s.startswith("sha256:") else ("sha256:" + pin_s)
    if want.lower() != fp.lower():
        return False, f"authority trust-root pin MISMATCH — expected {want}, got {fp}"
    msg = canonical_json(cert)
    if sig_env.get("scorecard_digest") is not None and sig_env.get("scorecard_digest") != "sha256:" + sha256_hex(msg):
        return False, "authority certificate digest does not match the canonical bytes"
    ok, _valid, reason = verify_threshold(msg, sig_env.get("signatures") or [], tr)
    if not ok:
        return False, f"authority signature: {reason}"
    eok, ereason = _verify_auth_envelope(cert.get("envelope") or {}, owner_pubkey, engagement)
    if not eok:
        return False, f"authority envelope: {ereason}"
    rederived = _derive_conformance(cert.get("envelope") or {}, cert.get("actions") or [])
    if rederived != cert.get("conformance"):
        return False, "conformance does not match the re-derivation from the recorded ledger"
    if not rederived["conformant"]:
        return False, f"NON-CONFORMANT: {len(rederived['violations'])} executed action(s) left the envelope"
    return True, (f"SOUND: {rederived['n_executed']}/{rederived['n_actions']} executed action(s) all inside "
                  f"the owner-signed authority envelope (conformance over the recorded ledger)")


def verify_bundle(bundle: dict, *, signer_pubkeys: Optional[dict] = None,
                  trust_root: Optional[dict] = None, witness_trust_root: Optional[dict] = None,
                  pin: str = "", witness_pin: str = "",
                  min_distinct_signers: Optional[int] = None,
                  tsa_cert_pin: Optional[str] = None,
                  notary_pin: str = "",
                  posture_pin: str = "", posture_owner_pubkey: str = "",
                  posture_engagement: str = "", posture_now: Optional[int] = None,
                  authority_pin: str = "", authority_owner_pubkey: str = "",
                  authority_engagement: str = "") -> tuple[bool, list]:
    """Verify every component present in ``bundle`` against the out-of-band-pinned trust material. Returns
    (sound, log_lines). ``sound`` is True iff at least one component is present and EVERY present component
    is SOUND. A component whose required trust material is missing is a NOT-SOUND (fail-closed)."""
    log: list[str] = []
    results: list[bool] = []

    # --- optional out-of-band fingerprint pins (anchor authenticity before any crypto is trusted) ---
    if trust_root is not None:
        ok, note = _check_pin(trust_root, pin)
        log.append(f"  governance trust-root: {note}")
        if not ok:
            return False, log + ["bundle NOT SOUND (governance trust root not the pinned key)"]
    if witness_trust_root is not None:
        ok, note = _check_pin(witness_trust_root, witness_pin)
        log.append(f"  witness trust-root: {note}")
        if not ok:
            return False, log + ["bundle NOT SOUND (witness trust root not the pinned key)"]

    # --- prove-cert ---
    if "prove_cert" in bundle:
        if not isinstance(signer_pubkeys, dict):
            log.append("  [BAD] prove_cert present but no --signer-pubkeys supplied")
            results.append(False)
        else:
            ok, reason = verify_prove_cert(bundle["prove_cert"], signer_pubkeys=signer_pubkeys)
            log.append(f"  [{'OK ' if ok else 'BAD'}] prove_cert "
                       f"({bundle['prove_cert'].get('state', '?')}): {reason}")
            results.append(ok)

    # --- attestation series ---
    if "attestation" in bundle:
        att = bundle["attestation"] or {}
        if not isinstance(signer_pubkeys, dict) or not isinstance(trust_root, dict):
            log.append("  [BAD] attestation present but --signer-pubkeys and/or --trust-root missing")
            results.append(False)
        else:
            ok, reason, series = verify_attestation_series(
                att.get("ticks") or [], att.get("head"), att.get("floor"),
                trust_root=trust_root, signer_pubkeys=signer_pubkeys)
            log.append(f"  [{'OK ' if ok else 'BAD'}] attestation series: {reason}")
            if ok:
                log.append("     drift: " + " -> ".join(f"{s['state']}({s['label']})" for s in series))
            results.append(ok)

    # --- witnessed timed checkpoint ---
    if "witnessed" in bundle:
        wt = bundle["witnessed"] or {}
        if not isinstance(witness_trust_root, dict):
            log.append("  [BAD] witnessed present but no --witness-trust-root supplied")
            results.append(False)
        else:
            anchor = wt.get("external_time_anchor")
            if anchor is not None and not tsa_cert_pin:
                log.append("     (external_time_anchor present but no --tsa-cert-pin supplied — the "
                           "stronger anchored bound is NOT checked; the median bound below stands)")
            ok, T, reason = verify_timed_witnessed(
                wt.get("checkpoint") or {}, wt.get("witness_signatures") or [],
                witness_trust_root=witness_trust_root, min_distinct_signers=min_distinct_signers,
                external_time_anchor=anchor if tsa_cert_pin else None, tsa_cert_pin=tsa_cert_pin)
            log.append(f"  [{'OK ' if ok else 'BAD'}] witnessed checkpoint "
                       f"(no-later-than T={T}): {reason}")
            results.append(ok)

    # --- Z1 channel-binding (zkTLS notary co-sign) ---
    if "channel_binding" in bundle:
        if not notary_pin:
            log.append("  [BAD] channel_binding present but no --notary-pin supplied")
            results.append(False)
        else:
            ok, reason = verify_channel_binding_evidence(
                bundle["channel_binding"] or {}, notary_public_key_pin_b64=notary_pin)
            log.append(f"  [{'OK ' if ok else 'BAD'}] channel_binding: {reason}")
            results.append(ok)

    # --- PostureCertificate (Certificate of Non-Exploitability) ---
    if "posture" in bundle:
        if not posture_pin:
            log.append("  [BAD] posture present but no --posture-fingerprint (out-of-band) — fail-closed")
            results.append(False)
        elif not posture_owner_pubkey or not posture_engagement or posture_now is None:
            log.append("  [BAD] posture present but --posture-owner-pubkey / --posture-engagement / "
                       "--posture-now missing (needed to bind the certificate to its target)")
            results.append(False)
        else:
            ok, reason = verify_posture(bundle["posture"] or {}, pin=posture_pin,
                                        owner_pubkey=posture_owner_pubkey, engagement=posture_engagement,
                                        now=int(posture_now))
            log.append(f"  [{'OK ' if ok else 'BAD'}] posture: {reason}")
            results.append(ok)

    # --- Authority-Envelope certificate (the accountability twin) ---
    if "authority" in bundle:
        if not authority_pin:
            log.append("  [BAD] authority present but no --authority-fingerprint (out-of-band) — fail-closed")
            results.append(False)
        elif not authority_owner_pubkey or not authority_engagement:
            log.append("  [BAD] authority present but --authority-owner-pubkey / --authority-engagement missing")
            results.append(False)
        else:
            ok, reason = verify_authority(bundle["authority"] or {}, pin=authority_pin,
                                          owner_pubkey=authority_owner_pubkey, engagement=authority_engagement)
            log.append(f"  [{'OK ' if ok else 'BAD'}] authority: {reason}")
            results.append(ok)

    sound = bool(results) and all(results)
    log.append(f"bundle {'SOUND' if sound else 'NOT SOUND'} "
               f"(standalone: signatures + binding + structure + chain + quorum; "
               f"oracle silence/fire needs the VIGIL verifier)")
    return sound, log


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cmd_verify(args: argparse.Namespace) -> int:
    if args.prove_standalone:
        _assert_vigil_free()
    try:
        bundle = _load_json(args.bundle)
        signer_pubkeys = _load_json(args.signer_pubkeys) if args.signer_pubkeys else None
        trust_root = _load_json(args.trust_root) if args.trust_root else None
        witness_trust_root = _load_json(args.witness_trust_root) if args.witness_trust_root else None
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    _known = {"prove_cert", "attestation", "witnessed", "channel_binding", "posture", "authority"}
    if not isinstance(bundle, dict) or not (_known & set(bundle)):
        print("[ERROR] bundle has none of prove_cert / attestation / witnessed / channel_binding / "
              "posture / authority", file=sys.stderr)
        return 3
    sound, log = verify_bundle(
        bundle, signer_pubkeys=signer_pubkeys, trust_root=trust_root,
        witness_trust_root=witness_trust_root, pin=args.fingerprint, witness_pin=args.witness_fingerprint,
        min_distinct_signers=args.min_distinct_signers, tsa_cert_pin=args.tsa_cert_pin,
        notary_pin=args.notary_pin,
        posture_pin=getattr(args, "posture_fingerprint", "") or "",
        posture_owner_pubkey=getattr(args, "posture_owner_pubkey", "") or "",
        posture_engagement=getattr(args, "posture_engagement", "") or "",
        posture_now=getattr(args, "posture_now", None),
        authority_pin=getattr(args, "authority_fingerprint", "") or "",
        authority_owner_pubkey=getattr(args, "authority_owner_pubkey", "") or "",
        authority_engagement=getattr(args, "authority_engagement", "") or "")
    for line in log:
        print(line)
    return 0 if sound else 2


def _cmd_reexec_general(args: argparse.Namespace) -> int:
    """Re-derive a general FACT's verdict from its retained ``oracle_context`` (Step 2, the pure
    oracle families) with ZERO VIGIL code. Prints the re-fired signals + the combined verdict, and
    names any IRREDUCIBLE oracle key present (whose re-verification needs an in-VIGIL re-run)."""
    if args.prove_standalone:
        _assert_vigil_free()
    try:
        oc = _load_json(args.context)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    # Accept either a bare oracle_context, or a {oracle_context: {...}} / PCF {value: {...}} wrapper.
    if isinstance(oc, dict) and "oracle_context" in oc and isinstance(oc["oracle_context"], dict):
        oc = oc["oracle_context"]
    if isinstance(oc, dict) and set(oc) <= {"digest", "value"} and isinstance(oc.get("value"), dict):
        oc = oc["value"]
    res = reexecute_general_oracle(oc)
    if not res["reproduced"]:
        print("NOT REPRODUCED — the oracle_context carries no PORTED (pure, stdlib) general oracle key"
              + (f"; IRREDUCIBLE keys present: {res['unported_keys']}" if res["unported_keys"] else ""))
        return 2
    for s in res["signals"]:
        print(f"  oracle {s['kind']}: fired={s['fired']} conclusive={s['conclusive']} "
              f"confidence={s['confidence']:.3f}")
    if res["unported_keys"]:
        print(f"  NOTE: IRREDUCIBLE oracle key(s) also present (re-verify needs an in-VIGIL re-run, "
              f"NOT reproduced here): {res['unported_keys']}")
    verdict = "FIRED (re-derived positive)" if res["fired"] else "no high-confidence fire (re-derived)"
    print(f"RE-DERIVED: {verdict} — the verdict is the correct function of the RETAINED evidence "
          f"(producer-supplied; a live re-run is still required to prove it reflects the live target)")
    return 0 if res["fired"] else 2


def main(argv: list) -> int:
    p = argparse.ArgumentParser(
        prog="verify_vf.py",
        description="Standalone verifier for the VIGIL Verifiable-Fact remediation lifecycle "
                    "(stdlib + Ed25519 only; imports no VIGIL code).")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a VF bundle {prove_cert | attestation | witnessed}")
    v.add_argument("--bundle", required=True, help="the VF bundle JSON")
    v.add_argument("--signer-pubkeys", default="", dest="signer_pubkeys",
                   help="{key_id: pubkey_b64} — pinned prove-cert + tick admission keys")
    v.add_argument("--trust-root", default="", dest="trust_root",
                   help="governance TrustRoot JSON (for the attestation head signature)")
    v.add_argument("--witness-trust-root", default="", dest="witness_trust_root",
                   help="witness TrustRoot JSON (for the timed witnessed checkpoint)")
    v.add_argument("--fingerprint", default="", help="out-of-band pin on --trust-root (sha256:… or hex)")
    v.add_argument("--witness-fingerprint", default="", dest="witness_fingerprint",
                   help="out-of-band pin on --witness-trust-root (sha256:… or hex)")
    v.add_argument("--min-distinct-signers", type=int, default=None, dest="min_distinct_signers",
                   help="require at least N distinct verifying witnesses (blunts producer curation)")
    v.add_argument("--tsa-cert-pin", default=None, dest="tsa_cert_pin",
                   help="path to the PINNED TSA cert (PEM) for the A1 RFC3161 external time anchor over the "
                        "witnessed checkpoint; when supplied and the bundle carries external_time_anchor, "
                        "its genTime supersedes the quorum-median bound (openssl ts, VIGIL-free)")
    v.add_argument("--notary-pin", default="", dest="notary_pin",
                   help="out-of-band PINNED notary Ed25519 public key (base64) for a Z1 channel_binding "
                        "bundle; the co-signature is trusted ONLY when it is from this key (zkTLS mechanism — "
                        "a software notary is not producer-unforgeable, see Z1 residual)")
    v.add_argument("--prove-standalone", action="store_true",
                   help="first assert no VIGIL module is imported or importable, else exit non-zero")
    # --- PostureCertificate (Certificate of Non-Exploitability) ---
    v.add_argument("--posture-fingerprint", default="", dest="posture_fingerprint",
                   help="REQUIRED for a `posture` bundle: the out-of-band pin on the posture certificate's "
                        "authorizer set (sha256:… ) — fail-closed without it")
    v.add_argument("--posture-owner-pubkey", default="", dest="posture_owner_pubkey",
                   help="the target-owner's Ed25519 public key (base64) that signed the certificate's "
                        "IdentityAttestation — binds the posture proof to its target")
    v.add_argument("--posture-engagement", default="", dest="posture_engagement",
                   help="the engagement the IdentityAttestation must be for")
    v.add_argument("--posture-now", type=int, default=None, dest="posture_now",
                   help="the epoch time to check the IdentityAttestation's not_after against")
    # --- Authority-Envelope certificate (the accountability twin) ---
    v.add_argument("--authority-fingerprint", default="", dest="authority_fingerprint",
                   help="REQUIRED for an `authority` bundle: the out-of-band pin on the certificate's "
                        "authorizer set (fail-closed without it)")
    v.add_argument("--authority-owner-pubkey", default="", dest="authority_owner_pubkey",
                   help="the owner's Ed25519 public key (base64) that signed the authority envelope")
    v.add_argument("--authority-engagement", default="", dest="authority_engagement",
                   help="the engagement the authority envelope must be for")
    v.set_defaults(fn=_cmd_verify)

    rg = sub.add_parser("reexec-general",
                        help="re-derive a general FACT's verdict from its retained oracle_context "
                             "(Step 2, the PURE stdlib oracle families) — VIGIL-free")
    rg.add_argument("--context", required=True,
                    help="the retained oracle_context JSON (bare, or a {oracle_context|value: {...}} wrapper)")
    rg.add_argument("--prove-standalone", action="store_true",
                    help="first assert no VIGIL module is imported or importable, else exit non-zero")
    rg.set_defaults(fn=_cmd_reexec_general)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
