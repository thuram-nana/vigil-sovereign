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

WHAT IT DOES NOT DO (the documented boundary — same as verify_pcf): it NEVER RE-FIRES THE ORACLE.
Re-executing the deterministic oracle over a retained ``oracle_context`` — the check that turns "the bytes
are authentic and bound" into "the oracle is genuinely silent / genuinely fired" — is framework-specific
(it needs the oracle bodies) and is the VIGIL verifier's job
(``prove_driver.verify_prove_certificate`` / ``remediation_cert.verify_remediation_certificate`` /
``attestation_log.verify_log``). This file checks SIGNATURES, BINDING, and STRUCTURE — authenticity,
cross-binding, digest binding, chain, anti-rollback, quorum, and the median clock — all fully checkable
standalone; oracle silence/fire is the one layer that needs VIGIL. A single flipped byte anywhere flips a
standalone verdict to NOT SOUND.

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
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

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
# external time anchor binds). Byte-identical to transparency._WITNESS_DOMAIN.
_TRANSPARENCY_CHECKPOINT_DOMAIN = b"vigil-transparency-checkpoint-v1\x00"
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
#    BOUNDARY (the honest residual, same as every component here): it does NOT re-fire the oracle — a
#    CLOSED claim's "binding" tier means the signed coverage verdict is re-checked, not re-derived from
#    raw bytes; re-firing needs VIGIL (a coverage re-run / `framework.v2 evidence verify`).
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


def _project_posture_claims(coverage_cert: dict) -> list:
    """VIGIL-free mirror of posture.certificate.project_posture_claims (fail-closed on a false-CLOSED
    source: a 'clean' probe with no conclusive oracle)."""
    probes = coverage_cert.get("probes")
    if not isinstance(probes, list):
        raise ValueError("coverage certificate has no probes list")
    groups: dict = {}
    for p in probes:
        if not isinstance(p, dict):
            raise ValueError("malformed probe row")
        verdict = p.get("verdict")
        kinds = p.get("oracle_kinds_run") or []
        if verdict == "clean" and not kinds:
            raise ValueError("a 'clean' probe carries no oracle_kinds_run — invalid coverage certificate")
        key = (str(p.get("surface", "")), str(p.get("param", "")), str(p.get("class", "")))
        g = groups.setdefault(key, {"finding": 0, "clean": 0, "inconclusive": 0, "kinds": set(), "n": 0})
        g["n"] += 1
        if verdict in ("finding", "clean", "inconclusive"):
            g[verdict] += 1
        if verdict == "clean":
            g["kinds"].update(str(k) for k in kinds)
    claims = []
    for (surface, param, cls), g in groups.items():
        if g["finding"] > 0:
            status, kinds = "OPEN", []
        elif g["clean"] > 0:
            status, kinds = "CLOSED", sorted(g["kinds"])
        else:
            status, kinds = "UNPROVEN", []
        claims.append({"surface": surface, "param": param, "class": cls, "status": status,
                       "verification": "binding", "evidence_oracle_kinds": kinds, "n_probes": g["n"]})
    claims.sort(key=lambda c: (c["surface"], c["param"], c["class"]))
    return claims


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
    # 4. target binding (closes target-swap)
    iok, ireason = _verify_identity_attestation(cert.get("target_identity") or {}, owner_pubkey, engagement, now)
    if not iok:
        return False, f"posture target-binding: {ireason}"
    if not _identity_matches((cert.get("target_identity") or {}).get("policy") or {}, cert.get("target_sample") or {}):
        return False, "posture target_sample does not satisfy the owner's identity policy"
    s = cert.get("summary") or {}
    return True, (f"SOUND: {s.get('n_closed', '?')} CLOSED / {s.get('n_open', '?')} OPEN / "
                  f"{s.get('n_unproven', '?')} UNPROVEN over {cert.get('target_sample')} "
                  f"(re-firing the oracle needs VIGIL — binding tier)")


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

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
