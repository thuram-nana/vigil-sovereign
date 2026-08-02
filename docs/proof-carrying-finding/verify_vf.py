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
    keys) TIMED-co-signed the attestation head, yielding a median no-later-than ``T``.

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
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# 0. VIGIL-free self-proof (optional, --prove-standalone). Same guarantee as verify_pcf: this verifier
#    imports only stdlib + cryptography; this check lets a caller *demonstrate* the running interpreter
#    has no VIGIL module reachable at all (used by the conformance test's clean subprocess).
# ---------------------------------------------------------------------------
_VIGIL_MODULES = ("framework", "vigil_core", "vigil_integration", "strix", "gateway")


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
    print("  [standalone] confirmed VIGIL-free: framework / vigil_core / vigil_integration / strix / "
          "gateway are neither imported nor importable in this interpreter")


# ---------------------------------------------------------------------------
# 1. Canonical bytes + digests + domain separation.
#    TWO canonicalizers, because the producers use two:
#      * canonical_json      — ensure_ascii=False  (vigil_core.canonical / the crucible spine): used for
#        the prove-cert signing bytes, digest_payload, the chain entry/head bytes, and the timed-witness
#        bytes. This is the same function verify_pcf.py re-implements.
#      * canonical_json_ascii — ensure_ascii=True  (remediation_cert._canon): used ONLY for the embedded
#        RemediationCertificate's context digests and whole-cert signing bytes. For ASCII content the two
#        are byte-identical; they diverge only on non-ASCII, and the differential test pins both.
# ---------------------------------------------------------------------------
GENESIS_PREV = "0" * 64
_EVIDENCE_DOMAIN = b"crucible-evidence-v1\x00"
_PROVE_CERT_DOMAIN = b"vigil-remediation-prove-cert-v1\x00"
_REM_CERT_DOMAIN = b"vigil-remediation-cert-v2\x00"
_WITNESS_TIME_DOMAIN = b"vigil-attestation-witness-time-v1\x00"

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


def verify_timed_witnessed(checkpoint: dict, timed_sigs: list, *, witness_trust_root: dict,
                           min_distinct_signers: Optional[int] = None) -> tuple[bool, Optional[int], str]:
    """Verify a strict-majority witness quorum TIMED-co-signed ``checkpoint`` and return its no-later-than
    bound (mirrors ``attestation_witness.verify_timed_witnessed``). Returns (ok, T, reason), FAIL-CLOSED:

      1. quorum SHAPE — refuse unless :func:`is_split_view_resistant` holds;
      2. verify + de-duplicate — per sig resolve the authoriser by key_id and verify over the timed bytes
         (each commits to its OWN observed_time); collect DISTINCT verifying witnesses by decoded key. An
         unknown key_id / weak-or-malformed key / non-verifying-or-malformed signature is IGNORED (never
         counted, never raised);
      3. quorum COUNT — distinct verifying witnesses >= max(threshold, min_distinct_signers);
      4. no-later-than T — the (n//2)-th of the sorted distinct-verifying observed times (exact median for
         odd n; upper-median for even n — deterministic integer).

    HONEST LIMIT (does NOT overclaim, per WITNESS-TRUST §4): T bounds when the head was WITNESSED, not when
    the oracle re-fired; independence of the distinct keyholders is a deployment assumption uncheckable by
    code; and a fully-dishonest PRODUCER curates which sigs are presented (raise min_distinct_signers toward
    n, or use an external RFC3161/OTS anchor, for a hard guarantee)."""
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
    T = observed_times[len(observed_times) // 2]
    return (True, T,
            f"{len(distinct_verified)} distinct witness(es) co-signed; no-later-than T={T} = median of the "
            f"PRESENTED signing quorum's clocks (sound only if that quorum is strict-majority honest — a "
            f"hard time guarantee needs the external anchor)")


# ---------------------------------------------------------------------------
# 8. Bundle verification (compose everything) + CLI
# ---------------------------------------------------------------------------
def verify_bundle(bundle: dict, *, signer_pubkeys: Optional[dict] = None,
                  trust_root: Optional[dict] = None, witness_trust_root: Optional[dict] = None,
                  pin: str = "", witness_pin: str = "",
                  min_distinct_signers: Optional[int] = None) -> tuple[bool, list]:
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
            ok, T, reason = verify_timed_witnessed(
                wt.get("checkpoint") or {}, wt.get("witness_signatures") or [],
                witness_trust_root=witness_trust_root, min_distinct_signers=min_distinct_signers)
            log.append(f"  [{'OK ' if ok else 'BAD'}] witnessed checkpoint "
                       f"(no-later-than T={T}): {reason}")
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
    if not isinstance(bundle, dict) or not ({"prove_cert", "attestation", "witnessed"} & set(bundle)):
        print("[ERROR] bundle has none of prove_cert / attestation / witnessed", file=sys.stderr)
        return 3
    sound, log = verify_bundle(
        bundle, signer_pubkeys=signer_pubkeys, trust_root=trust_root,
        witness_trust_root=witness_trust_root, pin=args.fingerprint, witness_pin=args.witness_fingerprint,
        min_distinct_signers=args.min_distinct_signers)
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
    v.add_argument("--prove-standalone", action="store_true",
                   help="first assert no VIGIL module is imported or importable, else exit non-zero")
    v.set_defaults(fn=_cmd_verify)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
