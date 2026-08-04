#!/usr/bin/env python3
"""verify_offline — a SELF-CONTAINED, VIGIL-free re-verifier for a VIGIL external-audit package (H4).

This file is shipped VERBATIM inside every audit package as ``verify_offline.py``. It imports NOTHING from
``framework`` / ``vigil`` — only the Python standard library and ``cryptography`` (pyca; "we don't roll our
own crypto"). An external audit team runs it OFFLINE, with no network, no target, and no VIGIL runtime:

    python3 verify_offline.py --package . --trust-root-fingerprint <fingerprint published OUT-OF-BAND>

It re-derives, from first principles, the CRYPTOGRAPHIC + INTEGRITY layers of the bundle:

  1. AUTHENTICITY  — each certificate carries an m-of-n Ed25519 governance signature over its own
     canonical bytes, valid against the pinned trust root.
  2. BINDING       — each certificate's ``oracle_context_digest`` equals the sha256 of the oracle_context
     shipped for it, so a signature cannot be lifted onto different evidence.
  3. ARTIFACT INTEGRITY — every raw file the certificate manifests still hashes to its recorded sha256.
  4. CHAIN / ANTI-SUPPRESSION — the hash chain links cleanly, the signed head anchors it, and the chain's
     digests equal EXACTLY the certificates' digests in order (nothing suppressed, injected, or reordered).
  5. TRUST-ROOT PIN — the shipped trust root's fingerprint must equal the value you pinned out-of-band;
     the copy in the package is only a convenience. Without the pin, authenticity is unproven.

Exit 0 iff ALL of the above hold for EVERY certificate. A single flipped byte anywhere → non-zero.

WHAT THIS DOES NOT DO — the honest residual, stated plainly:
  * REPRODUCTION. It does NOT re-fire the deterministic oracle over each oracle_context (that would
    re-derive the verdict WITHOUT trusting the signer's honesty about it). Re-firing an oracle needs the
    oracle's code — the open-source VIGIL verifier (``python3 -m framework.v2 evidence verify``), shipped
    as a reference and referenced in RUNBOOK.md. So this standalone check proves the governance authorisers
    ATTESTED these exact oracle_contexts + verdicts, tamper-evidently; it does not independently re-run the
    verdict. Whom you still trust after this step: the signer's honesty about each verdict (removed only by
    the reproduction step) and the verifier you are reading.
  * THE AUDIT ITSELF. A package is what VIGIL can PREPARE; an independent audit needs an external team.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - the one external dependency, present on any auditor's machine
    print("NOT SOUND: this verifier needs the `cryptography` package (pip install cryptography)",
          file=sys.stderr)
    sys.exit(3)

# --- canonical-bytes discipline (ported verbatim from vigil_core.canonical; NOT imported) ----------
_EVIDENCE_DOMAIN = b"crucible-evidence-v1\x00"
_GENESIS_PREV = "0" * 64
_HEAD_V2_FIELDS = ("base_seq", "base_prev_hash", "base_count", "cumulative_merkle_root",
                   "snapshot_seq", "prev_head_hash")


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_payload(obj: Any) -> str:
    return _sha256_hex(_canonical(obj))


def _signing_bytes(obj: dict) -> bytes:
    return _EVIDENCE_DOMAIN + _canonical(obj)


# --- Ed25519 with the SAME weak-key rejection the producer uses (canonical y < p; no low-order) -----
_ED25519_P = 2 ** 255 - 19
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


def _b64decode_exact(value: str, n: int) -> bytes:
    import base64
    import binascii
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"bad base64: {e}") from e
    if len(raw) != n:
        raise ValueError(f"expected {n} bytes, got {len(raw)}")
    return raw


def _load_pubkey(pub_b64: str) -> Ed25519PublicKey:
    raw = _b64decode_exact(pub_b64, 32)
    if (int.from_bytes(raw, "little") & _Y_MASK) >= _ED25519_P:
        raise ValueError("non-canonical public key (y >= p)")
    for entry in _SMALL_ORDER_POINTS:
        if raw[:31] == entry[:31] and (raw[31] & 0x7F) == (entry[31] & 0x7F):
            raise ValueError("low-order (weak) public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_one(pub_b64: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = _load_pubkey(pub_b64)
        sig = _b64decode_exact(sig_b64, 64)
    except ValueError:
        return False
    try:
        pub.verify(sig, message)
        return True
    except InvalidSignature:
        return False


def _verify_threshold(message: bytes, signatures: list[dict], trust_root: dict) -> bool:
    by_id = {a["key_id"]: a for a in trust_root.get("authorizers", [])}
    threshold = int(trust_root.get("threshold", 1))
    valid: set[str] = set()
    seen: set[str] = set()
    for sig in signatures:
        kid = sig.get("key_id")
        if kid in seen:
            continue
        seen.add(kid)
        auth = by_id.get(kid)
        if auth is None:
            continue
        if _verify_one(auth["public_key_b64"], message, sig.get("signature_b64", "")):
            valid.add(kid)
    return len(valid) >= threshold


def _entry_hash(seq: int, prev_hash: str, cert_digest: str) -> str:
    return _sha256_hex(_canonical({"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))


def _head_payload(head: dict) -> dict:
    d = dict(head)
    d.pop("signatures", None)
    if int(d.get("schema_version", 1)) < 2:
        for f in _HEAD_V2_FIELDS:
            d.pop(f, None)
    return d


def _fingerprint(trust_root: dict) -> str:
    return "sha256:" + _digest_payload(trust_root)


def _confined(root: Path, rel: str) -> Path | None:
    p = Path(rel)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        return None
    fp = (root / p).resolve()
    try:
        fp.relative_to(root.resolve())
    except ValueError:
        return None
    return fp


def _hash_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 16)
            if not chunk:
                break
            size += len(chunk)
            if size > 256 * 1024 * 1024:
                raise ValueError("artifact too large")
            h.update(chunk)
    return h.hexdigest(), size


def verify_package(pkg: Path, pinned_fingerprint: str | None) -> tuple[bool, list[str]]:
    """Return (sound, notes). ``sound`` is True iff every layer holds for every certificate."""
    notes: list[str] = []

    def load(name: str) -> Any:
        return json.loads((pkg / name).read_text(encoding="utf-8"))

    try:
        trust_root = load("trust-root.json")
        bundle = load("evidence-bundle.json")
        contexts = load("contexts.json")
    except (OSError, ValueError) as e:
        return False, [f"cannot load package files: {e}"]

    # 5. trust-root pin (out-of-band). Required for an authenticity claim.
    fp = _fingerprint(trust_root)
    if pinned_fingerprint is None:
        notes.append(f"WARNING: no --trust-root-fingerprint pin given; loaded root fingerprint is {fp} "
                     "(authenticity is UNPROVEN without an out-of-band pin)")
    elif pinned_fingerprint.strip() != fp:
        return False, [f"trust-root fingerprint MISMATCH: pinned {pinned_fingerprint!r} != loaded {fp!r}"]
    else:
        notes.append(f"trust-root fingerprint matches the out-of-band pin ({fp})")

    certs = bundle.get("certificates", [])
    chain = bundle.get("chain", [])
    head = bundle.get("head")
    path_certs = bundle.get("path_certs", []) or []
    if not certs:
        return False, notes + ["bundle carries no certificates"]

    evidence_root = pkg / "evidence"
    all_ok = True

    # 1-3. per-certificate: authenticity, binding, artifact integrity.
    for sc in certs:
        cert = sc.get("certificate", {})
        ref = cert.get("finding_ref", "?")
        if not _verify_threshold(_signing_bytes(cert), sc.get("signatures", []), trust_root):
            notes.append(f"[{ref}] AUTHENTICITY FAILED (m-of-n signature invalid)")
            all_ok = False
        ctx = contexts.get(ref)
        if ctx is None or _digest_payload(ctx) != cert.get("oracle_context_digest"):
            notes.append(f"[{ref}] BINDING FAILED (oracle_context digest mismatch / missing context)")
            all_ok = False
        for art in cert.get("artifacts", []):
            fp_art = _confined(evidence_root, art.get("path", ""))
            if fp_art is None or not fp_art.is_file():
                notes.append(f"[{ref}] ARTIFACT MISSING/UNSAFE: {art.get('path')!r}")
                all_ok = False
                continue
            try:
                digest, size = _hash_file(fp_art)
            except (OSError, ValueError) as e:
                notes.append(f"[{ref}] ARTIFACT UNREADABLE {art.get('path')!r}: {e}")
                all_ok = False
                continue
            if digest != art.get("sha256") or size != art.get("size"):
                notes.append(f"[{ref}] ARTIFACT TAMPERED: {art.get('path')!r}")
                all_ok = False

    # 4. chain integrity + anti-suppression + signed head.
    prev = _GENESIS_PREV
    for i, e in enumerate(chain):
        if e.get("prev_hash") != prev:
            notes.append(f"CHAIN BREAK at seq {e.get('seq')}: prev_hash mismatch (deleted/reordered)")
            all_ok = False
            break
        if e.get("entry_hash") != _entry_hash(e.get("seq"), e.get("prev_hash"), e.get("cert_digest")):
            notes.append(f"CHAIN BREAK at seq {e.get('seq')}: entry_hash mismatch (tampered)")
            all_ok = False
            break
        if i > 0 and e.get("seq") != chain[i - 1].get("seq") + 1:
            notes.append(f"CHAIN BREAK: seq gap at {e.get('seq')}")
            all_ok = False
            break
        prev = e.get("entry_hash")

    cert_digests = [_digest_payload(sc.get("certificate", {})) for sc in certs]
    path_digests = [_digest_payload(pc) for pc in path_certs]
    chain_digests = [e.get("cert_digest") for e in chain]
    if cert_digests + path_digests != chain_digests:
        notes.append("CERT-SET MISMATCH: chain does not cover exactly the certificate set (in order)")
        all_ok = False

    if head is not None:
        exp_hash = chain[-1]["entry_hash"] if chain else _GENESIS_PREV
        exp_seq = chain[-1]["seq"] if chain else head.get("base_seq", 0)
        base_count = int(head.get("base_count", 0))
        if (head.get("head_hash") != exp_hash or head.get("last_seq") != exp_seq
                or head.get("entry_count") != base_count + len(chain)):
            notes.append("HEAD does not match the chain (log truncated or head rewritten)")
            all_ok = False
        elif not _verify_threshold(_signing_bytes(_head_payload(head)), head.get("signatures", []),
                                   trust_root):
            notes.append("HEAD signature invalid (not anchored to governance)")
            all_ok = False
        else:
            notes.append(f"signed head anchors {len(chain)} chain entr(ies)")
    else:
        notes.append("WARNING: bundle has an UNSIGNED head — chain links but is not governance-anchored")
        all_ok = False

    if all_ok:
        notes.append(f"SOUND: {len(certs)} certificate(s) authentic + bound + integral; chain anchored. "
                     "(Reproduction — re-firing each oracle — is the separate VIGIL-verifier step; see "
                     "RUNBOOK.md.)")
    return all_ok, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline re-verifier for a VIGIL external-audit package.")
    ap.add_argument("--package", default=".", help="path to the unpacked audit package (default: .)")
    ap.add_argument("--trust-root-fingerprint", default=None,
                    help="the fingerprint the operator published OUT-OF-BAND (pins authenticity)")
    args = ap.parse_args(argv)
    sound, notes = verify_package(Path(args.package), args.trust_root_fingerprint)
    for n in notes:
        print(("  - " + n))
    print("RESULT:", "SOUND" if sound else "NOT SOUND")
    return 0 if sound else 1


if __name__ == "__main__":
    raise SystemExit(main())
