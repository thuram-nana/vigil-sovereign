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
     the copy in the package is only a convenience. Without the pin the shipped root is unauthenticated
     (an attacker can forge a fresh root and re-sign the whole bundle), so the package is NOT SOUND and
     the tool exits non-zero — FAIL-CLOSED. A forgotten pin can never surface as a clean SOUND / exit-0.

Exit 0 iff ALL of the above hold for EVERY certificate — INCLUDING the out-of-band pin (item 5). A single
flipped byte anywhere, OR a missing --trust-root-fingerprint, → non-zero.

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


def _validate_trust_root(trust_root: Any) -> str | None:
    """Structurally validate a governance trust-root policy. Returns an error string if INVALID (so
    verification refuses), else None. An out-of-band fingerprint pin proves WHICH root; this proves the root
    is a well-formed m-of-n policy — a threshold of 0 (or > the number of distinct authorizers, or duplicate
    key_ids, or missing fields) must NEVER surface as SOUND, even if it was provisioned by mistake."""
    if not isinstance(trust_root, dict):
        return "trust root is not an object"
    authorizers = trust_root.get("authorizers")
    if not isinstance(authorizers, list) or not authorizers:
        return "trust root has no authorizers"
    key_ids: list[str] = []
    for a in authorizers:
        if not isinstance(a, dict):
            return "authorizer entry is not an object"
        kid = a.get("key_id")
        pub = a.get("public_key_b64")
        if not isinstance(kid, str) or not kid:
            return "authorizer missing key_id"
        if not isinstance(pub, str) or not pub:
            return f"authorizer {kid!r} missing public_key_b64"
        key_ids.append(kid)
    if len(set(key_ids)) != len(key_ids):
        return "trust root has DUPLICATE authorizer key_ids"
    thr = trust_root.get("threshold", 1)
    if not isinstance(thr, int) or isinstance(thr, bool):
        return f"threshold must be an integer, got {type(thr).__name__}"
    if thr < 1:
        return f"threshold {thr} < 1 (a 0/negative threshold accepts with no valid signature)"
    if thr > len(set(key_ids)):
        return f"threshold {thr} > {len(set(key_ids))} distinct authorizers (unsatisfiable / mis-provisioned)"
    return None


def _verify_threshold(message: bytes, signatures: list[dict], trust_root: dict) -> bool:
    # Structurally invalid policy (validated separately in verify_package) can never be satisfied here either.
    if _validate_trust_root(trust_root) is not None:
        return False
    by_id = {a["key_id"]: a for a in trust_root.get("authorizers", [])}
    threshold = int(trust_root.get("threshold", 1))
    valid: set[str] = set()
    seen: set[str] = set()
    for sig in signatures if isinstance(signatures, list) else []:
        if not isinstance(sig, dict):
            continue
        kid = sig.get("key_id")
        if kid in seen:
            continue
        seen.add(kid)
        auth = by_id.get(kid)
        if auth is None:
            continue
        if _verify_one(auth["public_key_b64"], message, sig.get("signature_b64", "")):
            valid.add(kid)
    return threshold >= 1 and len(valid) >= threshold


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

    _MAX_JSON = 64 * 1024 * 1024   # a hostile package must not exhaust memory before any check runs

    def load(name: str) -> Any:
        fp_j = _confined(pkg, name)
        if fp_j is None or not fp_j.is_file() or fp_j.is_symlink():
            raise ValueError(f"{name}: missing or unsafe path")
        if fp_j.stat().st_size > _MAX_JSON:
            raise ValueError(f"{name}: file too large (> {_MAX_JSON} bytes)")
        return json.loads(fp_j.read_text(encoding="utf-8"))

    try:
        trust_root = load("trust-root.json")
        bundle = load("evidence-bundle.json")
        contexts = load("contexts.json")
    except (OSError, ValueError) as e:
        return False, [f"cannot load package files: {e}"]

    # STRUCTURAL trust-root validity (fail-closed): a malformed / zero-threshold / duplicate-key_id policy is
    # NOT SOUND even if it matches the pin (an out-of-band pin proves WHICH root, not that it is a valid policy).
    tr_err = _validate_trust_root(trust_root)
    if tr_err is not None:
        return False, [f"INVALID trust-root policy: {tr_err}"]

    # 5. trust-root pin (out-of-band). REQUIRED for an authenticity claim: without it the shipped
    #    trust root is unauthenticated (an attacker who forges a fresh root + re-signs every cert and
    #    the head produces an internally-consistent bundle), so the package is NOT SOUND — fail-closed.
    #    A forgotten pin must never surface as a clean SOUND / exit-0.
    fp = _fingerprint(trust_root)
    authenticity_pinned = pinned_fingerprint is not None
    if pinned_fingerprint is None:
        notes.append(f"WARNING: no --trust-root-fingerprint pin given; loaded root fingerprint is {fp} "
                     "(authenticity is UNPROVEN — the shipped trust root is unauthenticated)")
    elif pinned_fingerprint.strip() != fp:
        return False, [f"trust-root fingerprint MISMATCH: pinned {pinned_fingerprint!r} != loaded {fp!r}"]
    else:
        notes.append(f"trust-root fingerprint matches the out-of-band pin ({fp})")

    certs = bundle.get("certificates", [])
    chain = bundle.get("chain", [])
    head = bundle.get("head")
    path_certs = bundle.get("path_certs", []) or []
    # Resource bounds (fail-closed): a hostile package must not exhaust memory/CPU by sheer count.
    _MAX_CERTS = 100_000
    if not (isinstance(certs, list) and isinstance(chain, list) and isinstance(path_certs, list)):
        return False, notes + ["bundle certificates/chain/path_certs must be lists"]
    if len(certs) > _MAX_CERTS or len(chain) > _MAX_CERTS or len(path_certs) > _MAX_CERTS:
        return False, notes + [f"bundle exceeds the {_MAX_CERTS}-entry safety bound"]
    for sc in certs:
        if isinstance(sc, dict) and isinstance(sc.get("signatures"), list) and len(sc["signatures"]) > 10_000:
            return False, notes + ["a certificate carries an excessive number of signatures"]
    if not certs:
        return False, notes + ["bundle carries no certificates"]

    evidence_root = pkg / "evidence"
    # PRIMARY ARTIFACTS (posture FACTs that opted into the gating re-check): finding_ref -> relpath, shipped
    # under artifacts/. Optional (absent for a package with no such certs). A hostile index cannot escape the
    # package (paths are confined via _confined below).
    try:
        artifacts_index = load("artifacts.json")
        if not isinstance(artifacts_index, dict):
            artifacts_index = {}
    except (OSError, ValueError):
        artifacts_index = {}
    all_ok = True
    consumed_art_refs: set[str] = set()   # artifacts.json keys legitimately consumed by a recheck cert

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

        # 3b. PRIMARY ARTIFACT RE-CHECK (BLOCK #3): when the cert opted in, recompute sha256 over the shipped
        #     raw artifact and cross-check the SIGNED artifact_sha256 — a swapped artifact fails. FAIL CLOSED
        #     when the artifact is absent or no digest is bound (a re-checkable cert that is never re-checked
        #     is not sound). Mirrors the in-tree verify_certificate gate for the VIGIL-free verifier.
        if cert.get("artifact_recheck_required"):
            want = cert.get("artifact_sha256")
            rel = artifacts_index.get(ref)
            if rel is not None:
                consumed_art_refs.add(ref)
            raw_path = (pkg / str(rel)) if rel else None
            fp_pa = _confined(pkg, str(rel)) if rel else None
            # reject a symlink or non-regular file (is_file() follows symlinks, so check the un-resolved path)
            is_symlink = bool(raw_path and raw_path.is_symlink())
            if not want:
                notes.append(f"[{ref}] PRIMARY ARTIFACT re-check required but no artifact_sha256 bound")
                all_ok = False
            elif not rel or fp_pa is None or is_symlink or not fp_pa.is_file():
                notes.append(f"[{ref}] PRIMARY ARTIFACT MISSING/UNSAFE (re-check required) — refusing "
                             f"(fail-closed)")
                all_ok = False
            else:
                try:
                    pa_digest, pa_size = _hash_file(fp_pa)
                except (OSError, ValueError) as e:
                    notes.append(f"[{ref}] PRIMARY ARTIFACT UNREADABLE: {e}")
                    all_ok = False
                else:
                    if pa_size == 0:
                        notes.append(f"[{ref}] PRIMARY ARTIFACT is EMPTY — refusing (a posture artifact is "
                                     f"never empty)")
                        all_ok = False
                    elif pa_digest != want:
                        notes.append(f"[{ref}] PRIMARY ARTIFACT MISMATCH/TAMPERED "
                                     f"(recomputed {pa_digest} != bound {want})")
                        all_ok = False

    # 3c. every artifacts.json entry must be CONSUMED by a recheck certificate — an ORPHANED / unexpected
    #     index entry (or a duplicate pointing at an unreferenced ref) means the package is not well-formed.
    orphaned = sorted(set(map(str, artifacts_index.keys())) - consumed_art_refs)
    if orphaned:
        notes.append(f"artifacts.json has ORPHANED/UNEXPECTED entries (no recheck cert consumes them): "
                     f"{orphaned[:10]}")
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

    if all_ok and authenticity_pinned:
        notes.append(f"SOUND: {len(certs)} certificate(s) authentic + bound + integral; chain anchored. "
                     "(Reproduction — re-firing each oracle — is the separate VIGIL-verifier step; see "
                     "RUNBOOK.md.)")
    elif all_ok and not authenticity_pinned:
        notes.append(f"NOT SOUND (authenticity UNPROVEN): {len(certs)} certificate(s) are bound + integral "
                     "and the chain is internally consistent, BUT the trust root is unauthenticated — "
                     "re-run with --trust-root-fingerprint <the value published OUT-OF-BAND> to prove it.")
    return (all_ok and authenticity_pinned), notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline re-verifier for a VIGIL external-audit package.")
    ap.add_argument("--package", default=".", help="path to the unpacked audit package (default: .)")
    ap.add_argument("--trust-root-fingerprint", default=None,
                    help="the fingerprint the operator published OUT-OF-BAND (pins authenticity)")
    args = ap.parse_args(argv)
    sound, notes = verify_package(Path(args.package), args.trust_root_fingerprint)
    for n in notes:
        print(("  - " + n))
    if sound:
        print("RESULT: SOUND")
    elif args.trust_root_fingerprint is None:
        print("RESULT: NOT SOUND (authenticity UNPROVEN — no out-of-band --trust-root-fingerprint pin)")
    else:
        print("RESULT: NOT SOUND")
    return 0 if sound else 1


if __name__ == "__main__":
    raise SystemExit(main())
