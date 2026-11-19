#!/usr/bin/env python3
"""verify_pcf.py — a STANDALONE reference verifier for VIGIL proof bundles / PCF v0.1 certificates.

This file is the whole point of proof-carrying findings: a third party who does NOT trust or run
VIGIL can check a finding's authenticity, integrity, and chain with nothing but the Python standard
library and one Ed25519 library. It imports NO VIGIL code — not ``framework``, not ``vigil_core``,
not ``vigil_integration``, not ``strix``. It is derived from the published wire spec (``SPEC.md`` +
``schemas/``), re-implementing the canonical bytes, domain separation, m-of-n Ed25519 threshold, the
hash chain / signed head / anti-rollback high-water, and the out-of-band trust-root fingerprint pin.

What it PROVES (offline, no target, no network):
  * fingerprint — the trust root matches the operator's out-of-band pin;
  * authentic   — each certificate's m-of-n Ed25519 signature validates against the pinned root;
  * bound       — each oracle_context_digest matches the retained oracle_context;
  * artifacts   — each raw file re-hashes to its recorded digest (confined to the evidence tree);
  * chained     — the hash chain + signed head bind the whole certificate set (no
                  suppress/inject/reorder), anchored and not rolled back.

What it does NOT do: re-run the oracle. Reproduction (re-executing the deterministic oracle over the
retained oracle_context, plus the oracle-version staleness and claim-grounding checks) is
framework-specific and requires the VIGIL verifier
(``python -m framework.v2 evidence verify`` / ``pcf-verify``). Authenticity, binding, integrity, and
chain are fully checkable here; reproduction is the one layer that needs VIGIL. See README.md.

The ``finding`` mode (SPEC §8) checks ONE signed finding record — the single-finding bundle a VIGIL
customer downloads for one finding: the fingerprint pin, the m-of-n authenticity of that one
certificate, the no-lying-wrapper fields of the bundle, and the certificate's own FACT provenance. Its
binding and artifact layers are checked only when their inputs are supplied (``--oracle-context`` /
``--evidence-root``), and it says so, layer by layer, in its output; a single-finding bundle carries no
engagement chain, so the chain layer is the ``bundle`` mode's.

Verification only — this file contains no offensive capability. It never writes (except an optional
anti-rollback high-water file), never phones home, and is deterministic.

Usage:
    verify_pcf.py bundle  --bundle DIR --trust-root-fingerprint sha256:<hex>
                  [--report reverifiable.json] [--evidence-root evidence] [--highwater FILE]
    verify_pcf.py pcf     --pcf pcf.json --trust-root trust-root.json
                  [--trust-root-fingerprint sha256:<hex>] [--evidence-root DIR]
    verify_pcf.py finding --bundle proof-bundle.json --trust-root-fingerprint sha256:<hex>
                  [--oracle-context oracle-context.json] [--evidence-root DIR]

Exit 0 iff SOUND (``finding``: VERIFIED); 2 if NOT SOUND / NOT VERIFIED; 3 on a usage / I/O error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# 0. VIGIL-free self-proof (optional, --prove-standalone). This verifier's guarantee is that it
#    imports only stdlib + cryptography; this check lets a caller *demonstrate* the running env has
#    no VIGIL modules reachable at all (used by the conformance test's clean subprocess).
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
    print("  [standalone] confirmed VIGIL-free: framework / vigil_core / vigil_integration / strix "
          "are neither imported nor importable in this interpreter")


# ---------------------------------------------------------------------------
# 1. Canonical bytes + digests + domain separation (SPEC §1, §2)
# ---------------------------------------------------------------------------
_EVIDENCE_DOMAIN = b"crucible-evidence-v1\x00"
GENESIS_PREV = "0" * 64


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def evidence_signing_bytes(payload: dict[str, Any]) -> bytes:
    return _EVIDENCE_DOMAIN + canonical_json(payload)


# ---------------------------------------------------------------------------
# 2. Ed25519 m-of-n threshold, with weak-key rejection (SPEC §3)
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
    """A trust-root public key that must never be admitted (non-canonical or low-order)."""


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


def _verify_one(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    raw = _b64_exact(public_key_b64, 32, "Ed25519 public key")
    _reject_weak_public_key(raw)  # fail-closed before any verify
    sig = _b64_exact(signature_b64, 64, "Ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except InvalidSignature:
        return False


def verify_threshold(message: bytes, signatures: list[dict], trust_root: dict) -> tuple[bool, list[str], str]:
    """Count DISTINCT trust-root authorisers with a valid signature; compare to threshold.

    ``signatures`` items carry ``key_id`` + a base64 signature under either ``signature_b64`` (evidence
    wire) or ``sig`` (PCF wire). Returns (satisfied, valid_key_ids, human_reason)."""
    by_id = {a.get("key_id"): a for a in trust_root.get("authorizers", []) if isinstance(a, dict)}
    threshold = int(trust_root.get("threshold", 0))
    valid: list[str] = []
    seen: set[str] = set()
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
        try:
            if _verify_one(str(auth.get("public_key_b64", "")), message, str(sig_b64)):
                valid.append(str(kid))
        except (WeakKey, ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            continue
    satisfied = len(valid) >= threshold and threshold >= 1
    reason = (f"{len(valid)} valid distinct signature(s) vs threshold {threshold}")
    return satisfied, valid, reason


def trust_root_fingerprint(trust_root: dict) -> str:
    return "sha256:" + digest_payload(trust_root)


def _check_pin(trust_root: dict, pin: str) -> tuple[bool, str, str]:
    """Compare the trust root's fingerprint to an out-of-band pin. Returns (ok, computed_fp, note)."""
    fp = trust_root_fingerprint(trust_root)
    pin = (pin or "").strip()
    if not pin:
        return True, fp, "UNPINNED (authenticity NOT anchored — obtain the operator's fingerprint out-of-band)"
    want = pin if pin.startswith("sha256:") else ("sha256:" + pin)
    if want.lower() != fp.lower():
        return False, fp, f"fingerprint pin MISMATCH — expected {want}, got {fp}"
    return True, fp, "PINNED OK"


# ---------------------------------------------------------------------------
# 3. Chain + signed head (SPEC §5)
# ---------------------------------------------------------------------------
_HEAD_V2_FIELDS = ("base_seq", "base_prev_hash", "base_count", "cumulative_merkle_root",
                   "snapshot_seq", "prev_head_hash")


def _entry_hash(seq: int, prev_hash: str, cert_digest: str) -> str:
    return sha256_hex(canonical_json({"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))


def verify_chain(entries: list[dict], *, genesis_prev: str = GENESIS_PREV) -> tuple[bool, str]:
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


def verify_head(head: dict, entries: list[dict], trust_root: dict,
                *, prev_highwater: int | None = None, genesis_prev: str = GENESIS_PREV) -> tuple[bool, str]:
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
# 4. Artifact manifest re-check, path-confined (SPEC §4)
# ---------------------------------------------------------------------------
_READ_CHUNK = 1 << 16
_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def _confined(root: Path, rel: str) -> Path | None:
    p = Path(rel)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        return None
    fp = (root / p)
    try:
        resolved = fp.resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if resolved != root_resolved and root_resolved not in resolved.parents:
        return None
    return fp


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_ARTIFACT_BYTES:
                raise ValueError("artifact exceeds size cap")
            h.update(chunk)
    return h.hexdigest(), size


def verify_manifest(artifacts: list[dict], root: Path) -> list[tuple[str, bool, str]]:
    out: list[tuple[str, bool, str]] = []
    for a in artifacts:
        rel = str(a.get("path", ""))
        fp = _confined(root, rel)
        if fp is None:
            out.append((rel, False, "path escapes the evidence root (refused)"))
            continue
        if fp.is_symlink() or not fp.is_file():
            out.append((rel, False, "missing or not a regular file"))
            continue
        try:
            digest, size = _sha256_file(fp)
        except (OSError, ValueError) as e:
            out.append((rel, False, f"unreadable: {e}"))
            continue
        if digest != a.get("sha256"):
            out.append((rel, False, "sha256 mismatch (bytes altered)"))
        elif size != int(a.get("size", -1)):
            out.append((rel, False, "size mismatch"))
        else:
            out.append((rel, True, "ok"))
    return out


# ---------------------------------------------------------------------------
# 5. Bundle verification (compose everything)
# ---------------------------------------------------------------------------
def _ctx_by_ref(report: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    findings = report.get("active_findings")
    findings = findings if isinstance(findings, list) else ([report] if report.get("oracle_context") else [])
    for f in findings:
        if isinstance(f, dict) and f.get("oracle_context"):
            ref = str(f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding")
            out[ref] = f["oracle_context"]
    return out


def verify_bundle_dir(bundle_dir: Path, *, pin: str = "", report_path: Path | None = None,
                      evidence_root: Path | None = None, prev_highwater: int | None = None) -> tuple[bool, list[str]]:
    log: list[str] = []
    bundle = json.loads((bundle_dir / "evidence-bundle.json").read_text(encoding="utf-8"))
    trust_root = json.loads((bundle_dir / "trust-root.json").read_text(encoding="utf-8"))

    # --- fingerprint pin (out-of-band anchor) ---
    pin_ok, fp, pin_note = _check_pin(trust_root, pin)
    log.append(f"  trust-root fingerprint: {fp}  ({pin_note})")
    shipped = bundle_dir / "TRUST-ROOT-FINGERPRINT.txt"
    if shipped.is_file():
        got = shipped.read_text(encoding="utf-8").strip()
        if got != fp:
            pin_ok = False
            log.append(f"  [BAD] shipped TRUST-ROOT-FINGERPRINT.txt ({got}) != computed ({fp})")
    if not pin_ok:
        log.append("bundle NOT SOUND (trust root not the pinned governance key)")
        return False, log

    if report_path is None:
        report_path = bundle_dir / "reverifiable.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    ctx = _ctx_by_ref(report)
    if evidence_root is None:
        er = bundle_dir / "evidence"
        evidence_root = er if er.is_dir() else None

    certificates = bundle.get("certificates", [])
    chain = bundle.get("chain", [])
    head = bundle.get("head")

    all_ok = True
    verified_digests: list[str] = []
    for sc in certificates:
        cert = sc.get("certificate", {})
        ref = str(cert.get("finding_ref", "?"))
        cert_bytes = canonical_json(cert)
        cert_digest = sha256_hex(cert_bytes)

        authentic, valid, thr_reason = verify_threshold(
            _EVIDENCE_DOMAIN + cert_bytes, sc.get("signatures", []), trust_root)

        oc = ctx.get(ref, {})
        bound = digest_payload(oc) == cert.get("oracle_context_digest")

        artifacts_ok = True
        art_note = ""
        arts = cert.get("artifacts") or []
        if arts:
            if evidence_root is None:
                artifacts_ok = False
                art_note = "; artifacts CLAIMED but no evidence root — refusing to pass"
            else:
                res = verify_manifest(arts, evidence_root)
                bad = [f"{p}: {n}" for p, ok, n in res if not ok]
                artifacts_ok = not bad
                if bad:
                    art_note = "; artifacts FAILED: " + ", ".join(bad)

        ok = authentic and bound and artifacts_ok
        all_ok = all_ok and ok
        if ok:
            verified_digests.append(cert_digest)
        log.append(f"  [{'OK ' if ok else 'BAD'}] {ref}: authentic={authentic} bound={bound} "
                   f"artifacts_ok={artifacts_ok} (reproduction NOT checked standalone) — "
                   f"{thr_reason}{art_note}")

    # --- chain / head / cert-set binding / anti-rollback ---
    chain_digests = [str(e.get("cert_digest")) for e in chain]
    cert_digests = [sha256_hex(canonical_json(sc.get("certificate", {}))) for sc in certificates]
    cert_set_bound = cert_digests == chain_digests
    if head is not None:
        chain_ok, chain_note = verify_head(head, chain, trust_root, prev_highwater=prev_highwater)
    else:
        chain_ok, chain_note = verify_chain(chain)
        chain_note += " (UNSIGNED head — not anchored to governance)"
        chain_ok = False  # standalone: a bundle with no signed head is not authenticity-anchored
    if not cert_set_bound:
        chain_note += (f"; CERT-SET MISMATCH: {len(cert_digests)} cert(s) vs {len(chain_digests)} "
                       f"chain entr(ies) — a certificate was suppressed, injected, or reordered")
    log.append(f"  chain: {'OK ' if (chain_ok and cert_set_bound) else 'BAD'} — {chain_note}")

    sound = bool(certificates) and all_ok and chain_ok and cert_set_bound
    log.append(f"bundle {'SOUND' if sound else 'NOT SOUND'} "
               f"(standalone: authenticity + binding + artifacts + chain; reproduction needs the VIGIL verifier)")
    return sound, log


# ---------------------------------------------------------------------------
# 6. PCF v0.1 certificate verification (authenticity + binding + no-lying-wrapper subset)
# ---------------------------------------------------------------------------
def verify_pcf_cert(pcf: dict, trust_root: dict, *, pin: str = "",
                    evidence_root: Path | None = None) -> tuple[bool, str]:
    if not isinstance(pcf, dict):
        return False, "certificate is not an object"
    if pcf.get("pcf_version") != "0.1":
        return False, f"unsupported pcf_version {pcf.get('pcf_version')!r}"
    for m in ("claim", "subject", "evidence", "oracle", "verdict", "provenance", "signature", "_crucible"):
        if not isinstance(pcf.get(m), dict):
            return False, f"member {m!r} must be an object"

    pin_ok, fp, pin_note = _check_pin(trust_root, pin)
    if not pin_ok:
        return False, pin_note

    cert = (pcf.get("_crucible") or {}).get("certificate")
    if not isinstance(cert, dict):
        return False, "embedded _crucible.certificate missing"
    cert_bytes = canonical_json(cert)

    # authenticity over the embedded (authoritative) certificate
    authentic, _valid, thr_reason = verify_threshold(
        _EVIDENCE_DOMAIN + cert_bytes, pcf["signature"].get("signatures", []), trust_root)
    if not authentic:
        return False, f"signature: {thr_reason}"

    # no-lying-wrapper: the projected view fields checkable WITHOUT the framework vocabulary must equal
    # the signed certificate's values. (oracle.binding + claim.vocabulary validity are framework-derived;
    # those, plus oracle reproduction, are the VIGIL verifier's job.)
    checks = {
        "id": sha256_hex(cert_bytes),
        "claim.class": cert.get("bug_class", ""),
        "oracle.id": cert.get("confirmed_by", ""),
        "oracle.version": cert.get("oracle_version", ""),
        "verdict.confidence": cert.get("confidence", 0.0),
        "subject.identifier": cert.get("finding_ref", ""),
        "subject.context.surface": cert.get("surface", ""),
        "subject.context.engagement": cert.get("engagement_slug", ""),
        "grounding": "FACT",
        "verdict.fired": True,
    }
    presented = {
        "id": pcf.get("id"),
        "claim.class": pcf["claim"].get("class"),
        "oracle.id": pcf["oracle"].get("id"),
        "oracle.version": pcf["oracle"].get("version"),
        "verdict.confidence": pcf["verdict"].get("confidence"),
        "subject.identifier": pcf["subject"].get("identifier"),
        "subject.context.surface": (pcf["subject"].get("context") or {}).get("surface"),
        "subject.context.engagement": (pcf["subject"].get("context") or {}).get("engagement"),
        "grounding": pcf.get("grounding"),
        "verdict.fired": pcf["verdict"].get("fired"),
    }
    for k, want in checks.items():
        if presented.get(k) != want:
            return False, f"PCF view field {k!r} != signed certificate ({presented.get(k)!r} vs {want!r}) — lying wrapper"

    # binding: the carried oracle_context re-hashes to the signed digest
    oc_item = pcf["evidence"].get("oracle_context") or {}
    oc = oc_item.get("value")
    if not isinstance(oc, dict):
        return False, "evidence.oracle_context.value missing — certificate is not re-runnable"
    if digest_payload(oc) != cert.get("oracle_context_digest"):
        return False, "oracle_context digest mismatch — evidence altered"
    if oc_item.get("digest") != cert.get("oracle_context_digest"):
        return False, "evidence.oracle_context.digest != signed digest — lying wrapper"

    # artifacts (if any) re-hash under the evidence root
    if cert.get("artifacts"):
        if evidence_root is None:
            return False, "artifacts claimed but no evidence root — fail-closed"
        bad = [f"{p}: {n}" for p, ok, n in verify_manifest(cert["artifacts"], evidence_root) if not ok]
        if bad:
            return False, "artifact check failed: " + ", ".join(bad)

    return True, (f"authentic (m-of-n over the embedded certificate) + bound + faithful projection; "
                  f"reproduction/vocabulary/grounding NOT checked standalone (needs the VIGIL verifier). "
                  f"trust-root {pin_note}")


# ---------------------------------------------------------------------------
# 7. Single signed-finding bundle (SPEC §8): ONE SignedEvidence + its trust root
# ---------------------------------------------------------------------------
FINDING_BUNDLE_FORMAT = "vigil.pcf-finding-bundle/1"
# The oracle_context provenance values that may back a FACT (SPEC §8.3). A certificate whose SIGNED
# ``provenance`` member is present and outside this set declares a non-FACT context (e.g. "llm").
_FACT_PROVENANCE = ("reproduced", "live_redrive")
_HEX64 = "0123456789abcdef"


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX64 for ch in value)


def verify_finding_bundle(bundle: Any, *, pin: str = "", oracle_context: Any = None,
                          evidence_root: Path | None = None) -> tuple[bool, list[str]]:
    """Verify ONE signed finding record (a ``vigil.pcf-finding-bundle/1`` document, SPEC §8).

    Always checked (each one fails the bundle closed):
      * shape        — the format tag, a certificate object, a non-empty signature list, a trust root;
      * fingerprint  — the trust root matches the out-of-band pin (and the bundle's own convenience copy
                       of the fingerprint, when present, matches the computed one);
      * faithful     — the bundle's ``cert_digest`` / ``finding_ref`` (when present) equal the signed
                       certificate's own values (no lying wrapper);
      * authentic    — m-of-n Ed25519 over ``crucible-evidence-v1\\0`` + the canonical certificate;
      * provenance   — the certificate does not declare a non-FACT oracle_context provenance.
    Checked only when the input is supplied (and reported NOT CHECKED otherwise):
      * bound        — ``oracle_context`` re-hashes to the signed ``oracle_context_digest``;
      * artifacts    — each declared raw file re-hashes under ``evidence_root``.
    Never checked here: reproduction (needs the VIGIL verifier) and the engagement chain (a
    single-finding bundle carries none — that is the ``bundle`` mode's layer).

    Returns ``(verified, log)``; ``verified`` is True iff every always-checked layer and every supplied
    optional layer passed. A hostile shape no layer anticipates (an unhashable key id, a non-numeric
    threshold, ...) is a refusal like any other — ``False`` and ``finding NOT VERIFIED`` — never a crash."""
    log: list[str] = []
    try:
        return _verify_finding_bundle(bundle, log, pin=pin, oracle_context=oracle_context,
                                      evidence_root=evidence_root)
    except Exception as e:  # noqa: BLE001 — fail closed: an unanticipated shape refuses, it never verifies
        log.append(f"  [BAD] malformed bundle: {type(e).__name__}: {str(e)[:200]}")
        log.append("finding NOT VERIFIED")
        return False, log


def _verify_finding_bundle(bundle: Any, log: list[str], *, pin: str, oracle_context: Any,
                           evidence_root: Path | None) -> tuple[bool, list[str]]:
    def refuse(reason: str) -> tuple[bool, list[str]]:
        log.append(f"  [BAD] {reason}")
        log.append("finding NOT VERIFIED")
        return False, log

    if not isinstance(bundle, dict):
        return refuse("the bundle is not a JSON object")
    if bundle.get("format") != FINDING_BUNDLE_FORMAT:
        return refuse(f"unsupported bundle format {bundle.get('format')!r} (expected {FINDING_BUNDLE_FORMAT!r})")
    se = bundle.get("signed_evidence")
    if not isinstance(se, dict):
        return refuse("signed_evidence must be an object")
    cert = se.get("certificate")
    sigs = se.get("signatures")
    if not isinstance(cert, dict):
        return refuse("signed_evidence.certificate must be an object")
    if not isinstance(sigs, list) or not sigs:
        return refuse("signed_evidence.signatures must be a non-empty list")
    trust_root = bundle.get("trust_root")
    if not isinstance(trust_root, dict):
        return refuse("trust_root must be an object")

    # --- fingerprint pin (the out-of-band anchor), before any crypto ---
    pin_ok, fp, pin_note = _check_pin(trust_root, pin)
    log.append(f"  trust-root fingerprint: {fp}  ({pin_note})")
    if not pin_ok:
        return refuse("trust root is not the pinned governance key set")
    shipped = bundle.get("trust_root_fingerprint")
    if shipped is not None and shipped != fp:
        return refuse(f"the bundle's trust_root_fingerprint ({shipped}) != computed ({fp})")

    # --- faithful wrapper: the convenience fields restate the SIGNED certificate exactly ---
    cert_bytes = canonical_json(cert)
    cert_digest = sha256_hex(cert_bytes)
    declared = bundle.get("cert_digest")
    if declared is not None and declared != cert_digest:
        return refuse(f"the bundle's cert_digest ({declared}) != the signed certificate's ({cert_digest}) "
                      f"— lying wrapper")
    ref = bundle.get("finding_ref")
    if ref is not None and ref != cert.get("finding_ref"):
        return refuse(f"the bundle's finding_ref ({ref!r}) != the signed certificate's "
                      f"({cert.get('finding_ref')!r}) — lying wrapper")
    log.append(f"  certificate: finding_ref={cert.get('finding_ref')!r} bug_class={cert.get('bug_class')!r} "
               f"cert_digest={cert_digest}")

    # --- authenticity: m-of-n over the canonical certificate under the evidence domain ---
    authentic, valid, thr_reason = verify_threshold(_EVIDENCE_DOMAIN + cert_bytes, sigs, trust_root)
    log.append(f"  [{'OK ' if authentic else 'BAD'}] authentic: {thr_reason}"
               + (f" (valid key_ids: {', '.join(valid)})" if valid else ""))

    # --- provenance: an LLM-authored (non-FACT) context declared in the signed bytes is refused ---
    prov = cert.get("provenance")
    prov_ok = prov is None or prov in _FACT_PROVENANCE
    log.append(f"  [{'OK ' if prov_ok else 'BAD'}] provenance: "
               + ("reproduced (a FACT-eligible oracle_context channel)" if prov is None
                  else f"{prov!r}" + ("" if prov_ok else " — a NON-FACT context; this is not a FACT")))

    # --- binding (optional input) ---
    bound: bool | None = None
    if oracle_context is not None:
        want = cert.get("oracle_context_digest")
        bound = _is_hex64(want) and digest_payload(oracle_context) == want
        log.append(f"  [{'OK ' if bound else 'BAD'}] bound: the supplied oracle_context "
                   + ("re-hashes to the signed oracle_context_digest" if bound
                      else "does NOT re-hash to the signed oracle_context_digest (evidence altered or wrong file)"))
    else:
        log.append("  [-- ] bound: NOT CHECKED — the retained oracle_context is not part of this bundle "
                   "(pass --oracle-context FILE to check it)")

    # --- artifacts (optional input) ---
    artifacts_ok: bool | None = None
    arts = cert.get("artifacts") or []
    if not isinstance(arts, list):
        return refuse("certificate.artifacts must be a list")
    if not arts:
        log.append("  [-- ] artifacts: none declared by the certificate")
    elif evidence_root is None:
        log.append(f"  [-- ] artifacts: {len(arts)} declared, NOT CHECKED — the raw evidence is not part of "
                   f"this bundle (pass --evidence-root DIR to re-hash it)")
    else:
        res = verify_manifest([a if isinstance(a, dict) else {} for a in arts], evidence_root)
        bad = [f"{p}: {n}" for p, ok, n in res if not ok]
        artifacts_ok = not bad
        log.append(f"  [{'OK ' if artifacts_ok else 'BAD'}] artifacts: "
                   + (f"{len(res)} file(s) re-hash" if artifacts_ok else "FAILED: " + ", ".join(bad)))

    log.append("  [-- ] reproduced / chained: NOT CHECKED standalone — re-running the oracle needs the retained "
               "oracle_context and the VIGIL verifier; a single-finding bundle carries no engagement chain")
    pinned = bool((pin or "").strip())
    checked = (["fingerprint"] if pinned else []) + ["authenticity", "provenance"]
    if bound is not None:
        checked.append("binding")
    if artifacts_ok is not None:
        checked.append("artifacts")
    ok = authentic and prov_ok and bound is not False and artifacts_ok is not False
    log.append(f"finding {'VERIFIED' if ok else 'NOT VERIFIED'} (standalone: {' + '.join(checked)}; "
               f"reproduction needs the VIGIL verifier"
               + ("" if pinned else "; UNPINNED — pass --trust-root-fingerprint to anchor authenticity") + ")")
    return ok, log


# ---------------------------------------------------------------------------
# 8. CLI
# ---------------------------------------------------------------------------
def _cmd_bundle(args: argparse.Namespace) -> int:
    if args.prove_standalone:
        _assert_vigil_free()
    try:
        prev_hw = None
        if args.highwater:
            try:
                prev_hw = int(json.loads(Path(args.highwater).read_text(encoding="utf-8"))["last_seq"])
            except (OSError, json.JSONDecodeError, KeyError, ValueError, TypeError):
                prev_hw = None
        sound, log = verify_bundle_dir(
            Path(args.bundle), pin=args.trust_root_fingerprint,
            report_path=Path(args.report) if args.report else None,
            evidence_root=Path(args.evidence_root) if args.evidence_root else None,
            prev_highwater=prev_hw)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    for line in log:
        print(line)
    return 0 if sound else 2


def _cmd_pcf(args: argparse.Namespace) -> int:
    if args.prove_standalone:
        _assert_vigil_free()
    try:
        trust_root = json.loads(Path(args.trust_root).read_text(encoding="utf-8"))
        doc = json.loads(Path(args.pcf).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    certs = doc.get("pcf_certificates") if isinstance(doc, dict) and "pcf_certificates" in doc \
        else (doc if isinstance(doc, list) else [doc])
    er = Path(args.evidence_root) if args.evidence_root else None
    ok_n = 0
    for c in certs:
        ok, reason = verify_pcf_cert(c, trust_root, pin=args.trust_root_fingerprint, evidence_root=er)
        ok_n += ok
        cid = c.get("id") if isinstance(c, dict) else "?"
        print(f"  [{'VERIFIED' if ok else 'REJECTED':8}] {cid} — {reason}")
    print(f"{ok_n}/{len(certs)} PCF certificate(s) verified standalone")
    return 0 if certs and ok_n == len(certs) else 2


def _cmd_finding(args: argparse.Namespace) -> int:
    if args.prove_standalone:
        _assert_vigil_free()
    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        oracle_context = (json.loads(Path(args.oracle_context).read_text(encoding="utf-8"))
                          if args.oracle_context else None)
    except (OSError, ValueError, RecursionError) as e:    # unreadable / not UTF-8 / not JSON / nested too deep
        print(f"[ERROR] {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
        return 3
    verified, log = verify_finding_bundle(
        bundle, pin=args.trust_root_fingerprint, oracle_context=oracle_context,
        evidence_root=Path(args.evidence_root) if args.evidence_root else None)
    for line in log:
        print(line)
    return 0 if verified else 2


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="verify_pcf.py",
        description="Standalone reference verifier for VIGIL proof bundles / PCF v0.1 (stdlib + Ed25519 only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bundle", help="verify an evidence bundle directory")
    b.add_argument("--bundle", required=True, help="the bundle directory (evidence-bundle.json + trust-root.json + …)")
    b.add_argument("--trust-root-fingerprint", default="", dest="trust_root_fingerprint",
                   help="the out-of-band fingerprint pin (sha256:… or bare hex); a mismatch refuses the bundle")
    b.add_argument("--report", default="", help="reverifiable.json (default: <bundle>/reverifiable.json)")
    b.add_argument("--evidence-root", default="", dest="evidence_root",
                   help="raw evidence tree (default: <bundle>/evidence)")
    b.add_argument("--highwater", default="", help="anti-rollback high-water JSON ({\"last_seq\": N})")
    b.add_argument("--prove-standalone", action="store_true",
                   help="first assert no VIGIL module is imported or importable, else exit non-zero")
    b.set_defaults(fn=_cmd_bundle)

    c = sub.add_parser("pcf", help="verify PCF v0.1 certificate(s)")
    c.add_argument("--pcf", required=True, help="a PCF certificate JSON file (single cert or {pcf_certificates:[…]})")
    c.add_argument("--trust-root", required=True, dest="trust_root", help="the governance TrustRoot JSON")
    c.add_argument("--trust-root-fingerprint", default="", dest="trust_root_fingerprint",
                   help="the out-of-band fingerprint pin (sha256:… or bare hex)")
    c.add_argument("--evidence-root", default="", dest="evidence_root", help="raw evidence tree (for artifact certs)")
    c.add_argument("--prove-standalone", action="store_true",
                   help="first assert no VIGIL module is imported or importable, else exit non-zero")
    c.set_defaults(fn=_cmd_pcf)

    f = sub.add_parser("finding", help="verify ONE signed finding record (a single-finding bundle, SPEC §8)")
    f.add_argument("--bundle", required=True, help="the single-finding bundle JSON (e.g. proof-bundle.json)")
    f.add_argument("--trust-root-fingerprint", default="", dest="trust_root_fingerprint",
                   help="the out-of-band fingerprint pin (sha256:… or bare hex); a mismatch refuses the bundle")
    f.add_argument("--oracle-context", default="", dest="oracle_context",
                   help="OPTIONAL: the finding's retained oracle_context JSON, to also check binding")
    f.add_argument("--evidence-root", default="", dest="evidence_root",
                   help="OPTIONAL: the raw evidence tree, to re-hash the artifacts the certificate declares")
    f.add_argument("--prove-standalone", action="store_true",
                   help="first assert no VIGIL module is imported or importable, else exit non-zero")
    f.set_defaults(fn=_cmd_finding)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
