"""
evidence.cli — `python3 -m framework.v2 evidence <subcommand>`.

    keygen                                  generate an Ed25519 authoriser keypair (provisioning)
    certify --report R --slug S --out DIR [--signer kid:privb64 ...]
              build a signed evidence bundle (certificate per confirmed finding + a
              hash-linked, signed chain) from a ScanReport
    verify  --report R --bundle DIR --trust-root TR.json
              independently verify every certificate (authenticity + binding + artifact
              integrity + reproduction) AND the tamper-evident chain. Exit 0 iff all sound.
    pcf-export --report R --bundle DIR --out FILE
              project the signed bundle into Proof-Carrying Findings (PCF v0.1) certificates
    pcf-verify --pcf FILE --trust-root TR.json
              independently verify PCF certificates offline (PCF §6's five fail-closed steps).
              Exit 0 iff all verify.

Signing is a governance/provisioning action; the runtime path is `verify`, which only
ever checks. Offline throughout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from ..common import paths
from ..entitlement.crypto import generate_keypair
from ..entitlement.models import TrustRoot
from .certify import build_certificate, sign_certificate, verify_bundle
from .chain import build_chain, sign_head
from .models import ChainEntry, SignedChainHead, SignedEvidence


def _keygen(_args: argparse.Namespace) -> int:
    kp = generate_keypair()
    print(json.dumps({"public_key_b64": kp.public_key_b64,
                      "private_key_b64": kp.private_key_b64}, indent=2))
    return 0


def _parse_signers(specs: list[str]) -> list[tuple[str, str]]:
    """Parse ``key_id:private_key_b64`` signer specs STRICTLY: a malformed spec is an ERROR (never silently
    dropped — a governance signer that vanished would produce an unsigned bundle unnoticed), and a duplicate
    key_id is refused."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for s in specs or []:
        kid, sep, priv = s.partition(":")
        if not sep or not kid or not priv:
            raise ValueError(f"malformed --signer {s!r} (expected key_id:private_key_b64)")
        if kid in seen:
            raise ValueError(f"duplicate --signer key_id {kid!r}")
        seen.add(kid)
        out.append((kid, priv))
    return out


def _findings(report: dict) -> list[dict]:
    fs = report.get("active_findings")
    return fs if isinstance(fs, list) else ([report] if report.get("oracle_context") else [])


def _certify(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    signers = _parse_signers(args.signer)
    evidence_root = Path(args.evidence_root) if args.evidence_root else None

    signed_certs: list[SignedEvidence] = []
    for i, f in enumerate(_findings(report)):
        if not (isinstance(f, dict) and f.get("oracle_context")):
            continue
        cert = build_certificate(f, engagement_slug=args.slug, seq=i,
                                 evidence_root=evidence_root, action_id=f.get("action_id"))
        signed_certs.append(sign_certificate(cert, signers) if signers
                            else SignedEvidence(certificate=cert, signatures=[]))

    chain = build_chain([sc.certificate.cert_digest for sc in signed_certs])
    head = sign_head(chain, engagement_slug=args.slug, signers=signers) if signers else None

    out = paths.secure_dir(Path(args.out))          # X2: owner-only evidence dir
    paths.secure_write(out / "evidence-bundle.json", json.dumps({
        "engagement_slug": args.slug,
        "certificates": [sc.model_dump(mode="json") for sc in signed_certs],
        "chain": [e.model_dump(mode="json") for e in chain],
        "head": head.model_dump(mode="json") if head else None,
    }, indent=2))
    print(f"wrote {len(signed_certs)} certificate(s) + a {len(chain)}-entry chain to {out}"
          + ("" if signers else "  (UNSIGNED — no --signer given)"))
    return 0


class _HighwaterCorrupt(Exception):
    """The anti-rollback state file EXISTS but cannot be trusted — verification must REFUSE (fail-closed)."""


def _load_highwater(path: Path) -> int | None:
    """None iff the file is ABSENT (a legitimate first verification). If the file EXISTS but is a symlink,
    unreadable, malformed, or carries a non-integer last_seq, raise _HighwaterCorrupt so verification REFUSES
    — anti-rollback state you cannot trust must NEVER silently degrade to 'no previous mark' (that disables
    rollback protection exactly when its state is compromised)."""
    if not path.exists():
        return None
    if path.is_symlink():
        raise _HighwaterCorrupt(f"{path} is a symlink")
    try:
        seq = json.loads(path.read_text(encoding="utf-8"))["last_seq"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as e:
        raise _HighwaterCorrupt(f"{path} unreadable/malformed: {e}") from e
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise _HighwaterCorrupt(f"{path} last_seq is not a non-negative integer: {seq!r}")
    return seq


def _save_highwater(path: Path, seq: int) -> None:
    """Atomic + owner-only persist: temp file in the same dir → fsync → atomic rename → chmod 0600. Refuses a
    symlink target. (This is LOCAL rollback detection; a governance-signed or platform-monotonic store would be
    needed for cryptographically-guaranteed rollback PREVENTION — documented, not claimed here.)"""
    path = path.resolve()
    if path.is_symlink():
        raise ValueError(f"high-water path {path} is a symlink (refusing)")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".hw-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"last_seq": int(seq)}))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _verify(args: argparse.Namespace) -> int:
    from .certify import trust_root_fingerprint

    bundle = json.loads((Path(args.bundle) / "evidence-bundle.json").read_text(encoding="utf-8"))
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    trust_root = TrustRoot.model_validate_json(Path(args.trust_root).read_text(encoding="utf-8"))
    evidence_root = Path(args.evidence_root) if args.evidence_root else None

    # AUTHENTICITY ANCHOR (the one thing a verifier must trust): the trust root's public keys. Print its
    # fingerprint so it can be compared to a value the operator PUBLISHED OUT-OF-BAND. A --trust-root-
    # fingerprint pin makes that comparison enforceable (mismatch → refuse before any verify). If no pin is
    # given AND --trust-root resolves INSIDE --bundle, the anchor travels with the evidence, so authenticity
    # is UNPINNED — a party who controls the bundle could re-sign it under their own key + ship a matching
    # root; warn loudly (the reproduction/binding/artifact/chain layers still hold, so content cannot be forged).
    fp = trust_root_fingerprint(trust_root)
    print(f"  trust-root fingerprint: {fp}  (threshold {trust_root.threshold} of {len(trust_root.authorizers)})")
    pin = str(getattr(args, "trust_root_fingerprint", "") or "").strip()
    if pin:
        want = pin if pin.startswith("sha256:") else ("sha256:" + pin)
        if want.lower() != fp.lower():
            print(f"  [BAD] trust-root fingerprint pin MISMATCH — expected {want}, got {fp}", file=sys.stderr)
            print("bundle NOT SOUND (trust root not the pinned governance key)")
            return 2
        print("  trust-root fingerprint: PINNED OK")
    else:
        try:
            tr_inside = Path(args.trust_root).resolve().is_relative_to(Path(args.bundle).resolve())
        except (OSError, ValueError):
            tr_inside = False
        if tr_inside:
            print("  [WARN] UNPINNED TRUST ROOT — --trust-root is the copy shipped inside the bundle. Exit 0 "
                  "proves internal consistency + reproduction, NOT authenticity. Obtain the operator's "
                  f"governance fingerprint OUT-OF-BAND and re-run with --trust-root-fingerprint {fp}",
                  file=sys.stderr)

    # oracle_contexts indexed by finding_ref (the certify ref rule). DUPLICATE refs are REFUSED (an overwrite
    # would silently bind one certificate to another's context; the per-cert digest binding would then flag it,
    # but we refuse up-front rather than depend on that catch).
    ctx_by_ref: dict[str, dict] = {}
    for f in _findings(report):
        if isinstance(f, dict) and f.get("oracle_context"):
            ref = str(f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding")
            if ref in ctx_by_ref:
                print(f"  [BAD] DUPLICATE finding_ref in report: {ref!r} — refusing", file=sys.stderr)
                print("bundle NOT SOUND (duplicate finding_ref in the report contexts)")
                return 2
            ctx_by_ref[ref] = f["oracle_context"]

    certificates = [SignedEvidence.model_validate(raw) for raw in bundle.get("certificates", [])]
    chain = [ChainEntry.model_validate(e) for e in bundle.get("chain", [])]
    head = SignedChainHead.model_validate(bundle["head"]) if bundle.get("head") else None

    # anti-rollback: read the persisted high-water mark so a stale, validly-signed
    # smaller bundle (a suppressed finding) is refused.
    hw_path = Path(args.highwater) if args.highwater else None
    try:
        prev_hw = _load_highwater(hw_path) if hw_path else None
    except _HighwaterCorrupt as e:
        print(f"  [BAD] anti-rollback high-water state is corrupt: {e}", file=sys.stderr)
        print("bundle NOT SOUND (untrustworthy rollback state — refusing, fail-closed)")
        return 2

    # PRIMARY ARTIFACTS (posture FACTs that opted into the gating re-check): load the raw bytes the package
    # shipped under artifacts/ (indexed by finding_ref) so verify_bundle can recompute sha256 + cross-check the
    # signed artifact_sha256. Paths are CONFINED to the package dir (a hostile index cannot escape). A
    # re-checkable cert whose artifact is absent fails CLOSED inside verify_bundle.
    artifact_bytes_by_ref: dict[str, bytes] = {}
    pkg_root = Path(args.bundle).resolve()
    art_index_path = pkg_root / "artifacts.json"
    if art_index_path.is_file():
        try:
            art_index = json.loads(art_index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            art_index = {}
        for ref, rel in (art_index.items() if isinstance(art_index, dict) else []):
            try:
                fp_art = (pkg_root / str(rel)).resolve()
                if fp_art.is_relative_to(pkg_root) and fp_art.is_file():
                    artifact_bytes_by_ref[str(ref)] = fp_art.read_bytes()
            except (OSError, ValueError):
                continue

    result = verify_bundle(certificates, chain, head, contexts=ctx_by_ref,
                           trust_root=trust_root, evidence_root=evidence_root,
                           prev_highwater=prev_hw, artifact_bytes_by_ref=artifact_bytes_by_ref)

    for v in result.certificate_results:
        mark = "OK " if v.ok else "BAD"
        print(f"  [{mark}] {v.finding_ref}: authentic={v.authentic} bound={v.bound} "
              f"artifacts_ok={v.artifacts_ok} primary_artifact_ok={v.primary_artifact_ok} "
              f"reproduced={v.reproduced} — {v.reason}")
    print(f"  chain: {'OK ' if result.chain_ok and result.cert_set_bound else 'BAD'} — {result.chain_note}")

    ok_n = sum(1 for v in result.certificate_results if v.ok)
    print(f"verified {ok_n}/{len(result.certificate_results)} certificate(s) sound; "
          f"bundle {'SOUND' if result.ok else 'NOT SOUND'}")

    # advance the high-water only on a fully-sound bundle (atomic + owner-only + symlink-refusing)
    if result.ok and hw_path is not None and head is not None:
        new_hw = max(prev_hw or 0, head.last_seq)
        _save_highwater(hw_path, new_hw)

    return 0 if result.ok else 2


def _ctx_by_ref(report: dict) -> dict[str, dict]:
    return {str(f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding"): f["oracle_context"]
            for f in _findings(report) if isinstance(f, dict) and f.get("oracle_context")}


def _pcf_export(args: argparse.Namespace) -> int:
    """Project each signed certificate in a bundle into the PCF v0.1 wire format (the retained
    oracle_context comes from the report, by finding_ref — the same rule ``certify`` uses)."""
    from .pcf import to_pcf
    bundle = json.loads((Path(args.bundle) / "evidence-bundle.json").read_text(encoding="utf-8"))
    ctx = _ctx_by_ref(json.loads(Path(args.report).read_text(encoding="utf-8")))
    pcf_certs = []
    for raw in bundle.get("certificates", []):
        sc = SignedEvidence.model_validate(raw)
        oc = ctx.get(sc.certificate.finding_ref)
        if oc is None:
            print(f"  skip {sc.certificate.finding_ref}: no oracle_context in report", file=sys.stderr)
            continue
        pcf_certs.append(to_pcf(sc, oracle_context=oc))
    Path(args.out).write_text(json.dumps({"pcf_certificates": pcf_certs}, indent=2), encoding="utf-8")
    print(f"wrote {len(pcf_certs)} PCF certificate(s) to {args.out}")
    return 0


def _pcf_verify(args: argparse.Namespace) -> int:
    """Independently verify PCF certificates offline (PCF §6's five fail-closed steps). Exit 0 iff all
    verify. A trust root is REQUIRED — an un-anchored verify fails closed (ungoverned)."""
    from .pcf import verify_pcf
    doc = json.loads(Path(args.pcf).read_text(encoding="utf-8"))
    trust_root = TrustRoot.model_validate_json(Path(args.trust_root).read_text(encoding="utf-8"))
    evidence_root = Path(args.evidence_root) if args.evidence_root else None
    certs = doc.get("pcf_certificates") if isinstance(doc, dict) and "pcf_certificates" in doc \
        else (doc if isinstance(doc, list) else [doc])
    ok_n = 0
    for c in certs:
        r = verify_pcf(c, trust_root, evidence_root=evidence_root)
        ok_n += r.verified
        cid = c.get("id") if isinstance(c, dict) else "?"
        print(f"  [{'VERIFIED' if r.verified else 'REJECTED':8}] {cid}"
              + (f"  step={r.step}: {r.reason}" if not r.verified else ""))
    print(f"{ok_n}/{len(certs)} PCF certificate(s) verified")
    return 0 if certs and ok_n == len(certs) else 2


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 evidence",
        description="Cryptographic evidence integrity — signed, hash-linked, replayable certificates.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 authoriser keypair (provisioning)")
    p.set_defaults(fn=_keygen)

    p = sub.add_parser("certify", help="build a signed evidence bundle from a report")
    p.add_argument("--report", required=True)
    p.add_argument("--slug", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--signer", action="append", default=[], help="key_id:private_key_b64 (repeatable)")
    p.add_argument("--evidence-root", default="", dest="evidence_root")
    p.set_defaults(fn=_certify)

    p = sub.add_parser("verify", help="independently verify a signed evidence bundle")
    p.add_argument("--report", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--trust-root", required=True, dest="trust_root")
    p.add_argument("--trust-root-fingerprint", default="", dest="trust_root_fingerprint",
                   help="pin the governance trust root to a fingerprint the operator PUBLISHED OUT-OF-BAND "
                        "(sha256:… or bare hex); a mismatch refuses the bundle. Without it, an in-bundle "
                        "trust root is UNPINNED — exit 0 then proves consistency + reproduction, not authenticity")
    p.add_argument("--evidence-root", default="", dest="evidence_root",
                   help="root of the raw evidence tree — REQUIRED to check certificates "
                        "that carry an artifact manifest (they fail closed without it)")
    p.add_argument("--highwater", default="",
                   help="persisted anti-rollback high-water file: refuses a stale bundle "
                        "whose head last_seq is below the highest previously accepted")
    p.set_defaults(fn=_verify)

    p = sub.add_parser("pcf-export", help="project a signed evidence bundle into PCF v0.1 certificates")
    p.add_argument("--report", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--out", required=True, help="output JSON file of PCF certificates")
    p.set_defaults(fn=_pcf_export)

    p = sub.add_parser("pcf-verify", help="independently verify PCF v0.1 certificates offline (PCF §6)")
    p.add_argument("--pcf", required=True, help="a PCF certificates JSON file (from pcf-export)")
    p.add_argument("--trust-root", required=True, dest="trust_root")
    p.add_argument("--evidence-root", default="", dest="evidence_root",
                   help="root of the raw evidence tree — REQUIRED to check certs carrying an artifact manifest")
    p.set_defaults(fn=_pcf_verify)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
