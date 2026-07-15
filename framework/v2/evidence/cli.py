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
import sys
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
    out = []
    for s in specs or []:
        kid, _, priv = s.partition(":")
        if kid and priv:
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


def _load_highwater(path: Path) -> int | None:
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["last_seq"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None


def _verify(args: argparse.Namespace) -> int:
    bundle = json.loads((Path(args.bundle) / "evidence-bundle.json").read_text(encoding="utf-8"))
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    trust_root = TrustRoot.model_validate_json(Path(args.trust_root).read_text(encoding="utf-8"))
    evidence_root = Path(args.evidence_root) if args.evidence_root else None

    # oracle_contexts indexed by finding_ref (the certify ref rule); per-cert digest
    # binding catches any mismatch even if refs collide.
    ctx_by_ref: dict[str, dict] = {}
    for f in _findings(report):
        if isinstance(f, dict) and f.get("oracle_context"):
            ref = str(f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding")
            ctx_by_ref[ref] = f["oracle_context"]

    certificates = [SignedEvidence.model_validate(raw) for raw in bundle.get("certificates", [])]
    chain = [ChainEntry.model_validate(e) for e in bundle.get("chain", [])]
    head = SignedChainHead.model_validate(bundle["head"]) if bundle.get("head") else None

    # anti-rollback: read the persisted high-water mark so a stale, validly-signed
    # smaller bundle (a suppressed finding) is refused.
    hw_path = Path(args.highwater) if args.highwater else None
    prev_hw = _load_highwater(hw_path) if hw_path else None

    result = verify_bundle(certificates, chain, head, contexts=ctx_by_ref,
                           trust_root=trust_root, evidence_root=evidence_root,
                           prev_highwater=prev_hw)

    for v in result.certificate_results:
        mark = "OK " if v.ok else "BAD"
        print(f"  [{mark}] {v.finding_ref}: authentic={v.authentic} bound={v.bound} "
              f"artifacts_ok={v.artifacts_ok} reproduced={v.reproduced} — {v.reason}")
    print(f"  chain: {'OK ' if result.chain_ok and result.cert_set_bound else 'BAD'} — {result.chain_note}")

    ok_n = sum(1 for v in result.certificate_results if v.ok)
    print(f"verified {ok_n}/{len(result.certificate_results)} certificate(s) sound; "
          f"bundle {'SOUND' if result.ok else 'NOT SOUND'}")

    # advance the high-water only on a fully-sound bundle
    if result.ok and hw_path is not None and head is not None:
        new_hw = max(prev_hw or 0, head.last_seq)
        hw_path.write_text(json.dumps({"last_seq": new_hw}), encoding="utf-8")

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
