"""
proof.bundle — assemble a CLIENT-VERIFIABLE proof bundle from a run's retained proofs (Proof Studio C1).

A "proof bundle" is a self-contained directory a third party verifies OFFLINE, with ZERO trust in VIGIL:

    <out>/
      evidence-bundle.json   # the signed EvidenceCertificates + hash chain + governance-signed head
      trust-root.json        # the PUBLIC governance keys + m-of-n threshold (the only thing to trust)
      reverifiable.json      # the {active_findings:[...]} report — each finding's oracle_context, to re-fire
      evidence/<action_id>/… # the raw executor-captured bytes the certificate binds by sha256
      README.md              # the one-command verify

Verify it yourself (needs no target, no network, and none of VIGIL's offense engine — the open-source
verifier loads only the evidence + verify + entitlement + common subpackages of ``framework.v2``):

    python -m framework.v2 evidence verify \\
        --report reverifiable.json --bundle . --trust-root trust-root.json --evidence-root evidence \\
        --trust-root-fingerprint <the fingerprint the operator published OUT-OF-BAND>

Exit 0 iff SOUND: every certificate's signature validates m-of-n against the trust root, its oracle_context
re-fires the SAME deterministic oracle (reproduction), its bound raw bytes re-hash, and the chain/head bind
the certificate set so none was suppressed, injected, or reordered. A single flipped byte anywhere → NOT SOUND.

You do NOT trust VIGIL's word — you re-run the deterministic check yourself. What you DO trust reduces to two
auditable things: (1) the operator's governance PUBLIC key, identified by the fingerprint in
``TRUST-ROOT-FINGERPRINT.txt`` — you must obtain that fingerprint from the operator OUT-OF-BAND (a channel
independent of this bundle) and pin it with ``--trust-root-fingerprint``, because the ``trust-root.json``
shipped here is only a convenience copy; and (2) the open-source verifier itself, which you obtain and audit
separately. Without the out-of-band pin, exit 0 proves internal consistency + reproduction but NOT
authenticity (whoever produced the bundle could have signed it with any key).

FATAL-2: every ``framework.v2`` import here is LAZY (function-local); the module scope pulls only ``.run``
(import-clean) + stdlib, so importing ``proof.bundle`` in the sovereign env never loads ``framework``.
Determinism: no wallclock / rng — cert order is the reverifiable-finding order; ``seq`` is the index.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional

from .run import read_reverifiable

_README = """# VIGIL proof bundle — verify it yourself, offline

This bundle proves each finding with a signed, re-runnable certificate. You do NOT have to trust VIGIL's
word — you re-run the deterministic check yourself. It needs no target and no network.

## Step 1 — pin the trust root OUT-OF-BAND (this is what makes it zero-trust)

`trust-root.json` here is only a CONVENIENCE COPY. Its authenticity is anchored by a fingerprint you must
obtain from the operator through a channel INDEPENDENT of this bundle (their website, a signed email, etc.),
then compare to `TRUST-ROOT-FINGERPRINT.txt`. Without that out-of-band comparison, anyone who handed you the
bundle could have re-signed it under their own key — so pin it:

    python -m framework.v2 evidence verify \\
        --report reverifiable.json --bundle . --trust-root trust-root.json --evidence-root evidence \\
        --trust-root-fingerprint <fingerprint the operator published out-of-band>

The verifier prints the loaded root's fingerprint and REFUSES the bundle if your pin does not match.

## Step 2 — read the verdict

Exit code 0 means SOUND. For every certificate the verifier independently checks, ALL must hold:

  * authentic  — the signature validates m-of-n against the pinned governance public keys;
  * bound      — the certificate is bound (by sha256) to this exact oracle_context, not another;
  * reproduced — the SAME deterministic oracle re-fires over the retained context (the proof reproduces);
  * artifacts  — every raw byte under evidence/ re-hashes to the value the certificate recorded;
  * chained    — the hash chain + governance-signed head bind the whole certificate SET, so none was
                 suppressed, injected, or reordered.

Flip a single byte in any file and the verify fails closed. `trust-root.json` carries only PUBLIC keys.

## What you trust (and what you don't)

You do NOT trust VIGIL's claims — the reproduction + binding + artifact + chain layers are re-run by the
open-source verifier, so no signer (not even a dishonest one) can make a NON-reproducing finding pass. You DO
trust exactly two auditable things: the operator's governance public key (pinned by fingerprint, Step 1) and
the open-source `framework.v2` verifier, which you obtain and audit separately.
"""


def _secure_write(path: Path, data: str) -> None:
    """Write owner-only (0600), no world-readable window (mirrors framework paths.secure_write, stdlib-only)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)


def export_bundle(
    *,
    run_dir: str | os.PathLike,
    out_dir: str | os.PathLike,
    engagement_slug: str = "engagement",
    base_dir: Optional[str] = None,
    vault: Any = None,
) -> dict:
    """Build the client-verifiable bundle for ``run_dir`` under ``out_dir`` and return a summary dict
    ``{ok, bundle, certificates, verify_cmd}`` (``{ok: False, error}`` when there is nothing to export or a
    step fails). Signs with the run's STABLE governance authority (``base_dir`` seals the key) — the private
    key is only ever a Python argument, never argv/spine; only the PUBLIC trust root is written to disk."""
    from framework.v2.evidence.certify import build_certificate, sign_certificate, trust_root_fingerprint  # lazy — FATAL-2
    from framework.v2.evidence.chain import build_chain, sign_head
    from ..live.wiring import provision_authority

    doc = read_reverifiable(run_dir)
    findings = [f for f in doc.get("active_findings", []) if isinstance(f, dict) and f.get("oracle_context")]
    if not findings:
        return {"ok": False, "error": "no proven findings to export (a bundle carries only oracle-confirmed "
                                      "FACTs — run a scan that reproduces one first)"}

    prov = provision_authority(slug=engagement_slug, scope=["127.0.0.1"],
                               base_dir=(base_dir or str(run_dir)), vault=vault)
    evidence_root = Path(run_dir) / "evidence"

    signed_certs = []
    for i, f in enumerate(findings):
        # CONFINE the (file-supplied, hence untrusted) action_id to a single path segment INSIDE the
        # evidence tree before probing/manifesting it — an absolute or ``..``-bearing id would otherwise make
        # build_certificate walk + hash files outside the tree. A rejected id simply drops artifacts (the
        # cert still binds the oracle_context + reproduces); it never traverses.
        aid = str(f.get("action_id") or "")
        ap = Path(aid)
        safe_aid = bool(aid) and not ap.is_absolute() and ".." not in ap.parts and ap == Path(ap.name)
        has_artifacts = safe_aid and (evidence_root / aid).is_dir()
        cert = build_certificate(
            f, engagement_slug=engagement_slug, seq=i,
            evidence_root=(evidence_root if has_artifacts else None),
            action_id=(aid if has_artifacts else None))
        signed_certs.append(sign_certificate(cert, prov.signers))

    chain = build_chain([sc.certificate.cert_digest for sc in signed_certs])
    head = sign_head(chain, engagement_slug=engagement_slug, signers=prov.signers)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out, 0o700)
    except OSError:
        pass
    _secure_write(out / "evidence-bundle.json", json.dumps({
        "engagement_slug": engagement_slug,
        "certificates": [sc.model_dump(mode="json") for sc in signed_certs],
        "chain": [e.model_dump(mode="json") for e in chain],
        "head": head.model_dump(mode="json"),
    }, indent=2, sort_keys=True))
    _secure_write(out / "trust-root.json", prov.trust_root.model_dump_json())
    # the authenticity anchor the verifier PINS out-of-band (the shipped trust-root.json is only a copy).
    fingerprint = trust_root_fingerprint(prov.trust_root)
    _secure_write(out / "TRUST-ROOT-FINGERPRINT.txt", fingerprint + "\n")
    _secure_write(out / "reverifiable.json", json.dumps({"active_findings": findings}, sort_keys=True))
    _secure_write(out / "README.md", _README)

    # copy the raw executor-captured evidence tree the certificates bind (best-effort; a cert with no
    # artifacts verifies on reproduction alone). SYMLINKS ARE NEVER FOLLOWED OR SHIPPED: shutil.copytree with
    # the default symlinks=False DEREFERENCES them, materialising an OUTSIDE target's content into the bundle
    # (a "hand-to-anyone" exfiltration, and a signed manifest that would then vouch for it). We copy only
    # REGULAR files under REGULAR dirs, pruning every symlink — a certificate binds real captured bytes, never
    # a link. (Root-cause fix for the dossier BLOCK: the earlier copytree let an evidence-tree symlink escape.)
    if evidence_root.is_dir() and not evidence_root.is_symlink():
        dst = out / "evidence"
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        for root, dirs, files in os.walk(evidence_root, followlinks=False):
            rootp = Path(root)
            dirs[:] = [d for d in dirs if not (rootp / d).is_symlink()]   # never descend a symlinked subdir
            rel = rootp.relative_to(evidence_root)
            (dst / rel).mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(dst / rel, 0o700)
            except OSError:
                pass
            for name in files:
                src = rootp / name
                if src.is_symlink() or not src.is_file():
                    continue                     # skip symlinks + fifos/sockets/devices — never ship a link
                target = dst / rel / name
                shutil.copyfile(src, target)     # src verified a real file → copies bytes, follows no link
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    pass

    return {
        "ok": True,
        "bundle": str(out),
        "certificates": len(signed_certs),
        "trust_root_fingerprint": fingerprint,
        "verify_cmd": ("python -m framework.v2 evidence verify --report reverifiable.json --bundle . "
                       "--trust-root trust-root.json --evidence-root evidence "
                       "--trust-root-fingerprint " + fingerprint),
        "pin_note": ("PUBLISH this fingerprint out-of-band; the client pins it with --trust-root-fingerprint "
                     "so a re-signed bundle under another key is refused."),
    }
