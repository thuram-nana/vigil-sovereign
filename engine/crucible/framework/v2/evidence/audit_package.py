"""
evidence.audit_package — assemble a REPRODUCIBLE EXTERNAL-AUDIT PACKAGE (TRUTHENOVATION H4).

An audit package is a self-contained directory an EXTERNAL audit team re-verifies OFFLINE — with no VIGIL
runtime, no network, and no target. It bundles four things:

    <out>/
      evidence-bundle.json          # signed EvidenceCertificates + hash chain + governance-signed head
      contexts.json                 # {finding_ref: oracle_context} — what BINDING re-hashes against
      reverifiable.json             # {active_findings:[...]} — inputs for the FULL reproduction step
      trust-root.json               # PUBLIC governance keys + m-of-n threshold (the only thing to trust)
      TRUST-ROOT-FINGERPRINT.txt    # pin this against a value the operator publishes OUT-OF-BAND
      evidence/<action_id>/…        # the raw executor-captured bytes the certificates bind by sha256
      verify_offline.py             # the STANDALONE (stdlib + cryptography, NO VIGIL) re-verifier
      SCOPE.md / CHARTER.md         # the engagement scope + charter the audit is bounded by
      RUNBOOK.md                    # the external auditor's step-by-step

WHAT THE PACKAGE LETS AN EXTERNAL TEAM PROVE, AND WHAT STAYS RESIDUAL
--------------------------------------------------------------------
``verify_offline.py`` (shipped in the package, importing NOTHING from ``framework``/``vigil``) re-derives
AUTHENTICITY (m-of-n signature), BINDING (oracle_context ↔ digest), ARTIFACT INTEGRITY (raw bytes re-hash),
and CHAIN / anti-suppression — all offline, all without VIGIL. What it does NOT do is REPRODUCTION —
re-firing each deterministic oracle to re-derive the verdict without trusting the signer's honesty about
it. Re-firing an oracle needs the oracle's code, which is the OPEN-SOURCE VIGIL verifier
(``python3 -m framework.v2 evidence verify``), documented in the runbook as the second step. And the audit
ITSELF needs an external team — we PREPARE the package; we cannot BE the third party (the H4 residual).

This module REUSES the evidence/verify layer verbatim (``build_certificate`` / ``sign_certificate`` /
``build_chain`` / ``sign_head``) — it adds no new crypto. Signing is provisioning-only (the caller supplies
governance signers); the package on disk carries only PUBLIC material. FATAL-2: offense-side, imports
nothing sovereign.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional

from ..entitlement.models import TrustRoot
from .certify import (
    build_certificate,
    sign_certificate,
    trust_root_fingerprint,
)
from .chain import build_chain, sign_head
from .models import ChainEntry, EvidenceCertificate, PathCertificate, SignedChainHead, SignedEvidence

_VERIFIER_SRC = Path(__file__).with_name("audit_offline_verifier.py")


def _secure_write_text(path: Path, data: str) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)


def _secure_write_bytes(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _copy_evidence_tree(evidence_root: Path, dst: Path) -> None:
    """Copy the raw executor-captured evidence tree, NEVER following or shipping a symlink (a dereferenced
    link would materialise an outside file into a signed package — the dossier-BLOCK class). Only regular
    files under regular dirs are copied."""
    import shutil
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        return
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    for root, dirs, files in os.walk(evidence_root, followlinks=False):
        rootp = Path(root)
        dirs[:] = [d for d in dirs if not (rootp / d).is_symlink()]
        rel = rootp.relative_to(evidence_root)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(dst / rel, 0o700)
        except OSError:
            pass
        for name in files:
            src = rootp / name
            if src.is_symlink() or not src.is_file():
                continue
            target = dst / rel / name
            shutil.copyfile(src, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass


def _runbook_md(engagement_slug: str, fingerprint: str) -> str:
    return f"""# External-audit runbook — VIGIL package for `{engagement_slug}`

You are an INDEPENDENT auditor. This package proves each finding with a signed, re-runnable certificate.
You do NOT have to trust VIGIL's word — you re-run the checks yourself, offline. Nothing here needs a
network, a target, or the VIGIL runtime for Step 1.

## Step 0 — pin the trust root OUT-OF-BAND (this is what makes authenticity meaningful)

`trust-root.json` here is only a CONVENIENCE COPY. Obtain the operator's governance fingerprint through a
channel INDEPENDENT of this package (their website, a signed email), and compare it to
`TRUST-ROOT-FINGERPRINT.txt`:

    {fingerprint}

If they differ, STOP — someone re-signed the package under a different key.

## Step 1 — re-verify OFFLINE with the standalone verifier (NO VIGIL runtime)

`verify_offline.py` imports only the Python standard library and `cryptography`. It re-derives, from first
principles: authenticity (m-of-n Ed25519 signature), binding (oracle_context ↔ digest), artifact integrity
(raw bytes re-hash), and chain / anti-suppression (nothing deleted, injected, or reordered):

    python3 verify_offline.py --package . --trust-root-fingerprint <the fingerprint you pinned in Step 0>

Exit 0 = SOUND. A single flipped byte anywhere → non-zero.

## Step 2 — (optional, for a fully trust-free verdict) REPRODUCTION with the open-source VIGIL verifier

Step 1 proves the governance authorisers ATTESTED these exact oracle_contexts + verdicts, tamper-evidently.
To remove trust in the signer's honesty about a verdict, RE-FIRE each deterministic oracle over its
oracle_context. That needs the oracle's code — the open-source VIGIL verifier, which you obtain and audit
separately, then run:

    python3 -m framework.v2 evidence verify \\
        --report reverifiable.json --bundle . --trust-root trust-root.json --evidence-root evidence \\
        --trust-root-fingerprint <the fingerprint you pinned in Step 0>

This loads only the `evidence` / `verify` / `entitlement` / `common` subpackages (no offense engine).

## What you can conclude — and the honest residual

- After Step 1: authenticity + binding + integrity + anti-suppression, with NO trust in VIGIL's tooling
  beyond the verifier you just read.
- After Step 2: the above PLUS reproduction — each verdict re-derived by re-running the oracle.
- Residual: this package is what VIGIL can PREPARE. An independent audit conclusion is YOURS to write —
  VIGIL cannot BE the third party. Your scope is bounded by `SCOPE.md` / `CHARTER.md`.
"""


def write_package(
    out_dir: str | os.PathLike[str],
    *,
    certificates: list[SignedEvidence],
    chain: list[ChainEntry],
    head: Optional[SignedChainHead],
    contexts: dict[str, dict],
    trust_root: TrustRoot,
    evidence_root: Optional[Path] = None,
    scope: str = "",
    charter: str = "",
    engagement_slug: str = "engagement",
    path_certs: Optional[list[PathCertificate]] = None,
    reverifiable: Optional[dict] = None,
    artifact_bytes_by_ref: Optional[dict[str, bytes]] = None,
    replace: bool = False,
) -> dict:
    """Write a self-contained external-audit package to ``out_dir`` from ALREADY-SIGNED bundle components.

    ``contexts`` maps each certificate's ``finding_ref`` to the oracle_context it authenticates (what the
    standalone verifier re-hashes for BINDING). ``reverifiable`` (optional) is the ``{active_findings:[…]}``
    doc the Step-2 VIGIL reproduction consumes; when omitted it is synthesised from ``contexts``.

    ``artifact_bytes_by_ref`` (optional) ships the RAW PRIMARY ARTIFACT for each certificate that opted into
    the gating re-check (``artifact_recheck_required`` — posture FACTs whose bytes live in memory, not the
    on-disk evidence tree). The bytes travel under ``artifacts/`` with an ``artifacts.json`` index so a third
    party recomputes sha256 + cross-checks the signed ``artifact_sha256`` OFFLINE (a swapped artifact fails).

    Returns a summary dict ``{ok, package, fingerprint, verify_cmd, certificates}``."""
    path_certs = path_certs or []
    artifact_bytes_by_ref = artifact_bytes_by_ref or {}

    # CONSTRUCTION-TIME INVARIANTS (fail-closed — a missing required artifact must make CREATION fail, never
    # defer to the auditor). (1) finding_refs are UNIQUE (a duplicate would overwrite a context / collide in
    # the artifact index and make the package unverifiable after apparent success). (2) EVERY certificate that
    # opted into the gating re-check (artifact_recheck_required) MUST have non-empty raw bytes supplied here.
    refs = [sc.certificate.finding_ref for sc in certificates]
    dup_refs = sorted({r for r in refs if refs.count(r) > 1})
    if dup_refs:
        raise ValueError(f"duplicate finding_ref(s) in the certificate set: {dup_refs} — refusing to build")
    missing = sorted(sc.certificate.finding_ref for sc in certificates
                     if getattr(sc.certificate, "artifact_recheck_required", False)
                     and not artifact_bytes_by_ref.get(sc.certificate.finding_ref))
    if missing:
        raise ValueError(f"certificate(s) require an artifact re-check but no raw bytes were supplied: "
                         f"{missing} — refusing to build a package that would fail closed at verify")

    out = Path(out_dir)
    # Refuse a NON-EMPTY destination unless explicitly replacing it — a reused dir could retain another
    # engagement's certificates / artifacts (cross-engagement leakage). The caller passes a fresh dir.
    if out.exists() and any(out.iterdir()) and not replace:
        raise ValueError(f"output dir {out} is not empty (pass replace=True to overwrite) — refusing")
    if out.exists() and replace:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out, 0o700)
    except OSError:
        pass

    fingerprint = trust_root_fingerprint(trust_root)

    bundle = {
        "engagement_slug": engagement_slug,
        "certificates": [sc.model_dump(mode="json") for sc in certificates],
        "chain": [e.model_dump(mode="json") for e in chain],
        "head": head.model_dump(mode="json") if head is not None else None,
        "path_certs": [pc.model_dump(mode="json") for pc in path_certs],
    }
    _secure_write_text(out / "evidence-bundle.json", json.dumps(bundle, indent=2, sort_keys=True))
    _secure_write_text(out / "contexts.json", json.dumps(contexts, sort_keys=True))
    _secure_write_text(out / "trust-root.json", trust_root.model_dump_json())
    _secure_write_text(out / "TRUST-ROOT-FINGERPRINT.txt", fingerprint + "\n")

    if reverifiable is None:
        # Carry check_id == finding_ref: the documented step-2 `evidence verify` CLI derives its context ref
        # from check_id/finding_slug/bug_class, so an entry with only finding_ref would map to the fallback
        # "finding" and MISS a posture FACT's composite ref (k8s:cis:...#digest) — reporting NOT SOUND a package
        # verify_offline.py reports SOUND (red-pen). Setting check_id keeps step-1 and step-2 consistent.
        reverifiable = {"active_findings": [
            {"finding_ref": ref, "check_id": ref, "oracle_context": ctx} for ref, ctx in sorted(contexts.items())]}
    _secure_write_text(out / "reverifiable.json", json.dumps(reverifiable, sort_keys=True))

    _secure_write_text(out / "SCOPE.md", scope or f"# Scope — {engagement_slug}\n\n(no scope text supplied)\n")
    _secure_write_text(out / "CHARTER.md", charter or f"# Charter — {engagement_slug}\n\n(no charter supplied)\n")
    _secure_write_text(out / "RUNBOOK.md", _runbook_md(engagement_slug, fingerprint))

    # ship the standalone verifier VERBATIM (it imports no VIGIL). Made executable for convenience.
    verifier_bytes = _VERIFIER_SRC.read_bytes()
    _secure_write_bytes(out / "verify_offline.py", verifier_bytes)
    try:
        os.chmod(out / "verify_offline.py", 0o700)
    except OSError:
        pass
    # A verifier shipped INSIDE the object it verifies cannot bootstrap its own trust: publish this SHA-256
    # out-of-band (the VIGIL repo) and have the auditor compare it — or, better, obtain verify_offline.py from
    # the separately-authenticated VIGIL source. This sidecar makes that comparison concrete + honest.
    verifier_sha = hashlib.sha256(verifier_bytes).hexdigest()
    _secure_write_text(out / "VERIFIER-SHA256.txt", verifier_sha + "  verify_offline.py\n")

    if evidence_root is not None:
        _copy_evidence_tree(Path(evidence_root), out / "evidence")

    # Ship the raw PRIMARY ARTIFACTS for certs that opted into the gating re-check, under artifacts/ with a
    # finding_ref -> relpath index. The filename is derived from a hash of the finding_ref (confined, no
    # attacker-controlled path); the verifier recomputes sha256 over the file and cross-checks the SIGNED
    # artifact_sha256 — so a swapped artifact fails offline (a re-checkable cert whose artifact is missing
    # fails CLOSED).
    art_index: dict[str, str] = {}
    if artifact_bytes_by_ref:
        art_dir = out / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(art_dir, 0o700)
        except OSError:
            pass
        for ref, raw in sorted(artifact_bytes_by_ref.items()):
            if not raw:
                continue
            fname = hashlib.sha256(str(ref).encode("utf-8")).hexdigest()[:32] + ".bin"
            _secure_write_bytes(art_dir / fname, bytes(raw))
            art_index[str(ref)] = f"artifacts/{fname}"
    _secure_write_text(out / "artifacts.json", json.dumps(art_index, sort_keys=True))

    return {
        "ok": True,
        "package": str(out),
        "fingerprint": fingerprint,
        "certificates": len(certificates),
        "verify_cmd": f"python3 verify_offline.py --package . --trust-root-fingerprint {fingerprint}",
    }


def build_audit_package(
    out_dir: str | os.PathLike[str],
    *,
    findings: list[dict],
    signers: list[tuple[str, str]],
    trust_root: TrustRoot,
    evidence_root: Optional[Path] = None,
    scope: str = "",
    charter: str = "",
    engagement_slug: str = "engagement",
    artifact_bytes_by_ref: Optional[dict[str, bytes]] = None,
) -> dict:
    """End-to-end: build + sign certificates from oracle-confirmed ``findings`` (each carrying an
    ``oracle_context``), chain + sign a head, and write the external-audit package. Reuses the evidence
    layer verbatim — no new crypto.

    ``signers`` is a list of (key_id, private_key_b64) governance authorisers whose PUBLIC keys are the
    ``trust_root`` (provisioning-only; the private keys never touch disk here). A finding with no
    ``oracle_context`` is dropped (a package carries only oracle-confirmed FACTs)."""
    usable = [f for f in findings if isinstance(f, dict) and f.get("oracle_context")]
    if not usable:
        return {"ok": False, "error": "no oracle-confirmed findings to package (each needs an oracle_context)"}

    ev_root = Path(evidence_root) if evidence_root is not None else None
    signed_certs: list[SignedEvidence] = []
    contexts: dict[str, dict] = {}
    for i, f in enumerate(usable):
        aid = str(f.get("action_id") or "")
        ap = Path(aid)
        safe_aid = bool(aid) and not ap.is_absolute() and ".." not in ap.parts and ap == Path(ap.name)
        has_artifacts = bool(ev_root) and safe_aid and (ev_root / aid).is_dir()
        cert: EvidenceCertificate = build_certificate(
            f, engagement_slug=engagement_slug, seq=i,
            evidence_root=(ev_root if has_artifacts else None),
            action_id=(aid if has_artifacts else None))
        signed_certs.append(sign_certificate(cert, signers))
        contexts[cert.finding_ref] = f.get("oracle_context") or {}

    chain = build_chain([sc.certificate.cert_digest for sc in signed_certs])
    head = sign_head(chain, engagement_slug=engagement_slug, signers=signers)

    return write_package(
        out_dir, certificates=signed_certs, chain=chain, head=head, contexts=contexts,
        trust_root=trust_root, evidence_root=ev_root, scope=scope, charter=charter,
        engagement_slug=engagement_slug,
        reverifiable={"active_findings": usable},
        artifact_bytes_by_ref=artifact_bytes_by_ref)
