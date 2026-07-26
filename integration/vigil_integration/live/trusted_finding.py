"""trusted_finding — SOUND, provenance-grounded finding sources for ``vigil patch`` (VIGIL-FUSION LAP-3b).

The auto-patch pipeline remediates ONLY an oracle-CONFIRMED fact — but a ``TriageFinding`` deserialized from
raw JSON is trivially forgeable: its own validator accepts ``confirmed=True`` with any NON-EMPTY
``evidence_ref`` STRING (a *present* ref, not a *verified* one). So ``vigil patch`` NEVER builds its driving
finding from argv / stdin / a raw finding file. It admits a finding only from a source whose confirmed
status is CRYPTOGRAPHICALLY grounded, and it sets ``confirmed=True`` only AFTER that verification passes:

  * :func:`finding_from_envelope` — a signed inert finding envelope (the offense→sovereign seam datum). The
    m-of-n CRUCIBLE-governance signature (anchor 1) is verified with ``vigil_core`` alone, under a trust root
    DERIVED from an OWNER-SIGNED delegation (``verify_delegation``, fail-closed on wrong-owner / wrong-role /
    out-of-scope / expired), and the cert's OWN signed ``engagement_slug`` is bound to the delegated scope
    (anti-laundering). This mirrors the sovereign ``FindingReceiver.ingest`` verification exactly.
  * :func:`finding_from_spine` — a fact rebuilt from the engagement's OWN signed, hash-chained offense spine
    (``{slug}.spine``). ``VigilCoreSpine.verify()`` audits the whole file fail-closed, then ``.rebuild()``
    re-verifies each record signature AND the fact/evidence validator, so ``state.facts`` are cryptographically
    confirmed (a forged evidence-less "fact" is dropped by rebuild and never materialises).

Two provisioning loaders (:func:`load_destruction_authority`, :func:`load_signed_authorization`) let the
``--open-pr`` leg wire the m-of-n ``file_backed_quorum`` from operator-provisioned files.

Import-clean: ``vigil_core`` + the offense-local remediation/spine modules only — NO framework/strix/sigil.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable, Optional


class TrustedFindingError(Exception):
    """A finding source (or destruction provisioning) could not be cryptographically grounded — refuse.

    Every path in this module fails CLOSED by raising this: an unreadable/forged/expired/out-of-scope
    delegation, an unverified signature, a mismatched engagement scope, a failed spine audit, or a malformed
    provisioning file all raise — a caller must then patch nothing."""


def finding_from_envelope(*, envelope_path: str, owner_pubkey: str, delegation_path: str, scope: str,
                          target_repo: str, target_branch: str = "",
                          now: Optional[int] = None) -> Any:
    """Build a CONFIRMED ``TriageFinding`` from a signed inert finding envelope (Option C — the soundest,
    portable input). Fail-closed at every axis; ``confirmed=True`` is set ONLY after anchor-1 verifies.

    Order mirrors ``FindingReceiver.ingest``: derive the governance trust root from the OWNER-signed
    delegation → validate the inert envelope → verify the m-of-n governance signature (anchor 1) → bind the
    cert's own signed ``engagement_slug`` to the delegated scope. ``target_repo`` (which repo to patch) is an
    operator deployment choice, not part of the signed finding, so it comes from the caller.
    """
    from vigil_core.delegation import (
        OFFENSE_GOVERNANCE_ROLE,
        DelegationCert,
        DelegationError,
        verify_delegation,
    )

    from ..inert_finding import InertFindingError, validate_inert_finding
    from ..remediation.triage import TriageFinding

    if not str(owner_pubkey or "").strip():
        raise TrustedFindingError("an owner public key (--owner-pubkey) is required to anchor the delegation")
    if not str(scope or "").strip():
        raise TrustedFindingError("a --scope (engagement slug) is required for the envelope path")
    clock = int(now if now is not None else time.time())

    # (1) The owner-signed delegation authorizing the offense-governance trust root.
    try:
        cert = DelegationCert.model_validate_json(Path(delegation_path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — unreadable/invalid cert ⇒ no forged owner tie
        raise TrustedFindingError(f"could not load the offense-governance delegation: {exc}") from exc

    # (2) Derive the governance trust root FROM the owner-signed delegation (never handed in blindly).
    try:
        trust_root = verify_delegation(cert, trusted_owner_pubkey=str(owner_pubkey), now=clock,
                                       role=OFFENSE_GOVERNANCE_ROLE, scope=str(scope))
    except DelegationError as exc:
        raise TrustedFindingError(
            f"offense-governance delegation invalid — refusing the finding: {exc}") from exc

    # (3) Validate the inbound envelope as INERT DATA (json-only, size-bounded, strictly shaped).
    try:
        blob = Path(envelope_path).read_bytes()
    except OSError as exc:
        raise TrustedFindingError(f"could not read the finding envelope: {exc}") from exc
    try:
        vf = validate_inert_finding(blob)
    except InertFindingError as exc:
        raise TrustedFindingError(f"not a valid inert finding envelope: {exc}") from exc

    # (4) Anchor 1 — the m-of-n governance signature must satisfy the delegated trust root.
    try:
        verified = vf.verify_signature(trust_root)
    except Exception as exc:  # noqa: BLE001 — malformed sig/key material ⇒ fail-closed
        raise TrustedFindingError(
            f"finding {vf.finding_ref!r}: signature material is malformed — {exc} (anchor 1 failed)") from exc
    if verified is not True:
        raise TrustedFindingError(
            f"finding {vf.finding_ref!r}: m-of-n governance signature does not satisfy the trust root — "
            f"refusing to patch an unverified finding (anchor 1 failed)")

    # (5) Scope binding (anti-laundering, mirrors FindingReceiver.ingest): a non-wildcard scope admits ONLY a
    #     finding whose OWN signed engagement_slug matches it — else an authentic finding could be laundered
    #     under another engagement's label.
    if str(scope) != "*" and vf.engagement_slug != str(scope):
        raise TrustedFindingError(
            f"finding {vf.finding_ref!r}: engagement_slug {vf.engagement_slug!r} is outside the delegated "
            f"scope {str(scope)!r} — refusing (cross-engagement finding)")

    # (6) Build the CONFIRMED TriageFinding from the VERIFIED certificate. confirmed=True is JUSTIFIED: the
    #     m-of-n governance signature over these exact bytes verified. evidence_ref = the signed proof digest
    #     (non-empty: validate_inert_finding guarantees oracle_context_digest is a non-empty string).
    cert_d = vf.certificate
    evidence_ref = vf.oracle_context_digest
    return TriageFinding(
        ref=vf.finding_ref,
        title=str(cert_d.get("title") or ""),
        bug_class=str(cert_d.get("bug_class") or cert_d.get("category") or ""),
        severity=str(cert_d.get("severity") or ""),
        target=str(cert_d.get("target") or cert_d.get("location") or ""),
        confirmed=True,
        evidence_ref=evidence_ref,
        spine_hash=evidence_ref,
        target_repo=str(target_repo or ""),
        target_branch=str(target_branch or ""),
    )


def finding_from_spine(*, base_dir: str, slug: str, target_repo: str, finding_ref: str = "",
                       target_branch: str = "") -> Any:
    """Build a CONFIRMED ``TriageFinding`` from the engagement's OWN signed offense spine (Option B — the
    offense-local convenience). ``VigilCoreSpine.verify()`` audits the whole ``{slug}.spine`` file fail-closed
    (every Ed25519 entry sig + the vigil_core hash-chain), then ``.rebuild()`` re-verifies each record and the
    fact/evidence validator — so a rebuilt ``state.facts`` entry is cryptographically confirmed, not a copied
    flag. Picks the single confirmed fact (or the one matching ``finding_ref``); refuses ambiguity."""
    from vigil_core.vault import Vault

    from ..remediation.triage import TriageFinding
    from .spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from .spine_vigilcore import VigilCoreSpine

    base = Path(base_dir)
    spine_path = base / f"{slug}.spine"
    if not spine_path.exists():
        raise TrustedFindingError(
            f"no engagement spine at {spine_path} (run `vigil engage --slug {slug} --base-dir {base_dir}` first)")

    # Load the STABLE offense-spine keypair the engagement wrote with (its public half verifies signatures). A
    # missing key file yields a fresh key whose pubkey won't match → verify() fails → refuse (fail-closed).
    vault = Vault(base / "vault")
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=vault)
    spine = VigilCoreSpine(spine_kp, str(spine_path), readonly=True)   # readonly: NEVER mutate the audited spine
    if spine.verify() is not True:
        raise TrustedFindingError(
            f"{spine_path} FAILED integrity verification — refusing to patch from a tampered spine (fail-closed)")

    state = spine.rebuild(engagement=slug)
    facts = [f for f in getattr(state, "facts", [])
             if str(getattr(f, "status", "")) == "fact" and str(getattr(f, "evidence_ref", "") or "").strip()]
    if not facts:
        raise TrustedFindingError(f"{spine_path}: no confirmed facts to patch")
    if str(finding_ref or "").strip():
        facts = [f for f in facts if str(getattr(f, "ref", "")) == str(finding_ref)]
        if not facts:
            raise TrustedFindingError(f"no confirmed fact with ref {finding_ref!r} on {spine_path}")
    if len(facts) > 1:
        refs = ", ".join(sorted(str(getattr(f, "ref", "")) for f in facts))
        raise TrustedFindingError(
            f"{spine_path} has {len(facts)} confirmed facts — pass --finding-ref to choose one of: {refs}")

    f = facts[0]
    return TriageFinding(
        ref=str(getattr(f, "ref", "")),
        title=str(getattr(f, "title", "") or ""),
        bug_class=str(getattr(f, "bug_class", "") or ""),
        severity=str(getattr(f, "severity", "") or ""),
        target=str(getattr(f, "target", "") or ""),
        confirmed=True,
        evidence_ref=str(getattr(f, "evidence_ref", "")),
        spine_hash=str(getattr(f, "evidence_ref", "")),
        target_repo=str(target_repo or ""),
        target_branch=str(target_branch or ""),
    )


def load_destruction_authority(*, trust_root_path: str, mandatory_signer_ids: Iterable[str]) -> Any:
    """Load the m-of-n destruction ``DestructionAuthority`` from a provisioned ``TrustRoot`` JSON + the set of
    MANDATORY signer key_ids (must include the owner). Fail-closed: an unreadable/invalid trust root, or a
    mandatory set that is empty or not a subset of the trust root's authorizers, raises."""
    from vigil_core import TrustRoot

    from ..destruction_gate import DestructionAuthority

    try:
        tr = TrustRoot.model_validate_json(Path(trust_root_path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — unreadable/invalid ⇒ refuse
        raise TrustedFindingError(f"could not load the destruction trust root: {exc}") from exc
    ids = frozenset(str(s).strip() for s in mandatory_signer_ids if str(s).strip())
    if not ids:
        raise TrustedFindingError("at least one --mandatory-signer (the owner) is required for --open-pr")
    try:
        return DestructionAuthority(trust_root=tr, mandatory_signer_ids=ids)
    except ValueError as exc:
        raise TrustedFindingError(f"invalid destruction authority: {exc}") from exc


def load_signed_authorization(path: str) -> Any:
    """Load a ``SignedDestructionAuthorization`` (the owner+workers' m-of-n signature over ONE destructive
    action) from JSON of shape ``{"authorization": {action_id, engagement_slug, target, blast_class,
    not_before, not_after, nonce}, "signatures": [{key_id, signature_b64}, ...]}``. This is inert DATA — the
    signatures are re-verified by ``authorize_destruction`` (the gate), not trusted here; this loader only
    reconstructs the typed record fail-closed on any malformation."""
    from vigil_core import Signature

    from ..destruction_gate import DestructionAuthorization, SignedDestructionAuthorization

    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — unreadable/invalid JSON ⇒ refuse
        raise TrustedFindingError(f"could not load the signed authorization: {exc}") from exc
    if not isinstance(d, dict):
        raise TrustedFindingError("signed authorization must be a JSON object")
    auth_d = d.get("authorization")
    sigs_d = d.get("signatures")
    if not isinstance(auth_d, dict) or not isinstance(sigs_d, list) or not sigs_d:
        raise TrustedFindingError(
            'signed authorization needs {"authorization": {...}, "signatures": [{key_id, signature_b64}, ...]}')
    try:
        auth = DestructionAuthorization(
            action_id=str(auth_d["action_id"]), engagement_slug=str(auth_d["engagement_slug"]),
            target=str(auth_d["target"]), blast_class=str(auth_d["blast_class"]),
            not_before=float(auth_d["not_before"]), not_after=float(auth_d["not_after"]),
            nonce=str(auth_d["nonce"]))
        sigs = tuple(Signature(key_id=str(s["key_id"]), signature_b64=str(s["signature_b64"]))
                     for s in sigs_d if isinstance(s, dict))
    except (KeyError, TypeError, ValueError) as exc:
        raise TrustedFindingError(f"malformed signed authorization: {exc}") from exc
    if len(sigs) != len(sigs_d):
        raise TrustedFindingError("every signature must be an object with key_id + signature_b64")
    return SignedDestructionAuthorization(authorization=auth, signatures=sigs)
