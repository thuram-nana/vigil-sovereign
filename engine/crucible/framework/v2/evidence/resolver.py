"""
evidence.resolver — a tenant-scoped, read-only, content-addressed evidence-by-id resolver.

WHAT THIS IS (and is NOT). This closes the "no evidence-by-ID resolver" gap: given a
certificate's content-address (its ``cert_digest``), dereference the exact ``SignedEvidence``
for it from the signed PCF bundle(s) ALREADY on disk under ``crucible_root()``, and — through
the ONE existing verifier (``evidence.certify.verify_certificate``) — re-establish its truth
over the retained bytes and the pinned governance trust root. It is a thin INDEX over evidence
certs the system already wrote; it is NOT a new store, adds no database, and the append-only
event spine remains the single source of truth. A later investigation-graph slice can resolve +
re-verify an ``evidence_ref`` through this before trusting it.

INVARIANTS (all mechanised by the test suite beside this file):

  * DEFAULT-OFF behind ``VIGIL_EVIDENCE_RESOLVER`` (affirmative-flag parsing, mirroring the rest
    of this package). When the flag is not affirmative, :func:`get_resolver` constructs NOTHING
    and the module-level :func:`resolve` / :func:`resolve_and_verify` return the inert ``None`` /
    not-resolved answer — nothing observable changes, and every existing evidence/certify byte
    stays identical (this module is purely additive and is imported by nothing on the hot path).

  * CONTENT-ADDRESSED. A match is decided by RECOMPUTING ``signed.certificate.cert_digest`` from
    the parsed certificate's own canonical bytes and comparing it to the requested id — never by
    a filename, a bundle key, or any external alias. So a one-byte mutation of a stored cert
    changes its digest, and the OLD id resolves to ``None`` (no stale alias).

  * TENANT-SCOPED + READ-ONLY. The index walks ONLY the ``crucible_root()`` tree (an id that
    exists only under a different root is invisible), never follows symlinks out of it, and only
    ever READS — it writes nothing and changes no mtimes.

  * FAIL-CLOSED. An unknown, dangling, backing-less, cross-tenant, or malformed id resolves to
    ``None``; a resolver NEVER fabricates a ``SignedEvidence``. :func:`EvidenceResolver.resolve_and_verify`
    is ``ok`` ONLY when the EXISTING ``verify_certificate`` re-fires the oracle and confirms over the
    retained bytes AND the m-of-n Ed25519 signatures verify against the pinned trust root. Signature
    authority is only ever TIGHTENED, never relaxed.

  * DETERMINISTIC. No wallclock, no RNG — a pure function of the on-disk contents (bundle files are
    walked in sorted order, so a duplicated cert_digest resolves to the first copy in path order).

  * REUSE, don't rebuild. Verification is delegated to ``verify_certificate`` verbatim; this module
    defines NO second verifier and carries no network, exec, or offense capability — it is defensive
    indexing over bytes the system already retained.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from ..common.paths import crucible_root
from ..entitlement.models import TrustRoot
from .certify import EvidenceVerification, verify_certificate
from .models import SignedEvidence

# --------------------------------------------------------------------------------------------------
# Default-OFF flag. Same affirmative vocabulary + parsing as the rest of this package (e.g.
# ``certify._PRESENTATION_AFFIRMATIVE``), so an operator turns the resolver on with one env value.
# --------------------------------------------------------------------------------------------------
_RESOLVER_ENV = "VIGIL_EVIDENCE_RESOLVER"
_RESOLVER_AFFIRMATIVE = frozenset({"1", "true", "yes", "on", "enabled"})

# The on-disk PCF bundle layout (written by ``evidence.audit_package.write_package``): a directory
# holding the signed certificate set, the governance trust root, the per-ref oracle_contexts, an
# optional primary-artifact index, and the raw executor-captured evidence tree.
_BUNDLE_FILENAME = "evidence-bundle.json"
_TRUST_ROOT_FILENAME = "trust-root.json"
_CONTEXTS_FILENAME = "contexts.json"
_ARTIFACTS_INDEX_FILENAME = "artifacts.json"
_EVIDENCE_SUBDIR = "evidence"

# Directory names the index never descends into: VCS / build-state / vendored / worktree-state trees
# that never hold a published evidence bundle. Pruning them keeps the index inside the visible
# engagement tree (and off the heavy, cross-worktree state dirs), and is a pure function of the
# directory names on disk — so the walk stays deterministic and confined.
_PRUNE_DIRNAMES = frozenset({
    ".git", ".hg", ".svn", ".claude", "node_modules", "__pycache__",
    ".venv", ".venv-offense", ".venv-sovereign", ".mypy_cache", ".pytest_cache", ".ruff_cache",
})


def resolver_enabled() -> bool:
    """True iff ``VIGIL_EVIDENCE_RESOLVER`` is affirmative (default False). The single arming point:
    when False, :func:`get_resolver` builds nothing and the module is inert."""
    return (os.environ.get(_RESOLVER_ENV) or "").strip().lower() in _RESOLVER_AFFIRMATIVE


def _normalize_id(cert_digest: str) -> str:
    """Normalise a requested id to the bare lowercase hex ``cert_digest`` form: strip an optional
    ``sha256:`` prefix and surrounding whitespace, and lowercase it (sha256 hex is case-insensitive).
    A non-string / empty id normalises to ``""`` (which never matches — fail-closed)."""
    if not isinstance(cert_digest, str):
        return ""
    s = cert_digest.strip()
    if s[:7].lower() == "sha256:":
        s = s[7:]
    return s.strip().lower()


@dataclass(frozen=True)
class ResolveVerification:
    """The verdict of :func:`EvidenceResolver.resolve_and_verify` for a resolved id. ``ok`` delegates
    to the REUSED ``verify_certificate`` verdict — the resolver adds no soundness logic of its own.

    A caller that wanted a certificate's content-address re-established holds, at once: the exact
    on-disk ``signed`` evidence (``cert_digest`` is the id that resolved to it), and the full
    ``EvidenceVerification`` (authenticity / binding / artifact integrity / reproduction / grounding /
    schema / tier). ``resolve_and_verify`` returns ``None`` — never a ``ResolveVerification`` — when the
    id does not resolve, so a verdict object always carries a real resolved certificate."""

    cert_digest: str                     # the normalised id that resolved
    signed: SignedEvidence               # the exact on-disk SignedEvidence whose cert_digest == id
    verification: EvidenceVerification    # the reused verify_certificate verdict over retained bytes

    @property
    def ok(self) -> bool:
        return self.verification.ok


class EvidenceResolver:
    """A read-only, content-addressed index over the signed PCF bundle(s) under one root.

    Construct via :func:`get_resolver` (which honours the default-OFF flag and defaults the root to
    ``crucible_root()``). The index is rebuilt from disk on each public call, so the resolver is a
    pure function of current on-disk contents (a cert mutated on disk is reflected immediately — no
    stale cache)."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    # -- bundle discovery ---------------------------------------------------------------------------
    def _iter_bundle_files(self) -> Iterator[Path]:
        """Every ``evidence-bundle.json`` under the root, in deterministic (sorted) traversal order.
        Never follows a symlinked directory out of the root, and skips a symlinked bundle file — so the
        index can never reach another tenant's tree or a file outside ``crucible_root()``."""
        root = self._root
        try:
            if not root.is_dir():
                return
        except OSError:
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune state/vendored dirs and any symlinked subdir; sort for a deterministic walk.
            kept = []
            for d in sorted(dirnames):
                if d in _PRUNE_DIRNAMES:
                    continue
                try:
                    if os.path.islink(os.path.join(dirpath, d)):
                        continue
                except OSError:
                    continue
                kept.append(d)
            dirnames[:] = kept
            if _BUNDLE_FILENAME in filenames:
                p = Path(dirpath) / _BUNDLE_FILENAME
                try:
                    if not p.is_symlink():
                        yield p
                except OSError:
                    continue

    def _load_signed(self, bundle_file: Path) -> list[SignedEvidence]:
        """Parse one bundle file into its ``SignedEvidence`` set. A malformed bundle, or a certificate
        entry that does not validate, contributes nothing (fail-closed — never raises)."""
        try:
            raw = json.loads(bundle_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(raw, dict):
            return []
        out: list[SignedEvidence] = []
        for entry in raw.get("certificates") or []:
            try:
                out.append(SignedEvidence.model_validate(entry))
            except Exception:  # noqa: BLE001 — a malformed cert is skipped, never fatal (fail-closed)
                continue
        return out

    def _find(self, want_normalized: str) -> Optional[tuple[SignedEvidence, Path]]:
        """The first on-disk ``(SignedEvidence, bundle_dir)`` whose RECOMPUTED ``cert_digest`` equals the
        normalised id, in deterministic path order; ``None`` if none matches. Recomputing the digest from
        the parsed certificate is what makes the lookup content-addressed (a mutated cert no longer
        answers to its old id)."""
        if not want_normalized:
            return None
        for bundle_file in self._iter_bundle_files():
            for signed in self._load_signed(bundle_file):
                try:
                    digest = signed.certificate.cert_digest
                except Exception:  # noqa: BLE001 — a cert whose digest cannot be computed cannot match
                    continue
                if digest.lower() == want_normalized:
                    return (signed, bundle_file.parent)
        return None

    # -- public API ---------------------------------------------------------------------------------
    def resolve(self, cert_digest: str) -> Optional[SignedEvidence]:
        """Content-addressed lookup: the exact ``SignedEvidence`` whose
        ``certificate.cert_digest == cert_digest``, or ``None`` when no on-disk bundle under the root
        carries it. Never raises, never partial, never fabricates."""
        match = self._find(_normalize_id(cert_digest))
        return match[0] if match is not None else None

    def resolve_and_verify(
        self,
        cert_digest: str,
        contexts: Optional[dict[str, dict]] = None,
        *,
        trust_root: Optional[TrustRoot] = None,
        expected_trust_root_fingerprint: Optional[str] = None,
    ) -> Optional[ResolveVerification]:
        """Resolve the id, then re-establish its truth through the EXISTING ``verify_certificate``.

        Returns ``None`` when the id does not resolve (fail-closed — an unknown / dangling / cross-tenant
        id never yields a fabricated verdict). Otherwise returns a :class:`ResolveVerification` whose
        ``ok`` is True ONLY when ``verify_certificate`` confirms authenticity (m-of-n Ed25519 over the
        pinned trust root) + binding + artifact integrity + reproduction + claim grounding + a known
        schema over the retained bytes.

        ``contexts`` maps ``finding_ref -> oracle_context`` (the re-fire evidence); the certificate's own
        ``finding_ref`` selects its context. When the ref is absent from ``contexts`` the bundle's own
        ``contexts.json`` is used as a fallback. The governance trust root, the raw-artifact evidence
        root, and any gating primary-artifact bytes come from the resolved certificate's own bundle dir
        unless an explicit ``trust_root`` is supplied. ``expected_trust_root_fingerprint`` (optional)
        pins the bundle's trust root to an out-of-band fingerprint — a mismatch fails authenticity
        before any signature check (authority only ever tightens)."""
        match = self._find(_normalize_id(cert_digest))
        if match is None:
            return None
        signed, bundle_dir = match
        cert = signed.certificate
        ref = cert.finding_ref

        oracle_context: dict = {}
        if isinstance(contexts, dict):
            supplied = contexts.get(ref)
            if isinstance(supplied, dict):
                oracle_context = supplied
        if not oracle_context:
            oracle_context = self._bundle_context(bundle_dir, ref)

        tr = trust_root if trust_root is not None else self._bundle_trust_root(bundle_dir)
        if tr is None:
            # No governance anchor on disk and none supplied: there is nothing to authenticate against,
            # so the certificate cannot be sound. Fail-closed to a not-ok verdict rather than raising.
            verification = EvidenceVerification(
                finding_ref=ref, authentic=False, bound=False,
                reason="no trust root available for the resolved bundle — cannot authenticate (fail-closed)")
            return ResolveVerification(cert_digest=_normalize_id(cert_digest), signed=signed,
                                       verification=verification)

        evidence_root_dir = bundle_dir / _EVIDENCE_SUBDIR
        try:
            ev_root: Optional[Path] = evidence_root_dir if evidence_root_dir.is_dir() else None
        except OSError:
            ev_root = None
        artifact_bytes = self._primary_artifact_bytes(bundle_dir, ref, signed)

        verification = verify_certificate(
            signed,
            oracle_context=oracle_context,
            trust_root=tr,
            evidence_root=ev_root,
            expected_trust_root_fingerprint=expected_trust_root_fingerprint,
            artifact_bytes=artifact_bytes,
        )
        return ResolveVerification(cert_digest=_normalize_id(cert_digest), signed=signed,
                                   verification=verification)

    # -- bundle-sidecar readers (all read-only, all fail-closed) ------------------------------------
    def _bundle_trust_root(self, bundle_dir: Path) -> Optional[TrustRoot]:
        p = bundle_dir / _TRUST_ROOT_FILENAME
        try:
            if p.is_file() and not p.is_symlink():
                return TrustRoot.model_validate_json(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 — an absent/malformed trust root is handled by the caller
            return None
        return None

    def _bundle_context(self, bundle_dir: Path, ref: str) -> dict:
        p = bundle_dir / _CONTEXTS_FILENAME
        try:
            if p.is_file() and not p.is_symlink():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    oc = data.get(ref)
                    if isinstance(oc, dict):
                        return oc
        except (OSError, ValueError):
            return {}
        return {}

    def _primary_artifact_bytes(self, bundle_dir: Path, ref: str,
                                signed: SignedEvidence) -> Optional[bytes]:
        """The raw bytes of the gating primary artifact for ``ref`` (posture FACTs that opted into the
        ``artifact_recheck_required`` re-check ship them under ``artifacts/`` via an ``artifacts.json``
        index), or ``None`` when the cert did not opt in / the index is absent. The path is CONFINED to
        the bundle dir, so a hostile index can never read a file outside it. A re-checkable cert whose
        bytes are missing fails CLOSED inside ``verify_certificate``."""
        if not getattr(signed.certificate, "artifact_recheck_required", False):
            return None
        idx_path = bundle_dir / _ARTIFACTS_INDEX_FILENAME
        try:
            if not (idx_path.is_file() and not idx_path.is_symlink()):
                return None
            index = json.loads(idx_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(index, dict):
            return None
        rel = index.get(ref)
        if not isinstance(rel, str) or not rel:
            return None
        try:
            root = bundle_dir.resolve()
            fp = (bundle_dir / rel).resolve()
            if fp.is_relative_to(root) and fp.is_file() and not fp.is_symlink():
                return fp.read_bytes()
        except (OSError, ValueError):
            return None
        return None


# --------------------------------------------------------------------------------------------------
# Module-level entry points. The factory honours the default-OFF flag; the convenience wrappers return
# the inert answer when the flag is off, so a caller can call them unconditionally.
# --------------------------------------------------------------------------------------------------
def get_resolver(root: Optional[Path] = None) -> Optional[EvidenceResolver]:
    """Construct an :class:`EvidenceResolver`, or ``None`` when ``VIGIL_EVIDENCE_RESOLVER`` is not
    affirmative (default OFF — NOTHING is constructed). ``root`` defaults to ``crucible_root()`` (the
    tenant-scoped tree); pass an explicit root for a scoped / hermetic lookup."""
    if not resolver_enabled():
        return None
    return EvidenceResolver(Path(root) if root is not None else crucible_root())


def resolve(cert_digest: str, *, root: Optional[Path] = None) -> Optional[SignedEvidence]:
    """Flag-gated convenience: resolve an evidence id to its ``SignedEvidence`` (``None`` when the flag
    is off or the id does not resolve)."""
    r = get_resolver(root)
    return r.resolve(cert_digest) if r is not None else None


def resolve_and_verify(
    cert_digest: str,
    contexts: Optional[dict[str, dict]] = None,
    *,
    root: Optional[Path] = None,
    trust_root: Optional[TrustRoot] = None,
    expected_trust_root_fingerprint: Optional[str] = None,
) -> Optional[ResolveVerification]:
    """Flag-gated convenience: resolve + re-verify an evidence id (``None`` when the flag is off or the
    id does not resolve)."""
    r = get_resolver(root)
    if r is None:
        return None
    return r.resolve_and_verify(
        cert_digest, contexts, trust_root=trust_root,
        expected_trust_root_fingerprint=expected_trust_root_fingerprint)


__all__ = [
    "EvidenceResolver",
    "ResolveVerification",
    "get_resolver",
    "resolve",
    "resolve_and_verify",
    "resolver_enabled",
]
