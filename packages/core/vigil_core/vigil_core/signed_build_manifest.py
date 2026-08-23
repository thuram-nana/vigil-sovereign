"""vigil_core.signed_build_manifest — a SIGNED build manifest over ALL shipped artifacts, with EXPLICIT
integrity states (W4-3 #443 + W9-7 #440).

THE DEFECT THIS CLOSES. Two gaps, one mechanism:

  * #443 — the only build identifier the product carried covered the *browser bundle* only (a content hash
    stamped by ``uiproxy.assemble_serve_dir``). Three of the four things that ship — the Python code, the
    Rust WARDEN kernel, the gateway image — had NO identity at all. This module records EVERY shipped
    artifact (python / rust / browser bundle / gateway image) in ONE signed manifest, each with a
    content-addressed digest, and a manifest-wide ``build_id`` derived from those digests.

  * #440 — nothing let an operator ask a running install "are my own files the ones that shipped?" This
    module answers that with SIX explicit, mutually-exclusive integrity states — and NEVER an optimistic
    default:

      VALID              a signed manifest verifies under the pinned trust root AND every artifact on disk
                         matches its recorded digest.
      MODIFIED           the manifest verifies, but a shipped artifact's on-disk content differs.
      MISSING            the manifest verifies, but a shipped artifact is absent from disk.
      UNSIGNED_BUILD     a manifest is present (release channel) but carries NO signatures.
      UNKNOWN_BUILD      no manifest, an unreadable/malformed/too-new manifest, OR a manifest whose
                         signatures do NOT satisfy the pinned trust root — i.e. we cannot establish what
                         shipped. FAIL-CLOSED: this is the default when nothing can be attested, never VALID.
      DEVELOPMENT_BUILD  the manifest declares itself a development build (channel="development") — an
                         un-attested working tree, honestly labelled so it is never mistaken for a release.

REUSE, NOT A PARALLEL MECHANISM. Signing is byte-for-byte the repo's established pattern: domain-tagged
canonical JSON (``vigil_core.canonical``) signed with Ed25519 and verified by the SAME m-of-n
``verify_threshold`` the signed spine head uses (``vigil_core.chain.verify_head``). The only new constant is
this manifest's own domain tag. Signing is PROVISIONING-only (the release build signs); the runtime only
ever VERIFIES, exactly as the rest of vigil_core does.

DETERMINISM (a hard constraint on any signed path). The signed region — ``{manifest_schema, channel,
product_version, build_id, artifacts}`` — contains NO wall-clock and NO rng. ``build_id`` is DERIVED
(a digest over the sorted artifact digests), and ``artifacts`` is sorted by name. Given the same artifact
bytes the signing bytes are byte-identical, so two independent builds of the same tree produce the same
``build_id`` and the same signable manifest — and a REBUILT artifact with different content produces a
DIFFERENT ``build_id`` that fails verification against the old manifest (#443's negative control).

M-OF-N. The manifest is verified against a pinned :class:`~vigil_core.models.TrustRoot`; a solo owner is a
1-of-1 root, a release team an m-of-n one. When ``threshold > 1`` we additionally reject a trust root with
duplicate authoriser PUBLIC KEYS — a repeated pubkey under distinct key_ids would collapse the quorum to
one holder — mirroring ``vigil_core.delegation``'s own quorum-integrity guard.

HONEST SCOPE — READ THIS (mirrors ``install_manifest`` / ``integrity_verifier`` §). This is USER-SPACE
self-verification. It proves that the files on disk match a manifest signed by a key the RUNNING PROCESS
trusts. It does NOT, and cannot, defend against a HOSTILE ADMINISTRATOR who controls the same host: such an
admin can replace the shipped files, the manifest, the trust root AND this verifier together, then re-sign a
manifest under their own key. The only mitigation this module offers against that is an OUT-OF-BAND pinned
trust-root fingerprint (env ``VIGIL_BUILD_TRUST_ROOT_SHA256``): if the pin is delivered over a channel the
admin does not control and does not match the on-disk trust root, verification fails closed. Genuine
tamper-resistance against a hostile admin requires a hardware root of trust / measured boot / remote
attestation — OUTSIDE this user-space install. This is a tamper-DETECTION aid for an honest operator, not a
containment boundary against a privileged attacker.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .canonical import canonical_json, sha256_hex
from .crypto import verify_threshold
from .crypto import IntegrityError
from .spine_domains import DOMAIN_TAGS as _DOMAIN_TAGS
from .crypto import sign as _ed25519_sign
from .models import Signature, TrustRoot

# ── the six explicit integrity states (never an optimistic default) ─────────────────────────────────────


class BuildIntegrityState:
    """The six named build-integrity states. Mutually exclusive; the fail-closed default is UNKNOWN_BUILD
    (nothing can be attested), NEVER VALID."""

    VALID = "VALID"
    MODIFIED = "MODIFIED"
    MISSING = "MISSING"
    UNSIGNED_BUILD = "UNSIGNED_BUILD"
    UNKNOWN_BUILD = "UNKNOWN_BUILD"
    DEVELOPMENT_BUILD = "DEVELOPMENT_BUILD"


ALL_STATES: "frozenset[str]" = frozenset({
    BuildIntegrityState.VALID, BuildIntegrityState.MODIFIED, BuildIntegrityState.MISSING,
    BuildIntegrityState.UNSIGNED_BUILD, BuildIntegrityState.UNKNOWN_BUILD,
    BuildIntegrityState.DEVELOPMENT_BUILD,
})

# Per-artifact statuses (the breakdown inside a result). ATTESTED_ONLY marks an artifact whose identity is
# recorded and signed but which THIS context cannot re-hash locally (a gateway image with no observed
# digest supplied) — it is surfaced explicitly and never counted as a silent VALID.
ART_VALID = "VALID"
ART_MODIFIED = "MODIFIED"
ART_MISSING = "MISSING"
ART_ATTESTED_ONLY = "ATTESTED_ONLY"

#: The manifest's own format version. Bump only when the STRUCTURE changes in a way an older build cannot
#: read; an older build then refuses-newer the whole manifest (fail closed → UNKNOWN_BUILD).
BUILD_MANIFEST_SCHEMA = 1
_MAX_BUILD_MANIFEST_SCHEMA = BUILD_MANIFEST_SCHEMA

#: The domain tag over which the manifest content is signed. Distinct from the evidence-spine tag so a
#: signature over one can never be replayed as a signature over the other. Never change without a schema
#: bump (it invalidates every prior build signature).
BUILD_MANIFEST_DOMAIN = _DOMAIN_TAGS["build-manifest"]  # single source of truth (uniqueness-guarded in spine_domains)

#: Conventional on-disk filenames, relative to an install/tree root.
MANIFEST_FILENAME = "build-manifest.json"
TRUST_ROOT_FILENAME = "build-trust-root.json"

#: An out-of-band trust-root pin (sha256 hex of the trust-root file bytes). When set, a trust root whose
#: bytes do not match is refused (fail closed) — the one defence this module offers against a hostile admin
#: who swapped the on-disk trust root, and only as strong as the channel that delivered the pin.
_TRUST_ROOT_PIN_ENV = "VIGIL_BUILD_TRUST_ROOT_SHA256"

#: The two legal release channels.
CHANNEL_RELEASE = "release"
CHANNEL_DEVELOPMENT = "development"
_CHANNELS = frozenset({CHANNEL_RELEASE, CHANNEL_DEVELOPMENT})

#: Artifact kinds.
KIND_FILE = "file"
KIND_TREE = "tree"
KIND_IMAGE = "image"
_KINDS = frozenset({KIND_FILE, KIND_TREE, KIND_IMAGE})

#: Tree-digest exclusions: never-shipped build detritus that must not perturb a content hash.
_DEFAULT_TREE_EXCLUDES: "tuple[str, ...]" = ("__pycache__", ".pyc", ".pyo", ".DS_Store")


class BuildManifestError(Exception):
    """A malformed / unreadable / too-new build manifest, or malformed artifact material. Raised on the
    PARSE path; the evaluate path catches it and maps it to the fail-closed UNKNOWN_BUILD state."""


# ── artifact model ──────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BuildArtifact:
    """One shipped artifact recorded in the manifest.

    ``kind`` is one of ``file`` (a single file — e.g. the Rust WARDEN kernel binary or a wheel), ``tree``
    (a directory hashed as a Merkle over its sorted files — e.g. the Python package or the browser bundle),
    or ``image`` (a container image, identified by its content digest; not locally re-hashable from a
    user-space process without the image present, so verified against a supplied OBSERVED digest or reported
    ATTESTED_ONLY). ``digest`` is ``sha256:<hex>``. ``size`` is informational (total bytes for a tree; the
    file size for a file; ``0`` for an image)."""

    name: str
    kind: str
    path: str
    digest: str
    size: int = 0

    def content(self) -> dict:
        return {"name": str(self.name), "kind": str(self.kind), "path": str(self.path),
                "digest": str(self.digest), "size": int(self.size)}


# ── digest helpers (deterministic; content-addressed) ───────────────────────────────────────────────────


def _sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_file(path) -> "tuple[str, int]":
    """``(sha256:<hex>, size_bytes)`` for a single regular file. Raises if it is absent or not a regular
    file (a symlink/dir/device is not a shippable file artifact)."""
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise BuildManifestError(f"not a regular file: {path}")
    return "sha256:" + _sha256_of_file(p), p.stat().st_size


def digest_tree(root, *, excludes: "Sequence[str]" = _DEFAULT_TREE_EXCLUDES) -> "tuple[str, int]":
    """A deterministic Merkle-style digest over a directory tree: ``sha256`` over the sorted list of
    ``"<relpath>\\0<filehash>"`` for every REGULAR file under ``root`` (symlinks are NOT followed and are
    excluded — a symlink is not shippable content and following one is a traversal risk). Returns
    ``(sha256:<hex>, total_bytes)``.

    DETERMINISTIC: files are sorted by their POSIX relpath, so directory-walk order never changes the
    digest. Adding, removing, or altering ANY file under the tree changes the digest — which is exactly what
    makes a rebuilt bundle fail verification against the old manifest (#443)."""
    base = Path(root)
    if not base.is_dir():
        raise BuildManifestError(f"not a directory: {root}")
    exclude_suffixes = tuple(e for e in excludes if e.startswith("."))
    exclude_names = frozenset(e for e in excludes if not e.startswith("."))
    entries: "list[tuple[str, str, int]]" = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        # prune excluded directories (e.g. __pycache__) in place so os.walk does not descend into them
        dirnames[:] = sorted(d for d in dirnames if d not in exclude_names)
        for fn in filenames:
            if fn in exclude_names or fn.endswith(exclude_suffixes):
                continue
            fp = Path(dirpath) / fn
            if fp.is_symlink() or not fp.is_file():
                continue
            rel = fp.relative_to(base).as_posix()
            entries.append((rel, _sha256_of_file(fp), fp.stat().st_size))
    entries.sort(key=lambda e: e[0])
    h = hashlib.sha256()
    total = 0
    for rel, fh, sz in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(fh.encode("ascii"))
        h.update(b"\0")
        total += sz
    return "sha256:" + h.hexdigest(), total


# ── the signed manifest ─────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SignedBuildManifest:
    """A signed build manifest over every shipped artifact.

    ``build_id`` is NOT stored as an independent field — it is DERIVED from the artifact digests, so it can
    never disagree with them and adds no wall-clock/rng to the signed region. It is written into the on-disk
    form (``to_disk``) purely as a convenience identifier; verification always recomputes it."""

    manifest_schema: int
    channel: str
    product_version: str
    artifacts: "tuple[BuildArtifact, ...]"
    signatures: "tuple[Signature, ...]" = ()

    def _sorted_artifacts(self) -> "list[dict]":
        return [a.content() for a in sorted(self.artifacts, key=lambda a: a.name)]

    def build_id(self) -> str:
        """A deterministic 16-hex content id over the sorted artifact digests. Content-addressed: the same
        artifacts always yield the same id; any changed artifact yields a different one."""
        payload = [{"name": a["name"], "digest": a["digest"]} for a in self._sorted_artifacts()]
        return sha256_hex(canonical_json(payload))[:16]

    def content(self) -> dict:
        """The canonical SIGNED region — no signatures, no wall-clock, no rng."""
        return {
            "manifest_schema": int(self.manifest_schema),
            "channel": str(self.channel),
            "product_version": str(self.product_version),
            "build_id": self.build_id(),
            "artifacts": self._sorted_artifacts(),
        }

    def signing_bytes(self) -> bytes:
        """The exact bytes signed/verified: the manifest domain tag + canonical JSON of the signed region."""
        return BUILD_MANIFEST_DOMAIN + canonical_json(self.content())

    def to_disk(self) -> dict:
        d = self.content()
        d["signatures"] = [{"key_id": s.key_id, "signature_b64": s.signature_b64} for s in self.signatures]
        return d


def build_manifest_from_specs(*, product_version: str, channel: str,
                              specs: "Sequence[Mapping[str, object]]", tree_root) -> SignedBuildManifest:
    """Construct an UNSIGNED manifest by hashing artifact specs against ``tree_root``.

    Each spec is ``{"name", "kind", "path"}`` (``kind`` in ``file``/``tree``/``image``). For ``file`` /
    ``tree`` the ``path`` is resolved under ``tree_root`` and hashed now; for ``image`` the spec MUST also
    carry ``"digest"`` (``sha256:<hex>`` from ``docker inspect`` RepoDigests or the image tarball) and an
    optional ``"path"`` naming the image reference — an image is not hashed from the filesystem here."""
    if channel not in _CHANNELS:
        raise BuildManifestError(f"channel must be one of {sorted(_CHANNELS)}, got {channel!r}")
    root = Path(tree_root)
    artifacts: "list[BuildArtifact]" = []
    for spec in specs:
        name = str(spec.get("name", "")).strip()
        kind = str(spec.get("kind", "")).strip()
        rel = str(spec.get("path", "")).strip()
        if not name or kind not in _KINDS:
            raise BuildManifestError(f"artifact spec needs a name and kind in {sorted(_KINDS)}: {spec!r}")
        if kind == KIND_FILE:
            digest, size = digest_file(root / rel)
        elif kind == KIND_TREE:
            digest, size = digest_tree(root / rel)
        else:  # image
            digest = str(spec.get("digest", "")).strip()
            if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
                raise BuildManifestError(f"image artifact {name!r} needs a sha256:<hex> digest, got {digest!r}")
            size = int(spec.get("size", 0) or 0)
        artifacts.append(BuildArtifact(name=name, kind=kind, path=rel, digest=digest, size=size))
    return SignedBuildManifest(manifest_schema=BUILD_MANIFEST_SCHEMA, channel=channel,
                               product_version=str(product_version), artifacts=tuple(artifacts))


def sign_manifest(manifest: SignedBuildManifest,
                  signers: "Sequence[tuple[str, str]]") -> SignedBuildManifest:
    """Attach Ed25519 signatures over ``manifest.signing_bytes()`` (PROVISIONING-only — the release build
    signs; the runtime only verifies). ``signers`` is ``[(key_id, private_key_b64), ...]``."""
    msg = manifest.signing_bytes()
    sigs = tuple(Signature(key_id=kid, signature_b64=_ed25519_sign(priv, msg)) for kid, priv in signers)
    return SignedBuildManifest(manifest_schema=manifest.manifest_schema, channel=manifest.channel,
                               product_version=manifest.product_version, artifacts=manifest.artifacts,
                               signatures=sigs)


def build_signed_manifest(*, product_version: str, channel: str,
                          specs: "Sequence[Mapping[str, object]]", tree_root,
                          signers: "Sequence[tuple[str, str]]") -> SignedBuildManifest:
    """One-shot: hash the specs and sign the result."""
    return sign_manifest(build_manifest_from_specs(product_version=product_version, channel=channel,
                                                   specs=specs, tree_root=tree_root), signers)


# ── parse (fail-closed) ─────────────────────────────────────────────────────────────────────────────────


def parse_signed_manifest(data) -> SignedBuildManifest:
    """Parse an on-disk manifest (a dict or JSON text) into a :class:`SignedBuildManifest`, FAIL-CLOSED.

    Raises :class:`BuildManifestError` if it is unreadable, not a JSON object, missing a field, carries an
    unknown channel/kind, or declares a format NEWER than this build understands (refuse-newer). Does NOT
    check signatures or hashes — that is :func:`verify_build_integrity`'s job."""
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except ValueError as e:
            raise BuildManifestError(f"manifest is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise BuildManifestError("manifest is not a JSON object")
    try:
        schema = int(data["manifest_schema"])
    except (KeyError, TypeError, ValueError) as e:
        raise BuildManifestError("manifest_schema missing or not an integer") from e
    if schema > _MAX_BUILD_MANIFEST_SCHEMA:
        raise BuildManifestError(
            f"manifest format v{schema} is newer than this build understands (max "
            f"v{_MAX_BUILD_MANIFEST_SCHEMA}) — upgrade the binary; refusing to trust it (fail closed)")
    channel = str(data.get("channel", ""))
    if channel not in _CHANNELS:
        raise BuildManifestError(f"manifest channel {channel!r} is not one of {sorted(_CHANNELS)}")
    raw_arts = data.get("artifacts")
    if not isinstance(raw_arts, list):
        raise BuildManifestError("manifest artifacts is not a list")
    artifacts: "list[BuildArtifact]" = []
    for a in raw_arts:
        if not isinstance(a, dict):
            raise BuildManifestError("an artifact entry is not an object")
        kind = str(a.get("kind", ""))
        if kind not in _KINDS:
            raise BuildManifestError(f"artifact kind {kind!r} is not one of {sorted(_KINDS)}")
        digest = str(a.get("digest", ""))
        if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
            raise BuildManifestError(f"artifact {a.get('name')!r} has a malformed digest {digest!r}")
        try:
            size = int(a.get("size", 0))
        except (TypeError, ValueError) as e:
            raise BuildManifestError(f"artifact {a.get('name')!r} has a non-integer size") from e
        artifacts.append(BuildArtifact(name=str(a.get("name", "")), kind=kind,
                                       path=str(a.get("path", "")), digest=digest, size=size))
    if not artifacts:
        raise BuildManifestError("manifest lists no artifacts")
    raw_sigs = data.get("signatures", []) or []
    if not isinstance(raw_sigs, list):
        raise BuildManifestError("manifest signatures is not a list")
    sigs: "list[Signature]" = []
    for s in raw_sigs:
        if not isinstance(s, dict) or "key_id" not in s or "signature_b64" not in s:
            raise BuildManifestError("a signature entry is malformed")
        sigs.append(Signature(key_id=str(s["key_id"]), signature_b64=str(s["signature_b64"])))
    return SignedBuildManifest(manifest_schema=schema, channel=channel,
                               product_version=str(data.get("product_version", "")),
                               artifacts=tuple(artifacts), signatures=tuple(sigs))


def read_signed_manifest(path) -> "Optional[SignedBuildManifest]":
    """Read the manifest at ``path``. Returns ``None`` if the file is ABSENT (→ UNKNOWN_BUILD at the
    evaluate layer). Raises :class:`BuildManifestError` if it is present but unreadable/malformed."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise BuildManifestError(f"manifest at {p} is unreadable: {e}") from e
    return parse_signed_manifest(raw)


def load_trust_root(path) -> "Optional[TrustRoot]":
    """Load a pinned build-signing :class:`TrustRoot` from ``path`` (public key material — safe to commit).
    Returns ``None`` if absent. Raises :class:`BuildManifestError` on malformed content, and — when the
    out-of-band pin env ``VIGIL_BUILD_TRUST_ROOT_SHA256`` is set — refuses (fail closed) a trust-root file
    whose bytes do not match the pin (a hostile-admin swap defence, only as strong as the pin's channel)."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise BuildManifestError(f"trust root at {p} is unreadable: {e}") from e
    pin = (os.environ.get(_TRUST_ROOT_PIN_ENV) or "").strip().lower()
    if pin and not hmac.compare_digest(pin, hashlib.sha256(raw).hexdigest()):
        raise BuildManifestError(
            f"trust root at {p} does not match the out-of-band pin {_TRUST_ROOT_PIN_ENV} — refusing to trust "
            "it (fail closed; a hostile admin may have swapped the on-disk trust root)")
    try:
        return TrustRoot.model_validate_json(raw)
    except Exception as e:  # noqa: BLE001 — pydantic ValidationError or JSON error → malformed, fail closed
        raise BuildManifestError(f"trust root at {p} is malformed: {e}") from e


# ── the integrity result + verifier (the fail-closed state machine) ─────────────────────────────────────


@dataclass(frozen=True)
class BuildIntegrityResult:
    """The outcome of a build-integrity evaluation. ``state`` is one of the six named states — computed
    explicitly, never defaulted to VALID. The per-artifact ``artifacts`` breakdown plus the ``modified`` /
    ``missing`` / ``attested_only`` lists make the residual explicit (nothing is hidden behind the
    headline)."""

    state: str
    detail: str = ""
    build_id: str = ""
    channel: str = ""
    product_version: str = ""
    signature: dict = field(default_factory=dict)
    artifacts: "tuple[dict, ...]" = ()
    modified: "tuple[str, ...]" = ()
    missing: "tuple[str, ...]" = ()
    attested_only: "tuple[str, ...]" = ()

    @property
    def ok(self) -> bool:
        """True IFF the state is VALID. Every other state (including the fail-closed UNKNOWN_BUILD and the
        honest DEVELOPMENT_BUILD) is not-ok, so no consumer can read a non-VALID state as clean."""
        return self.state == BuildIntegrityState.VALID

    def to_dict(self) -> dict:
        return {"state": self.state, "ok": self.ok, "detail": self.detail, "build_id": self.build_id,
                "channel": self.channel, "product_version": self.product_version,
                "signature": self.signature, "artifacts": list(self.artifacts),
                "modified": list(self.modified), "missing": list(self.missing),
                "attested_only": list(self.attested_only)}


def _verify_one_artifact(a: BuildArtifact, tree_root: Path,
                         observed_image_digests: "Mapping[str, str]") -> "tuple[str, str]":
    """Return ``(status, detail)`` for one artifact against the on-disk tree."""
    if a.kind == KIND_IMAGE:
        observed = (observed_image_digests.get(a.name) or observed_image_digests.get(a.path) or "").strip()
        if not observed:
            return ART_ATTESTED_ONLY, "image identity recorded + signed; not re-hashable from this process"
        if observed == a.digest:
            return ART_VALID, "observed image digest matches"
        return ART_MODIFIED, f"observed image digest {observed} != recorded {a.digest}"
    target = tree_root / a.path
    if a.kind == KIND_FILE:
        if a.path == "" or not target.exists():
            return ART_MISSING, f"file {a.path} is absent"
        try:
            actual, _ = digest_file(target)
        except BuildManifestError as e:
            return ART_MISSING, str(e)
        return (ART_VALID, "matches") if actual == a.digest else (ART_MODIFIED, f"{actual} != {a.digest}")
    # tree
    if a.path == "" or not target.is_dir():
        return ART_MISSING, f"tree {a.path} is absent"
    actual, _ = digest_tree(target)
    return (ART_VALID, "matches") if actual == a.digest else (ART_MODIFIED, f"{actual} != {a.digest}")


def verify_build_integrity(manifest: "Optional[SignedBuildManifest]", *, tree_root,
                           trust_root: "Optional[TrustRoot]",
                           observed_image_digests: "Optional[Mapping[str, str]]" = None
                           ) -> BuildIntegrityResult:
    """The fail-closed integrity state machine. Never raises; every failure resolves to one of the six
    states. Evaluation ORDER (each step short-circuits):

      1. no manifest                          -> UNKNOWN_BUILD
      2. channel == development               -> DEVELOPMENT_BUILD (artifact breakdown still included)
      3. no signatures                        -> UNSIGNED_BUILD
      4. no pinned trust root, or the signatures do not satisfy it (incl. a quorum-collapsing duplicate
         pubkey under threshold>1)            -> UNKNOWN_BUILD   (cannot authenticate → fail closed)
      5. signatures satisfy the trust root, then walk the artifacts:
           any artifact MISSING               -> MISSING
           else any artifact MODIFIED         -> MODIFIED
           else                               -> VALID
         (MISSING outranks MODIFIED: the content of an absent file cannot be spoken to, so absence is
         reported before alteration. Both are surfaced in full via the ``missing``/``modified`` lists.)

    An ``image`` artifact with no supplied observed digest is ATTESTED_ONLY — recorded + signed but not
    re-hashed here — and is listed in ``attested_only``; it never produces a false VALID nor a false
    MODIFIED/MISSING."""
    root = Path(tree_root)
    observed = dict(observed_image_digests or {})

    if manifest is None:
        return BuildIntegrityResult(
            state=BuildIntegrityState.UNKNOWN_BUILD,
            detail="no build manifest present — the shipped identity of this install cannot be established")

    common = dict(build_id=manifest.build_id(), channel=manifest.channel,
                  product_version=manifest.product_version)

    # per-artifact breakdown is computed once and attached to every result (informational even for
    # non-VALID headline states) so nothing is hidden.
    breakdown: "list[dict]" = []
    missing: "list[str]" = []
    modified: "list[str]" = []
    attested_only: "list[str]" = []
    for a in sorted(manifest.artifacts, key=lambda a: a.name):
        status, adetail = _verify_one_artifact(a, root, observed)
        breakdown.append({"name": a.name, "kind": a.kind, "path": a.path, "status": status,
                          "detail": adetail})
        if status == ART_MISSING:
            missing.append(a.name)
        elif status == ART_MODIFIED:
            modified.append(a.name)
        elif status == ART_ATTESTED_ONLY:
            attested_only.append(a.name)
    art_tuple = tuple(breakdown)

    if manifest.channel == CHANNEL_DEVELOPMENT:
        return BuildIntegrityResult(
            state=BuildIntegrityState.DEVELOPMENT_BUILD,
            detail="a development build — an un-attested working tree, not a shipped release",
            artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
            attested_only=tuple(attested_only), **common)

    if not manifest.signatures:
        return BuildIntegrityResult(
            state=BuildIntegrityState.UNSIGNED_BUILD,
            detail="the manifest carries no signatures — the build was not signed at release time",
            artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
            attested_only=tuple(attested_only), **common)

    if trust_root is None:
        return BuildIntegrityResult(
            state=BuildIntegrityState.UNKNOWN_BUILD,
            detail="no pinned build trust root — the manifest's signatures cannot be authenticated",
            signature={"checked": False, "satisfied": False,
                       "reason": "no trust root supplied"},
            artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
            attested_only=tuple(attested_only), **common)

    # m-of-n quorum integrity: a repeated pubkey under distinct key_ids would let one holder satisfy a
    # threshold>1 root. Mirror delegation's guard, fail closed.
    if trust_root.threshold > 1:
        pubs = [a.public_key_b64 for a in trust_root.authorizers]
        if len(set(pubs)) != len(pubs):
            return BuildIntegrityResult(
                state=BuildIntegrityState.UNKNOWN_BUILD,
                detail="the build trust root has duplicate authoriser public keys — an m-of-n quorum would "
                       "collapse to one holder; refusing to authenticate (fail closed)",
                signature={"checked": True, "satisfied": False,
                           "reason": "duplicate authoriser public keys under threshold>1"},
                artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
                attested_only=tuple(attested_only), **common)

    try:
        thr = verify_threshold(manifest.signing_bytes(), list(manifest.signatures), trust_root)
    except IntegrityError as e:
        # A signature or authoriser key that parsed structurally but is malformed at the byte level
        # (non-canonical base64, wrong length, low-order/non-canonical pubkey) makes the crypto layer
        # raise. This state machine's contract is NEVER-RAISES: a material we cannot decode is a material
        # we cannot authenticate, so it fails closed to UNKNOWN_BUILD — never a crash, never a false VALID.
        return BuildIntegrityResult(
            state=BuildIntegrityState.UNKNOWN_BUILD,
            detail=f"the manifest signatures could not be authenticated — malformed signature or key material: {e}",
            signature={"checked": True, "satisfied": False,
                       "reason": f"malformed signature/key material: {e}"},
            artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
            attested_only=tuple(attested_only), **common)
    sig_block = {"checked": True, "satisfied": thr.satisfied, "threshold": thr.threshold,
                 "valid_signers": list(thr.valid_signers), "reason": thr.reason}
    if not thr.satisfied:
        return BuildIntegrityResult(
            state=BuildIntegrityState.UNKNOWN_BUILD,
            detail=f"the manifest signature does not satisfy the pinned trust root: {thr.reason}",
            signature=sig_block, artifacts=art_tuple, modified=tuple(modified), missing=tuple(missing),
            attested_only=tuple(attested_only), **common)

    # authenticated — now the on-disk artifacts decide. MISSING outranks MODIFIED.
    if missing:
        state, detail = BuildIntegrityState.MISSING, f"shipped artifact(s) absent from disk: {', '.join(missing)}"
    elif modified:
        state, detail = BuildIntegrityState.MODIFIED, f"shipped artifact(s) differ from the manifest: {', '.join(modified)}"
    else:
        state = BuildIntegrityState.VALID
        detail = "every locally verifiable shipped artifact matches the signed manifest"
        if attested_only:
            detail += f" ({len(attested_only)} artifact(s) attested-only, not re-hashed here: {', '.join(attested_only)})"
    return BuildIntegrityResult(state=state, detail=detail, signature=sig_block, artifacts=art_tuple,
                                modified=tuple(modified), missing=tuple(missing),
                                attested_only=tuple(attested_only), **common)


def evaluate_build_integrity(tree_root, *, manifest_path=None, trust_root_path=None,
                             observed_image_digests: "Optional[Mapping[str, str]]" = None
                             ) -> BuildIntegrityResult:
    """The one call a surface (``vigil doctor`` / the health endpoint) makes. Reads the manifest and the
    pinned trust root from their conventional locations under ``tree_root`` (overridable), then evaluates.
    NEVER raises: an unreadable/malformed manifest or trust root resolves to the fail-closed UNKNOWN_BUILD
    state, with the reason in ``detail``."""
    root = Path(tree_root)
    mpath = Path(manifest_path) if manifest_path else root / MANIFEST_FILENAME
    tpath = Path(trust_root_path) if trust_root_path else root / TRUST_ROOT_FILENAME
    try:
        manifest = read_signed_manifest(mpath)
    except BuildManifestError as e:
        return BuildIntegrityResult(state=BuildIntegrityState.UNKNOWN_BUILD,
                                    detail=f"build manifest could not be read: {e}")
    try:
        trust_root = load_trust_root(tpath)
    except BuildManifestError as e:
        # A present-but-untrustworthy trust root (malformed, or failing the out-of-band pin) means we
        # cannot authenticate — but a manifest that never claimed a signature (unsigned / development /
        # absent) still resolves to its own honest state, so route through the verifier with NO trust root
        # (which fails closed to UNKNOWN_BUILD only for a signed release manifest) and prepend the reason.
        result = verify_build_integrity(manifest, tree_root=root, trust_root=None,
                                        observed_image_digests=observed_image_digests)
        if result.state == BuildIntegrityState.UNKNOWN_BUILD:
            return BuildIntegrityResult(
                state=result.state, detail=f"trust root rejected ({e}); signatures cannot be authenticated",
                build_id=result.build_id, channel=result.channel, product_version=result.product_version,
                signature=result.signature, artifacts=result.artifacts, modified=result.modified,
                missing=result.missing, attested_only=result.attested_only)
        return result
    return verify_build_integrity(manifest, tree_root=root, trust_root=trust_root,
                                  observed_image_digests=observed_image_digests)
