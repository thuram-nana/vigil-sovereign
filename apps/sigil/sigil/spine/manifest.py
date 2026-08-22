"""The spine's segment MANIFEST — the sole linearization point for the retain-all segment set.

The spine is stored as a sequence of size-bounded, immutable **sealed** segments plus exactly one
**active** (append) segment; the manifest names them in seq order. It is deliberately UNSIGNED and
NON-LOAD-BEARING: record order, count, and every tamper decision are re-derived from the segment BYTES
(via `verify_chain`/`classify_head`), never from the manifest's convenience fields. A doctored manifest
therefore fails CLOSED — dropping/reordering an interior segment breaks `prev_hash`/seq contiguity, a
dropped tail shortens `entries()` (the signed head's `n < entry_count` gate fires), a dropped front fails
the genesis check. That byte-level fail-closed guarantee is the FLOOR and is unconditional.

The signed-manifest tier (W16-STD-3) is defence-in-depth ON TOP of that floor: `write_manifest(...,
private_key_b64=…)` sets `manifest_sig` to an Ed25519 signature over the canonical sig-nulled body (via the
shared `vigil_core` signing — no new crypto), and `read_manifest(..., public_key_b64=…)` then REFUSES any
edited or unsigned manifest before it is used. It is OPTIONAL: called without a key, both paths behave
byte-identically to the historical unsigned manifest (retain-all does not depend on the signature for
correctness — it catches a doctored manifest EARLIER, at read, rather than only downstream at chain
re-derivation). Wiring a persisted per-store signing key so a running store signs its manifest BY DEFAULT is
tracked separately (see the module's callers / W16 blocking-work).

`SpineLayout` derives the whole on-disk layout from the spine data-file path a `SpineStore` is constructed
with, so a store on a temp path is fully isolated. This module does no locking — the caller (`SpineStore`)
holds the cross-process flock while reading/writing/migrating.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath, Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..reuse import canonical_json, sign, verify_one
from ..reuse.chain import _GENESIS_PREV
from .atomicio import atomic_write_text
from .schema_guard import refuse_newer

SEGMENT_STEM = "seg-"
_SCHEMA_VERSION = 1
_MAX_MANIFEST_SCHEMA = _SCHEMA_VERSION   # refuse-newer gate (W5-3): a manifest schema above this is "upgrade sigil"


def segment_filename(seg_id: int, codec: str = "none") -> str:
    """Zero-padded segment file name; `.gz` suffix when gzip-sealed (Slice 4)."""
    base = f"{SEGMENT_STEM}{seg_id:08d}.jsonl"
    return base + ".gz" if codec == "gzip" else base


class Segment(BaseModel):
    """One segment in the manifest. `first_prev_hash`/`boundary_hash` are the chain-linkage the reader
    CROSS-CHECKS against the segment's real first/last records — they are convenience, not authority."""
    model_config = ConfigDict(extra="ignore")   # forward-compatible: tolerate fields a newer writer added
    id: int = Field(ge=0)
    file: str                                    # path RELATIVE to the spine dir, e.g. "segments/seg-00000000.jsonl"
    codec: str = "none"                          # "none" | "gzip"
    sealed: bool = False
    first_seq: int = Field(ge=0)
    last_seq: int | None = None                  # null while active
    count: int | None = None                     # null while active; CONVENIENCE ONLY — never a tamper input
    first_prev_hash: str = _GENESIS_PREV         # == the prior segment's boundary_hash (seg 0 == genesis)
    boundary_hash: str | None = None             # == entry_hash(last_seq); null while active
    bytes: int = 0
    sha256: str | None = None                    # at-rest file integrity; NOT a chain digest

    @field_validator("file")
    @classmethod
    def _file_is_contained_relative(cls, v: str) -> str:
        """A segment `file` must be a plain relative path under the spine dir — never absolute and never
        `..`-escaping. `get()`/`iter_records()`/`tail()` open segment files WITHOUT running verify(), so a
        doctored manifest pointing `file` at `/etc/passwd` or `../../secret` would otherwise surface that
        file's bytes AS spine records. Reject it at the model boundary so the read path stays fail-closed
        even though the manifest itself is unsigned."""
        pp = PurePosixPath(v)
        if not v or pp.is_absolute() or PurePosixPath(v.replace("\\", "/")).is_absolute() or ".." in pp.parts:
            raise ValueError(f"segment file must be a contained relative path, got {v!r}")
        return v


class Manifest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    schema_version: int = _SCHEMA_VERSION
    generation: int = Field(default=0, ge=0)     # monotonic epoch; ++ on EVERY swap — the unified change token
    scope: str = ""
    segments: list[Segment] = Field(default_factory=list)
    manifest_sig: str | None = None              # Ed25519 signature over the canonical body (sig field NULLED);
    #                                              populated by sign_manifest / write_manifest(private_key_b64=…)

    def active(self) -> Segment | None:
        """The single unsealed (append) segment, if any. There is at most one."""
        act = [s for s in self.segments if not s.sealed]
        return act[-1] if act else None

    def sealed_in_order(self) -> list[Segment]:
        return sorted((s for s in self.segments if s.sealed), key=lambda s: s.first_seq)

    def ordered(self) -> list[Segment]:
        """All segments in seq order (sealed by first_seq, then the active tail)."""
        out = self.sealed_in_order()
        act = self.active()
        if act is not None:
            out.append(act)
        return out


@dataclass(frozen=True)
class SpineLayout:
    """The on-disk layout derived from a spine data-file path (…/spine.jsonl). Every artifact is
    NAMESPACED BY THE DATA FILE'S STEM (`spine.manifest.json`, `spine.lock`, `spine.segments/`) so two
    stores whose data files merely SHARE a directory — e.g. the `tempfile.mktemp()` idiom that drops files
    straight into /tmp — never collide on a manifest/lock/segments set. Without this, one migrated store's
    `manifest.json` would be read by every other store in that directory and silently steer it onto the
    wrong segment (a real cross-store contamination the review caught)."""
    data_path: Path            # the legacy/identity path (…/spine.jsonl) — the stable lock/identity token
    spine_dir: Path
    segments_dir: Path
    manifest_path: Path
    lockfile_path: Path
    trash_dir: Path

    @classmethod
    def for_path(cls, data_path: Path | str) -> "SpineLayout":
        p = Path(data_path)
        d = p.parent
        ns = p.stem or p.name       # "spine.jsonl" -> "spine"; namespaces every derived artifact
        return cls(
            data_path=p, spine_dir=d, segments_dir=d / f"{ns}.segments",
            manifest_path=d / f"{ns}.manifest.json", lockfile_path=d / f"{ns}.lock", trash_dir=d / f"{ns}.trash",
        )

    def seg_path(self, seg: Segment) -> Path:
        """Absolute path of a segment's file (its `file` is stored relative to the spine dir). The
        `Segment.file` validator guarantees it is a plain relative path that cannot escape spine_dir."""
        return self.spine_dir / seg.file

    def segment_rel(self, seg_id: int, codec: str = "none") -> str:
        """The manifest `file` value (relative to spine_dir) for a segment id — under the namespaced
        segments dir, e.g. 'spine.segments/seg-00000000.jsonl'."""
        return f"{self.segments_dir.name}/{segment_filename(seg_id, codec)}"


class ManifestSignatureError(Exception):
    """A manifest was required to carry a valid signature and did not (missing, or does not verify under the
    expected public key) — an edited/forged manifest is refused fail-closed."""


def manifest_signing_bytes(manifest: Manifest) -> bytes:
    """The canonical bytes signed by :func:`sign_manifest` — the manifest body with ``manifest_sig`` NULLED,
    serialized deterministically. Nulling the signature field is what makes the signature a fixed point:
    signer and verifier hash the identical body regardless of any prior signature value."""
    body = manifest.model_copy(update={"manifest_sig": None})
    return canonical_json(body.model_dump(mode="json"))


def sign_manifest(manifest: Manifest, private_key_b64: str) -> Manifest:
    """Return a copy of ``manifest`` with ``manifest_sig`` set to an Ed25519 signature over
    :func:`manifest_signing_bytes` — reuses the shared ``vigil_core`` signing (no new crypto)."""
    sig = sign(private_key_b64, manifest_signing_bytes(manifest))
    return manifest.model_copy(update={"manifest_sig": sig})


def verify_manifest(manifest: Manifest, public_key_b64: str) -> bool:
    """True iff ``manifest`` carries a ``manifest_sig`` that verifies under ``public_key_b64`` over the
    canonical (sig-nulled) body. False for a missing signature or any tamper (a changed field re-derives a
    different body, so the retained signature no longer matches)."""
    sig = manifest.manifest_sig
    if not sig:
        return False
    try:
        return verify_one(public_key_b64, manifest_signing_bytes(manifest), sig)
    except Exception:  # noqa: BLE001 — a malformed signature/key is a verification FAILURE, not a crash
        return False


def read_manifest(layout: SpineLayout, *, public_key_b64: str | None = None) -> Manifest | None:
    """Load the manifest, or None if absent. A present-but-unparseable manifest RAISES (fail closed) —
    the atomic write path guarantees it is never torn, so a parse failure means genuine corruption, not a
    partial write, and must never be silently treated as 'no manifest' (which would strand the segments).

    When ``public_key_b64`` is supplied the signed-manifest tier is ENFORCED fail-closed: the manifest MUST
    carry a ``manifest_sig`` that verifies under that key, else :class:`ManifestSignatureError` is raised — an
    edited (or unsigned) manifest is refused. When it is omitted the manifest is read as before (unsigned,
    non-load-bearing: tamper is still caught downstream by the byte-level chain re-derivation)."""
    mp = layout.manifest_path
    if not mp.exists():
        return None
    m = Manifest.model_validate_json(mp.read_text(encoding="utf-8"))
    # REFUSE-NEWER (W5-3): the model keeps ``extra="ignore"`` so a same-schema writer may add a field, but a
    # SCHEMA BUMP means the writer changed segment/linearization semantics this build cannot honour — refuse
    # it fail-closed rather than silently linearize a v(N+1) manifest as v1 (the "silently treats v2 as v1"
    # defect). A read failure is already fail-closed (raises); this raise joins it.
    refuse_newer(m.schema_version, _MAX_MANIFEST_SCHEMA, artifact="segment manifest")
    if public_key_b64 is not None and not verify_manifest(m, public_key_b64):
        raise ManifestSignatureError(
            "segment manifest signature missing or does not verify under the expected key — refusing a "
            "tampered/unsigned manifest")
    return m


def write_manifest(layout: SpineLayout, manifest: Manifest, *, private_key_b64: str | None = None) -> None:
    """Atomically publish the manifest (temp→fsync→os.replace→dir-fsync). THE cutover commit instant.

    When ``private_key_b64`` is supplied the manifest is SIGNED before it is written (``manifest_sig`` is
    populated), so a subsequent ``read_manifest(..., public_key_b64=…)`` verifies it and refuses any edit.
    When it is omitted the manifest is written unsigned, byte-identical to the historical behaviour."""
    if private_key_b64 is not None:
        manifest = sign_manifest(manifest, private_key_b64)
    layout.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(layout.manifest_path, manifest.model_dump_json(), prefix=".manifest-")


def initial_manifest(scope: str, *, active_file: str, first_seq: int = 0,
                     first_prev_hash: str = _GENESIS_PREV) -> Manifest:
    """A single-active-segment manifest (generation 0) — the shape produced by a fresh store or a
    migration of an existing single-file spine."""
    return Manifest(
        generation=0, scope=scope,
        segments=[Segment(id=0, file=active_file, codec="none", sealed=False,
                          first_seq=first_seq, first_prev_hash=first_prev_hash)],
    )
