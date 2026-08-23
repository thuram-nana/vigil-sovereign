"""vigil_core.install_manifest — the per-data-directory INSTALL MANIFEST + fail-closed startup verify (W5-4, #448).

The defect (#448): a data directory (``~/.sigil``, ``.vigil-live``, the spine dir) carried NO version
marker, so an upgraded binary run against an older — or a NEWER — data directory had no way to know.
Nothing was checked at startup; a store written by a build this one does not understand loaded silently as
the old shape.

This module is the ONE shared install-manifest primitive both trust planes use. It writes a small,
DETERMINISTIC manifest into a data directory and verifies it at startup, FAILING CLOSED (raising
:class:`InstallManifestRefused`) when the directory was written by a build this one does not understand — a
manifest whose own format is newer, a tracked data schema newer than (or unknown to) this build, or a
manifest whose self-integrity hash does not match its bytes (corruption / a naive hand-edit).

WHY IT LIVES IN vigil_core. Both planes need it and the FATAL-2 boundary forbids the offense plane
importing the sovereign ``sigil.spine.schema_guard.refuse_newer``. This module therefore MIRRORS that
gate's fail-closed int-coercion semantics inline (the exact pattern the offense blackboard's own
``_MAX_BB_SCHEMA`` gate uses — "its own inline gate since the FATAL-2 boundary forbids it importing this
sovereign helper") rather than importing across the boundary. Each plane supplies its OWN product version
and its OWN ``{schema-name -> max-version-understood}`` map; this module owns only the manifest format, the
serialization, and the decision.

DETERMINISM. The manifest content is ``{manifest_schema, product_version, install_id, schema_versions}``
plus a ``content_hash`` over the canonical bytes of that content. There is NO wall-clock and NO rng in the
verified content: the ONLY non-derived value is ``install_id``, which is generated ONCE at fresh-install
time (or supplied — argument / env ``VIGIL_INSTALL_ID``) and then PERSISTED, never regenerated. Given the
same inputs the written bytes are byte-identical, so generation is reproducible and the content hash is
stable. Serialization is ``vigil_core.canonical_json`` (sorted keys, compact) — the same primitive the
signed spine uses.

HONEST SCOPE (do NOT overclaim — mirrors ``integrity_verifier``'s own §). The ``content_hash`` is an
UNKEYED sha-256 over the manifest's own bytes. It detects corruption, truncation, a partial write, and a
NAIVE hand-edit that forgets to recompute the hash — all of which fail CLOSED. It does NOT by itself prove
AUTHENTICITY against an adversary who edits the manifest AND recomputes the hash; installation-wide
authenticity is the SIGNED spine head's concern, not this marker's. This is a version-skew + corruption
gate, not a code-signing mechanism.

ADOPT-ON-ABSENT. A data directory with NO manifest is a FRESH or a legacy (pre-W5-4) install, not a
tampered one: :func:`ensure_operable` WRITES the manifest (fresh-install write, no operator action) rather
than refusing. Refusal is reserved for a directory that carries a manifest this build cannot understand.
This mirrors W5-5's "a fresh/empty store is operable" and the spine's ``LEGACY_SCHEMA_VERSION`` adoption
pattern. An OLDER tracked schema is understood (this build can load/migrate it — W5-5's concern), so only a
NEWER/foreign schema is refused here.
"""
from __future__ import annotations

import hmac
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple

from .canonical import canonical_json, sha256_hex

#: The filename of the install manifest inside a data directory.
MANIFEST_FILENAME = "install-manifest.json"

#: The install manifest's OWN format version. Bump ONLY when the manifest's structure changes in a way an
#: older build cannot read; an older build then refuses-newer this whole file (fail closed).
INSTALL_MANIFEST_SCHEMA = 1
_MAX_INSTALL_MANIFEST_SCHEMA = INSTALL_MANIFEST_SCHEMA

#: The four content fields that are hashed + verified. ``content_hash`` is stored ALONGSIDE them on disk but
#: is NOT part of the hashed region (it is the hash OF that region).
_CONTENT_FIELDS: Tuple[str, ...] = ("manifest_schema", "product_version", "install_id", "schema_versions")

#: Injectable install id (deterministic tests / a reproducible install).
_INSTALL_ID_ENV = "VIGIL_INSTALL_ID"


class InstallManifestError(Exception):
    """Base for any install-manifest failure."""


class InstallManifestRefused(InstallManifestError):
    """Fail-closed refusal: the data directory carries a manifest this build does not understand (a newer
    manifest format, or a newer/foreign tracked schema) or whose self-integrity hash does not match its
    bytes (corruption / a naive hand-edit). The caller refuses to operate on the directory rather than
    silently load it as the old shape."""


@dataclass(frozen=True)
class InstallManifest:
    """The install marker for one data directory."""

    manifest_schema: int
    product_version: str
    install_id: str
    schema_versions: dict  # {schema-name -> int version this install writes / understands}

    def content(self) -> dict:
        """The canonical, hashed region (no ``content_hash``). Deterministic; ``canonical_json`` sorts keys
        recursively so on-disk key order never changes the hash."""
        return {
            "manifest_schema": int(self.manifest_schema),
            "product_version": str(self.product_version),
            "install_id": str(self.install_id),
            "schema_versions": {str(k): int(v) for k, v in self.schema_versions.items()},
        }

    def content_hash(self) -> str:
        return sha256_hex(canonical_json(self.content()))

    def to_disk(self) -> dict:
        d = self.content()
        d["content_hash"] = self.content_hash()
        return d


def manifest_path(data_dir) -> Path:
    return Path(data_dir) / MANIFEST_FILENAME


def _coerce_version(value, *, artifact: str) -> int:
    """Fail-closed int coercion, mirroring ``sigil.spine.schema_guard.refuse_newer``: an uncoercible
    version (``None``, a string, a hostile type) is itself suspicious and is treated as "too new" — refuse,
    never a comparison that silently succeeds."""
    try:
        return int(value)
    except (TypeError, ValueError) as e:
        raise InstallManifestRefused(
            f"{artifact}: version {value!r} is not an integer — refusing to load (fail closed)") from e


def new_install_id(explicit: Optional[str] = None) -> str:
    """A stable per-install id. Precedence: ``explicit`` arg > env ``VIGIL_INSTALL_ID`` > a fresh uuid4.
    Generated ONCE at fresh install and then PERSISTED in the manifest — never regenerated, so it is stable
    across restarts; injectable so tests and a reproducible install are deterministic."""
    v = (explicit or os.environ.get(_INSTALL_ID_ENV) or "").strip()
    return v or uuid.uuid4().hex


def build_manifest(*, product_version: str, schema_versions: Mapping[str, int],
                   install_id: Optional[str] = None) -> InstallManifest:
    """Construct an :class:`InstallManifest` for THIS build. ``install_id`` is resolved via
    :func:`new_install_id` (persisted once, injectable)."""
    return InstallManifest(
        manifest_schema=INSTALL_MANIFEST_SCHEMA,
        product_version=str(product_version),
        install_id=new_install_id(install_id),
        schema_versions={str(k): int(v) for k, v in schema_versions.items()},
    )


def write_manifest(data_dir, manifest: InstallManifest) -> InstallManifest:
    """Atomically write ``manifest`` into ``data_dir`` (0600, tmp + ``os.replace``), creating the directory
    if needed. Deterministic: given the same manifest the bytes on disk are byte-identical."""
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(manifest.to_disk())
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".install-manifest.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, str(manifest_path(d)))
        tmp = None  # renamed away; nothing to clean up
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return manifest


def read_manifest(data_dir) -> Optional[InstallManifest]:
    """Return the manifest at ``data_dir``, or ``None`` if ABSENT (a fresh / legacy install). Raise
    :class:`InstallManifestRefused` if a manifest is PRESENT but unreadable, not a JSON object, missing a
    required field, or whose self-integrity hash does not match its bytes (corruption / a naive tamper) —
    fail closed. Reads only; touches nothing."""
    p = manifest_path(data_dir)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InstallManifestRefused(f"install manifest at {p} is unreadable/corrupt: {e}") from e
    if not isinstance(d, dict):
        raise InstallManifestRefused(f"install manifest at {p} is not a JSON object")
    missing = [f for f in _CONTENT_FIELDS + ("content_hash",) if f not in d]
    if missing:
        raise InstallManifestRefused(f"install manifest at {p} is missing field(s): {missing}")
    if not isinstance(d.get("schema_versions"), dict):
        raise InstallManifestRefused(f"install manifest at {p}: schema_versions is not an object")
    m = InstallManifest(
        manifest_schema=_coerce_version(d["manifest_schema"], artifact="install manifest format"),
        product_version=str(d["product_version"]),
        install_id=str(d["install_id"]),
        schema_versions={str(k): _coerce_version(v, artifact=f"schema {k!r}")
                         for k, v in d["schema_versions"].items()},
    )
    if not hmac.compare_digest(str(d["content_hash"]), m.content_hash()):
        raise InstallManifestRefused(
            f"install manifest at {p}: content_hash mismatch (corruption or a naive hand-edit) — fail closed")
    return m


def verify_manifest(manifest: InstallManifest, *, schema_versions_understood: Mapping[str, int]) -> None:
    """Refuse-newer gate. Raise :class:`InstallManifestRefused` if the on-disk manifest is one this build
    does not understand: its own format newer than this build; or ANY tracked schema newer than — or unknown
    to — this build. An OLDER-or-equal, all-known manifest returns quietly (this build can operate on it; an
    older schema is a W5-5 migrate concern, not a refusal here)."""
    if manifest.manifest_schema > _MAX_INSTALL_MANIFEST_SCHEMA:
        raise InstallManifestRefused(
            f"install manifest format v{manifest.manifest_schema} is newer than this build understands "
            f"(max v{_MAX_INSTALL_MANIFEST_SCHEMA}) — upgrade the binary; refusing to run "
            "(never treated as clean)")
    understood = {str(k): int(v) for k, v in schema_versions_understood.items()}
    for name, ver in sorted(manifest.schema_versions.items()):
        if name not in understood:
            raise InstallManifestRefused(
                f"the data directory declares schema {name!r}=v{ver}, which this build does not recognise "
                "at all — it was written by a newer build; upgrade the binary (refusing to run)")
        if ver > understood[name]:
            raise InstallManifestRefused(
                f"the data directory declares schema {name!r}=v{ver}, newer than this build understands "
                f"(max v{understood[name]}) — upgrade the binary (refusing to run)")


def ensure_operable(data_dir, *, product_version: str, schema_versions: Mapping[str, int],
                    install_id: Optional[str] = None) -> Tuple[InstallManifest, bool]:
    """THE one startup call. Returns ``(manifest, created)``.

      * ABSENT  -> WRITE the manifest (fresh / legacy install; NO operator action) and return ``(m, True)``;
      * PRESENT -> READ it (fail-closed on corrupt / tamper) then VERIFY it (fail-closed refuse-newer),
        returning ``(m, False)`` on success.

    Raises :class:`InstallManifestRefused` if the directory carries a manifest this build cannot understand
    or whose integrity hash does not match. ``schema_versions`` is BOTH what a fresh install writes AND what
    this build understands (its max), so one map drives write and verify."""
    existing = read_manifest(data_dir)  # raises on corrupt / tamper
    if existing is None:
        m = build_manifest(product_version=product_version, schema_versions=schema_versions,
                           install_id=install_id)
        write_manifest(data_dir, m)
        return m, True
    verify_manifest(existing, schema_versions_understood=schema_versions)
    return existing, False
