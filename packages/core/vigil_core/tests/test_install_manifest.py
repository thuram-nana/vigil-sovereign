"""W5-4 (#448) — the shared install manifest + fail-closed startup verify (``vigil_core.install_manifest``).

Proves the marker BOTH trust planes write into a data directory and verify at startup:

  * a fresh install writes the manifest with no operator action (product version + schema versions +
    install id), and an intact install verifies and starts normally;
  * NEGATIVE CONTROLS (the gate is not a no-op): a manifest declaring a NEWER tracked schema is refused; a
    schema key this build does not recognise is refused; a NEWER manifest FORMAT is refused; a corrupted /
    naively hand-edited manifest (content-hash mismatch) is refused — each asserted in the same run;
  * DETERMINISM: generation is reproducible (same install id -> byte-identical bytes) and the verified
    content carries NO wall-clock / rng — the only non-derived value is the persisted install id.

WITHOUT THE FIX this file fails at import (`vigil_core.install_manifest` does not exist), so the failure is
observed on a tree without the change, not assumed.

Run: pytest packages/core/vigil_core/tests/test_install_manifest.py -q
"""
from __future__ import annotations

import json

import pytest

from vigil_core.install_manifest import (
    INSTALL_MANIFEST_SCHEMA,
    InstallManifestRefused,
    build_manifest,
    ensure_operable,
    manifest_path,
    read_manifest,
    verify_manifest,
    write_manifest,
)

# A representative "what this build understands" map (mirrors the shape each plane supplies).
UNDERSTOOD = {"spine_record": 1, "signed_head": 2, "anti_rollback_floor": 1}


# --------------------------------------------------------------------------------------------------
# Fresh install + intact verify (the happy path).
# --------------------------------------------------------------------------------------------------
def test_fresh_install_writes_manifest_without_operator_action(tmp_path):
    m, created = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD,
                                 install_id="fixed-id")
    assert created is True
    p = manifest_path(tmp_path)
    assert p.is_file()
    disk = json.loads(p.read_text(encoding="utf-8"))
    # The AC's required fields are all present.
    assert disk["product_version"] == "0.1.0"
    assert disk["install_id"] == "fixed-id"
    assert disk["manifest_schema"] == INSTALL_MANIFEST_SCHEMA
    assert disk["schema_versions"] == UNDERSTOOD
    assert disk["content_hash"]  # self-integrity hash written


def test_intact_install_verifies_and_starts_normally(tmp_path):
    ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="i")
    # A second startup with the SAME build must not rewrite and must not refuse.
    m, created = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert created is False
    assert m.install_id == "i"  # id is stable across restarts (persisted, not regenerated)


def test_install_id_is_persisted_not_regenerated(tmp_path):
    m1, _ = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    m2, created = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert created is False and m1.install_id == m2.install_id


def test_an_older_tracked_schema_is_understood_and_starts(tmp_path):
    """An OLDER schema than this build understands is NOT refused here (this build can load/migrate it —
    that is W5-5's concern). Only NEWER/foreign is refused."""
    write_manifest(tmp_path, build_manifest(product_version="0.0.9",
                                            schema_versions={"spine_record": 1, "signed_head": 1},
                                            install_id="old"))
    m, created = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert created is False and m.install_id == "old"


# --------------------------------------------------------------------------------------------------
# NEGATIVE CONTROLS — the gate rejects a data dir this build does not understand (proves not a no-op).
# --------------------------------------------------------------------------------------------------
def test_newer_tracked_schema_is_refused(tmp_path):
    write_manifest(tmp_path, build_manifest(product_version="9.9.9",
                                            schema_versions={"spine_record": 2, "signed_head": 2},
                                            install_id="future"))
    with pytest.raises(InstallManifestRefused) as ei:
        ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert "spine_record" in str(ei.value) and "newer" in str(ei.value)


def test_unknown_schema_key_is_refused(tmp_path):
    write_manifest(tmp_path, build_manifest(product_version="9.9.9",
                                            schema_versions={"a_future_artifact": 1}, install_id="f"))
    with pytest.raises(InstallManifestRefused):
        ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)


def test_newer_manifest_format_is_refused(tmp_path):
    # Hand-craft a manifest whose OWN format version is newer, with a matching (recomputed) content hash so
    # only the format-newer check can fire.
    from vigil_core.canonical import canonical_json, sha256_hex
    content = {"manifest_schema": INSTALL_MANIFEST_SCHEMA + 1, "product_version": "0.1.0",
               "install_id": "x", "schema_versions": {}}
    disk = dict(content, content_hash=sha256_hex(canonical_json(content)))
    manifest_path(tmp_path).write_text(json.dumps(disk), encoding="utf-8")
    with pytest.raises(InstallManifestRefused) as ei:
        ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert "format" in str(ei.value)


def test_corrupt_or_tampered_manifest_is_refused(tmp_path):
    ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="i")
    disk = json.loads(manifest_path(tmp_path).read_text(encoding="utf-8"))
    disk["product_version"] = "tampered"  # edit a field but keep the OLD content_hash
    manifest_path(tmp_path).write_text(json.dumps(disk), encoding="utf-8")
    with pytest.raises(InstallManifestRefused) as ei:
        read_manifest(tmp_path)
    assert "content_hash" in str(ei.value)


def test_unparseable_manifest_is_refused(tmp_path):
    manifest_path(tmp_path).write_text("{not json", encoding="utf-8")
    with pytest.raises(InstallManifestRefused):
        read_manifest(tmp_path)


def test_non_integer_schema_version_fails_closed(tmp_path):
    # A hostile/corrupt manifest carrying a non-integer version must not slip past as an uncomparable value.
    from vigil_core.canonical import canonical_json, sha256_hex
    content = {"manifest_schema": 1, "product_version": "0.1.0", "install_id": "x",
               "schema_versions": {"spine_record": "not-an-int"}}
    disk = dict(content, content_hash=sha256_hex(canonical_json(content)))
    manifest_path(tmp_path).write_text(json.dumps(disk), encoding="utf-8")
    with pytest.raises(InstallManifestRefused):
        read_manifest(tmp_path)


# --------------------------------------------------------------------------------------------------
# DETERMINISM — reproducible generation, no wall-clock / rng in the verified content.
# --------------------------------------------------------------------------------------------------
def test_generation_is_reproducible_byte_identical(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    write_manifest(a, build_manifest(product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="same"))
    write_manifest(b, build_manifest(product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="same"))
    assert manifest_path(a).read_bytes() == manifest_path(b).read_bytes()


def test_verified_content_has_no_wallclock_or_rng(tmp_path):
    ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="i")
    disk = json.loads(manifest_path(tmp_path).read_text(encoding="utf-8"))
    # Exactly the four content fields plus the integrity hash — no created_at / timestamp / nonce.
    assert set(disk.keys()) == {"manifest_schema", "product_version", "install_id",
                                "schema_versions", "content_hash"}


def test_env_install_id_is_honoured(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_INSTALL_ID", "from-env")
    m, _ = ensure_operable(tmp_path, product_version="0.1.0", schema_versions=UNDERSTOOD)
    assert m.install_id == "from-env"


def test_verify_manifest_direct_matching_passes(tmp_path):
    m = build_manifest(product_version="0.1.0", schema_versions=UNDERSTOOD, install_id="i")
    # A matching (equal) set of understood versions must not raise.
    verify_manifest(m, schema_versions_understood=UNDERSTOOD)
