"""W4-3 (#443) + W9-7 (#440) — the signed build manifest over ALL shipped artifacts + explicit integrity
states (``vigil_core.signed_build_manifest``).

Proves the ONE mechanism both issues share:

  * #443 — Python (tree), Rust WARDEN kernel (file), the browser bundle (tree) and the gateway image
    (image) all carry a build id recorded in ONE signed manifest; it is verifiable OFFLINE (signature +
    content-addressed digests, no network); and a REBUILT artifact with different content produces a
    different build_id and FAILS verification against the old manifest.
  * #440 — a signed manifest yields one of the SIX explicit integrity states, never an optimistic default:
    VALID / MODIFIED / MISSING / UNSIGNED_BUILD / UNKNOWN_BUILD / DEVELOPMENT_BUILD.

NEGATIVE CONTROLS (the gate is not a no-op), each asserted in the same run: modifying a shipped file yields
MODIFIED; deleting one yields MISSING; an unsigned build yields UNSIGNED_BUILD; no manifest yields
UNKNOWN_BUILD; a below-threshold / forged signature yields UNKNOWN_BUILD (fail-closed authentication); a
quorum-collapsing duplicate pubkey under m-of-n is refused; a manifest whose FORMAT is newer than this
build is refused.

DETERMINISM: two independent builds of the same tree produce byte-identical signing bytes and the same
build_id; the signed region carries NO wall-clock and NO rng.

WITHOUT THE FIX this file fails at import (`vigil_core.signed_build_manifest` does not exist), so the
failure is observed on a tree without the change, not assumed.

Run: pytest packages/core/vigil_core/tests/test_signed_build_manifest.py -q
"""
from __future__ import annotations

import json

import pytest

from vigil_core import (
    AuthorizerKey,
    Signature,
    TrustRoot,
    generate_keypair,
    sign as ed25519_sign,
)
from vigil_core.signed_build_manifest import (
    BUILD_MANIFEST_SCHEMA,
    BuildIntegrityState as S,
    BuildManifestError,
    build_manifest_from_specs,
    build_signed_manifest,
    digest_tree,
    evaluate_build_integrity,
    parse_signed_manifest,
    read_signed_manifest,
    sign_manifest,
    verify_build_integrity,
)

_IMG_DIGEST = "sha256:" + "ab" * 32


@pytest.fixture()
def tree(tmp_path):
    """A minimal shipped tree: a python package (tree), a Rust kernel binary (file), a browser bundle
    (tree). The gateway image is recorded by digest (an image is not on the filesystem)."""
    (tmp_path / "python").mkdir()
    (tmp_path / "python" / "__init__.py").write_text("VERSION = '1.5.0'\n")
    (tmp_path / "python" / "core.py").write_text("def run():\n    return 42\n")
    (tmp_path / "ui").mkdir()
    (tmp_path / "ui" / "app.js").write_text("console.log('vigil');\n")
    (tmp_path / "ui" / "style.css").write_text("body{margin:0}\n")
    (tmp_path / "warden").write_bytes(b"\x7fELF" + b"\x00" * 64)
    return tmp_path


def _specs():
    return [
        {"name": "python-core", "kind": "tree", "path": "python"},
        {"name": "browser-bundle", "kind": "tree", "path": "ui"},
        {"name": "warden-kernel", "kind": "file", "path": "warden"},
        {"name": "gateway-image", "kind": "image", "path": "vigil-gateway:latest", "digest": _IMG_DIGEST},
    ]


def _solo_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="rel1", name="Release signer 1", public_key_b64=kp.public_key_b64)])
    return kp, tr


def _sign(tree, kp, channel="release"):
    return build_signed_manifest(product_version="1.5.0", channel=channel, specs=_specs(),
                                 tree_root=tree, signers=[("rel1", kp.private_key_b64)])


# --------------------------------------------------------------------------------------------------
# #443 — every shipped artifact carries an id in ONE signed manifest; offline-verifiable; VALID.
# --------------------------------------------------------------------------------------------------


def test_manifest_covers_all_four_shipped_artifact_kinds(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    names = {a.name for a in m.artifacts}
    kinds = {a.kind for a in m.artifacts}
    assert names == {"python-core", "browser-bundle", "warden-kernel", "gateway-image"}
    assert kinds == {"tree", "file", "image"}  # python+browser=tree, rust=file, gateway=image
    for a in m.artifacts:
        assert a.digest.startswith("sha256:") and len(a.digest) == len("sha256:") + 64
    assert m.build_id() and len(m.build_id()) == 16


def test_clean_signed_tree_is_VALID_and_offline_verifiable(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    # OFFLINE: verification touches only the on-disk tree + the in-memory trust root — no network.
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.VALID and r.ok
    assert r.signature["satisfied"] is True and r.signature["valid_signers"] == ["rel1"]
    # the image is attested-only (recorded + signed, not re-hashed) — surfaced, never a silent VALID
    assert r.attested_only == ("gateway-image",)


def test_image_verified_when_an_observed_digest_is_supplied(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr,
                               observed_image_digests={"gateway-image": _IMG_DIGEST})
    assert r.state == S.VALID and r.attested_only == ()
    # a WRONG observed image digest is a MODIFIED negative control (offline, satisfies #443)
    bad = verify_build_integrity(m, tree_root=tree, trust_root=tr,
                                 observed_image_digests={"gateway-image": "sha256:" + "cd" * 32})
    assert bad.state == S.MODIFIED and "gateway-image" in bad.modified


# --------------------------------------------------------------------------------------------------
# #440 — the six explicit integrity states, with negative controls in the same run.
# --------------------------------------------------------------------------------------------------


def test_modifying_a_shipped_file_yields_MODIFIED(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    (tree / "python" / "core.py").write_text("def run():\n    return 1337  # tampered\n")
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.MODIFIED and "python-core" in r.modified and not r.ok


def test_deleting_a_shipped_file_yields_MISSING(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    (tree / "warden").unlink()
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.MISSING and "warden-kernel" in r.missing and not r.ok


def test_deleting_a_whole_shipped_tree_yields_MISSING(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    for p in sorted((tree / "ui").iterdir()):
        p.unlink()
    (tree / "ui").rmdir()
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.MISSING and "browser-bundle" in r.missing


def test_unsigned_build_yields_UNSIGNED_BUILD(tree):
    _kp, tr = _solo_root()
    m = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                  tree_root=tree)  # NOT signed
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.UNSIGNED_BUILD and not r.ok


def test_no_manifest_yields_UNKNOWN_BUILD(tree):
    _kp, tr = _solo_root()
    r = verify_build_integrity(None, tree_root=tree, trust_root=tr)
    assert r.state == S.UNKNOWN_BUILD and not r.ok


def test_no_trust_root_for_a_signed_manifest_yields_UNKNOWN_BUILD(tree):
    kp, _tr = _solo_root()
    m = _sign(tree, kp)
    r = verify_build_integrity(m, tree_root=tree, trust_root=None)
    assert r.state == S.UNKNOWN_BUILD and r.signature["checked"] is False


def test_development_channel_yields_DEVELOPMENT_BUILD(tree):
    _kp, tr = _solo_root()
    # a dev build may legitimately be unsigned; the honest headline is DEVELOPMENT_BUILD, not UNSIGNED
    m = build_manifest_from_specs(product_version="0.0.0-dev", channel="development", specs=_specs(),
                                  tree_root=tree)
    r = verify_build_integrity(m, tree_root=tree, trust_root=tr)
    assert r.state == S.DEVELOPMENT_BUILD and not r.ok


# --------------------------------------------------------------------------------------------------
# Signature soundness — a forged / wrong-key / below-threshold signature must NOT verify (fail-closed).
# --------------------------------------------------------------------------------------------------


def test_a_signature_by_an_untrusted_key_is_not_authenticated(tree):
    attacker = generate_keypair()
    _kp, tr = _solo_root()  # trust root pins rel1's key
    # attacker signs under the key_id "rel1" but with THEIR OWN private key
    m = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                  tree_root=tree)
    forged = sign_manifest(m, [("rel1", attacker.private_key_b64)])
    r = verify_build_integrity(forged, tree_root=tree, trust_root=tr)
    assert r.state == S.UNKNOWN_BUILD and r.signature["satisfied"] is False


def test_tampering_the_manifest_after_signing_breaks_the_signature(tree):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    # swap an artifact digest AFTER signing (the on-disk bytes an attacker would edit to cover a swap)
    tampered = m.__class__(
        manifest_schema=m.manifest_schema, channel=m.channel, product_version=m.product_version,
        artifacts=tuple(
            (a.__class__(name=a.name, kind=a.kind, path=a.path, digest="sha256:" + "00" * 32, size=a.size)
             if a.name == "warden-kernel" else a) for a in m.artifacts),
        signatures=m.signatures)
    r = verify_build_integrity(tampered, tree_root=tree, trust_root=tr)
    assert r.state == S.UNKNOWN_BUILD and r.signature["satisfied"] is False


# --------------------------------------------------------------------------------------------------
# m-of-n threshold + quorum-integrity.
# --------------------------------------------------------------------------------------------------


def test_m_of_n_below_threshold_is_UNKNOWN_BUILD(tree):
    a, b, c = generate_keypair(), generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="A", public_key_b64=a.public_key_b64),
        AuthorizerKey(key_id="b", name="B", public_key_b64=b.public_key_b64),
        AuthorizerKey(key_id="c", name="C", public_key_b64=c.public_key_b64)])
    m = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                  tree_root=tree)
    one = sign_manifest(m, [("a", a.private_key_b64)])  # only 1 of the required 2
    assert verify_build_integrity(one, tree_root=tree, trust_root=tr).state == S.UNKNOWN_BUILD
    two = sign_manifest(m, [("a", a.private_key_b64), ("b", b.private_key_b64)])  # 2 of 2 → authenticated
    assert verify_build_integrity(two, tree_root=tree, trust_root=tr).state == S.VALID


def test_duplicate_pubkey_under_m_of_n_is_refused(tree):
    a = generate_keypair()
    # two distinct key_ids, SAME pubkey — would collapse a 2-of-2 quorum to one holder
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a1", name="A1", public_key_b64=a.public_key_b64),
        AuthorizerKey(key_id="a2", name="A2", public_key_b64=a.public_key_b64)])
    m = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                  tree_root=tree)
    both = sign_manifest(m, [("a1", a.private_key_b64), ("a2", a.private_key_b64)])
    r = verify_build_integrity(both, tree_root=tree, trust_root=tr)
    assert r.state == S.UNKNOWN_BUILD and "duplicate" in r.detail.lower()


# --------------------------------------------------------------------------------------------------
# #443 negative control — a rebuilt artifact with different content changes the id and fails old manifest.
# --------------------------------------------------------------------------------------------------


def test_rebuilt_artifact_changes_build_id_and_fails_old_manifest(tree):
    kp, tr = _solo_root()
    m_old = _sign(tree, kp)
    old_id = m_old.build_id()
    # rebuild the browser bundle with different content
    (tree / "ui" / "app.js").write_text("console.log('vigil v2');\n")
    m_new = _sign(tree, kp)
    assert m_new.build_id() != old_id, "a rebuilt artifact must change the build_id"
    # the OLD signed manifest now fails verification against the rebuilt tree
    r = verify_build_integrity(m_old, tree_root=tree, trust_root=tr)
    assert r.state == S.MODIFIED and "browser-bundle" in r.modified


# --------------------------------------------------------------------------------------------------
# Determinism — no wall-clock / rng in the signed region.
# --------------------------------------------------------------------------------------------------


def test_two_builds_of_the_same_tree_are_byte_identical(tree):
    kp, _tr = _solo_root()
    m1 = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                   tree_root=tree)
    m2 = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=_specs(),
                                   tree_root=tree)
    assert m1.signing_bytes() == m2.signing_bytes()
    assert m1.build_id() == m2.build_id()
    # signing is deterministic for Ed25519 (RFC 8032), so even the signature bytes are identical
    s1 = sign_manifest(m1, [("rel1", kp.private_key_b64)])
    s2 = sign_manifest(m2, [("rel1", kp.private_key_b64)])
    assert s1.signatures[0].signature_b64 == s2.signatures[0].signature_b64


def test_artifact_order_in_specs_does_not_change_the_manifest(tree):
    # specs are hashed then SORTED by name; a different spec order must produce the same signed region
    kp, _tr = _solo_root()
    forward = _specs()
    reverse = list(reversed(forward))
    a = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=forward, tree_root=tree)
    b = build_manifest_from_specs(product_version="1.5.0", channel="release", specs=reverse, tree_root=tree)
    assert a.signing_bytes() == b.signing_bytes()


def test_digest_tree_is_stable_and_content_addressed(tree):
    d1, sz1 = digest_tree(tree / "python")
    d2, sz2 = digest_tree(tree / "python")
    assert d1 == d2 and sz1 == sz2
    (tree / "python" / "core.py").write_text("def run():\n    return 43\n")
    d3, _ = digest_tree(tree / "python")
    assert d3 != d1  # any content change changes the tree digest


def test_pycache_is_excluded_from_the_tree_digest(tree):
    before, _ = digest_tree(tree / "python")
    (tree / "python" / "__pycache__").mkdir()
    (tree / "python" / "__pycache__" / "core.cpython-313.pyc").write_bytes(b"\x00compiled")
    (tree / "python" / "core.pyo").write_bytes(b"\x00")
    after, _ = digest_tree(tree / "python")
    assert after == before, "build detritus must not perturb the content hash"


# --------------------------------------------------------------------------------------------------
# On-disk round trip + parse fail-closed.
# --------------------------------------------------------------------------------------------------


def test_on_disk_round_trip_reparses_and_verifies(tree, tmp_path):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    p = tmp_path / "build-manifest.json"
    p.write_text(json.dumps(m.to_disk(), indent=2, sort_keys=True) + "\n")
    reloaded = read_signed_manifest(p)
    assert reloaded is not None
    assert reloaded.build_id() == m.build_id()
    assert verify_build_integrity(reloaded, tree_root=tree, trust_root=tr).state == S.VALID


def test_absent_manifest_file_reads_as_None(tmp_path):
    assert read_signed_manifest(tmp_path / "nope.json") is None


def test_a_newer_manifest_format_is_refused(tree):
    kp, _tr = _solo_root()
    d = _sign(tree, kp).to_disk()
    d["manifest_schema"] = BUILD_MANIFEST_SCHEMA + 1
    with pytest.raises(BuildManifestError, match="newer than this build"):
        parse_signed_manifest(d)


def test_a_malformed_digest_is_refused(tree):
    kp, _tr = _solo_root()
    d = _sign(tree, kp).to_disk()
    d["artifacts"][0]["digest"] = "not-a-sha"
    with pytest.raises(BuildManifestError, match="malformed digest"):
        parse_signed_manifest(d)


def test_an_unknown_channel_is_refused(tree):
    kp, _tr = _solo_root()
    d = _sign(tree, kp).to_disk()
    d["channel"] = "nightly"
    with pytest.raises(BuildManifestError, match="channel"):
        parse_signed_manifest(d)


# --------------------------------------------------------------------------------------------------
# The evaluate() convenience over on-disk manifest + trust root (what doctor / the endpoint call).
# --------------------------------------------------------------------------------------------------


def test_evaluate_reads_manifest_and_trust_root_from_the_tree(tree, tmp_path):
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    (tree / "build-manifest.json").write_text(json.dumps(m.to_disk()) + "\n")
    (tree / "build-trust-root.json").write_text(tr.model_dump_json())
    r = evaluate_build_integrity(tree)
    assert r.state == S.VALID and r.ok


def test_evaluate_with_no_manifest_is_UNKNOWN_BUILD(tree):
    assert evaluate_build_integrity(tree).state == S.UNKNOWN_BUILD


def test_evaluate_never_raises_on_a_corrupt_manifest(tree):
    (tree / "build-manifest.json").write_text("{ this is not json")
    r = evaluate_build_integrity(tree)
    assert r.state == S.UNKNOWN_BUILD  # fail-closed, no exception


def test_out_of_band_pin_mismatch_refuses_the_trust_root(tree, monkeypatch):
    import hashlib
    kp, tr = _solo_root()
    m = _sign(tree, kp)
    (tree / "build-manifest.json").write_text(json.dumps(m.to_disk()) + "\n")
    tr_bytes = tr.model_dump_json().encode()
    (tree / "build-trust-root.json").write_bytes(tr_bytes)
    # a pin that MATCHES → VALID
    monkeypatch.setenv("VIGIL_BUILD_TRUST_ROOT_SHA256", hashlib.sha256(tr_bytes).hexdigest())
    assert evaluate_build_integrity(tree).state == S.VALID
    # a pin that does NOT match → the on-disk trust root is refused → cannot authenticate → UNKNOWN_BUILD
    monkeypatch.setenv("VIGIL_BUILD_TRUST_ROOT_SHA256", "00" * 32)
    r = evaluate_build_integrity(tree)
    assert r.state == S.UNKNOWN_BUILD and "pin" in r.detail.lower()
