"""W16-STD-3 (3) — the segment manifest's signed tier: sign it, verify it, REFUSE an edited manifest.

The manifest was reserved-but-unsigned (`manifest_sig: null`). This suite pins the implemented signed tier
(reusing the shared `vigil_core` Ed25519 — no new crypto):

  * `write_manifest(..., private_key_b64=…)` populates `manifest_sig`; `read_manifest(..., public_key_b64=…)`
    then VERIFIES it.
  * a manifest whose body was edited AFTER signing is REFUSED fail-closed (`ManifestSignatureError`) — the
    exact property an unsigned manifest lacks.
  * NEGATIVE CONTROL: a correctly signed, untampered manifest read back under the right key SUCCEEDS (the
    gate is not a no-op that refuses everything), and reading without a key stays byte-identical/unsigned.

FAILS-WITHOUT-THE-CHANGE: on a tree where the manifest tier is unsigned, `write_manifest` ignores the key,
`manifest_sig` stays None, and `read_manifest(..., public_key_b64=…)` either has no such parameter or cannot
refuse a tampered manifest — so the `ManifestSignatureError` assertions below fail.

Run: PYTHONPATH=packages/core/vigil_core:apps/sigil:integration <venv-sovereign>/bin/python -m pytest \
     apps/sigil/tests/test_spine_manifest_signature.py -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sigil.reuse import generate_keypair
from sigil.spine.manifest import (
    Manifest,
    ManifestSignatureError,
    Segment,
    SpineLayout,
    read_manifest,
    sign_manifest,
    verify_manifest,
    write_manifest,
)


def _layout(tmp_path: Path) -> SpineLayout:
    return SpineLayout.for_path(tmp_path / "spine.jsonl")


def _manifest() -> Manifest:
    return Manifest(
        generation=3, scope="sigil",
        segments=[Segment(id=0, file="spine.segments/seg-00000000.jsonl", sealed=False, first_seq=0)],
    )


def test_sign_then_verify_roundtrip():
    kp = generate_keypair()
    signed = sign_manifest(_manifest(), kp.private_key_b64)
    assert signed.manifest_sig                       # populated, no longer the reserved null
    assert verify_manifest(signed, kp.public_key_b64) is True


def test_verify_rejects_unsigned_and_wrong_key():
    kp = generate_keypair()
    other = generate_keypair()
    m = _manifest()
    assert verify_manifest(m, kp.public_key_b64) is False          # unsigned → not verified
    signed = sign_manifest(m, kp.private_key_b64)
    assert verify_manifest(signed, other.public_key_b64) is False  # signed, but wrong key


def test_verify_rejects_tampered_body():
    kp = generate_keypair()
    signed = sign_manifest(_manifest(), kp.private_key_b64)
    # keep the signature, edit a body field → the re-derived canonical body no longer matches the signature
    tampered = signed.model_copy(update={"generation": signed.generation + 1})
    assert verify_manifest(tampered, kp.public_key_b64) is False


def test_write_signed_read_verified_roundtrip(tmp_path):
    """NEGATIVE CONTROL: a signed manifest written then read back under the right key SUCCEEDS."""
    kp = generate_keypair()
    layout = _layout(tmp_path)
    write_manifest(layout, _manifest(), private_key_b64=kp.private_key_b64)
    m = read_manifest(layout, public_key_b64=kp.public_key_b64)
    assert m is not None and m.generation == 3
    assert m.manifest_sig                            # persisted signed


def test_read_refuses_edited_manifest_on_disk(tmp_path):
    """The property an UNSIGNED manifest lacks: an on-disk manifest edited after signing is REFUSED."""
    kp = generate_keypair()
    layout = _layout(tmp_path)
    write_manifest(layout, _manifest(), private_key_b64=kp.private_key_b64)
    # tamper the persisted bytes: bump generation, keep the (now-stale) signature
    import json
    obj = json.loads(layout.manifest_path.read_text(encoding="utf-8"))
    obj["generation"] = 99
    layout.manifest_path.write_text(json.dumps(obj), encoding="utf-8")
    with pytest.raises(ManifestSignatureError):
        read_manifest(layout, public_key_b64=kp.public_key_b64)


def test_read_refuses_unsigned_manifest_when_key_required(tmp_path):
    """When a verifying key is supplied, an UNSIGNED manifest is refused (the tier is enforced)."""
    kp = generate_keypair()
    layout = _layout(tmp_path)
    write_manifest(layout, _manifest())              # no key → written unsigned
    assert read_manifest(layout) is not None         # unsigned read still works (backward-compatible)
    with pytest.raises(ManifestSignatureError):
        read_manifest(layout, public_key_b64=kp.public_key_b64)
