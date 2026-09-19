"""The framework authority schema/canonical are the SAME objects as the shared vigil_core core.

``EngagementAuthority`` / ``SignedAuthority`` / ``TargetEnvironment`` and ``authority_signing_bytes`` were
lifted into ``vigil_core.authority`` so the SOVEREIGN plane can owner-sign an authority without importing
``framework`` (the two-env boundary). framework re-exports them. This proves the re-export is not a
divergent second definition:

* framework's names ARE vigil_core's names (class identity) — so isinstance / model identity hold and there
  is exactly one schema;
* the signing bytes are byte-identical across the two import paths;
* an authority the SOVEREIGN signer produces (vigil_core alone) verifies with THIS engine's
  ``verify_authority`` — the sovereign signer and the offense verifier agree by construction.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import vigil_core.authority as VC
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair

from framework.v2.authority.canonical import authority_signing_bytes as fw_signing_bytes
from framework.v2.authority.models import EngagementAuthority, SignedAuthority, TargetEnvironment
from framework.v2.authority.signing import verify_authority

_TS = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)


def _doc() -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="apme-cm", environment=TargetEnvironment.STAGING, scope=["apme.cm"],
        not_before=_TS, not_after=_TS + timedelta(hours=8), issued_by="owner",
    )


def test_framework_authority_types_are_the_vigil_core_types():
    assert EngagementAuthority is VC.EngagementAuthority
    assert SignedAuthority is VC.SignedAuthority
    assert TargetEnvironment is VC.TargetEnvironment


def test_signing_bytes_byte_identical_across_import_paths():
    doc = _doc()
    assert fw_signing_bytes(doc) == VC.authority_signing_bytes(doc)
    assert fw_signing_bytes(doc).startswith(b"crucible-authority-v1\x00")


def test_sovereign_signed_authority_verifies_with_the_offense_verifier():
    """The sovereign plane signs with vigil_core ONLY; this engine's verify_authority accepts it."""
    owner = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])
    signed = VC.sign_engagement_authority(_doc(), {"owner": owner.private_key_b64})
    ok, reason = verify_authority(signed, tr)
    assert ok, reason
    # negative control: a tampered scope is rejected by the offense verifier too.
    tampered = signed.model_copy(update={"document": signed.document.model_copy(update={"scope": ["evil"]})})
    ok2, _ = verify_authority(tampered, tr)
    assert not ok2
