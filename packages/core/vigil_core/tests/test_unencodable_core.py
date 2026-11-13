"""A signed core that cannot be canonicalised to UTF-8 fails with the module's OWN typed error.

Inert signed data crosses process and plane boundaries as JSON, and JSON can carry a lone surrogate
(``"\\ud800"``) that no signer could have produced. Encoding it to UTF-8 raises ``UnicodeEncodeError`` (a
``ValueError``). Every verifier documents a fail-closed contract — raise ``CapabilityError`` /
``DelegationError`` on ANY failure — so callers catch exactly that type; an untyped error would escape them.
"""
from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.capability import (
    CapabilityError,
    attenuate,
    identity_digest,
    prove_wielder,
    sign_capability,
    sign_identity_attestation,
    verify_capability,
    verify_identity_attestation,
    verify_wielder_proof,
)
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, DelegationError, sign_delegation, verify_delegation

OWNER = generate_keypair()
HOLDER = generate_keypair()
ENG, NOW = "acme", 1_000
BAD = "\ud800"   # a lone surrogate: valid in a JSON string, impossible to encode as UTF-8


def _cap(audience="*"):
    ident = sign_identity_attestation(OWNER, engagement=ENG, policy={"host": ["shop.acme.test"]}, not_after=2_000)
    return sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                           class_allowlist=["reflected_xss"], not_before=0, not_after=2_000, rate_limit=5,
                           revocation_id="rev-1", audience=audience)


def test_identity_attestation_with_an_unencodable_core_raises_capability_error():
    att = sign_identity_attestation(OWNER, engagement=ENG, policy={"host": ["shop.acme.test"]}, not_after=2_000)
    bad = att.model_copy(update={"policy": {"host": [BAD]}})
    with pytest.raises(CapabilityError, match="malformed"):
        verify_identity_attestation(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_capability_with_an_unencodable_core_raises_capability_error():
    bad = _cap().model_copy(update={"revocation_id": f"rev-{BAD}"})
    with pytest.raises(CapabilityError, match="malformed"):
        verify_capability(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG)


def test_attenuation_with_an_unencodable_core_raises_capability_error():
    cap = _cap()
    att = attenuate(HOLDER, prev=cap, class_subset=["reflected_xss"])
    bad = att.model_copy(update={"class_subset": [BAD]})
    with pytest.raises(CapabilityError, match="attenuation #0 signature is malformed"):
        verify_capability(cap, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, engagement=ENG,
                          attenuations=[bad])


def test_wielder_proof_with_an_unencodable_core_raises_capability_error():
    cap = _cap(audience=HOLDER.public_key_b64)
    proof = prove_wielder(HOLDER, challenge="nonce-1", capability=cap).model_copy(update={"challenge": BAD})
    with pytest.raises(CapabilityError, match="wielder proof signature is malformed"):
        verify_wielder_proof(proof, expected_audience=HOLDER.public_key_b64, challenge=BAD, capability=cap)


def test_delegation_with_an_unencodable_core_raises_delegation_error():
    gov = generate_keypair()
    cert = sign_delegation(OWNER, role=OFFENSE_GOVERNANCE_ROLE, scope="loopback",
                           authorizers=[AuthorizerKey(key_id="root0", name="root0", public_key_b64=gov.public_key_b64)],
                           threshold=1, not_after=2_000)
    bad = cert.model_copy(update={"scope": BAD})
    with pytest.raises(DelegationError, match="malformed"):
        verify_delegation(bad, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW, role=OFFENSE_GOVERNANCE_ROLE,
                          scope=BAD)


# ---- the m-of-n document verifiers: documented "never raises, always (ok, reason)" -----------------------------
# authority / monitoring authority: a lone surrogate passes json.loads + model_validate (free-text fields), i.e.
# the REAL load path. The other four documents constrain every string field, so pydantic refuses the surrogate on
# load; their catch is defence in depth for a caller that builds a document without validation (model_copy).
import json  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from vigil_core import TrustRoot  # noqa: E402
from vigil_core import authority as _A  # noqa: E402
from vigil_core import credit_lease as _C  # noqa: E402
from vigil_core import engagement_completion as _E  # noqa: E402
from vigil_core import git_write_grant as _G  # noqa: E402
from vigil_core import monitoring_authority as _M  # noqa: E402
from vigil_core import target_credentials as _T  # noqa: E402

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_T1 = _T0 + timedelta(hours=8)
_ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                          public_key_b64=OWNER.public_key_b64)])
_SIGNERS = {"owner": OWNER.private_key_b64}


def _reload_with(signed, cls, path):
    """The real load path: the signed JSON, with one document string replaced by a lone surrogate, through
    json.loads + model_validate (what framework's authority store does)."""
    raw = json.loads(signed.model_dump_json())
    cur = raw["document"]
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = BAD
    return cls.model_validate(raw)


@pytest.mark.parametrize("path", [("issued_by",), ("note",), ("scope", 0)])
def test_engagement_authority_loaded_with_an_unencodable_field_is_refused_not_raised(path):
    doc = _A.EngagementAuthority(engagement_slug="apme-cm", environment=_A.TargetEnvironment.STAGING,
                                 scope=["apme.cm"], not_before=_T0, not_after=_T1, issued_by="owner")
    bad = _reload_with(_A.sign_engagement_authority(doc, _SIGNERS), _A.SignedAuthority, path)
    ok, reason = _A.verify_engagement_authority(bad, _ROOT)
    assert ok is False and "malformed" in reason


def test_monitoring_authority_loaded_with_an_unencodable_field_is_refused_not_raised():
    doc = _M.MonitoringAuthority(org_id="org_acme", host="apme.cm", mode=_M.MonitoringMode.OBSERVE,
                                 not_before=_T0, not_after=_T1, issued_by="owner")
    bad = _reload_with(_M.sign_monitoring_authority(doc, _SIGNERS), _M.SignedMonitoringAuthority, ("issued_by",))
    ok, reason = _M.verify_monitoring_authority(bad, _ROOT)
    assert ok is False and "malformed" in reason


def _unvalidated(signed, field):
    return signed.model_copy(update={"document": signed.document.model_copy(update={field: BAD})})


def test_credit_lease_with_an_unencodable_document_is_refused_not_raised():
    doc = _C.CreditLaunchLease(engagement_slug="cust_abc", org_id="org_acme", scope_host="apme.cm",
                               units_reserved=10, not_before=_T0, not_after=_T1, nonce="n-1", issued_at=1000.0)
    ok, reason = _C.verify_credit_launch_lease(_unvalidated(_C.sign_credit_launch_lease(doc, _SIGNERS), "nonce"), _ROOT)
    assert ok is False and "malformed" in reason


def test_engagement_completion_with_an_unencodable_document_is_refused_not_raised():
    doc = _E.EngagementCompletion(engagement_slug="cust_abc123", nonce="n1", outcome=_E.EngagementOutcome.COMPLETED)
    signed = _E.sign_engagement_completion(doc, _SIGNERS)
    ok, reason = _E.verify_engagement_completion(_unvalidated(signed, "nonce"), _ROOT)
    assert ok is False and "malformed" in reason


def test_target_credentials_with_an_unencodable_document_is_refused_not_raised():
    hdr = _T.CredentialHeader(name="Cookie", value="sid=x")
    doc = _T.TargetCredentials(engagement_slug="apme-cm", credentials=[
        _T.AccountCredential(role=r, auth_headers=[hdr]) for r in
        (_T.CredentialRole.ATTACKER, _T.CredentialRole.VICTIM, _T.CredentialRole.UNAUTHORIZED_PEER)])
    signed = _T.sign_target_credentials(doc, _SIGNERS)
    ok, reason = _T.verify_target_credentials(_unvalidated(signed, "engagement_slug"), _ROOT)
    assert ok is False and "malformed" in reason


def test_git_write_grant_with_an_unencodable_document_is_refused_not_raised():
    doc = _G.GitWriteGrant(engagement_slug="repo-x", repo="github.com/acme/widget", grant_id="g1", epoch=1,
                           issued_at=_T0, not_before=_T0, not_after=_T1, allow_comment=True, allow_pr=False)
    ok, reason = _G.verify_git_write_grant(_unvalidated(_G.sign_git_write_grant(doc, _SIGNERS), "grant_id"), _ROOT)
    assert ok is False and "malformed" in reason


def test_build_manifest_parsed_with_an_unencodable_version_is_unknown_not_raised(tmp_path):
    from vigil_core.signed_build_manifest import (BuildIntegrityState, build_signed_manifest,
                                                  parse_signed_manifest, verify_build_integrity)
    (tmp_path / "f").write_text("x\n")
    m = build_signed_manifest(product_version="1.5.0", channel="release",
                              specs=[{"name": "f", "kind": "file", "path": "f"}], tree_root=tmp_path,
                              signers=[("owner", OWNER.private_key_b64)])
    disk = m.to_disk()
    disk["product_version"] = BAD
    bad = parse_signed_manifest(json.dumps(disk))                         # the real on-disk parse path
    r = verify_build_integrity(bad, tree_root=tmp_path, trust_root=_ROOT)   # documented: never raises
    assert r.state == BuildIntegrityState.UNKNOWN_BUILD and not r.ok


def test_verify_wielder_proof_with_an_unencodable_capability_raises_capability_error():
    cap = _cap(audience=HOLDER.public_key_b64)
    proof = prove_wielder(HOLDER, challenge="nonce-1", capability=cap)
    bad_cap = cap.model_copy(update={"revocation_id": f"rev-{BAD}"})
    with pytest.raises(CapabilityError, match="malformed"):
        verify_wielder_proof(proof, expected_audience=HOLDER.public_key_b64, challenge="nonce-1", capability=bad_cap)
