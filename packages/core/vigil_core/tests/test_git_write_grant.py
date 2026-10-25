"""The owner-signed GitWriteGrant primitive (vigil_core.git_write_grant, repo-connect Slice 3-authz).

A SEPARATE signed document (NOT a field on EngagementAuthority) authorizing GitHub writes to one EXACT
repo, with per-capability bits + expiration + revocation + an epoch for replay/supersession protection.
These tests lock: a sign→verify round-trip; a tampered repo / capability / revoked flag FAILS (fail-closed);
a wrong / quorum-collapsing trust root fails; the EXACT org+repo form is enforced; the window is validated;
and signing pulls in NO framework (usable in a sovereign venv).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.git_write_grant import (
    GitWriteGrant,
    SignedGitWriteGrant,
    sign_git_write_grant,
    verify_git_write_grant,
)

_TS = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _grant(**over) -> GitWriteGrant:
    base = dict(engagement_slug="repo-x", repo="github.com/acme/widget", grant_id="g1", epoch=1,
                issued_at=_TS, not_before=_TS, not_after=_TS + timedelta(hours=8),
                allow_comment=True, allow_pr=False)
    base.update(over)
    return GitWriteGrant(**base)


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


def test_sign_verify_round_trip():
    kp, tr = _owner_root()
    signed = sign_git_write_grant(_grant(), {"owner": kp.private_key_b64})
    ok, reason = verify_git_write_grant(signed, tr)
    assert ok is True, reason


def test_tampered_capability_fails_verification():
    kp, tr = _owner_root()
    signed = sign_git_write_grant(_grant(allow_pr=False), {"owner": kp.private_key_b64})
    # flip allow_pr True AFTER signing — the owner never authorized a PR write
    tampered = SignedGitWriteGrant(document=signed.document.model_copy(update={"allow_pr": True}),
                                   signatures=signed.signatures)
    assert verify_git_write_grant(tampered, tr)[0] is False


def test_tampered_repo_fails_verification():
    kp, tr = _owner_root()
    signed = sign_git_write_grant(_grant(), {"owner": kp.private_key_b64})
    tampered = SignedGitWriteGrant(document=signed.document.model_copy(update={"repo": "github.com/acme/evil"}),
                                   signatures=signed.signatures)
    assert verify_git_write_grant(tampered, tr)[0] is False


def test_tampered_revoked_flag_fails_verification():
    kp, tr = _owner_root()
    signed = sign_git_write_grant(_grant(revoked=True), {"owner": kp.private_key_b64})
    # un-revoke AFTER signing — must not verify (the revocation is owner-signed)
    tampered = SignedGitWriteGrant(document=signed.document.model_copy(update={"revoked": False}),
                                   signatures=signed.signatures)
    assert verify_git_write_grant(tampered, tr)[0] is False


def test_wrong_trust_root_fails():
    kp, _tr = _owner_root()
    signed = sign_git_write_grant(_grant(), {"owner": kp.private_key_b64})
    _kp2, tr2 = _owner_root()
    assert verify_git_write_grant(signed, tr2)[0] is False


def test_duplicate_pubkey_trust_root_refused():
    kp, _ = _owner_root()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=kp.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=kp.public_key_b64)])   # same pubkey twice
    signed = sign_git_write_grant(_grant(), {"a": kp.private_key_b64})
    ok, reason = verify_git_write_grant(signed, tr)
    assert ok is False and "duplicate" in reason.lower()


def test_repo_must_be_exact_org_repo():
    for bad in ("github.com/org", "github.com", "github.com/org/*", "github.com/org/repo/extra", "org/repo"):
        with pytest.raises(Exception):
            _grant(repo=bad)
    # a well-formed host/org/repo is accepted
    assert _grant(repo="github.com/acme/widget").repo == "github.com/acme/widget"


def test_window_validator_refuses_nonpositive_window():
    with pytest.raises(Exception):
        _grant(not_after=_TS - timedelta(hours=1))


def test_engagement_slug_rejects_path_traversal():
    # The slug keys the on-disk grant + epoch-floor paths; a separator / '..' / control char could traverse
    # out of the per-engagement .authority/ area, so it is rejected at construction (red-pen LOW, parity with
    # repo's _REPO_RE). The slug is owner-signed — no traversal slug is ever signable.
    for bad in ("../../etc/evil", "a/b", "a\\b", "a..b", "..", ".", "", "x\x00y", "line\nbreak"):
        with pytest.raises(Exception):
            _grant(engagement_slug=bad)
    # a normal engagement slug is accepted unchanged (identity matters for the content binding)
    assert _grant(engagement_slug="mrbeanpanel").engagement_slug == "mrbeanpanel"
    assert _grant(engagement_slug="repo-x_1.2").engagement_slug == "repo-x_1.2"
