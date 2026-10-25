"""repo-connect Slice 3-authz: the repo-exact write gate + the signed-grant store with replay protection.

`authorize_repo_write` is the pure, fail-closed DECISION over a verified GitWriteGrant (exact org+repo,
separate comment/pr capability bits, expiration window, revocation). `load_verified_git_write_grant` is the
store that verifies the owner signature AND enforces an epoch high-water so a revoked / superseded grant can
never be REPLAYED back into force. Mirrors the oob-egress test shape; runs in the crucible-core offense leg.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.git_write_grant import GitWriteGrant, sign_git_write_grant

from framework.v2.authority.gate import authorize_repo_write
from framework.v2.authority.store import (
    AuthorityUnsigned,
    load_verified_git_write_grant,
    save_signed_git_write_grant,
)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_REPO = "github.com/acme/widget"


def _grant(**over) -> GitWriteGrant:
    base = dict(engagement_slug="repo-x", repo=_REPO, grant_id="g1", epoch=1, issued_at=_NOW - timedelta(hours=1),
                not_before=_NOW - timedelta(hours=1), not_after=_NOW + timedelta(hours=1),
                allow_comment=True, allow_pr=False)
    base.update(over)
    return GitWriteGrant(**base)


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


# ---- the gate (pure decision) --------------------------------------------------------------------

def test_gate_allows_the_granted_capability_on_the_exact_repo():
    g = _grant(allow_comment=True, allow_pr=True)
    assert authorize_repo_write(g, _REPO, "comment", now=_NOW) is True
    assert authorize_repo_write(g, _REPO, "pr", now=_NOW) is True


def test_gate_separates_comment_and_pr_permissions():
    comment_only = _grant(allow_comment=True, allow_pr=False)
    assert authorize_repo_write(comment_only, _REPO, "comment", now=_NOW) is True
    assert authorize_repo_write(comment_only, _REPO, "pr", now=_NOW) is False   # PR NOT separately granted


def test_gate_fail_closed_wrong_repo_revoked_window_capability_and_none():
    g = _grant(allow_pr=True)
    assert authorize_repo_write(g, "github.com/acme/other", "pr", now=_NOW) is False   # exact-repo mismatch
    assert authorize_repo_write(_grant(allow_pr=True, revoked=True), _REPO, "pr", now=_NOW) is False  # revoked
    assert authorize_repo_write(g, _REPO, "pr", now=_NOW + timedelta(hours=2)) is False  # expired (out of window)
    assert authorize_repo_write(g, _REPO, "pr", now=_NOW - timedelta(hours=2)) is False  # too early
    assert authorize_repo_write(g, _REPO, "deploy", now=_NOW) is False   # unknown capability
    assert authorize_repo_write(None, _REPO, "pr", now=_NOW) is False    # no grant


# ---- the store (verify + epoch replay protection + revocation supersession) -----------------------

def _save(tmp, tr_kp, **over):
    kp = tr_kp
    signed = sign_git_write_grant(_grant(**over), {"owner": kp.private_key_b64})
    return save_signed_git_write_grant(signed, path=tmp / "grant.json")


def test_store_verifies_and_loads_then_enforces_epoch_high_water(tmp_path):
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    # a signed epoch-5 grant loads and advances the high-water to 5
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(epoch=5, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    got = load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)
    assert got is not None and got.epoch == 5 and got.allow_pr is True
    import json as _json
    assert _json.loads(epath.read_text())["epoch"] == 5   # the floor records {epoch, grant_id}
    # a REPLAYED older epoch-1 grant (e.g. a leaked earlier grant) is REFUSED (below the high-water)
    save_signed_git_write_grant(_s(_grant(epoch=1, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)


def test_store_revocation_supersedes_and_cannot_be_replayed(tmp_path):
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    # epoch-1 grant authorizes PR writes
    save_signed_git_write_grant(_s(_grant(epoch=1, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    g1 = load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)
    assert authorize_repo_write(g1, _REPO, "pr", now=_NOW) is True
    # owner REVOKES at epoch 2 (revoked=True, bits off) — loads, and the gate denies
    save_signed_git_write_grant(_s(_grant(epoch=2, revoked=True, allow_comment=False, allow_pr=False),
                                    {"owner": kp.private_key_b64}), path=gpath)
    g2 = load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)
    assert authorize_repo_write(g2, _REPO, "pr", now=_NOW) is False
    # REPLAY the old epoch-1 grant → refused (below the high-water of 2) — revocation cannot be rolled back
    save_signed_git_write_grant(_s(_grant(epoch=1, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)


def test_store_absent_grant_is_none_and_tampered_raises(tmp_path):
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    assert load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath) is None   # no grant ⇒ None
    # a wrong-trust-root signature fails verification → raise (fail-closed)
    _kp2, tr2 = _owner_root()
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(), {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr2, path=gpath, epoch_path=epath)


# ---- red-pen regressions: the floor is signed-free so it MUST fail closed, bind content, and not swap ----

def test_store_corrupt_floor_fails_closed(tmp_path):
    """A present-but-unparseable floor RAISES — it must NEVER silently reset to a lower floor (which would
    re-admit a superseded / revoked grant). This is the red-pen HIGH: the old plaintext int failed OPEN."""
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(epoch=5, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    epath.write_text("not-json-garbage")            # a corrupt / partially-written / tampered floor
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)
    epath.write_text('{"epoch": 5}')                # malformed shape (missing grant_id) also refuses
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)


def test_store_binds_grant_to_its_engagement_slug(tmp_path):
    """A grant signed for engagement A must not authorize engagement B even with a valid signature — the
    content binding (red-pen MEDIUM). The owner signs the slug, so a cross-engagement replay is refused."""
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(engagement_slug="repo-x", allow_pr=True),
                                    {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("other-engagement", tr, path=gpath, epoch_path=epath)


def test_store_same_epoch_swap_is_refused(tmp_path):
    """Two DISTINCT grants at the SAME epoch: only the first-seen grant_id stays in force. A second,
    differently-signed grant at the same epoch is a same-epoch swap and is refused (red-pen MEDIUM)."""
    kp, tr = _owner_root()
    gpath, epath = tmp_path / "grant.json", tmp_path / "epoch"
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(epoch=3, grant_id="g-first", allow_pr=True),
                                    {"owner": kp.private_key_b64}), path=gpath)
    assert load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath) is not None   # floor={3,g-first}
    save_signed_git_write_grant(_s(_grant(epoch=3, grant_id="g-second", allow_pr=True),
                                    {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(AuthorityUnsigned):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)   # same epoch, different id


def test_store_advance_write_failure_raises_not_swallowed(tmp_path):
    """A failed monotonic advance must be LOUD, not silently swallowed (red-pen MEDIUM): if the floor cannot
    be durably written, the load RAISES rather than proceeding as if the high-water had advanced."""
    kp, tr = _owner_root()
    gpath = tmp_path / "grant.json"
    (tmp_path / "blocker").write_text("i am a file, not a dir")   # so epoch_path's parent cannot be created
    epath = tmp_path / "blocker" / "epoch"
    from vigil_core.git_write_grant import sign_git_write_grant as _s
    save_signed_git_write_grant(_s(_grant(epoch=1, allow_pr=True), {"owner": kp.private_key_b64}), path=gpath)
    with pytest.raises(OSError):
        load_verified_git_write_grant("repo-x", tr, path=gpath, epoch_path=epath)
