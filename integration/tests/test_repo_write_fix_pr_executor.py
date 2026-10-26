"""repo-connect Slice 3c: the GATED fix-PR write-back is OFF by default + fully fail-closed.

``authorized_fix_pr`` opens a fix PR ONLY if the whole chain clears — ``pr_enabled`` ∧ an owner-signed repo-EXACT
``"pr"`` grant ∧ the clone's origin IS the granted repo — then runs the PCR ladder (``autopatch_live``, whose
``open_pr`` adds the WARDEN A3 + m-of-n + feature-branch gates) and emits a signed audit record. These tests
exercise the REAL grant verify (framework store, offense leg) and INJECT the autopatch ladder + the origin
reader, so no clone/patch/PR/network happens; a spy proves the ladder is never reached on a refused chain.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2.authority.store", reason="git-write-grant verify is framework-side (offense leg)")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_core.git_write_grant import GitWriteGrant, sign_git_write_grant  # noqa: E402

from framework.v2.authority.store import save_signed_git_write_grant  # noqa: E402

from vigil_integration.live.codefix_runner import CodefixConfig  # noqa: E402
from vigil_integration.live.github_fix_pr import (  # noqa: E402
    _normalize_remote,
    authorized_fix_pr,
)
from vigil_integration.live.github_write import GitHubWriteError  # noqa: E402

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_REPO = "github.com/acme/widget"
_FINDING = SimpleNamespace(ref="F-001")


class _Result:
    def __init__(self) -> None:
        self.status = "opened-pr"
        self.pr_ref = "https://github.com/acme/widget/pull/9"
        self.remediated = True


def _spy():
    calls: list = []

    def fake(finding, *, config, client=None, killswitch=None, quorum=None, verify_oracle=None):
        calls.append({"quorum": quorum})
        return _Result()

    return fake, calls


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


def _provision(tmp_path, kp, *, repo=_REPO, allow_comment=False, allow_pr=True, revoked=False, slug="repo-x"):
    g = GitWriteGrant(engagement_slug=slug, repo=repo, grant_id="g1", epoch=1,
                      issued_at=_NOW - timedelta(hours=1), not_before=_NOW - timedelta(hours=1),
                      not_after=_NOW + timedelta(hours=1), allow_comment=allow_comment,
                      allow_pr=allow_pr, revoked=revoked)
    save_signed_git_write_grant(sign_git_write_grant(g, {"owner": kp.private_key_b64}), path=tmp_path / "grant.json")


def _fix(tmp_path, tr, *, autopatch, audit, pr_enabled=True, remote="https://github.com/acme/widget.git", repo=_REPO):
    cfg = CodefixConfig(target_repo=str(tmp_path / "clone"), base_dir=str(tmp_path),
                        pr_enabled=pr_enabled, github_token="t")
    return authorized_fix_pr(
        slug="repo-x", trust_root=tr, repo=repo, finding=_FINDING, config=cfg, audit=audit,
        quorum=lambda req: None, now=_NOW, grant_path=tmp_path / "grant.json", epoch_path=tmp_path / "epoch",
        remote_of=lambda t, g="git": remote, _autopatch=autopatch)


# ---- fail-closed chain: each refused step raises AND never runs the PCR ladder --------------------

def test_off_by_default_refuses_without_running_ladder(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    fake, calls = _spy()
    recs: list = []
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, tr, autopatch=fake, audit=recs.append, pr_enabled=False)
    assert calls == [] and recs == []


def test_no_grant_refuses(tmp_path):
    _kp, tr = _owner_root()                        # no grant provisioned
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, tr, autopatch=fake, audit=lambda r: None)
    assert calls == []


def test_pr_bit_off_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp, allow_pr=False, allow_comment=True)   # only comment granted, not pr
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, tr, autopatch=fake, audit=lambda r: None)
    assert calls == []


def test_revoked_grant_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp, revoked=True)
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, tr, autopatch=fake, audit=lambda r: None)
    assert calls == []


def test_origin_mismatch_refuses_without_running_ladder(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)                        # grant is for acme/widget …
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):           # … but the clone's origin is a DIFFERENT repo ⇒ refuse
        _fix(tmp_path, tr, autopatch=fake, audit=lambda r: None, remote="https://github.com/acme/other.git")
    assert calls == []


def test_tampered_grant_refuses_with_write_error(tmp_path):
    kp, _tr = _owner_root()
    _provision(tmp_path, kp)
    _kp2, wrong_tr = _owner_root()                  # verify against a DIFFERENT trust root ⇒ AuthorityError
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, wrong_tr, autopatch=fake, audit=lambda r: None)
    assert calls == []


# ---- the authorized write: runs the ladder once + emits one audit record -------------------------

def test_authorized_runs_ladder_once_and_audits(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    fake, calls = _spy()
    recs: list = []
    result = _fix(tmp_path, tr, autopatch=fake, audit=recs.append)
    assert result.status == "opened-pr"
    assert len(calls) == 1 and callable(calls[0]["quorum"])          # the ladder ran once, with the m-of-n quorum
    assert len(recs) == 1
    r = recs[0]
    assert r["action"] == "github_pr" and r["repo"] == "github.com/acme/widget"   # canonical host/org/repo
    assert r["finding_ref"] == "F-001" and r["pr_ref"].endswith("/pull/9") and r["remediated"] is True


def test_audit_failure_raises(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    fake, calls = _spy()

    def _boom(_r):
        raise RuntimeError("audit down")

    with pytest.raises(Exception):
        _fix(tmp_path, tr, autopatch=fake, audit=_boom)
    assert len(calls) == 1                                           # the ladder ran; the un-audited result raises


def test_dotgithub_repo_write_is_still_audited(tmp_path):
    """red-pen MEDIUM: a valid 'pr' grant for a repo _owner_repo can't parse (the ubiquitous `.github` org
    repo, or a GHE host) must NOT run the writing ladder and THEN leave the write UN-AUDITED. The audit binds
    the canonical host/org/repo (never raises), so control 7 holds."""
    kp, tr = _owner_root()
    dot = "github.com/acme/.github"
    _provision(tmp_path, kp, repo=dot)
    fake, calls = _spy()
    recs: list = []
    result = _fix(tmp_path, tr, autopatch=fake, audit=recs.append, repo=dot, remote="git@github.com:acme/.github.git")
    assert result.status == "opened-pr"
    assert len(calls) == 1 and len(recs) == 1            # ladder ran once AND the write was audited (control 7)
    assert recs[0]["repo"] == "github.com/acme/.github"


def test_none_trust_root_refuses_with_write_error(tmp_path):
    """red-pen LOW: a None trust_root raises AttributeError internally; normalized to GitHubWriteError
    (fail-closed, no ladder) so the single-refusal-type contract holds."""
    kp, _tr = _owner_root()
    _provision(tmp_path, kp)
    fake, calls = _spy()
    with pytest.raises(GitHubWriteError):
        _fix(tmp_path, None, autopatch=fake, audit=lambda r: None)
    assert calls == []


# ---- the grant-vs-target normalizer treats URL forms of the SAME repo as equal -------------------

def test_normalize_remote_equates_url_forms():
    canon = _normalize_remote("github.com/acme/widget")
    assert _normalize_remote("https://github.com/acme/widget.git") == canon
    assert _normalize_remote("git@github.com:acme/widget.git") == canon
    assert _normalize_remote("https://x-access-token:TOK@github.com/acme/widget.git") == canon
    assert _normalize_remote("https://github.com/acme/other.git") != canon    # a different repo stays different
