"""repo-connect Slice 3b: the GATED review-comment write-back is OFF by default + fully fail-closed.

``post_review_comment`` is the ONLY sanctioned way to post a PR comment; it refuses (``GitHubWriteError``)
unless the WHOLE chain clears — ``comment_enabled`` ∧ an owner-signed repo-EXACT ``"comment"`` grant ∧ a
per-action owner approval — then POSTs via the gated transport and emits a signed audit record (a write is
never left un-audited). These tests exercise the REAL grant verify (the framework store), so they run in the
offense leg (module-level importorskip); a fake HTTP double proves no POST escapes a refused chain.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("framework.v2.authority.store", reason="git-write-grant verify is framework-side (offense leg)")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_core.git_write_grant import GitWriteGrant, sign_git_write_grant  # noqa: E402

from framework.v2.authority.store import save_signed_git_write_grant  # noqa: E402

from vigil_integration.live.github_write import (  # noqa: E402
    GitHubCommentConfig,
    GitHubWriteError,
    post_review_comment,
    signed_comment_audit_sink,
)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
_REPO = "github.com/acme/widget"


class _Resp:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _HTTP:
    """Fake httpx-like client recording POSTs; returns 201 + a comment payload by default."""

    def __init__(self, resp: "_Resp | None" = None) -> None:
        self.posts: list = []
        self._resp = resp or _Resp(201, {"id": 4242, "html_url": "https://github.com/acme/widget/pull/7#c4242"})

    def post(self, url, headers=None, json=None):   # noqa: A002 — matches httpx's kwarg name
        self.posts.append({"url": url, "headers": headers, "json": json})
        return self._resp


def _always(*a, **k) -> bool:
    return True


def _never(*a, **k) -> bool:
    return False


def _owner_root():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=kp.public_key_b64)])
    return kp, tr


def _provision(tmp_path, kp, *, repo=_REPO, allow_comment=True, allow_pr=False, revoked=False, slug="repo-x"):
    g = GitWriteGrant(engagement_slug=slug, repo=repo, grant_id="g1", epoch=1,
                      issued_at=_NOW - timedelta(hours=1), not_before=_NOW - timedelta(hours=1),
                      not_after=_NOW + timedelta(hours=1), allow_comment=allow_comment,
                      allow_pr=allow_pr, revoked=revoked)
    save_signed_git_write_grant(sign_git_write_grant(g, {"owner": kp.private_key_b64}), path=tmp_path / "grant.json")


def _post(tmp_path, tr, http, audit, *, enabled=True, approve=_always, body="finding: SQLi at /login", repo=_REPO):
    return post_review_comment(
        slug="repo-x", trust_root=tr, repo=repo, pr_number=7, body=body,
        config=GitHubCommentConfig(slug="repo-x", github_token="t", comment_enabled=enabled),
        approve=approve, audit=audit, http=http, now=_NOW,
        grant_path=tmp_path / "grant.json", epoch_path=tmp_path / "epoch")


# ---- the fail-closed chain: each refused step raises AND never POSTs ------------------------------

def test_off_by_default_refuses_without_posting(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)                                 # a valid grant exists …
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append, enabled=False)   # … but comment_enabled=False ⇒ refuse
    assert http.posts == [] and recs == []                   # nothing posted, nothing audited


def test_no_grant_refuses(tmp_path):
    _kp, tr = _owner_root()                                   # no grant provisioned on disk
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append)
    assert http.posts == []


def test_wrong_repo_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp, repo="github.com/acme/widget")   # grant is for widget …
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append, repo="github.com/acme/other")   # … posting to other ⇒ refuse
    assert http.posts == []


def test_comment_bit_off_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp, allow_comment=False, allow_pr=True)   # only PR granted, not comment
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append)
    assert http.posts == []


def test_revoked_grant_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp, revoked=True)
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append)
    assert http.posts == []


def test_not_approved_refuses(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    http, recs = _HTTP(), []
    with pytest.raises(GitHubWriteError):
        _post(tmp_path, tr, http, recs.append, approve=_never)   # owner did NOT approve ⇒ refuse
    assert http.posts == []


# ---- the authorized write: posts once + emits one signed-shape audit record ----------------------

def test_authorized_post_succeeds_and_audits(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    http, recs = _HTTP(), []
    result = _post(tmp_path, tr, http, recs.append)
    assert result == {"id": 4242, "html_url": "https://github.com/acme/widget/pull/7#c4242"}
    assert len(http.posts) == 1                               # exactly one POST
    assert http.posts[0]["url"] == "https://api.github.com/repos/acme/widget/issues/7/comments"
    assert http.posts[0]["json"] == {"body": "finding: SQLi at /login"}
    assert http.posts[0]["headers"]["Authorization"] == "Bearer t"
    assert len(recs) == 1                                     # exactly one audit record
    r = recs[0]
    assert r["action"] == "github_comment" and r["repo"] == "acme/widget" and r["pr_number"] == 7
    assert r["comment_id"] == 4242 and len(r["body_sha256"]) == 64


def test_audit_sink_failure_raises_no_silent_unaudited_write(tmp_path):
    kp, tr = _owner_root()
    _provision(tmp_path, kp)
    http = _HTTP()

    def _boom(_record):
        raise RuntimeError("audit sink down")

    with pytest.raises(Exception):                            # the whole call raises …
        _post(tmp_path, tr, http, _boom)
    assert len(http.posts) == 1                               # … though the POST already happened (surfaced loudly)


# ---- the signed audit sink is genuinely Ed25519-signed + offline-verifiable ----------------------

def test_signed_comment_audit_sink_signature_verifies(tmp_path):
    from vigil_core.canonical import canonical_json
    from vigil_core.crypto import verify_one
    import json as _json

    kp = generate_keypair()
    sink = signed_comment_audit_sink(tmp_path / "audit.jsonl", key_id="gov", private_key_b64=kp.private_key_b64)
    rec = {"action": "github_comment", "slug": "repo-x", "repo": "acme/widget", "pr_number": 7,
           "body_sha256": "a" * 64, "comment_id": 1, "comment_url": "u"}
    sink(rec)
    line = _json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert line["record"] == rec and line["key_id"] == "gov"
    # the signature verifies over the SAME domain-tagged canonical bytes the sink signed
    assert verify_one(kp.public_key_b64, b"vigil-git-write-audit-v1\x00" + canonical_json(rec), line["sig"])
    # a tampered record no longer verifies
    tampered = dict(rec, pr_number=8)
    assert not verify_one(kp.public_key_b64, b"vigil-git-write-audit-v1\x00" + canonical_json(tampered), line["sig"])
