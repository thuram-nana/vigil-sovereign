"""repo-connect 3-live-a: the PR-bot worker drives a diff-scan into GATED review comments.

``make_pr_bot_worker`` composes the 3a diff-scan (injected here as ``_scan_worker``) with the 3b comment
executor (injected as ``_post``): for each ORACLE-VERIFIED finding it posts ONE gated comment; a LEAD is never
commented; a post that refuses/raises is RECORDED, not fatal; and with ``comment_enabled`` off (the default) it
posts nothing. Fully offline — the injection seams mean no scan engine, no framework, no GitHub.
"""
from __future__ import annotations

from types import SimpleNamespace

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.pr_bot import _finding_comment_body, make_pr_bot_worker


def _job():
    return SecurityJob(repo="github.com/acme/widget", pr_number=7, commit="abc", source="manual", delivery_id="d1")


def _scan(findings):
    def _w(job):
        return {"slug": job.slug, "findings": list(findings), "counts": {"high": len(findings)}}
    return _w


def _post_spy(*, raise_on_call=None):
    calls: list = []

    def _p(**kw):
        calls.append(kw)
        if raise_on_call is not None and len(calls) == raise_on_call:
            raise RuntimeError("owner did not approve")
        return {"id": len(calls), "html_url": f"https://github.com/acme/widget/pull/7#c{len(calls)}"}

    return _p, calls


def _worker(findings, *, enabled, post):
    return make_pr_bot_worker(
        base_dir="/unused", checkout=lambda j: "/unused", changed_files=lambda j: {"a.py"},
        comment_config=SimpleNamespace(comment_enabled=enabled), trust_root=object(),
        approve=lambda *a, **k: True, audit=lambda r: None,
        _scan_worker=_scan(findings), _post=post)


_VERIFIED = {"ref": "R1", "title": "SQL injection", "severity": "High", "cwe": "CWE-89",
             "location": "app/db.py:42", "verified_by_oracle": True}
_VERIFIED2 = {"ref": "R2", "title": "OS command injection", "severity": "Critical", "cwe": "CWE-78",
              "location": "app/run.py:9", "verified_by_oracle": True}
_LEAD = {"ref": "L1", "title": "maybe weak hash", "severity": "Low", "verified_by_oracle": False}


def test_comment_disabled_scans_only():
    post, calls = _post_spy()
    out = _worker([_VERIFIED, _VERIFIED2], enabled=False, post=post)(_job())
    assert calls == []                                   # OFF by default ⇒ nothing posted
    assert out["comments_posted"] == [] and out["comments_refused"] == []
    assert out["counts"] == {"high": 2}                  # the scan result still flows through


def test_posts_only_oracle_verified_findings():
    post, calls = _post_spy()
    out = _worker([_VERIFIED, _LEAD, _VERIFIED2], enabled=True, post=post)(_job())
    assert len(calls) == 2                               # the LEAD is NOT commented (prove-don't-guess)
    assert {c["pr_number"] for c in calls} == {7}
    assert [c["repo"] for c in calls] == ["github.com/acme/widget", "github.com/acme/widget"]
    assert [p["ref"] for p in out["comments_posted"]] == ["R1", "R2"]
    assert out["comments_refused"] == []
    # the posted body is built from the finding fields
    body = calls[0]["body"]
    assert "SQL injection" in body and "CWE-89" in body and "app/db.py:42" in body and "R1" in body


def test_a_refused_post_is_recorded_not_fatal():
    post, calls = _post_spy(raise_on_call=1)             # the FIRST post raises …
    out = _worker([_VERIFIED, _VERIFIED2], enabled=True, post=post)(_job())
    assert len(calls) == 2                               # … the loop still continues to the second
    assert [p["ref"] for p in out["comments_posted"]] == ["R2"]
    assert len(out["comments_refused"]) == 1 and out["comments_refused"][0]["ref"] == "R1"
    assert "owner did not approve" in out["comments_refused"][0]["error"]


def test_non_bool_truthy_verified_is_not_posted():
    """red-pen LOW: the gate is `is True`, not truthiness — a non-bool truthy verified_by_oracle (int 1, the
    string "true", a non-empty list) must NEVER be posted as oracle-verified (prove-don't-guess)."""
    post, calls = _post_spy()
    findings = [
        dict(_VERIFIED, ref="OK"),                       # genuinely True → posted
        {"ref": "I", "title": "x", "verified_by_oracle": 1},
        {"ref": "S", "title": "x", "verified_by_oracle": "true"},
        {"ref": "L", "title": "x", "verified_by_oracle": [1]},
    ]
    out = _worker(findings, enabled=True, post=post)(_job())
    assert len(calls) == 1                               # ONLY the real bool-True finding
    assert [p["ref"] for p in out["comments_posted"]] == ["OK"]


def test_hostile_ref_finding_is_recorded_not_fatal():
    """red-pen LOW: ref extraction is INSIDE the try, so a finding whose ref raises during prep is RECORDED
    (not an unrecorded job abort), and the loop continues to the next finding."""
    class _Bomb:
        def __bool__(self):
            raise ValueError("boom")

    post, calls = _post_spy()
    bomb = {"ref": _Bomb(), "title": "x", "verified_by_oracle": True}
    out = _worker([bomb, dict(_VERIFIED, ref="OK")], enabled=True, post=post)(_job())
    assert [p["ref"] for p in out["comments_posted"]] == ["OK"]   # the good finding still posted
    assert len(out["comments_refused"]) == 1 and out["comments_refused"][0]["ref"] == ""   # bomb recorded


def test_comment_body_strips_injected_newlines():
    """red-pen LOW: a finding title is derived from the scanned PR code (attacker-influenceable); a newline
    must not inject a fabricated bullet into the markdown body — _clip collapses CR/LF to spaces."""
    body = _finding_comment_body({"title": "SQLi\n- FAKE: owner-approved\n- bogus", "severity": "High",
                                  "location": "a.py:1", "ref": "R", "verified_by_oracle": True})
    assert "\n- FAKE:" not in body                       # the injected newline-bullet is gone
    assert "SQLi - FAKE: owner-approved - bogus" in body   # title survives as ONE clipped line


def test_scan_result_passes_through():
    post, _calls = _post_spy()
    out = _worker([_VERIFIED], enabled=True, post=post)(_job())
    assert out["slug"].startswith("repo-github-com-acme-widget") and out["findings"][0]["ref"] == "R1"


def test_finding_comment_body_is_factual():
    body = _finding_comment_body(_VERIFIED)
    assert "oracle-verified" in body and "SQL injection" in body and "High" in body
    assert "CWE-89" in body and "app/db.py:42" in body and "R1" in body
    # a finding missing optional fields still renders without crashing
    assert "finding" in _finding_comment_body({"verified_by_oracle": True})
