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


# ======================================================================================================
# 3c fix-PR leg — the worker ALSO opens a gated fix PR per oracle-verified finding when a ``fix_pr`` is
# injected (parallel to the comment leg, independent opt-in). ``fix_pr`` is injected here as a double; the
# real one (make_pr_bot_fix_pr → authorized_fix_pr) is OFF by default and covered by its own test modules.
# ======================================================================================================

def _fix_spy(*, raise_on_call=None):
    calls: list = []

    def _f(job, finding, local_root=None):
        calls.append({"ref": (finding or {}).get("ref"), "local_root": local_root, "repo": job.repo})
        if raise_on_call is not None and len(calls) == raise_on_call:
            raise RuntimeError("m-of-n quorum denied")
        return SimpleNamespace(status="opened-pr", pr_ref=f"https://github.com/acme/widget/pull/{len(calls)+10}",
                               remediated=True)

    return _f, calls


def _checkout_spy(root="/clone"):
    calls: list = []

    def _c(job):
        calls.append(job.slug)
        return root

    return _c, calls


def _fixworker(findings, *, fix_pr, checkout, comment_enabled=False, post=None):
    return make_pr_bot_worker(
        base_dir="/unused", checkout=checkout, changed_files=lambda j: {"a.py"},
        comment_config=SimpleNamespace(comment_enabled=comment_enabled), trust_root=object(),
        approve=lambda *a, **k: True, audit=lambda r: None,
        _scan_worker=_scan(findings), _post=post, fix_pr=fix_pr)


def test_fix_leg_off_by_default_no_clone_no_fix():
    chk, chk_calls = _checkout_spy()
    out = make_pr_bot_worker(
        base_dir="/unused", checkout=chk, changed_files=lambda j: {"a.py"},
        comment_config=SimpleNamespace(comment_enabled=False), trust_root=object(),
        approve=lambda *a, **k: True, audit=lambda r: None,
        _scan_worker=_scan([_VERIFIED, _VERIFIED2]))(_job())            # fix_pr defaults to None
    assert out["fixes_opened"] == [] and out["fixes_refused"] == []     # no fix leg
    assert chk_calls == []                                              # and the fix leg never cloned


def test_fix_leg_opens_a_pr_per_oracle_verified_finding():
    fix, fix_calls = _fix_spy()
    chk, chk_calls = _checkout_spy()
    out = _fixworker([_VERIFIED, _LEAD, _VERIFIED2], fix_pr=fix, checkout=chk)(_job())
    assert [c["ref"] for c in fix_calls] == ["R1", "R2"]               # the LEAD is NEVER fixed (prove-don't-guess)
    assert [f["ref"] for f in out["fixes_opened"]] == ["R1", "R2"]
    assert out["fixes_refused"] == []
    # the result carries only the JSON-safe PatchResult summary
    assert out["fixes_opened"][0]["result"] == {"status": "opened-pr",
                                                "pr_ref": "https://github.com/acme/widget/pull/11",
                                                "remediated": True}


def test_fix_leg_clones_the_pr_head_once_per_job():
    fix, fix_calls = _fix_spy()
    chk, chk_calls = _checkout_spy(root="/clone-xyz")
    _fixworker([_VERIFIED, _VERIFIED2], fix_pr=fix, checkout=chk)(_job())
    assert len(chk_calls) == 1                                          # ONE clone, reused across both fixes
    assert [c["local_root"] for c in fix_calls] == ["/clone-xyz", "/clone-xyz"]   # the reused clone is passed in


def test_a_refused_fix_is_recorded_not_fatal():
    fix, fix_calls = _fix_spy(raise_on_call=1)                          # the FIRST fix raises …
    chk, _chk = _checkout_spy()
    out = _fixworker([_VERIFIED, _VERIFIED2], fix_pr=fix, checkout=chk)(_job())
    assert len(fix_calls) == 2                                          # … the loop still continues to the second
    assert [f["ref"] for f in out["fixes_opened"]] == ["R2"]
    assert len(out["fixes_refused"]) == 1 and out["fixes_refused"][0]["ref"] == "R1"
    assert "quorum denied" in out["fixes_refused"][0]["error"]


def test_only_leads_means_no_clone_no_fix():
    fix, fix_calls = _fix_spy()
    chk, chk_calls = _checkout_spy()
    out = _fixworker([_LEAD, {"ref": "L2", "verified_by_oracle": False}], fix_pr=fix, checkout=chk)(_job())
    assert fix_calls == [] and chk_calls == []                         # nothing verified ⇒ never clone, never fix
    assert out["fixes_opened"] == [] and out["fixes_refused"] == []


def test_comment_and_fix_legs_both_run_over_the_same_findings():
    post, post_calls = _post_spy()
    fix, fix_calls = _fix_spy()
    chk, chk_calls = _checkout_spy()
    out = _fixworker([_VERIFIED, _VERIFIED2], fix_pr=fix, checkout=chk, comment_enabled=True, post=post)(_job())
    assert [p["ref"] for p in out["comments_posted"]] == ["R1", "R2"]   # comment leg ran
    assert [f["ref"] for f in out["fixes_opened"]] == ["R1", "R2"]      # fix leg ran over the same findings
    assert len(post_calls) == 2 and len(fix_calls) == 2
    assert len(chk_calls) == 1                                          # still ONE clone for the fix leg


def test_non_bool_truthy_verified_is_not_fixed():
    """the fix leg uses the SAME `is True` gate — a non-bool truthy verified_by_oracle is never fixed."""
    fix, fix_calls = _fix_spy()
    chk, _chk = _checkout_spy()
    findings = [dict(_VERIFIED, ref="OK"), {"ref": "I", "verified_by_oracle": 1},
                {"ref": "S", "verified_by_oracle": "true"}]
    out = _fixworker(findings, fix_pr=fix, checkout=chk)(_job())
    assert [c["ref"] for c in fix_calls] == ["OK"]                      # ONLY the genuine bool-True finding
    assert [f["ref"] for f in out["fixes_opened"]] == ["OK"]


def test_fix_leg_clones_once_even_when_checkout_persistently_fails():
    """red-pen LOW (confirmed): a PERSISTENT PR-head clone failure is MEMOIZED — the leg clones at most ONCE
    per job even when checkout raises, and still records a refusal for EVERY verified finding (no N-times
    re-clone amplification on a revoked token / lost access / network black-hole)."""
    fix, fix_calls = _fix_spy()
    chk_calls: list = []

    def _boom_checkout(job):
        chk_calls.append(job.slug)
        raise RuntimeError("gh repo clone failed: token revoked")

    out = _fixworker([_VERIFIED, _VERIFIED2, dict(_VERIFIED, ref="R3")], fix_pr=fix, checkout=_boom_checkout)(_job())
    assert len(chk_calls) == 1                                          # cloned ONCE despite 3 verified findings
    assert fix_calls == []                                              # fix_pr never ran (no usable clone)
    assert [r["ref"] for r in out["fixes_refused"]] == ["R1", "R2", "R3"]   # EVERY finding recorded a refusal
    assert out["fixes_opened"] == []
    assert all("token revoked" in r["error"] for r in out["fixes_refused"])   # the clone error is carried through


def test_fix_leg_hostile_ref_does_not_poison_later_findings():
    """red-pen follow-up: a per-finding ref-prep failure must NOT be memoized as a clone failure — the clone is
    scoped to its own try, so a hostile ref on finding 1 records a refusal yet finding 2 still clones + fixes."""
    class _Bomb:
        def __bool__(self):
            raise ValueError("boom")

    fix, fix_calls = _fix_spy()
    chk, chk_calls = _checkout_spy()
    out = _fixworker([{"ref": _Bomb(), "verified_by_oracle": True}, dict(_VERIFIED, ref="OK")],
                     fix_pr=fix, checkout=chk)(_job())
    assert [c["ref"] for c in fix_calls] == ["OK"]                      # the good finding is still fixed …
    assert [f["ref"] for f in out["fixes_opened"]] == ["OK"]
    assert len(chk_calls) == 1                                          # … and the clone WAS attempted for it
    assert len(out["fixes_refused"]) == 1 and out["fixes_refused"][0]["ref"] == ""   # the bomb recorded, not fatal
