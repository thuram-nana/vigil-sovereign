"""repo-connect Slice 3c (worker leg): ``make_pr_bot_fix_pr`` wires rebuild-from-SIGNED-spine → pin-the-clone
→ the gated ``authorized_fix_pr`` executor, adding NO authority of its own.

Offline + framework-free: the signed-spine rebuild (``finding_from_spine``) and the 3c executor
(``authorized_fix_pr``) are both INJECTED (``_from_spine`` / ``_fix``), and the ``CodefixConfig`` is a local
dataclass double — so there is no spine, no clone, no framework and no network, and only the factory's WIRING
is under test. The executor's own fail-closed gating (``pr_enabled`` ∧ owner-signed repo-EXACT ``"pr"`` grant ∧
clone-origin-IS-the-granted-repo ∧ m-of-n quorum ∧ signed audit) is proven in
``test_repo_write_fix_pr_executor.py``; this module proves the factory feeds that executor the RIGHT inputs:
the signed fact (never the in-memory scan dict) and a config pinned to the PR-head clone.
"""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.pr_bot import make_pr_bot_fix_pr


@dataclasses.dataclass
class _Cfg:
    """A CodefixConfig stand-in carrying the fields the factory touches — enough to prove
    ``dataclasses.replace(target_repo=<clone>)`` pins the clone while preserving the other knobs."""
    base_dir: str = "/sandbox"
    target_repo: str = "__PLACEHOLDER__"     # the factory MUST replace this per job with the PR-head clone
    pr_enabled: bool = True
    github_token: str = "t"


def _job():
    return SecurityJob(repo="github.com/acme/widget", pr_number=7, commit="c", source="manual", delivery_id="d")


def _seams():
    spine_calls: list = []
    fix_calls: list = []

    def _from_spine(**kw):
        spine_calls.append(kw)
        return SimpleNamespace(ref=kw.get("finding_ref"), kind="confirmed-fact")

    def _fix(**kw):
        fix_calls.append(kw)
        return SimpleNamespace(status="opened-pr", pr_ref="https://github.com/acme/widget/pull/9", remediated=True)

    return _from_spine, _fix, spine_calls, fix_calls


def _build(*, checkout, _from_spine, _fix, spine_base_dir="/spine", cfg=None,
           quorum=None, now=None, grant_path="/g", epoch_path="/e"):
    return make_pr_bot_fix_pr(
        checkout=checkout, spine_base_dir=spine_base_dir, codefix_config=cfg or _Cfg(),
        trust_root=object(), audit=lambda r: None, quorum=quorum or (lambda req: None),
        now=now, grant_path=grant_path, epoch_path=epoch_path, _from_spine=_from_spine, _fix=_fix)


def test_rebuilds_confirmed_fact_from_signed_spine_by_ref():
    _from_spine, _fix, spine_calls, _fc = _seams()
    fix_pr = _build(checkout=lambda j: "/clone", _from_spine=_from_spine, _fix=_fix)
    fix_pr(_job(), {"ref": "daa:py.weak-hash:app/x.py:42", "verified_by_oracle": True})
    assert len(spine_calls) == 1
    sc = spine_calls[0]
    assert sc["base_dir"] == "/spine"                              # spine_base_dir — NOT codefix_config.base_dir
    assert sc["slug"] == _job().slug
    assert sc["target_repo"] == "/clone"                           # the fact is rebuilt against the PR-head clone
    assert sc["finding_ref"] == "daa:py.weak-hash:app/x.py:42"     # the finding's ref, matched RAW (no _clip)


def test_drives_executor_with_the_rebuilt_fact_and_pinned_clone():
    _from_spine, _fix, _sc, fix_calls = _seams()
    fix_pr = _build(checkout=lambda j: "/clone", _from_spine=_from_spine, _fix=_fix)
    result = fix_pr(_job(), {"ref": "R1"})
    assert result.status == "opened-pr"                            # the executor's PatchResult propagates back
    assert len(fix_calls) == 1
    fc = fix_calls[0]
    assert fc["slug"] == _job().slug and fc["repo"] == "github.com/acme/widget"
    assert fc["finding"].kind == "confirmed-fact"                  # the SIGNED-SPINE fact — never the scan dict
    assert fc["config"].target_repo == "/clone"                    # config PINNED to the clone …
    assert fc["config"].pr_enabled is True and fc["config"].github_token == "t"   # … other knobs preserved
    assert fc["grant_path"] == "/g" and fc["epoch_path"] == "/e" and callable(fc["quorum"])


def test_uses_local_root_without_cloning():
    _from_spine, _fix, spine_calls, fix_calls = _seams()
    chk_calls: list = []

    def _chk(job):
        chk_calls.append(job.slug)
        return "/fresh"

    fix_pr = _build(checkout=_chk, _from_spine=_from_spine, _fix=_fix)
    fix_pr(_job(), {"ref": "R1"}, local_root="/prehead")
    assert chk_calls == []                                         # a supplied local_root ⇒ the leg does NOT re-clone
    assert spine_calls[0]["target_repo"] == "/prehead"
    assert fix_calls[0]["config"].target_repo == "/prehead"


def test_clones_when_no_local_root():
    _from_spine, _fix, spine_calls, fix_calls = _seams()
    chk_calls: list = []

    def _chk(job):
        chk_calls.append(job.slug)
        return "/fresh"

    fix_pr = _build(checkout=_chk, _from_spine=_from_spine, _fix=_fix)
    fix_pr(_job(), {"ref": "R1"})                                  # no local_root ⇒ the leg clones the PR head itself
    assert chk_calls == [_job().slug]
    assert spine_calls[0]["target_repo"] == "/fresh"
    assert fix_calls[0]["config"].target_repo == "/fresh"


def test_empty_ref_fails_closed_before_spine_and_clone():
    """red-pen: a finding with no ref FAILS CLOSED in the factory — BEFORE finding_from_spine AND before any
    clone. A fix must positively identify the confirmed fact; there is NO silent fall-back to the sole fact on
    the spine (build UP to the guarantee, never soften it). The worker records this as a fixes_refused."""
    _from_spine, _fix, spine_calls, fix_calls = _seams()
    chk_calls: list = []

    def _chk(job):
        chk_calls.append(job.slug)
        return "/clone"

    fix_pr = _build(checkout=_chk, _from_spine=_from_spine, _fix=_fix)
    with pytest.raises(Exception):                                 # GitHubWriteError — fail-closed
        fix_pr(_job(), {"verified_by_oracle": True})               # a finding dict with NO "ref" key
    assert spine_calls == [] and fix_calls == [] and chk_calls == []   # refused before spine, executor AND clone
