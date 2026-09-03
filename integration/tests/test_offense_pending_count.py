"""Regression guard for the offense pending-approval counter (`api._pending_offense`).

`OFF /api/status.pending_approvals` and `OFF /api/approvals/` are documented to report the SAME
machine-wide count of queued offense approvals (api.approvals()'s docstring: the status counter uses
"the same import-clean broker path api.approvals() uses ... matching api.approvals()"). They diverged
in production: the status counter referenced a bare ``os.environ`` while ``os`` was not in that scope,
so it raised ``NameError`` that the broad ``except`` silently turned into ``0`` — the counter read 0
forever even with approvals queued. The "Waiting for you" merge, and any UI keyed off that count,
therefore under-reported a live agentic engage's unsigned actions (the exact bug the counter was added
to fix). This test pins the two surfaces to agree over the REAL broker.
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework")

from vigil_integration.live import approval_broker as B
from vigil_integration.live.approval_token import ApprovalAction, action_digest


def test_status_pending_count_matches_approvals_listing(tmp_path, monkeypatch):
    base = str(tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    from framework.v2.console import api

    # empty base: both surfaces agree at zero (and, critically, the counter does not throw→0-mask an error).
    assert api.status_data()["pending_approvals"] == 0
    assert len(api.approvals()["pending"]) == 0

    # queue two distinct offense approvals through the REAL broker (what a paused engage publishes).
    urls = ("http://127.0.0.1:19010/", "http://127.0.0.1:19010/records/search?q=test")
    for i, url in enumerate(urls):
        args = {"url": url}
        act = ApprovalAction("httpx", "127.0.0.1:19010",
                             action_digest("httpx", "127.0.0.1:19010", args))
        B.publish_pending(B.approvals_root(base), act, nonce=f"nonce-{i:032x}",
                          args_preview=args, now_iso="2026-01-01T00:00:00+00:00")

    listed = len(api.approvals()["pending"])
    counted = api.status_data()["pending_approvals"]
    assert listed == 2, f"broker did not list both queued approvals (got {listed})"
    # The load-bearing assertion: the status counter equals the listing. A NameError-swallowed-to-0
    # regression would make this 0 != 2.
    assert counted == listed, (
        f"status pending_approvals={counted} != approvals listing={listed} "
        "— the offense pending counter is under-reporting (regression of the os-NameError→0 bug)"
    )
