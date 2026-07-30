"""A2 — the console read-only provider for the offense worker's PENDING per-action approval requests.

KEYLESS + READ-ONLY: the offense console LISTS the public-safe pending requests the OWNER signs out-of-band
with ``vigil approve sign`` (the owner PRIVATE key is held off-box as ``VIGIL_APPROVAL_OWNER_KEY``). It can
NEVER sign (FATAL-2) — there is no signing route in this plane; this provider only reads. An absent approvals
dir yields an empty list, never a traceback.
"""

from __future__ import annotations

import json

from framework.v2.console import api
from vigil_integration.live.approval_broker import approvals_root, publish_pending
from vigil_integration.live.approval_token import ApprovalAction, action_digest


def _seed(base, tool_name, target, args, *, nonce="a" * 32):
    dig = action_digest(tool_name, target, args)
    action = ApprovalAction(tool_name=tool_name, target=target, action_digest=dig)
    return publish_pending(approvals_root(base), action, nonce=nonce,
                           args_preview=args, now_iso="2026-07-29T00:00:00+00:00")


def test_approvals_lists_seeded_pending(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))
    req = _seed(str(tmp_path), "sqlmap", "http://127.0.0.1:8080/tfSearch", {"data": "q=1"})
    r = api.approvals("loopback")
    assert r["ok"] is True and r["base_dir"] == str(tmp_path)
    by_id = {p["request_id"]: p for p in r["pending"]}
    assert req.request_id in by_id
    item = by_id[req.request_id]
    assert item["tool_name"] == "sqlmap"
    assert item["target"] == "http://127.0.0.1:8080/tfSearch"
    assert item["nonce"] == "a" * 32 and item["created_at_iso"] == "2026-07-29T00:00:00+00:00"


def test_approvals_empty_when_dir_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "no-such-base"))
    r = api.approvals("loopback")
    assert r["ok"] is True and r["pending"] == []


def test_approvals_preview_carries_no_secret(monkeypatch, tmp_path):
    # The args preview is redacted at publish time — a secret must never reach the read side / the UI.
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path))
    _seed(str(tmp_path), "curl", "http://127.0.0.1:8080/",
          {"headers": {"Authorization": "Bearer sk-ant-APPROVALSECRET0123456789"}})
    r = api.approvals("loopback")
    assert r["pending"]                                             # the request still surfaces (redacted)
    assert "sk-ant-APPROVALSECRET0123456789" not in json.dumps(r)   # scrubbed before egress
