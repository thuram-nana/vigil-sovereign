"""Charter & Attestation screen — the provision + ledger console actions.

The UI can provision a LOOPBACK authority (scope HARD-FIXED to 127.0.0.1 — the caller's scope is never used,
so the UI can never widen it or provision a remote charter); both actions fail closed without a `vigil` bin.
"""

from __future__ import annotations

from framework.v2.console import actions, api


def test_charter_status_empty_slug_is_guarded():
    assert api.charter_status("")["slug"] is None


def test_charter_status_loopback_only(monkeypatch):
    monkeypatch.setattr(api, "_authority_state", lambda slug: {"scope": ["127.0.0.1"], "not_after": "2026-01-01"})
    d = api.charter_status("acme")
    assert d["scope"] == ["127.0.0.1"]
    assert d["is_loopback_only"] is True and d["has_remote_authority"] is False and d["remote_hosts"] == []
    assert d["ceremony"].startswith("vigil provision --slug acme --scope")
    assert "OUT-OF-BAND" in d["remote_note"]


def test_charter_status_surfaces_remote_hosts(monkeypatch):
    monkeypatch.setattr(api, "_authority_state",
                        lambda slug: {"scope": ["127.0.0.1", "app.example.com", "*.staging.example.com"]})
    d = api.charter_status("acme")
    assert d["has_remote_authority"] is True and d["is_loopback_only"] is False
    assert d["remote_hosts"] == ["app.example.com", "*.staging.example.com"]   # loopback filtered out


def test_charter_status_no_authority_is_not_loopback_only(monkeypatch):
    monkeypatch.setattr(api, "_authority_state", lambda slug: None)
    d = api.charter_status("acme")
    assert d["scope"] == [] and d["is_loopback_only"] is False and d["has_remote_authority"] is False


def test_provision_rejects_empty_slug():
    assert actions.provision_loopback_authority("")["ok"] is False


def test_provision_and_ledger_fail_closed_without_a_vigil_bin(monkeypatch):
    monkeypatch.setattr(actions, "_vigil_bin", lambda: None)
    assert actions.provision_loopback_authority("loopback")["ok"] is False
    assert actions.attestation_ledger()["ok"] is False


def test_provision_scope_is_hardcoded_loopback_never_the_caller(monkeypatch):
    captured = {}

    class _P:
        returncode = 0
        stdout = "provisioned"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return _P()

    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    r = actions.provision_loopback_authority("evil; --scope 0.0.0.0/0")
    assert r["ok"] and r["scope"] == "127.0.0.1"
    argv = captured["argv"]
    assert argv[argv.index("--scope") + 1] == "127.0.0.1"          # scope is the literal, never the caller's
    slug_val = argv[argv.index("--slug") + 1]
    assert " " not in slug_val and ";" not in slug_val and "/" not in slug_val   # slug sanitized to one token
    assert "0.0.0.0/0" not in " ".join(argv)
