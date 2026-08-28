"""Slice 1b — `sigil serve --rotate-token` / `--revoke-token` are file operations that short-circuit
before the server starts (so they are safe to run against a live deployment; they apply on the next start).
"""
from __future__ import annotations

from argparse import Namespace

from sigil.cli import cmd_serve
from sigil.ui import bootstrap_token as bt


def test_serve_rotate_flag_mints_and_exits(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    tok = tmp_path / ".vigil-live" / "cockpit-bootstrap-token"
    cmd_serve(Namespace(rotate_token=True, revoke_token=False, port=8733))   # short-circuits, never serves
    assert tok.exists()
    out = capsys.readouterr().out
    assert "ROTATED" in out and "?token=" in out


def test_serve_revoke_flag_deletes_and_exits(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    tok = tmp_path / ".vigil-live" / "cockpit-bootstrap-token"
    bt.mint_bootstrap_token(tok)
    assert tok.exists()
    cmd_serve(Namespace(rotate_token=False, revoke_token=True, port=8733))
    assert not tok.exists()
    assert "REVOKED" in capsys.readouterr().out


def _serve_args():
    return Namespace(host=None, port=8733, allow_host=[], allow_origin=[],
                     token=None, rotate_token=False, revoke_token=False)


def test_cmd_serve_production_ignores_the_persistent_token(monkeypatch, tmp_path):
    """BLOCK-1 negative control: under VIGIL_POSTURE=production, cmd_serve must NOT load the persistent
    bootstrap file — it serves a FRESH ephemeral token. The persistent DEV token must never become the
    PRODUCTION security boundary. (A refactor routing production through resolve_bootstrap_token fails HERE.)"""
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    planted = bt.mint_bootstrap_token()                       # a token a prior dev run / rotate left on disk
    captured = {}
    monkeypatch.setattr("sigil.ui.server.serve", lambda **kw: captured.update(kw))
    cmd_serve(_serve_args())
    assert captured["token"] != planted, "production must NOT serve the persistent file token"
    assert len(captured["token"]) >= 24                      # a fresh ephemeral token
    assert bt.load_bootstrap_token() == planted              # the file is left untouched (never read/written)


def test_cmd_serve_dev_serves_the_persistent_token(monkeypatch, tmp_path):
    """Positive control: in the default (dev) posture cmd_serve LOADS the persisted token, so the same
    ?token= URL survives a restart."""
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    planted = bt.mint_bootstrap_token()
    captured = {}
    monkeypatch.setattr("sigil.ui.server.serve", lambda **kw: captured.update(kw))
    cmd_serve(_serve_args())
    assert captured["token"] == planted


def test_serve_rotate_flag_is_noop_in_production(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setattr(bt, "SIGIL_HOME", tmp_path)
    cmd_serve(Namespace(rotate_token=True, revoke_token=False, port=8733))
    assert "PRODUCTION" in capsys.readouterr().out
    assert not (tmp_path / ".vigil-live" / "cockpit-bootstrap-token").exists()   # no file written in production
