"""Slice 1b — the persistent owner bootstrap token.

Load-bearing invariants:
  * the token PERSISTS across a restart (resolve() twice returns the same value) — the "my session token
    changes on restart" pain this slice fixes;
  * it is stored owner-only (0600);
  * an explicit override (--token / $SIGIL_BOOTSTRAP_TOKEN) wins and is itself persisted;
  * revoke deletes the file so the NEXT start mints a fresh token (the old URL dies);
  * mint is FAIL-SAFE — an unwritable home still yields a usable in-memory token (the cockpit runs; it just
    will not survive the next restart), never a crash.
"""
from __future__ import annotations

import os
import stat

from sigil.ui import bootstrap_token as bt


def test_mint_persists_0600_and_load_roundtrips(tmp_path):
    p = tmp_path / ".vigil-live" / "cockpit-bootstrap-token"
    tok = bt.mint_bootstrap_token(p)
    assert tok and bt.load_bootstrap_token(p) == tok
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, f"token file must be owner-only, got {oct(mode)}"


def test_resolve_is_stable_across_restarts(tmp_path):
    p = tmp_path / "tok"
    first = bt.resolve_bootstrap_token(path=p)           # mints + persists
    second = bt.resolve_bootstrap_token(path=p)          # a "restart" LOADS the same token
    assert first == second and first


def test_override_wins_and_persists(tmp_path):
    p = tmp_path / "tok"
    bt.mint_bootstrap_token(p)                            # some pre-existing token
    got = bt.resolve_bootstrap_token(override="pinned-owner-token-xyz", path=p)
    assert got == "pinned-owner-token-xyz"
    assert bt.load_bootstrap_token(p) == "pinned-owner-token-xyz"   # the override is persisted too
    # a blank override is ignored → falls back to the (now-pinned) persisted value
    assert bt.resolve_bootstrap_token(override="   ", path=p) == "pinned-owner-token-xyz"


def test_revoke_then_resolve_mints_a_fresh_token(tmp_path):
    p = tmp_path / "tok"
    old = bt.resolve_bootstrap_token(path=p)
    assert bt.revoke_bootstrap_token(p) is True
    assert bt.load_bootstrap_token(p) is None
    new = bt.resolve_bootstrap_token(path=p)             # next start mints a fresh one
    assert new and new != old
    # revoking an absent file is a clean no-op (idempotent)
    assert bt.revoke_bootstrap_token(p) is True          # (a file exists again from the resolve above)
    assert bt.revoke_bootstrap_token(tmp_path / "never-existed") is False


def test_temp_write_refuses_a_planted_symlink_and_leaves_the_victim(tmp_path, monkeypatch):
    # Harden over the gateway pattern: O_EXCL|O_NOFOLLOW on a UNIQUE temp name. Pin the temp suffix to a
    # predictable value, plant a symlink there pointing at a victim, and prove the write is REFUSED (never
    # follows/clobbers the victim) — it fails to an in-memory token instead.
    victim = tmp_path / "victim"
    victim.write_text("SECRET", encoding="ascii")
    final = tmp_path / ".vigil-live" / "tok"
    final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    monkeypatch.setattr(bt.secrets, "token_hex", lambda n=8: "deadbeef")   # predictable temp suffix
    os.symlink(victim, final.with_name(f"{final.name}.deadbeef.tmp"))      # plant a symlink AT the temp path
    tok = bt.mint_bootstrap_token(final)
    assert tok, "mint must still return a usable in-memory token (fail-safe)"
    assert victim.read_text(encoding="ascii") == "SECRET", "the planted symlink must NOT be followed/clobbered"
    assert bt.load_bootstrap_token(final) is None, "nothing persisted (the write was refused)"


def test_write_replaces_a_symlink_at_the_final_path_without_clobbering(tmp_path):
    # os.replace REPLACES a symlink at the final path (it never writes through it), so a symlink planted at
    # the destination cannot redirect the token into a victim file.
    victim = tmp_path / "victim"
    victim.write_text("SECRET", encoding="ascii")
    final = tmp_path / ".vigil-live" / "tok"
    final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.symlink(victim, final)
    tok = bt.mint_bootstrap_token(final)
    assert tok and victim.read_text(encoding="ascii") == "SECRET"
    assert not final.is_symlink() and bt.load_bootstrap_token(final) == tok


def test_mint_is_failsafe_when_the_path_is_unwritable(tmp_path):
    # the parent is a regular FILE, so mkdir(parents=True) raises OSError → the write fails, but mint still
    # returns a usable in-memory token (nothing persisted).
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="ascii")
    p = blocker / "sub" / "tok"
    tok = bt.mint_bootstrap_token(p)
    assert tok and bt.load_bootstrap_token(p) is None
