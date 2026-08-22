"""sx-s2 short-lived gateway proxy credential.

The proxy's A7 client-auth secret is MINTED fresh at each gateway bring-up, persisted 0600, and read back
by the Strix launch pre-flight so the sandbox's Caido presents the exact secret the gateway was started
with (the two ends can never drift). A per-bring-up random token is "short-lived" in the plan's sense
(rotated every time the gate is stood up), never a committed constant. Every failure is fail-SAFE: a token
that cannot be minted/read means 'no client auth', never a gateway that demands a credential the sandbox
cannot present.
"""
from __future__ import annotations

import os
import stat

from vigil_gateway.docker import PROXY_TOKEN_RELPATH, load_proxy_token, mint_proxy_token


def test_mint_persists_owner_only_and_load_round_trips(tmp_path):
    p = tmp_path / ".vigil-live" / "gateway-proxy-token"
    tok = mint_proxy_token(p)
    assert tok and len(tok) >= 32                       # a real CSPRNG token
    assert load_proxy_token(p) == tok                   # the launch pre-flight reads the SAME secret
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, f"the token file must be owner-only, got {oct(mode)}"   # never world-readable


def test_each_bringup_mints_a_fresh_token(tmp_path):
    p = tmp_path / ".vigil-live" / "gateway-proxy-token"
    first = mint_proxy_token(p)
    second = mint_proxy_token(p)                          # a second bring-up rotates it
    assert first and second and first != second
    assert load_proxy_token(p) == second                 # the newest wins; no torn/duplicate file


def test_load_missing_is_none_not_error(tmp_path):
    assert load_proxy_token(tmp_path / "nope") is None    # absent ⇒ 'no client auth', never a crash


def test_load_empty_is_none(tmp_path):
    p = tmp_path / "tok"
    p.write_text("   \n", encoding="utf-8")               # a whitespace-only file is treated as no token
    assert load_proxy_token(p) is None


def test_mint_returns_none_when_unwritable(tmp_path):
    # a path whose parent cannot be created (a FILE sits where a dir is needed) → mint fails SAFE (None),
    # so the caller sets no token and the proxy keeps its prior no-client-auth posture (never a deadlock).
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    assert mint_proxy_token(blocker / "sub" / "token") is None


def test_relpath_is_under_vigil_live():
    assert PROXY_TOKEN_RELPATH.endswith("gateway-proxy-token")
    assert ".vigil-live" in PROXY_TOKEN_RELPATH
