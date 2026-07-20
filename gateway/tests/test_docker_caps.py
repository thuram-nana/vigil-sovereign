"""The Strix sandbox no longer receives NET_ADMIN by default (P6 / FATAL-1).

Runs only where Strix's runtime deps (openai-agents, docker) are importable; skipped
otherwise. The behaviour under test is the env-driven capability policy in
``strix.runtime.docker_client._sandbox_net_caps``.
"""

from __future__ import annotations

import pathlib
import sys

import pytest


def _docker_client():
    strix = pathlib.Path(__file__).resolve().parents[2] / "vendor" / "strix"
    if str(strix) not in sys.path:
        sys.path.insert(0, str(strix))
    return pytest.importorskip(
        "strix.runtime.docker_client",
        reason="Strix runtime deps (openai-agents/docker) not installed",
    )


def test_net_admin_dropped_by_default(monkeypatch):
    dc = _docker_client()
    monkeypatch.delenv("STRIX_SANDBOX_NET_CAPS", raising=False)
    caps = dc._sandbox_net_caps()
    assert caps == ["NET_RAW"]
    assert "NET_ADMIN" not in caps


def test_override_can_restore_net_admin(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", "NET_RAW,NET_ADMIN")
    assert dc._sandbox_net_caps() == ["NET_RAW", "NET_ADMIN"]


def test_empty_override_means_no_net_caps(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", "")
    assert dc._sandbox_net_caps() == []


def test_whitespace_and_case_normalised(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", " net_raw , net_admin ")
    assert dc._sandbox_net_caps() == ["NET_RAW", "NET_ADMIN"]
