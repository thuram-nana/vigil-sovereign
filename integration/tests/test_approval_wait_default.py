"""The approval poll window defaults to 5 minutes (was 0 = instant deny).

A queued offense action used to be refused the instant it was published (VIGIL_APPROVAL_WAIT_SECONDS
defaulted to 0), so a UI-launched codebase scan died before the operator could sign. It now waits
5 minutes by default — enough time to approve — while an EXPLICIT 0 still opts back into instant deny,
and NaN/negative still fail closed. The value stays capped at the token dead-man's bound.
"""
from __future__ import annotations

from vigil_integration.live import approval_broker as B


def test_unset_env_defaults_to_five_minutes(monkeypatch):
    monkeypatch.delenv("VIGIL_APPROVAL_WAIT_SECONDS", raising=False)
    assert B._resolve_wait(None) == B._DEFAULT_WAIT_SECONDS == 300.0


def test_explicit_zero_still_opts_into_instant_deny(monkeypatch):
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "0")
    assert B._resolve_wait(None) == 0.0


def test_an_explicit_value_wins_and_is_capped(monkeypatch):
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "60")
    assert B._resolve_wait(None) == 60.0
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "99999")
    assert B._resolve_wait(None) == B._MAX_WAIT_SECONDS == 900.0


def test_nan_and_negative_fail_closed_to_zero(monkeypatch):
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "-5")
    assert B._resolve_wait(None) == 0.0
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "nan")
    assert B._resolve_wait(None) == 0.0
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "not-a-number")
    assert B._resolve_wait(None) == 0.0


def test_an_explicit_arg_overrides_the_env_and_the_default(monkeypatch):
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "60")
    assert B._resolve_wait(10.0) == 10.0        # caller-provided wins over env
    monkeypatch.delenv("VIGIL_APPROVAL_WAIT_SECONDS", raising=False)
    assert B._resolve_wait(0.0) == 0.0          # an explicit arg of 0 is honoured, not replaced by the default
