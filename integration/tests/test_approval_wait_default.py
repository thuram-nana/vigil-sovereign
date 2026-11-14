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


# --- the SUITE default (integration/conftest.py ``_no_human_approval_wait``) -----------------------------
# A test has no human to sign, so the suite defaults the window to 0 s; the PRODUCT default above is
# unchanged and still proven (the first test here delenv's and reads 300.0).


def test_the_suite_defaults_the_window_to_zero_unless_the_shell_set_it(request):
    import os

    shell = getattr(request.config, "_vigil_shell_approval_wait", None)
    if shell is None or shell.strip() == "":
        # the shell was silent -> the conftest default applies inside every test
        assert os.environ.get("VIGIL_APPROVAL_WAIT_SECONDS") == "0"
        assert B._resolve_wait(None) == 0.0
    else:
        # an explicit shell value is NEVER overridden by the suite default
        assert os.environ.get("VIGIL_APPROVAL_WAIT_SECONDS") == shell


def test_the_suite_default_does_not_hide_the_product_default(monkeypatch):
    # removing the variable in a test body (applied AFTER the autouse fixture) restores the 300 s product
    # default — the suite default is a test-environment convenience, never a product change
    monkeypatch.delenv("VIGIL_APPROVAL_WAIT_SECONDS", raising=False)
    assert B._resolve_wait(None) == 300.0


def test_an_explicit_test_value_beats_the_suite_default(monkeypatch):
    # the shape test_strix_approver_is_concurrency_safe relies on (it sets 20 s explicitly)
    monkeypatch.setenv("VIGIL_APPROVAL_WAIT_SECONDS", "20")
    assert B._resolve_wait(None) == 20.0


def test_an_explicit_shell_value_is_never_overridden_by_the_suite_default():
    # The in-process test above takes its ``else`` branch only when the invoking shell exported a value, which
    # CI never does — so prove the "never override" half in a child pytest run whose shell DOES export one.
    import os
    import pathlib
    import subprocess
    import sys

    here = pathlib.Path(__file__).resolve()
    env = dict(os.environ, VIGIL_APPROVAL_WAIT_SECONDS="7", PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         f"{here}::test_the_suite_defaults_the_window_to_zero_unless_the_shell_set_it"],
        cwd=str(here.parents[2]), env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert "1 passed" in proc.stdout, proc.stdout[-2000:]
