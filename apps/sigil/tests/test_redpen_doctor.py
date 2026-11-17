"""Red-Pen R2 — the sovereign ``vigil doctor`` Red-Pen lines.

  * Red-Pen OFF ⇒ a clean OFF line (no hard issue), noting a provisioned-but-inert credential;
  * Red-Pen ON ⇒ the App id+key must be present (hard issue when absent) and the webhook secret set;
  * an org over its per-repo monthly limit is INFORMATIONAL, never hard;
  * the check is wired into ``sigil_doctor_report()``.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil import cli
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.redpen_spend import RedPenSpendLedger
from sigil.spine.store import SpineStore
from vigil_core import BlockThreshold

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for k in ("VIGIL_REDPEN_ENABLED", "VIGIL_GITHUB_APP_ID", "VIGIL_GITHUB_APP_PRIVATE_KEY",
              "VIGIL_GITHUB_APP_PRIVATE_KEY_SSM", "VIGIL_GH_WEBHOOK_SECRET"):
        monkeypatch.delenv(k, raising=False)


def test_red_pen_off_is_a_clean_line_noting_an_inert_credential(monkeypatch):
    ok, state, detail = cli._redpen_doctor()
    assert ok is True and state == "OFF"
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", "pem")
    ok, state, detail = cli._redpen_doctor()
    assert ok is True and state == "OFF" and "inert until Red-Pen is turned on" in detail


def test_red_pen_on_without_the_app_key_is_a_hard_issue(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_GH_WEBHOOK_SECRET", "wh")
    ok, state, detail = cli._redpen_doctor()
    assert ok is False and state == "ON" and "GitHub App id + private key" in detail


def test_red_pen_on_without_the_webhook_secret_is_a_hard_issue(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", "pem")
    ok, state, detail = cli._redpen_doctor()
    assert ok is False and "webhook secret" in detail


def test_red_pen_on_fully_provisioned_is_ok(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", "pem")
    monkeypatch.setenv("VIGIL_GH_WEBHOOK_SECRET", "wh")
    ok, state, detail = cli._redpen_doctor()
    assert ok is True and state == "ON" and "webhook secret set" in detail


def test_an_org_over_its_monthly_limit_is_informational_not_hard(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "1")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", "pem")
    monkeypatch.setenv("VIGIL_GH_WEBHOOK_SECRET", "wh")
    ensure_owner_keypair()
    s = SpineStore()                                            # the default spine under SIGIL_HOME (same path the doctor reads)
    ConnectedRepoRegistry(s).connect("acme", 42, "github.com/acme/widgets", monthly_limit_credits=10,
                                     issued_at=float(next(_iss)))
    import time
    RedPenSpendLedger(s).record_charge("acme", "github.com/acme/widgets", 10, nonce="n1", now=time.time())
    ok, state, detail = cli._redpen_doctor()
    assert ok is True and "1 at/over this month" in detail      # over limit -> informational, the check stays OK


def test_the_redpen_check_is_wired_into_the_doctor_report():
    rep = cli.sigil_doctor_report()
    ids = {c["id"] for c in rep["checks"]}
    assert "redpen" in ids
    rp = next(c for c in rep["checks"] if c["id"] == "redpen")
    assert rp["required"] is False and rp["state"] == "OFF"     # off by default, informational
