"""
Integration workstream I-B — the opt-in detection flags that expose already-merged
capabilities on the operator's CLI path.

`WebScanCampaign` has long supported `enable_sso`, `enable_graphql_dos`, `use_library`,
and the access-control pack, but no `scan`/`engage` flag turned them on — so an operator
could not reach them. These tests pin the wiring both ways:

  * SET — a flag threads through to the campaign (`enable_sso=True`, …), so the capability
    actually turns on.
  * UNSET (the default) — the campaign receives the flag's OFF value, byte-identical to the
    campaign's own default. This is what keeps `make gate` (which never sets these flags)
    unchanged.

The wiring is asserted at three seams without issuing any traffic: the `scan` CLI
(`cli.main` → `WebScanCampaign`), `engage`'s `run_engagement` (→ `WebScanCampaign`), and
`engage`'s argparse (`engage.main` → `run_engagement`). Each seam is exercised with a fake
that records the kwargs it was handed.
"""

from __future__ import annotations

import pytest

from framework.v2 import engage as engage_mod
from framework.v2.scanner import cli as cli_mod
from framework.v2.scanner.campaign import ScanReport
from framework.v2.engage import EngagementResult

# (CLI flag, campaign kwarg the flag drives). The pure-boolean opt-in flags — each is
# OFF by default and, when set, flips exactly one campaign kwarg to True.
BOOLEAN_FLAGS: list[tuple[str, str]] = [
    ("--sso", "enable_sso"),
    ("--graphql-dos", "enable_graphql_dos"),
    ("--library", "use_library"),
]


class _FakeCampaign:
    """Records the kwargs `WebScanCampaign(...)` is constructed with, then returns a
    minimal report from `.run()` — no crawl, no traffic."""

    captured: dict = {}

    def __init__(self, send, **kwargs) -> None:  # noqa: ANN001
        _FakeCampaign.captured = dict(kwargs)
        self._send = send

    def run(self, seed_url: str) -> ScanReport:
        return ScanReport(target=seed_url)


class _FakeExecutor:
    """A stand-in for HttpExecutor so `run_engagement` builds a campaign without opening
    the real gated executor (which would need a charter on disk). Never sends."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN001
        pass

    def gated_fetch(self, request) -> dict:  # noqa: ANN001 - never called by the fake campaign
        return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}

    def close(self) -> None:
        pass


@pytest.fixture()
def capture_scan_campaign(monkeypatch: pytest.MonkeyPatch) -> type[_FakeCampaign]:
    _FakeCampaign.captured = {}
    monkeypatch.setattr(cli_mod, "WebScanCampaign", _FakeCampaign)
    return _FakeCampaign


@pytest.fixture()
def capture_engage_campaign(monkeypatch: pytest.MonkeyPatch) -> type[_FakeCampaign]:
    """`run_engagement` → WebScanCampaign, with preflight/executor stubbed so no charter
    or traffic is needed — the test targets only the kwarg threading."""
    _FakeCampaign.captured = {}
    monkeypatch.setattr(engage_mod, "preflight", lambda slug, seed_url: None)
    monkeypatch.setattr(engage_mod, "HttpExecutor", _FakeExecutor)
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _FakeCampaign)
    return _FakeCampaign


# ---------------------------------------------------------------------------
# `scan` CLI → WebScanCampaign
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_scan_flag_enables_campaign_capability(capture_scan_campaign, flag: str, kwarg: str) -> None:
    rc = cli_mod.main(["http://127.0.0.1/", flag])
    assert rc == 0
    assert capture_scan_campaign.captured[kwarg] is True


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_scan_default_leaves_capability_off(capture_scan_campaign, flag: str, kwarg: str) -> None:
    rc = cli_mod.main(["http://127.0.0.1/"])
    assert rc == 0
    # unset → the campaign is handed the OFF value (byte-identical to its own default)
    assert capture_scan_campaign.captured[kwarg] is False


# ---------------------------------------------------------------------------
# `run_engagement` → WebScanCampaign
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_run_engagement_threads_flag_to_campaign(capture_engage_campaign, flag: str, kwarg: str) -> None:
    engage_mod.run_engagement(
        "acme", "http://127.0.0.1/", enable_chaining=False, **{kwarg: True})
    assert capture_engage_campaign.captured[kwarg] is True


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_run_engagement_default_leaves_capability_off(capture_engage_campaign, flag: str, kwarg: str) -> None:
    engage_mod.run_engagement("acme", "http://127.0.0.1/", enable_chaining=False)
    assert capture_engage_campaign.captured[kwarg] is False


# ---------------------------------------------------------------------------
# `engage` argparse → run_engagement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_engage_cli_maps_flag_to_run_engagement(monkeypatch: pytest.MonkeyPatch, flag: str, kwarg: str) -> None:
    captured: dict = {}

    def _fake_run_engagement(slug, seed_url, **kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return EngagementResult(report=ScanReport(target=seed_url))

    monkeypatch.setattr(engage_mod, "run_engagement", _fake_run_engagement)
    rc = engage_mod.main(["acme", "http://127.0.0.1/", flag])
    assert rc == 0
    assert captured[kwarg] is True


@pytest.mark.parametrize(("flag", "kwarg"), BOOLEAN_FLAGS)
def test_engage_cli_default_maps_flag_off(monkeypatch: pytest.MonkeyPatch, flag: str, kwarg: str) -> None:
    captured: dict = {}

    def _fake_run_engagement(slug, seed_url, **kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return EngagementResult(report=ScanReport(target=seed_url))

    monkeypatch.setattr(engage_mod, "run_engagement", _fake_run_engagement)
    rc = engage_mod.main(["acme", "http://127.0.0.1/"])
    assert rc == 0
    assert captured[kwarg] is False
