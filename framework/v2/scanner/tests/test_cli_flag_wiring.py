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

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from framework.v2 import engage as engage_mod
from framework.v2.scanner import cli as cli_mod
from framework.v2.scanner.campaign import ScanReport, WebScanCampaign
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.access_control import config_from_cli
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


# ---------------------------------------------------------------------------
# --access-control — the two-identity pack (needs operator victim refs)
# ---------------------------------------------------------------------------


def test_scan_access_control_threads_enable_and_config(capture_scan_campaign) -> None:
    rc = cli_mod.main([
        "http://127.0.0.1/", "--access-control",
        "--ac-ref", "idor:id:42", "--ac-victim-header", "Cookie: session=bob"])
    assert rc == 0
    assert capture_scan_campaign.captured["enable_access_control"] is True
    cfg = capture_scan_campaign.captured["access_control_config"]
    assert cfg is not None
    assert [(s.bug_class, s.ref_param, s.victim_ref) for s in cfg.cross_specs] == [("idor", "id", "42")]
    assert callable(cfg.victim_send)   # victim identity bound from --ac-victim-header


def test_scan_access_control_without_refs_is_documented_noop(capture_scan_campaign) -> None:
    # --access-control alone enables the pack but supplies no config, so it seeds nothing
    # (an explicit no-op) rather than guessing a reference.
    rc = cli_mod.main(["http://127.0.0.1/", "--access-control"])
    assert rc == 0
    assert capture_scan_campaign.captured["enable_access_control"] is True
    assert capture_scan_campaign.captured["access_control_config"] is None


def test_scan_access_control_default_off(capture_scan_campaign) -> None:
    rc = cli_mod.main(["http://127.0.0.1/"])
    assert rc == 0
    assert capture_scan_campaign.captured["enable_access_control"] is False
    assert capture_scan_campaign.captured["access_control_config"] is None


def test_run_engagement_threads_access_control(capture_engage_campaign) -> None:
    engage_mod.run_engagement(
        "acme", "http://127.0.0.1/", enable_chaining=False,
        enable_access_control=True, access_control_refs=("bola:oid:7",),
        access_control_victim_headers=("Authorization: Bearer victim",))
    assert capture_engage_campaign.captured["enable_access_control"] is True
    cfg = capture_engage_campaign.captured["access_control_config"]
    assert cfg is not None
    assert [(s.bug_class, s.ref_param, s.victim_ref) for s in cfg.cross_specs] == [("bola", "oid", "7")]


def test_run_engagement_access_control_default_off(capture_engage_campaign) -> None:
    engage_mod.run_engagement("acme", "http://127.0.0.1/", enable_chaining=False)
    assert capture_engage_campaign.captured["enable_access_control"] is False
    assert capture_engage_campaign.captured["access_control_config"] is None


def test_engage_cli_maps_access_control_args(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def _fake_run_engagement(slug, seed_url, **kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return EngagementResult(report=ScanReport(target=seed_url))

    monkeypatch.setattr(engage_mod, "run_engagement", _fake_run_engagement)
    rc = engage_mod.main([
        "acme", "http://127.0.0.1/", "--access-control",
        "--ac-ref", "idor:id:42", "--ac-victim-header", "Cookie: session=bob"])
    assert rc == 0
    assert captured["enable_access_control"] is True
    assert captured["access_control_refs"] == ("idor:id:42",)
    assert captured["access_control_victim_headers"] == ("Cookie: session=bob",)


# ---------------------------------------------------------------------------
# functional: the flag genuinely enables oracle-confirmed access-control checks
# ---------------------------------------------------------------------------

_SECRET = "SECRET-BOB-INVOICE-total=9001-acct=bob@example.test"


class _IdorApp(BaseHTTPRequestHandler):
    """A broken-object-level-auth app: object 2 (bob's) is readable by anyone, so the
    attacker cross-reads it — the achieved-state oracle's exact trigger."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            body = b'<html><a href="/obj?id=1">obj</a></html>'
        elif parsed.path == "/obj":
            rid = (parse_qs(parsed.query).get("id") or ["1"])[0]
            body = _SECRET.encode() if rid == "2" else b"alice's own object 1"
        else:
            body = b"not found"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _http_server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _IdorApp)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def test_access_control_flag_confirms_idor_end_to_end() -> None:
    with _http_server() as base:
        cfg = config_from_cli(loopback_send, ["Cookie: session=bob"], ["idor:id:2"])
        report = WebScanCampaign(
            loopback_send, max_pages=5, enable_oob=False,
            enable_access_control=True, access_control_config=cfg,
        ).run(base + "/")
    assert any(f.bug_class == "idor" and f.confirmed_by == "achieved_state"
               for f in report.active_findings), report.active_findings


def test_access_control_off_by_default_confirms_no_idor() -> None:
    # the SAME app, flag OFF: the access-control checks never run, so no idor finding —
    # this is the byte-identical default the gate relies on.
    with _http_server() as base:
        report = WebScanCampaign(loopback_send, max_pages=5, enable_oob=False).run(base + "/")
    assert not any(f.bug_class == "idor" for f in report.active_findings)
