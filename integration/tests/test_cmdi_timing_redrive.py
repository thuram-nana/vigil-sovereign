"""
Governed-engage SOUND in-band command-injection FACT: the TIMING channel.

The in-band COMPUTED-PRODUCT side_effect channel (cmdi_reflected_redrive / command_injection.reflected_output)
is LEAD-only — a benign arithmetic evaluator computes ``$((N1*N2))`` from the input and so an in-band product
does not distinguish shell execution from app math (an adversarial red-pen reproduced a rate-1.0 signed false
FACT against a plain calculator). The SOUND in-band cmdi FACT is the dose-scaled TIMING channel
(time_based_command_injection.timing_inference): a shell break-out that runs ``sleep {s}`` makes the response
latency SCALE with the injected delay, which only genuine shell execution produces — a calculator, a reflector
and a uniformly-slow endpoint all fail the dose-response.

This pins the arm end-to-end:
  * a VULNERABLE sink (``subprocess.run(..., shell=True)`` — GENUINE command injection, not a simulated sleep)
    that runs the injected ``;sleep {s}`` mints a signed FACT (dose-responsive);
  * the DECISIVE control — the same benign CALCULATOR that defeats the side_effect channel — mints NOTHING
    here (it computes arithmetic instantly, so there is no dose-scaled latency);
  * a UNIFORMLY-SLOW endpoint (a fixed delay for every request, no dose-response) mints NOTHING;
  * a reflector that echoes the payload verbatim mints NOTHING.
"""

from __future__ import annotations

import contextlib
import http.server
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str = "127.0.0.1", slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _host(path: str) -> str:
    return parse_qs(urlsplit(path).query).get("host", [""])[0]


def _send200(h: http.server.BaseHTTPRequestHandler, body: bytes) -> None:
    h.send_response(200)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class _CmdiSleepExec(http.server.BaseHTTPRequestHandler):
    """VULNERABLE: concatenates the host into a shell string and executes it (shell=True) — GENUINE command
    injection. The arm's ``;sleep {s}`` break-out therefore runs a REAL ``sleep``, so the response latency
    SCALES with the injected delay (dose-responsive). The body is constant; timing is latency-derived."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        try:
            subprocess.run("echo reached " + host, shell=True, capture_output=True, text=True, timeout=5)
        except Exception:  # noqa: BLE001
            pass
        _send200(self, b"<pre>done</pre>")


class _Calculator(_CmdiSleepExec):
    """BENIGN — the DECISIVE control: the same arithmetic evaluator that DEFEATS the side_effect channel. It
    computes ``$((N1*N2))`` from the input and echoes the product INSTANTLY, but it never executes a shell and
    never sleeps, so it produces no dose-scaled latency -> the timing channel refuses it (the side_effect
    channel did not). Proves the demotion is a real fix, not a loss of coverage."""

    _ARITH = re.compile(r"\$\(\((\d+)\s*\*\s*(\d+)\)\)")

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        m = self._ARITH.search(host)
        if m:
            product = int(m.group(1)) * int(m.group(2))
            _send200(self, f"<p>= {product}</p>".encode())
            return
        _send200(self, f"<p>you asked about {host}</p>".encode())


class _UniformlySlow(_CmdiSleepExec):
    """BENIGN: a FIXED delay for EVERY request regardless of payload (a slow/loaded endpoint). There is a
    latency offset but NO dose-response (the low and high sleep doses see the same delay) -> the timing oracle
    refuses (the dose-response does not scale) -> LEAD, never a FACT."""

    def do_GET(self) -> None:  # noqa: N802
        time.sleep(0.05)   # matches the reviewed time_based_sqli `/time-safe` control magnitude
        _send200(self, b"<p>slow but safe</p>")


class _Reflector(_CmdiSleepExec):
    """BENIGN: echoes the raw host verbatim (the literal ``;sleep 0.6`` survives in the body, never executed)
    and responds instantly -> no dose-scaled latency -> no FACT."""

    def do_GET(self) -> None:  # noqa: N802
        _send200(self, f"<p>you sent: {_host(self.path)}</p>".encode())


@contextlib.contextmanager
def _server(handler) -> Iterator[str]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _drive(monkeypatch, tmp_path, handler):
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    from vigil_integration.live.runtime_redrive import _cmdi_timing_redrive
    with _server(handler) as base:
        return _cmdi_timing_redrive(f"{base}/diagnostics/ping?host=x", slug="alpha",
                                    engagement_slug="alpha", signers=_signers())


def test_genuine_shell_sleep_mints_a_signed_timing_fact(monkeypatch, tmp_path) -> None:
    rr = _drive(monkeypatch, tmp_path, _CmdiSleepExec)
    assert len(rr.facts) >= 1, f"a dose-responsive shell `sleep` sink must mint a signed cmdi TIMING FACT; notes={rr.notes}"
    assert all(getattr(f, "is_fact", False) for f in rr.facts)


def test_benign_calculator_mints_nothing(monkeypatch, tmp_path) -> None:
    # DECISIVE: the arithmetic evaluator that false-FACTs the in-band side_effect channel computes instantly,
    # so it produces no dose-scaled latency -> the timing channel refuses it. This is why timing is the SOUND
    # in-band cmdi FACT and the computed-product channel is only a LEAD.
    rr = _drive(monkeypatch, tmp_path, _Calculator)
    assert len(rr.facts) == 0, f"a benign calculator minted a FALSE cmdi timing FACT; facts={rr.facts}"


def test_uniformly_slow_endpoint_mints_nothing(monkeypatch, tmp_path) -> None:
    rr = _drive(monkeypatch, tmp_path, _UniformlySlow)
    assert len(rr.facts) == 0, f"a uniformly-slow endpoint minted a FACT (no dose-response); facts={rr.facts}"


def test_reflector_mints_nothing(monkeypatch, tmp_path) -> None:
    rr = _drive(monkeypatch, tmp_path, _Reflector)
    assert len(rr.facts) == 0, f"a reflector minted a FACT; facts={rr.facts}"
