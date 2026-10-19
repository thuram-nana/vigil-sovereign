"""
Governed-engage IN-BAND command-injection side_effect arm: cmdi_reflected_redrive is a LEAD driver
(command_injection.reflected_output is fact_capable=false). The computed-product marker ($((N1*N2))) flags a
command sink with a VIGIL-owned capture, but it is NOT a FACT — a benign arithmetic evaluator (a calculator /
instant-answer / $(( )) config-expander) ALSO computes N1*N2 from the input, so an in-band product does not
distinguish shell execution from ordinary app math (an adversarial red-pen reproduced a rate-1.0 signed false
FACT against a plain calculator). The SOUND in-band cmdi FACT is the dose-scaled TIMING channel
(test_cmdi_timing_redrive.py) + the blind OOB curl-callback — channels a calculator cannot reproduce.

This pins: a GENUINE execution (subprocess, shell=True — real per-probe arithmetic) surfaces a command-sink
LEAD (never a FACT); and the arm stays silent (no lead, no fact) on a hardened twin, a uid= knowledge-base
(the path_traversal root:x:0:0: trap, which carries NO computed product), and a raw reflector (the product
VALUE is absent from the payload) — so even the LEAD is attributed to the computed product, never emitted on a
benign shape that merely echoes or documents.
"""

from __future__ import annotations

import contextlib
import http.server
import re
import subprocess
import threading
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
    # A DECLARED charset is required by the gated send before it will expose a body for a body-dependent
    # verdict (an undeclared charset -> body withheld, the arm sees nothing -> a LEAD, never a false FACT).
    # Real targets (MERIDIAN included) declare one; a charset-less cmdi sink stays a LEAD here by design.
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class _CmdiExec(http.server.BaseHTTPRequestHandler):
    """VULNERABLE: concatenates host into a shell string and reflects stdout. The arm's per-probe
    $((N1*N2)) is GENUINELY COMPUTED (shell=True), so the product is real execution output."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        try:
            cp = subprocess.run("echo reached " + host, shell=True, capture_output=True, text=True, timeout=5)
            out = (cp.stdout or "") + (cp.stderr or "")
        except Exception as exc:  # noqa: BLE001
            out = f"error: {exc}"
        _send200(self, f"<pre>$ echo reached {host}\n{out}</pre>".encode())


class _Hardened(_CmdiExec):
    """HARDENED twin: strict host validation refuses the break-out; a valid host uses argv (shell=False)."""

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        if not _HOSTNAME_RE.match(host):
            _send200(self, f"Refused: {host} is not a valid hostname".encode())
            return
        try:
            cp = subprocess.run(["echo", "reached", host], capture_output=True, text=True, timeout=5)
            _send200(self, ((cp.stdout or "") + (cp.stderr or "")).encode())
        except Exception as exc:  # noqa: BLE001
            _send200(self, f"error: {exc}".encode())


class _CmdiKb(_CmdiExec):
    """The path_traversal KB analog: emits the DOCUMENTED uid=0(root) PoC correlated with a cmdi-ish query,
    computing NOTHING. The old uid= signal would false-FACT; the computed-product signal must not."""

    def do_GET(self) -> None:  # noqa: N802
        host = _host(self.path)
        if any(t in host for t in (";", "|", "`", "$(", "id", "expr", "echo", "command")):
            body = (b"<article>Command injection (CWE-78): <code>;id</code> returns "
                    b"<code>uid=0(root) gid=0(root) groups=0(root)</code>.</article>")
        else:
            body = b"<p>host status: ok</p>"
        _send200(self, body)


class _ReflectsRaw(_CmdiExec):
    """Echoes the raw host verbatim (the literal $((N1*N2)) survives; its VALUE is never computed)."""

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
    from vigil_integration.live.runtime_redrive import cmdi_reflected_redrive
    with _server(handler) as base:
        return cmdi_reflected_redrive(f"{base}/diagnostics/ping?host=x", slug="alpha",
                                      engagement_slug="alpha", signers=_signers())


def test_genuine_execution_yields_a_lead_not_a_fact(monkeypatch, tmp_path) -> None:
    # The in-band computed-product channel is LEAD-only: a benign calculator reproduces the product, so a
    # genuine execution is flagged as a command-sink LEAD (the sink is real, VIGIL-captured) but is NEVER
    # minted as a FACT here — the sound FACT is the dose-scaled timing channel (test_cmdi_timing_redrive.py).
    rr = _drive(monkeypatch, tmp_path, _CmdiExec)
    assert len(rr.facts) == 0, f"the in-band computed-product channel must NOT mint a FACT; facts={rr.facts}"
    assert len(rr.leads) >= 1, f"genuine execution must still surface a command-sink LEAD; notes={rr.notes}"
    assert all(not getattr(r, "is_fact", False) for r in rr.leads)


def test_hardened_twin_mints_nothing(monkeypatch, tmp_path) -> None:
    rr = _drive(monkeypatch, tmp_path, _Hardened)
    assert len(rr.facts) == 0, f"hardened twin minted a FACT; facts={rr.facts}"


def test_cmdi_kb_documenting_uid_mints_nothing(monkeypatch, tmp_path) -> None:
    # DECISIVE soundness proof: the KB emits uid=0(root) correlated with the payload but CANNOT produce the
    # per-probe unguessable computed product -> no FACT. The old uid=-signature signal would have minted one.
    rr = _drive(monkeypatch, tmp_path, _CmdiKb)
    assert len(rr.facts) == 0, f"benign cmdi-KB minted a FALSE FACT; facts={rr.facts}"


def test_raw_reflection_mints_nothing(monkeypatch, tmp_path) -> None:
    rr = _drive(monkeypatch, tmp_path, _ReflectsRaw)
    assert len(rr.facts) == 0, f"raw reflection minted a FACT; facts={rr.facts}"
