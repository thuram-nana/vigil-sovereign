"""DEP-2 (#73) — `vigil ready` / ``readiness.wait_ready``: the bring-up READINESS GATE.

READY iff the proxy's ``/readyz`` answers 200 AND ``vigil doctor`` is ok, polled until a hard deadline. The
invariants pinned here: BOUNDED (deadline + an attempt cap that holds even if the clock stalls), LOOPBACK-ONLY
(a non-loopback /readyz URL is refused with no connection), FAIL-CLOSED (any probe/doctor fault is "not ready"),
and READ-ONLY / NOT AN ENABLER (readiness gating never enables execution — the module writes nothing and touches
no flag). Plus the opt-in ``vigil-ready.service`` unit's structural invariants.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path

import pytest

from vigil_integration import readiness as rd

_REPO = Path(rd.__file__).resolve().parents[2]
URL = "http://127.0.0.1:8770/readyz"


class Clock:
    def __init__(self, step=1.0):
        self.t, self.step = 0.0, step

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


def _seq_probe(results):
    calls = []

    def probe(url):
        calls.append(url)
        return results[min(len(calls) - 1, len(results) - 1)]
    probe.calls = calls  # type: ignore[attr-defined]
    return probe


def _doctor(ok=True, issues=()):
    calls = []

    def d(repo):
        calls.append(repo)
        return ok, list(issues)
    d.calls = calls  # type: ignore[attr-defined]
    return d


# --- the verdict ---------------------------------------------------------------------------------------

def test_ready_when_readyz_and_doctor_both_ok():
    v = rd.wait_ready(_REPO, url=URL, probe=_seq_probe([(True, "")]), doctor=_doctor(True),
                      clock=Clock(), sleep=lambda s: None)
    assert v["ready"] is True and v["attempts"] == 1 and v["doctor_ok"] is True


def test_doctor_gap_is_not_ready_and_names_the_issue():
    v = rd.wait_ready(_REPO, url=URL, probe=_seq_probe([(True, "")]), doctor=_doctor(False, ["venv missing"]),
                      clock=Clock(), sleep=lambda s: None)
    assert v["ready"] is False and v["doctor_ok"] is False and v["doctor_issues"] == ["venv missing"]


def test_doctor_is_not_run_while_readyz_is_down():
    doc = _doctor(True)
    v = rd.wait_ready(_REPO, url=URL, wait_s=5, interval_s=1, probe=_seq_probe([(False, "down")]), doctor=doc,
                      clock=Clock(1.0), sleep=lambda s: None)
    assert v["ready"] is False and doc.calls == [] and v["doctor_ok"] is None


def test_becomes_ready_within_the_deadline():
    probe = _seq_probe([(False, "down"), (False, "down"), (True, "")])
    v = rd.wait_ready(_REPO, url=URL, wait_s=60, interval_s=2, probe=probe, doctor=_doctor(True),
                      clock=Clock(2.0), sleep=lambda s: None)
    assert v["ready"] is True and v["attempts"] == 3


def test_the_wait_is_bounded_by_the_deadline():
    sleeps = []
    v = rd.wait_ready(_REPO, url=URL, wait_s=10, interval_s=2, probe=_seq_probe([(False, "down")]),
                      doctor=_doctor(True), clock=Clock(2.0), sleep=sleeps.append)
    assert v["ready"] is False and v["attempts"] <= 7 and sum(sleeps) <= 10


def test_the_wait_is_bounded_even_if_the_clock_stalls():
    v = rd.wait_ready(_REPO, url=URL, wait_s=10, interval_s=2, probe=_seq_probe([(False, "down")]),
                      doctor=_doctor(True), clock=lambda: 0.0, sleep=lambda s: None)
    assert v["ready"] is False and v["attempts"] == 10 // 2 + 2


@pytest.mark.parametrize("wait", [float("nan"), -5, "x", None])
def test_malformed_wait_checks_once(wait):
    v = rd.wait_ready(_REPO, url=URL, wait_s=wait, probe=_seq_probe([(False, "down")]), doctor=_doctor(True),
                      clock=Clock(), sleep=lambda s: None)
    assert v["attempts"] == 1


def test_a_huge_wait_is_clamped():
    v = rd.wait_ready(_REPO, url=URL, wait_s=10 ** 9, interval_s=3600, probe=_seq_probe([(False, "d")]),
                      doctor=_doctor(True), clock=Clock(3600.0), sleep=lambda s: None)
    assert v["attempts"] <= 6 * 3600 // 3600 + 2


def test_probe_and_doctor_faults_are_not_ready():
    def boom(_):
        raise OSError("socket gone")
    v = rd.wait_ready(_REPO, url=URL, probe=boom, doctor=_doctor(True), clock=Clock(), sleep=lambda s: None)
    assert v["ready"] is False and "OSError" in v["readyz_detail"]

    def doc_boom(_):
        raise RuntimeError("doctor exploded")
    v = rd.wait_ready(_REPO, url=URL, probe=_seq_probe([(True, "")]), doctor=doc_boom, clock=Clock(),
                      sleep=lambda s: None)
    assert v["ready"] is False and v["doctor_ok"] is False


@pytest.mark.parametrize("url", ["http://10.0.0.5:8770/readyz", "http://169.254.169.254/readyz",
                                 "http://localhost:8770/readyz",                    # a NAME is never resolved
                                 "http://evil.com\\@127.0.0.1:8770/readyz", "file:///etc/passwd"])
def test_non_loopback_url_is_refused_without_any_probe(url, monkeypatch):
    probe = _seq_probe([(True, "")])
    v = rd.wait_ready(_REPO, url=url, probe=probe, doctor=_doctor(True), clock=Clock(), sleep=lambda s: None)
    assert v["ready"] is False and probe.calls == [] and "not loopback" in v["readyz_detail"]
    # the real probe refuses BEFORE constructing any connection (never even attempts the off-box host)
    import http.client as hc

    def no_conn(*a, **k):
        raise AssertionError("probe_readyz must not open a connection to a non-loopback URL")
    monkeypatch.setattr(hc, "HTTPConnection", no_conn)
    monkeypatch.setattr(hc, "HTTPSConnection", no_conn)
    ok, detail = rd.probe_readyz(url)
    assert ok is False and "not loopback" in detail


# --- the real /readyz probe against a local server ------------------------------------------------------

@pytest.fixture
def server():
    state = {"status": 200}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(state["status"])
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/readyz", state
    srv.shutdown()


def test_real_probe_200_is_ready_503_is_not(server):
    url, state = server
    assert rd.probe_readyz(url) == (True, "")
    state["status"] = 503
    ok, detail = rd.probe_readyz(url)
    assert ok is False and "503" in detail


def test_real_probe_closed_port_is_not_ready():
    ok, detail = rd.probe_readyz("http://127.0.0.1:1/readyz", timeout=0.5)
    assert ok is False and "not answering" in detail


# --- CLI -----------------------------------------------------------------------------------------------

def test_cli_refuses_a_non_loopback_url(capsys):
    from vigil_integration.cli import main
    assert main(["ready", "--url", "http://10.0.0.5/readyz"]) == 2
    assert "loopback" in capsys.readouterr().err


@pytest.mark.parametrize("ready,rc", [(True, 0), (False, 1)])
def test_cli_exit_code_follows_the_verdict(monkeypatch, capsys, ready, rc):
    from vigil_integration.cli import main
    seen = {}

    def fake(repo, **kw):
        seen.update(kw)
        return {"ready": ready, "readyz_ok": ready, "readyz_detail": "", "doctor_ok": ready, "doctor_issues": [],
                "attempts": 1, "waited_s": 0.0, "url": kw["url"]}
    monkeypatch.setattr(rd, "wait_ready", fake)
    assert main(["ready", "--wait", "30"]) == rc
    assert seen["wait_s"] == 30.0 and seen["url"] == rd.DEFAULT_READYZ_URL
    assert ("READY" if ready else "NOT READY") in capsys.readouterr().out


# --- read-only / not an enabler ------------------------------------------------------------------------

def _code_without_docstrings(path: Path) -> str:
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
            body.pop(0)                            # docstrings may NAME the hold to promise it is never touched
    return ast.unparse(tree)                       # comments are dropped by the parse


def test_readiness_is_read_only_and_never_touches_an_execution_hold():
    src = _code_without_docstrings(Path(rd.__file__))
    for forbidden in ("PROD_EXECUTION", "os.environ[", "setenv", "subprocess", "write_text", "open(", ".write(",
                      "unlink", "systemctl"):
        assert forbidden not in src, f"readiness.py must be read-only / not an enabler: found {forbidden!r}"


# --- the opt-in unit -----------------------------------------------------------------------------------

_UNIT = _REPO / "infra" / "systemd" / "vigil-ready.service"


def _lines():
    return _UNIT.read_text(encoding="utf-8").splitlines()


def test_unit_is_a_bounded_failing_oneshot():
    lines = _lines()
    assert "Type=oneshot" in lines and "RemainAfterExit=no" in lines    # point-in-time, never a stale "ready"
    assert not any(ln.startswith("Restart=") for ln in lines)
    exec_line = next(ln for ln in lines if ln.startswith("ExecStart="))
    assert not exec_line.startswith("ExecStart=-"), "an unready box must FAIL the unit (no `-` prefix)"
    assert " ready --wait " in exec_line
    wait = float(exec_line.rsplit("--wait", 1)[1].split()[0])
    timeout = float(next(ln for ln in lines if ln.startswith("TimeoutStartSec=")).split("=", 1)[1])
    worst = wait + rd._PROBE_DEADLINE_S + rd.DOCTOR_DEADLINE_S
    assert timeout > worst, "TimeoutStartSec must be a hard backstop above the worst-case gate duration"
    assert "Environment=VIGIL_BIN=/home/kali/vigil/.venv-offense/bin/vigil" in lines   # user PATH lacks ~/.local/bin


def test_unit_orders_after_but_never_starts_or_blocks_the_ui():
    lines = _lines()
    after = next(ln for ln in lines if ln.startswith("After="))
    assert "vigil-command.service" in after and "vigil-bringup.service" in after
    for ln in lines:
        if ln.startswith(("Requires=", "Wants=", "BindsTo=", "Requisite=", "Before=")):
            assert "vigil-command" not in ln and "vigil-bringup" not in ln, ln


# --- red-pen folds: overall per-probe / per-doctor deadlines, NaN interval, malformed results -------------

def test_a_dripping_probe_is_bounded_by_its_overall_deadline():
    import time as _t
    release = threading.Event()

    def drip(url):
        release.wait(30)
        return True, ""
    t0 = _t.monotonic()
    try:
        v = rd.wait_ready(_REPO, url=URL, probe=drip, doctor=_doctor(True), probe_deadline_s=0.2,
                          clock=Clock(), sleep=lambda s: None)
    finally:
        release.set()
    assert _t.monotonic() - t0 < 5 and v["ready"] is False and "did not answer within" in v["readyz_detail"]


def test_a_hanging_doctor_is_bounded_by_its_overall_deadline():
    import time as _t
    release = threading.Event()

    def slow_doctor(repo):
        release.wait(30)
        return True, []
    t0 = _t.monotonic()
    try:
        v = rd.wait_ready(_REPO, url=URL, probe=_seq_probe([(True, "")]), doctor=slow_doctor,
                          doctor_deadline_s=0.2, clock=Clock(), sleep=lambda s: None)
    finally:
        release.set()
    assert _t.monotonic() - t0 < 5 and v["ready"] is False
    assert v["doctor_issues"] and "did not finish within" in v["doctor_issues"][0]


@pytest.mark.parametrize("interval", [float("nan"), float("inf")])
def test_a_non_finite_interval_never_raises(interval):
    v = rd.wait_ready(_REPO, url=URL, wait_s=4, interval_s=interval, probe=_seq_probe([(False, "d")]),
                      doctor=_doctor(True), clock=Clock(2.0), sleep=lambda s: None)
    assert v["ready"] is False and v["attempts"] >= 1


@pytest.mark.parametrize("bad", [None, "ok", (True,), (True, "", "extra")])
def test_malformed_probe_or_doctor_results_are_not_ready(bad):
    v = rd.wait_ready(_REPO, url=URL, probe=lambda u: bad, doctor=_doctor(True), clock=Clock(), sleep=lambda s: None)
    assert v["ready"] is False
    v = rd.wait_ready(_REPO, url=URL, probe=_seq_probe([(True, "")]), doctor=lambda r: bad, clock=Clock(),
                      sleep=lambda s: None)
    assert v["ready"] is False and v["doctor_ok"] is False
