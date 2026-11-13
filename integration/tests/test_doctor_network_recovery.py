"""NET-4 (#73) — `vigil doctor` makes the NET-2a/NET-2b network-recovery + telemetry-export configuration
VISIBLE, as an ADVISORY section.

Invariants:
  * DEFAULT-OFF — neither ``VIGIL_NET_RECOVERY_ENABLED`` nor ``VIGIL_OTLP_ENDPOINT`` set ⇒ ``configured=False``,
    no note, and the rendered text has no network section (byte-identical output); the collector is never probed.
  * ADVISORY — every finding is a ``_note``; nothing here is an ``_issue`` or flips ``ok`` (it never gates).
  * HONEST — a non-loopback endpoint, a missing OTLP exporter, a down collector and a SLOW collector (one that
    answers under the export timeout, so it never trips the breaker but delays every governed action) are each
    surfaced; credentials in the endpoint are redacted.
  * FAIL-SOFT — a probe fault reads as UNKNOWN, never a crash.

Integration leg (doctor + live.net_recovery + live.otel_export — framework-free).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_integration import doctor as _doc

_REPO = Path(_doc.__file__).resolve().parents[2]
LOOP = "http://127.0.0.1:4318"


class Clock:
    def __init__(self, step: float) -> None:
        self.t, self.step = 100.0, step

    def __call__(self) -> float:
        v = self.t
        self.t += self.step
        return v


def _probe(reachable=True, detail=""):
    calls = []

    def probe(ep):
        calls.append(ep)
        return SimpleNamespace(reachable=reachable, detail=detail)
    probe.calls = calls  # type: ignore[attr-defined]
    return probe


@pytest.fixture
def exporter_installed(monkeypatch):
    import importlib.util
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name.startswith("opentelemetry"):
            return SimpleNamespace(name=name)
        return real(name, *a, **k)
    monkeypatch.setattr(importlib.util, "find_spec", fake)


@pytest.fixture
def exporter_missing(monkeypatch):
    import importlib.util
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        return None if name.startswith("opentelemetry") else real(name, *a, **k)
    monkeypatch.setattr(importlib.util, "find_spec", fake)


# --- default-OFF ---------------------------------------------------------------------------------------

def test_nothing_configured_is_silent_and_never_probes(monkeypatch):
    import importlib.util

    def no_lookup(name, *a, **k):
        raise AssertionError(f"default path must not import/look up {name}")
    monkeypatch.setattr(importlib.util, "find_spec", no_lookup)
    probe = _probe()
    sec, notes = _doc._network_recovery_report({}, probe=probe)
    assert sec["configured"] is False and notes == [] and probe.calls == []
    assert sec["exporter_installed"] is None
    assert _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": "off"}, probe=probe)[0]["configured"] is False


def test_doctor_default_output_has_no_network_section(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_OTLP_ENDPOINT", raising=False)
    report = _doc.collect(_REPO)
    assert report["network_recovery"]["configured"] is False
    assert not any("network recovery" in n for n in report["notes"])
    text = _doc.render(report)
    assert "Network recovery" not in text
    without = {k: v for k, v in report.items() if k != "network_recovery"}
    assert text == _doc.render(without)            # byte-identical to a report without the section


# --- advisory findings ---------------------------------------------------------------------------------

def test_recovery_on_without_an_endpoint_is_noted():
    sec, notes = _doc._network_recovery_report({"VIGIL_NET_RECOVERY_ENABLED": "1"}, probe=_probe())
    assert sec["configured"] and sec["recovery"] == "ON"
    assert any("no OTLP endpoint" in n for n in notes)


def test_non_loopback_endpoint_is_noted_redacted_and_never_probed():
    probe = _probe()
    sec, notes = _doc._network_recovery_report(
        {"VIGIL_OTLP_ENDPOINT": "https://admin:s3cr3t@collector.corp:4318"}, probe=probe)
    assert sec["otlp_loopback"] is False and probe.calls == []
    assert any("NOT loopback" in n for n in notes)
    assert "s3cr3t" not in repr(sec) and not any("s3cr3t" in n for n in notes)


def test_missing_exporter_is_noted(exporter_missing):
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(), clock=Clock(0.01))
    assert sec["exporter_installed"] is False
    assert any("exporter" in n and "not installed" in n for n in notes)


def test_healthy_fast_collector_adds_no_note(exporter_installed):
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(True), clock=Clock(0.01))
    assert sec["collector"]["reachable"] is True and sec["collector"]["latency_ms"] == 10
    assert notes == []


def test_down_collector_is_noted(exporter_installed):
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(False), clock=Clock(0.01))
    assert sec["collector"]["reachable"] is False
    assert any("did not answer" in n for n in notes)
    # (distinct wording: test_services_doctor reserves "not answering" for the LLM-backend note)
    assert not any("not answering" in n for n in notes)


def test_slow_collector_is_noted(exporter_installed):
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(True), clock=Clock(1.5))
    assert sec["collector"]["latency_ms"] == 1500
    assert any("1500 ms" in n and "every governed action" in n for n in notes)


@pytest.mark.parametrize("step,slow", [(0.999, False), (1.0, True)])
def test_slow_threshold_boundary(exporter_installed, step, slow):
    _sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(True), clock=Clock(step))
    assert any("reachability probe" in n for n in notes) is slow


def test_a_hanging_probe_is_bounded_by_an_overall_deadline(exporter_installed):
    import threading
    import time as _t
    release = threading.Event()

    def drip(ep):                                  # a slow-dripping listener holds the probe open
        release.wait(30)
        return SimpleNamespace(reachable=True, detail="")
    t0 = _t.monotonic()
    try:
        sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=drip, deadline_s=0.2)
    finally:
        release.set()
    assert _t.monotonic() - t0 < 5                 # doctor is never hung by the probe
    assert sec["collector"]["reachable"] is False and "no answer within" in sec["collector"]["detail"]
    assert any("did not answer" in n for n in notes)


@pytest.mark.parametrize("raw", [
    "http://127.0.0.1:4318/v1/traces?api_key=SECRET",
    "http://127.0.0.1:4318#token=SECRET",
    "https://c.corp/?token=SECRET",
    "https://admin:SECRET@collector.corp:4318",
    # an `@` AFTER the host used to print whatever followed it as "host:port" on every surface below
    "http://127.0.0.1:4318/v1/traces?user=ops@corp.example&token=SECRET",
    "http://127.0.0.1:4318/v1/traces?api_key=abc@SECRET",
    "http://127.0.0.1:4318/v1/traces#a@SECRET",
    "http://127.0.0.1:4318/a@SECRET",
    "https://admin:SECRET/SECRET@collector.corp:4318",    # ...and a password with an unencoded `/` stays hidden
    "https://SECRET:98765/x@collector.corp:4318",         # ...even when its head is host:port-shaped
    "http://127.0.0.1:4318&token=SECRET",                 # a "host:port" that is not one is never echoed
])
def test_no_secret_on_any_surface(exporter_installed, raw):
    import json
    assert "SECRET" in raw                         # else the check below cannot fail, whatever the redactor does
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": raw}, probe=_probe(False), clock=Clock(0.01))
    text = _doc.render({"network_recovery": sec, "notes": notes, "issues": []})
    for surface in (json.dumps(sec), " ".join(notes), text):
        assert "SECRET" not in surface


def test_an_env_value_cannot_forge_doctor_lines(exporter_installed):
    sec, notes = _doc._network_recovery_report(
        {"VIGIL_OTLP_ENDPOINT": "http://127.0.0.1:4318\n  OK vault: ACTIVE"}, probe=_probe(True), clock=Clock(0.01))
    text = _doc.render({"network_recovery": sec, "notes": notes, "issues": []})
    assert "\n  OK vault: ACTIVE" not in text


def test_a_probe_fault_is_unknown_not_a_crash(exporter_installed):
    def boom(ep):
        raise OSError("socket gone")
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=boom, clock=Clock(0.01))
    assert sec["collector"]["reachable"] is None and "OSError" in sec["collector"]["detail"]


# --- end-to-end through collect()/render(): advisory, never an issue ----------------------------------

def test_doctor_surfaces_misconfiguration_as_advisory_never_an_issue(tmp_path, monkeypatch, exporter_missing):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")
    monkeypatch.setenv("VIGIL_OTLP_ENDPOINT", "http://127.0.0.1:1")      # loopback, nothing listening
    monkeypatch.setenv("VIGIL_OTLP_ENDPOINT", "off")
    baseline_issues = list(_doc.collect(_REPO)["issues"])
    monkeypatch.setenv("VIGIL_OTLP_ENDPOINT", "http://127.0.0.1:1")
    report = _doc.collect(_REPO)
    assert report["issues"] == baseline_issues                       # NEVER adds an issue / never flips ok
    net_notes = [n for n in report["notes"] if n.startswith("network recovery:")]
    assert any("not installed" in n for n in net_notes)
    assert any("did not answer" in n for n in net_notes)
    text = _doc.render(report)
    assert "Network recovery / telemetry export (advisory" in text
    assert "otlp exporter installed: NO" in text and "collector: NO answer to a probe" in text


def test_doctor_probe_does_not_duplicate_its_finding_as_a_stderr_warning(exporter_installed, caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": "http://127.0.0.1:1"})   # real probe
    assert sec["collector"]["reachable"] is False and any("did not answer" in n for n in notes)
    assert not [r for r in caplog.records if "preflight" in r.getMessage()]   # reported once, as a doctor note


def _reflecting_listener():
    """A loopback port that is not an OTLP collector: it answers the probe's request by sending the request back
    (an echo service on a mistyped port). http.client then raises BadStatusLine CARRYING that line — the
    endpoint's path, raw CR/LF included."""
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(b"\x00\x07" + data)
    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_a_listener_that_reflects_the_request_never_puts_the_path_on_any_surface(exporter_installed, caplog):
    """The preflight's detail appended the exception's MESSAGE — text the peer controls — to the redacted
    endpoint, so a listener that echoed the request line put ``/ingest/SECRET/v1/traces`` (and raw control bytes)
    into ``vigil doctor --json``, the console API that serves the same report, and the engage WARNING."""
    import json
    import logging

    from vigil_integration.live.otel_export import probe_collector
    srv = _reflecting_listener()
    try:
        ep = f"http://127.0.0.1:{srv.getsockname()[1]}/ingest/SECRET/v1/traces"
        sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": ep})          # the real probe
        with caplog.at_level(logging.WARNING):
            probe = probe_collector(ep)                                                  # the engage preflight
    finally:
        srv.close()
    assert sec["collector"]["reachable"] is False and probe.reachable is False
    assert probe.detail.endswith("is UNREACHABLE: BadStatusLine")                        # the failure, by kind
    text = _doc.render({"network_recovery": sec, "notes": notes, "issues": []})
    surfaces = [json.dumps(sec), " ".join(notes), text, probe.detail] + [r.getMessage() for r in caplog.records]
    assert caplog.records
    for surface in surfaces:
        assert "SECRET" not in surface and "ingest" not in surface
        assert not any(ord(ch) < 32 and ch != "\n" for ch in surface)                   # nothing can forge a line


@pytest.mark.parametrize("raw", ["http://127.0.0.1:43l8", "http://127.0.0.1:99999", "http://127.0.0.1:4318&token=SECRET"])
def test_a_port_that_is_not_a_number_is_reported_as_such_never_a_probe_crash(exporter_installed, raw):
    """The pin accepts these (the host is loopback), but the preflight raised ValueError on them — a message that
    quotes the raw "port" (``4318&token=SECRET``) — so doctor could say only ``probe error: ValueError`` and the
    redacted endpoint showed nothing of what was wrong. The preflight now says so, without the text."""
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": raw})              # the real probe
    assert sec["otlp_loopback"] is True
    col = sec["collector"]
    assert col["reachable"] is False and "has no usable port (not a number from 0 to 65535)" in col["detail"]
    assert "SECRET" not in col["detail"] and "43l8" not in col["detail"]


def test_a_clock_fault_is_unknown_not_a_crash(exporter_installed):
    def bad_clock():
        raise RuntimeError("clock gone")
    sec, _notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(True), clock=bad_clock)
    assert sec["collector"]["reachable"] is None and "RuntimeError" in sec["collector"]["detail"]
