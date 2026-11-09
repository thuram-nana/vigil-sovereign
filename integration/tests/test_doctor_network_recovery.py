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
    assert "Network recovery" not in _doc.render(report)


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
    assert any("not answering" in n for n in notes)


def test_slow_collector_is_noted(exporter_installed):
    sec, notes = _doc._network_recovery_report({"VIGIL_OTLP_ENDPOINT": LOOP}, probe=_probe(True), clock=Clock(1.5))
    assert sec["collector"]["latency_ms"] == 1500
    assert any("1500 ms" in n and "delays every governed action" in n for n in notes)


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
    assert any("not answering" in n for n in net_notes)
    text = _doc.render(report)
    assert "Network recovery / telemetry export (advisory" in text
    assert "otlp exporter installed: NO" in text and "collector: NOT answering" in text
