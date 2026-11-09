"""NET-2b (#73) — `vigil engage --otlp-endpoint` / ``$VIGIL_OTLP_ENDPOINT`` threads an opt-in, LOOPBACK-only
OTLP telemetry destination into ``EngineConfig.otlp_endpoint``.

Before this slice no production caller set ``otlp_endpoint``: the ``otel-collector`` service
(`vigil services up --with-observability`) received nothing from a real ``vigil engage``, and the OTLP sink
(and NET-2a's bounded recovery for it) was reachable only programmatically. The invariants pinned here:

  * DEFAULT-OFF — neither flag nor env ⇒ ``otlp_endpoint is None`` (byte-identical config).
  * FAIL-CLOSED ON EGRESS — a non-loopback value (or one that cannot be validated) is refused LOUDLY at the
    CLI and telemetry stays OFF; the sink's own loopback pin remains the second line.
  * NEVER BLOCKS THE RUN — a refused endpoint still runs the engagement (rc 0): telemetry never denies cognition.

Only the CLI wiring is asserted, by capturing the config a stubbed ``build_engine`` receives.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

ENV = "VIGIL_OTLP_ENDPOINT"


def _stub_engine():
    class _E:
        def engage(self, url, objective="", resume=False):
            return SimpleNamespace(
                slug="loopback", refused=False, refusal_reason="", attestation_ref="",
                iterations=0, decisions=[], tool_calls=[], denied_edges=[], fact_count=0,
                facts=[], leads=[], detection_facts=0, detection_leads=0, checkpoints=[], paused=None,
                resumed=False)
    return _E()


def _run(monkeypatch, tmp_path, extra=()):
    import vigil_integration.live.wiring as wiring
    from vigil_integration.cli import main
    captured = {}

    def _fake_build_engine(cfg):
        captured["otlp_endpoint"] = cfg.otlp_endpoint
        return _stub_engine()

    monkeypatch.setattr(wiring, "build_engine", _fake_build_engine)
    rc = main(["engage", "http://127.0.0.1:18080/", "--base-dir", str(tmp_path), *extra])
    return rc, captured


@pytest.fixture(autouse=True)
def _no_ambient_env(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


def test_default_is_off(monkeypatch, tmp_path):
    rc, cap = _run(monkeypatch, tmp_path)
    assert rc == 0 and cap["otlp_endpoint"] is None


@pytest.mark.parametrize("ep", ["http://127.0.0.1:4318", "http://localhost:4318", "http://[::1]:4318"])
def test_loopback_flag_is_threaded(monkeypatch, tmp_path, ep):
    rc, cap = _run(monkeypatch, tmp_path, ["--otlp-endpoint", ep])
    assert rc == 0 and cap["otlp_endpoint"] == ep


def test_env_fallback_and_flag_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV, "http://127.0.0.1:4318")
    rc, cap = _run(monkeypatch, tmp_path)
    assert rc == 0 and cap["otlp_endpoint"] == "http://127.0.0.1:4318"
    rc, cap = _run(monkeypatch, tmp_path, ["--otlp-endpoint", "http://127.0.0.1:14318"])
    assert cap["otlp_endpoint"] == "http://127.0.0.1:14318"          # the explicit flag wins


@pytest.mark.parametrize("ep", [
    "http://169.254.169.254:4318",        # cloud metadata — must never be a telemetry destination
    "http://10.0.0.5:4318",
    "https://collector.example.com:4318",
    "not a url",
])
def test_non_loopback_is_refused_loudly_and_the_run_continues(monkeypatch, tmp_path, capsys, ep):
    rc, cap = _run(monkeypatch, tmp_path, ["--otlp-endpoint", ep])
    assert rc == 0                                   # telemetry never blocks the engagement
    assert cap["otlp_endpoint"] is None              # ...and a non-loopback destination is never wired
    assert "refusing non-loopback OTLP endpoint" in capsys.readouterr().err


def test_non_loopback_env_is_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(ENV, "http://169.254.169.254:4318")
    rc, cap = _run(monkeypatch, tmp_path)
    assert rc == 0 and cap["otlp_endpoint"] is None
    assert "refusing non-loopback" in capsys.readouterr().err


def test_a_validation_fault_fails_closed(monkeypatch, tmp_path, capsys):
    import vigil_integration.live.otel_export as oe

    def boom(_ep):
        raise RuntimeError("observability plane broken")

    monkeypatch.setattr(oe, "endpoint_is_loopback", boom)
    rc, cap = _run(monkeypatch, tmp_path, ["--otlp-endpoint", "http://127.0.0.1:4318"])
    assert rc == 0 and cap["otlp_endpoint"] is None  # cannot prove loopback ⇒ not wired
    assert "could not validate the OTLP endpoint" in capsys.readouterr().err


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_values_are_off(monkeypatch, tmp_path, blank):
    monkeypatch.setenv(ENV, blank)
    rc, cap = _run(monkeypatch, tmp_path, ["--otlp-endpoint", blank])
    assert rc == 0 and cap["otlp_endpoint"] is None
