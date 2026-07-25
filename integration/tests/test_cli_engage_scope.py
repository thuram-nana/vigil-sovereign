"""WS-A — `vigil engage --scope` threads the authorized scope into EngineConfig (→ the signed authority).

The flag drives what gets SIGNED into the CRUCIBLE authority; the signed authority is the enforcement input
(the executor's egress guard + the gate both key off it). Here we only assert the CLI wiring — that
``--scope a,b`` reaches ``EngineConfig.scope`` as ``("a","b")`` and the default is loopback — by capturing
the config a stubbed ``build_engine`` receives (no engine is actually built).

Run: PYTHONPATH=integration pytest integration/tests/test_cli_engage_scope.py -q
"""
from __future__ import annotations

from types import SimpleNamespace


def _stub_engine():
    class _E:
        def engage(self, url, objective=""):
            return SimpleNamespace(
                slug="loopback", refused=False, refusal_reason="", attestation_ref="",
                iterations=0, decisions=[], tool_calls=[], denied_edges=[], fact_count=0,
                facts=[], leads=[], detection_facts=0, detection_leads=0, checkpoints=[], paused=None)
    return _E()


def _run_engage(monkeypatch, argv):
    import vigil_integration.live.wiring as wiring
    from vigil_integration.cli import main
    captured = {}

    def _fake_build_engine(cfg):
        captured["scope"] = cfg.scope
        return _stub_engine()

    monkeypatch.setattr(wiring, "build_engine", _fake_build_engine)  # _cmd_engage imports it at call time
    rc = main(argv)
    return rc, captured


def test_scope_flag_threads_into_engine_config(monkeypatch, tmp_path):
    rc, cap = _run_engage(monkeypatch, ["engage", "http://scanme.example.com/",
                                        "--scope", "scanme.example.com, *.acme.test",
                                        "--base-dir", str(tmp_path)])
    assert rc == 0
    assert cap["scope"] == ("scanme.example.com", "*.acme.test")


def test_scope_defaults_to_loopback(monkeypatch, tmp_path):
    rc, cap = _run_engage(monkeypatch, ["engage", "http://127.0.0.1:18080/", "--base-dir", str(tmp_path)])
    assert rc == 0
    assert cap["scope"] == ("127.0.0.1",)
