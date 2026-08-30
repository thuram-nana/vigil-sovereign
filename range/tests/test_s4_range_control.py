"""S4 — the Range Control cockpit (live command-center) and its closed-set runner.

Security-critical checks: the runner refuses any id outside the closed set, every spec's argv is built from
the fixed loopback target (no request-derived string), and a real run streams + executes.
"""

from __future__ import annotations

import json
import os
import urllib.request

from vigil_range.rangecontrol import runner


def test_cockpit_renders_tour_and_catalogue(range_client):
    with urllib.request.urlopen(range_client.control_base + "/", timeout=10) as r:  # type: ignore[attr-defined]
        body = r.read().decode()
    assert "Range Control" in body
    assert "Guided tour" in body and "Capability catalogue" in body
    assert body.count("run-btn") >= 4  # multiple runnable steps


def test_runner_refuses_unknown_spec():
    out = b"".join(runner.run_stream("'; DROP TABLE users; --", range_client_cfg()))
    assert b"refused: unknown run" in out


def range_client_cfg():
    from vigil_range.meridian.config import Config
    return Config(base_dir="/tmp/rc-argv-check", target_port=19010, control_port=19011)


def test_every_spec_argv_targets_loopback_only():
    """No spec may point the engine at anything but the loopback range, and none interpolates request input."""
    cfg = range_client_cfg()
    for spec_id, spec in runner.SPECS.items():
        argv = spec.build(cfg)
        assert argv, spec_id
        joined = " ".join(argv)
        # any URL in the argv must be the loopback target
        for tok in argv:
            if tok.startswith(("http://", "https://")):
                assert tok.startswith("http://127.0.0.1:"), f"{spec_id}: non-loopback target {tok}"
        # the slug, where present, is the fixed one
        if "--slug" in argv:
            assert argv[argv.index("--slug") + 1] == "meridian", spec_id
        # the victim header, where present, is a loopback session cookie (built by the runner, not the browser)
        assert "evil" not in joined.lower() and "attacker" not in joined.lower(), spec_id


def test_runner_streams_and_executes_a_real_run(range_client):
    """The harden-on run spawns the real target CLI, streams its output, and actually flips the mode."""
    cfg = range_client.config  # type: ignore[attr-defined]
    out = b"".join(runner.run_stream("harden-on", cfg)).decode()
    assert "python -m vigil_range.cli harden on" in out
    assert "exit code: 0" in out
    from vigil_range.meridian import config as cfgmod
    assert cfgmod.read_mode(cfg.base_dir) == "hardened"


def test_findings_view_reports_active_findings_as_facts(range_client):
    """The findings endpoint renders active_findings (oracle-confirmed) as FACTs."""
    rc_dir = os.path.join(range_client.config.base_dir, "rc")  # type: ignore[attr-defined]
    os.makedirs(rc_dir, exist_ok=True)
    with open(os.path.join(rc_dir, "records.reverify.json"), "w", encoding="utf-8") as fh:
        json.dump({"active_findings": [{"bug_class": "error_based_sqli", "param": "q"},
                                       {"bug_class": "xss", "param": "q"}],
                   "passive_findings": [{"bug_class": "missing_csp", "title": "Missing CSP"}]}, fh)
    with urllib.request.urlopen(range_client.control_base + "/findings.json", timeout=10) as r:  # type: ignore[attr-defined]
        doc = json.load(r)
    facts = [f for f in doc["findings"] if f["grounding"] == "fact"]
    assert {f["bug_class"] for f in facts} == {"error_based_sqli", "xss"}
    assert any(f["grounding"] == "lead" for f in doc["findings"])
