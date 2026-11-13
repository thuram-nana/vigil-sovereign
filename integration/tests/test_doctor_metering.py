"""PRICING M1c — `vigil doctor` reports the metered-billing posture (design §4-§5), without importing sigil.

  * neither flag set adds nothing (default output unchanged);
  * metered billing without the gateway, a gateway with no provider key, a gateway that does not answer while
    billing is metered, a pricing value the metering core refuses, and — when billing is metered — no target
    margin or no cancel-settlement policy are HARD issues; the margin's value is never printed;
  * with billing flat, the margin and the cancel policy are not required;
  * no daily ceiling, or an unanswering gateway while billing is still flat, is a note;
  * the line renders the mode, the gateway and the pricing in force.

Integration leg (doctor only — framework-free).
"""
from __future__ import annotations

from vigil_core import model_metering as mm

from vigil_integration import doctor as d

# A decoy margin assembled at runtime (this public repo carries no margin value; see tools/governance/money_hygiene.py).
_DECOY = "0." + str(3) + str(75)

ON = {"VIGIL_METERED_BILLING": "1", "VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk",
      "VIGIL_GATEWAY_DAILY_LIMIT_USD": "500", mm.MARGIN_ENV: _DECOY, mm.CANCEL_ENV: "metered"}


def _alive(url):
    return True


def _dead(url):
    return False


def test_nothing_configured_adds_nothing():
    assert d._metering_report({}, probe=_alive) == ({"configured": False}, [], [])


def test_a_healthy_metered_setup_is_reported_and_rendered():
    section, issues, notes = d._metering_report(dict(ON), probe=_alive)
    assert (issues, notes) == ([], [])
    assert section["ok"] and section["reachable"] is True and section["target_margin_set"] is True
    assert section["floor_credits"] == 25 and section["url"] == "http://127.0.0.1:8742"
    assert section["cancel_settlement"] == "metered"
    out = d.render({"ok": True, "issues": [], "notes": [], "metering": section})
    assert "billing: metered; model gateway http://127.0.0.1:8742: answering; floor 25 credits; target margin " \
           "set; cancelled runs: metered; daily ceiling $500" in out
    assert _DECOY not in out and _DECOY not in repr(section)             # the owner's margin is never printed


def test_misconfigurations_are_hard_issues():
    issues = d._metering_report({"VIGIL_METERED_BILLING": "1"}, probe=_alive)[1]
    assert any("VIGIL_MODEL_GATEWAY_ENABLED" in m for m in issues)
    issues = d._metering_report({**ON, "SIGIL_ANTHROPIC_API_KEY": ""}, probe=_alive)[1]
    assert any("provider key" in m for m in issues)
    issues = d._metering_report(dict(ON), probe=_dead)[1]
    assert any("does not answer" in m for m in issues)
    for k, v in (("VIGIL_RUN_FLOOR_CREDITS", "-1"), ("VIGIL_MODEL_PRICES", "{"),
                 ("VIGIL_GATEWAY_TENANT_CONCURRENCY", "0"), ("VIGIL_GATEWAY_DAILY_LIMIT_USD", "-5")):
        section, issues, _ = d._metering_report({**ON, k: v}, probe=_alive)
        assert section["ok"] is False and any("refused" in m for m in issues), (k, v)
    # metered billing needs the owner's two decisions; each missing one is its own hard issue
    for k, v, says in ((mm.MARGIN_ENV, "", "cannot price a run"),
                       (mm.MARGIN_ENV, "1.5", "cannot price a run"),
                       (mm.CANCEL_ENV, "", "no cancellation policy"),
                       (mm.CANCEL_ENV, "free", "no cancellation policy")):
        section, issues, _ = d._metering_report({**ON, k: v}, probe=_alive)
        assert section["ok"] is False and len(issues) == 1 and says in issues[0], (k, v, issues)


def test_the_run_model_must_be_priced_and_concurrency_is_digits_only():
    for k, v in (("VIGIL_RUN_MODEL", "claude-unpriced-1"), ("VIGIL_GATEWAY_GLOBAL_CONCURRENCY", "+4"),
                 ("VIGIL_GATEWAY_TENANT_CONCURRENCY", "4_0")):
        section, issues, _ = d._metering_report({**ON, k: v}, probe=_alive)
        assert section["ok"] is False and any("refused" in m for m in issues), (k, v)


def test_the_enabled_spelling_turns_metering_on_as_it_does_at_runtime():
    section, _issues, _ = d._metering_report({**ON, "VIGIL_METERED_BILLING": "enabled",
                                              "VIGIL_MODEL_GATEWAY_ENABLED": "Enabled"}, probe=_alive)
    assert section["configured"] and section["metered_billing"] and section["gateway_enabled"]


def test_something_else_on_the_gateway_port_is_reported():
    def other(url):
        return None
    _s, issues, _ = d._metering_report(dict(ON), probe=other)
    assert any("something other than the model gateway" in m for m in issues)
    flat = {"VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk", "VIGIL_GATEWAY_DAILY_LIMIT_USD": "9"}
    _s, issues, notes = d._metering_report(flat, probe=other)
    assert issues == [] and any("something other than the model gateway" in m for m in notes)


def test_flat_billing_needs_neither_owner_decision():
    flat = {"VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk", "VIGIL_GATEWAY_DAILY_LIMIT_USD": "9"}
    section, issues, _ = d._metering_report(flat, probe=_alive)
    assert issues == [] and section["ok"] and "target_margin_set" not in section and "cancel_settlement" not in section


def test_advisories_are_notes():
    env = {k: v for k, v in ON.items() if k != "VIGIL_GATEWAY_DAILY_LIMIT_USD"}
    section, issues, notes = d._metering_report(env, probe=_alive)
    assert issues == [] and any("daily spend ceiling" in m for m in notes)
    flat = {"VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk", "VIGIL_GATEWAY_DAILY_LIMIT_USD": "9"}
    section, issues, notes = d._metering_report(flat, probe=_dead)
    assert issues == [] and any("does not answer" in m for m in notes)
    assert "billing: flat (metering OFF)" in d.render({"ok": True, "issues": [], "notes": [], "metering": section})


def _serve(code, body):
    import http.server
    import json
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_the_default_probe_recognises_only_the_gateway():
    assert d._probe_model_gateway("http://127.0.0.1:9") is False                     # nothing listens
    gateway_401 = {"type": "error", "error": {"type": "authentication_error", "message": "x"}}
    for code, body, want in ((401, gateway_401, True), (401, {"error": {"type": "other"}}, None),
                             (403, gateway_401, None), (200, {}, None)):
        srv = _serve(code, body)
        try:
            assert d._probe_model_gateway(f"http://127.0.0.1:{srv.server_address[1]}") is want, (code, body)
        finally:
            srv.shutdown()
            srv.server_close()


def test_collect_wires_the_section_in(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.delenv("VIGIL_MODEL_GATEWAY_ENABLED", raising=False)
    section, issues, _ = d._metering_report()
    assert section["metered_billing"] is True and issues
