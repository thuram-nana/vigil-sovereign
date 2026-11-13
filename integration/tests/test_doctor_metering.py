"""PRICING M1c — `vigil doctor` reports the metered-billing posture (design §4-§5), without importing sigil.

  * neither flag set adds nothing (default output unchanged);
  * metered billing without the gateway, a gateway with no provider key, a gateway that does not answer while
    billing is metered, a pricing value the metering core refuses, and — when billing is metered — no target
    margin or an invalid cancel-settlement policy are HARD issues (an unset policy means metered, the owner's
    decision of 2026-11-13); the margin's value is never printed;
  * with billing flat, the margin and the cancel policy are not required;
  * a retired pricing setting (VIGIL_BILLING_MARKUP_K / VIGIL_MARGIN_MULTIPLIER_K) is a hard issue whatever the
    flags say — the target margin (over metered AI cost only) is the one pricing input;
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
           "set (over metered AI cost); cancelled runs: metered; daily ceiling $500" in out
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
    # metered billing needs a target margin, and a cancel policy that is either unset (= metered) or valid
    for k, v, says in ((mm.MARGIN_ENV, "", "cannot price a run"),
                       (mm.MARGIN_ENV, "1.5", "cannot price a run"),
                       (mm.CANCEL_ENV, "free", "invalid cancellation policy")):
        section, issues, _ = d._metering_report({**ON, k: v}, probe=_alive)
        assert section["ok"] is False and len(issues) == 1 and says in issues[0], (k, v, issues)
    # an UNSET cancel policy is the owner's default (metered), not an issue
    section, issues, _ = d._metering_report({**ON, mm.CANCEL_ENV: ""}, probe=_alive)
    assert issues == [] and section["cancel_settlement"] == "metered"


def test_a_retired_pricing_setting_is_a_hard_issue_whether_or_not_metering_is_on():
    flat = {"VIGIL_MODEL_GATEWAY_ENABLED": "1", "SIGIL_ANTHROPIC_API_KEY": "sk", "VIGIL_GATEWAY_DAILY_LIMIT_USD": "9"}
    for name in mm.OBSOLETE_PRICING_ENVS:
        says = f"{name} is set: remove it; the only pricing input is VIGIL_BILLING_TARGET_MARGIN"
        section, issues, notes = d._metering_report({name: ""}, probe=_alive)          # nothing else configured
        assert section == {"configured": False, "ok": False} and notes == []
        assert len(issues) == 1 and issues[0].startswith(says), issues
        section, issues, _ = d._metering_report({**flat, name: "3"}, probe=_alive)       # flat billing
        assert section["ok"] is False and len(issues) == 1 and issues[0].startswith(says), issues
        section, issues, _ = d._metering_report({**ON, name: "3"}, probe=_alive)         # metered: reported once
        assert section["ok"] is False and len(issues) == 1 and issues[0].startswith(says), issues
        assert section["target_margin_set"] is True                                     # the margin itself is fine
        assert _DECOY not in repr(section) + repr(issues)
    both = {n: "1" for n in mm.OBSOLETE_PRICING_ENVS}
    assert len(d._metering_report(both, probe=_alive)[1]) == 2
    # the doctor surfaces it in the report it renders
    report = {"ok": False, "issues": d._metering_report(both, probe=_alive)[1], "notes": [],
              "metering": {"configured": False, "ok": False}}
    out = d.render(report)
    assert "VIGIL_MARGIN_MULTIPLIER_K is set: remove it" in out and "VIGIL_BILLING_MARKUP_K is set: remove it" in out


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
                             (403, gateway_401, None), (200, {}, None),
                             # a foreign 401 of any other shape is "something else", never a crash
                             (401, {"error": "unauthorized"}, None), (401, [], None), (401, None, None),
                             (401, "denied", None), (401, 7, None)):
        srv = _serve(code, body)
        try:
            assert d._probe_model_gateway(f"http://127.0.0.1:{srv.server_address[1]}") is want, (code, body)
        finally:
            srv.shutdown()
            srv.server_close()


def test_a_service_that_does_not_speak_http_is_something_else():
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def answer():
        c, _ = srv.accept()
        c.recv(1024)
        c.sendall(b"hello, not http\r\n")
        c.close()
    threading.Thread(target=answer, daemon=True).start()
    try:
        assert d._probe_model_gateway(f"http://127.0.0.1:{srv.getsockname()[1]}") is None
    finally:
        srv.close()


def test_a_probe_that_breaks_never_hides_the_hard_issues():
    def broken(url):
        raise AttributeError("a probe bug")
    section, issues, _ = d._metering_report({**ON, mm.MARGIN_ENV: ""}, probe=broken)
    assert section["ok"] is False and section["reachable"] is None
    assert any("cannot price a run" in m for m in issues)
    assert any("something other than the model gateway" in m for m in issues)


def test_the_billing_line_names_the_gateway_state():
    section, _, _ = d._metering_report({k: v for k, v in ON.items() if k != "VIGIL_MODEL_GATEWAY_ENABLED"},
                                       probe=_alive)
    out = d.render({"ok": False, "issues": [], "notes": [], "metering": section})
    assert "model gateway http://127.0.0.1:8742: not enabled" in out
    section, _, _ = d._metering_report(dict(ON), probe=lambda url: None)
    out = d.render({"ok": False, "issues": [], "notes": [], "metering": section})
    assert "model gateway http://127.0.0.1:8742: something else answers" in out


def test_the_doctor_reads_sigil_env_as_the_cockpit_does(monkeypatch, tmp_path):
    # the cockpit layers $SIGIL_HOME/sigil.env under its environment (the settings UI saves the provider key there);
    # the doctor must read the same, or it reports a key the gateway has as missing and misses flags set there
    for k in list(ON) + ["ANTHROPIC_API_KEY", "VIGIL_MODEL_GATEWAY_PORT"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setenv("VIGIL_GATEWAY_DAILY_LIMIT_USD", "9")
    (tmp_path / "sigil.env").write_text(
        "# saved by the settings UI\nVIGIL_MODEL_GATEWAY_ENABLED=1\nANTHROPIC_API_KEY=sk-dummy-not-real\n"
        "VIGIL_GATEWAY_DAILY_LIMIT_USD=bad\n", encoding="utf-8")
    section, issues, _ = d._metering_report(probe=_alive)
    assert section["gateway_enabled"] is True and issues == [], issues   # the key is found; the real env wins
    assert section["daily_limit_usd"] == "9"
    (tmp_path / "sigil.env").write_text("VIGIL_METERED_BILLING=1\n", encoding="utf-8")
    section, issues, _ = d._metering_report(probe=_alive)
    assert section["metered_billing"] is True and any("VIGIL_MODEL_GATEWAY_ENABLED" in m for m in issues)
    (tmp_path / "sigil.env").unlink()
    assert d._metering_report(probe=_alive) == ({"configured": False}, [], [])


def test_collect_wires_the_section_in(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.delenv("VIGIL_MODEL_GATEWAY_ENABLED", raising=False)
    section, issues, _ = d._metering_report()
    assert section["metered_billing"] is True and issues


def test_a_retired_pricing_setting_kept_in_sigil_env_is_reported(monkeypatch, tmp_path):
    # billing reads sigil.env through sigil.config, so a retired setting kept there blocks metered billing: doctor
    # must say so too (it reads the same layered environment)
    for k in list(ON) + list(mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    (tmp_path / "sigil.env").write_text("VIGIL_MARGIN_MULTIPLIER_K=3\n", encoding="utf-8")
    section, issues, _ = d._metering_report(probe=_alive)
    assert section == {"configured": False, "ok": False}
    assert len(issues) == 1 and issues[0].startswith("VIGIL_MARGIN_MULTIPLIER_K is set: remove it")


def test_collect_reports_a_retired_setting_on_a_flat_deploy(monkeypatch, tmp_path):
    # the whole doctor, not just the section: neither flag on, a retired setting present -> not ok, and the refusal
    # is listed under "Action needed"
    for k in list(ON) + list(mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setenv("VIGIL_BILLING_MARKUP_K", "")
    report = d.collect(tmp_path)
    says = "VIGIL_BILLING_MARKUP_K is set: remove it; the only pricing input is VIGIL_BILLING_TARGET_MARGIN"
    assert report["ok"] is False and any(m.startswith(says) for m in report["issues"])
    assert report["metering"] == {"configured": False, "ok": False}
    out = d.render(report)
    assert "Action needed" in out and says in out.split("Action needed", 1)[1]
