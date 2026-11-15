"""`vigil doctor` on customer sign-in, read from the env files the customer edge and the cockpit units load:

* HARD: the Google switch, client id or redirect URI differ between the customer edge and the cockpit (the edge
  shows the button and sends people to Google, the cockpit finishes the sign-in); Google is on in one of them
  without its client id or redirect URI; on in the cockpit without the client secret. Values are never printed.
* NOTE: Google is on at the edge without VIGIL_CUSTOMER_OIDC_HANDOFF — inside an app installed to an iPhone Home
  Screen, Google sign-in would finish in another browser and the person would not be signed in to the app.
* Silent until the customer edge or the cockpit takes part; the shipped env examples, completed with the owner's
  Google client, agree and raise nothing.

Framework-free: tmp HOME trees only, no systemd needed.
"""
from __future__ import annotations

from pathlib import Path

from test_doctor_deploy_units import _REPO, _install, _isolated, _write

from vigil_integration import deploy_checks as dc
from vigil_integration import doctor as _doc

_ID = "VIGIL_CUSTOMER_OIDC_CLIENT_ID=client-123.apps.googleusercontent.com\n"
_URI = "VIGIL_CUSTOMER_OIDC_REDIRECT_URI=https://app.example/api/customer/oidc/callback\n"
_SECRET = "VIGIL_CUSTOMER_OIDC_CLIENT_SECRET=owner-secret-value\n"
_ON = "VIGIL_CUSTOMER_OIDC_ENABLED=1\n"


def _host(home: Path, *, cockpit: "str | None" = None, customer: "str | None" = None) -> None:
    for unit, text, name in (("sigil-cockpit.service", cockpit, "cockpit.env"),
                             ("sigil-customer.service", customer, "customer.env")):
        if text is not None:
            _install(home, unit)
            _write(home / ".sigil" / name, text)


def test_silent_without_the_edge_or_the_cockpit(tmp_path):
    assert dc.customer_signin_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def test_google_off_everywhere_is_quiet(tmp_path):
    _host(tmp_path, cockpit="", customer="")
    sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert sec["ok"] is True and issues == [] and notes == []
    assert sec["google"] == {"customer": "off", "cockpit": "off"}


def test_complete_google_with_the_handoff_is_clean(tmp_path):
    _host(tmp_path, cockpit=_ON + _ID + _URI + _SECRET,
          customer=_ON + _ID + _URI + "VIGIL_CUSTOMER_OIDC_HANDOFF=1\n")
    sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["ok"] is True and sec["handoff"] is True


def test_google_without_the_handoff_is_a_note(tmp_path):
    _host(tmp_path, cockpit=_ON + _ID + _URI + _SECRET, customer=_ON + _ID + _URI)
    sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert issues == [] and sec["ok"] is True and len(notes) == 1
    assert "VIGIL_CUSTOMER_OIDC_HANDOFF is off" in notes[0] and "iPhone Home Screen" in notes[0]


def test_the_switch_on_in_one_of_them_only_is_a_hard_issue(tmp_path):
    _host(tmp_path, cockpit=_ID + _URI + _SECRET, customer=_ON + _ID + _URI + "VIGIL_CUSTOMER_OIDC_HANDOFF=1\n")
    sec, issues, _notes = dc.customer_signin_report(tmp_path, _REPO)
    assert sec["ok"] is False and len(issues) == 1
    assert issues[0].startswith("VIGIL_CUSTOMER_OIDC_ENABLED must be the same")
    assert "on in the customer edge, off in the cockpit" in issues[0]


def test_a_different_client_id_is_a_hard_issue_and_no_value_is_printed(tmp_path):
    _host(tmp_path, cockpit=_ON + "VIGIL_CUSTOMER_OIDC_CLIENT_ID=other-client-value\n" + _URI + _SECRET,
          customer=_ON + _ID + _URI + "VIGIL_CUSTOMER_OIDC_HANDOFF=1\n")
    sec, issues, _notes = dc.customer_signin_report(tmp_path, _REPO)
    assert sec["ok"] is False and len(issues) == 1 and "VIGIL_CUSTOMER_OIDC_CLIENT_ID" in issues[0]
    assert "set differently" in issues[0]
    for value in ("other-client-value", "client-123", "owner-secret-value"):
        assert value not in issues[0]


def test_missing_settings_are_hard_issues_naming_them(tmp_path):
    _host(tmp_path, cockpit=_ON + _ID, customer=_ON + _ID + "VIGIL_CUSTOMER_OIDC_HANDOFF=1\n")
    sec, issues, _notes = dc.customer_signin_report(tmp_path, _REPO)
    assert sec["ok"] is False
    edge = [i for i in issues if "on in the customer edge but" in i]
    cockpit = [i for i in issues if "on in the cockpit but" in i]
    assert len(edge) == 1 and "VIGIL_CUSTOMER_OIDC_REDIRECT_URI" in edge[0]
    assert "VIGIL_CUSTOMER_OIDC_CLIENT_SECRET" not in edge[0]                  # the secret is never the edge's
    assert len(cockpit) == 1 and "VIGIL_CUSTOMER_OIDC_REDIRECT_URI" in cockpit[0]
    assert "VIGIL_CUSTOMER_OIDC_CLIENT_SECRET" in cockpit[0]


def test_one_value_in_sigil_env_reaches_both(tmp_path):
    _host(tmp_path, cockpit=_SECRET, customer="VIGIL_CUSTOMER_OIDC_HANDOFF=1\n")
    _write(tmp_path / ".sigil" / "sigil.env", _ON + _ID + _URI)
    sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["google"] == {"customer": "on", "cockpit": "on"}


def test_the_shipped_env_examples_completed_with_the_owners_client_agree(tmp_path):
    sigil = _REPO / "apps" / "sigil" / "deploy"
    _host(tmp_path, cockpit=(sigil / "cockpit.env.example").read_text() + _ID + _URI + _SECRET,
          customer=(sigil / "customer.env.example").read_text() + _ID + _URI)
    sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["google"] == {"customer": "on", "cockpit": "on"}
    assert sec["handoff"] is True


def test_the_shipped_env_examples_as_copied_name_what_the_owner_must_fill_in(tmp_path):
    sigil = _REPO / "apps" / "sigil" / "deploy"
    _host(tmp_path, cockpit=(sigil / "cockpit.env.example").read_text(),
          customer=(sigil / "customer.env.example").read_text())
    _sec, issues, _notes = dc.customer_signin_report(tmp_path, _REPO)
    assert len(issues) == 2 and all("VIGIL_CUSTOMER_OIDC_CLIENT_ID" in i for i in issues)
    # no secret is shipped in either example
    for name in ("cockpit.env.example", "customer.env.example"):
        text = (sigil / name).read_text()
        for secret in ("VIGIL_CUSTOMER_OIDC_CLIENT_SECRET", "SIGIL_EMAIL_PASSWORD"):
            assert not any(line.startswith(secret + "=") and line.split("=", 1)[1].strip()
                           for line in text.splitlines()), (name, secret)
    assert "VIGIL_CUSTOMER_OIDC_CLIENT_SECRET" not in (sigil / "customer.env.example").read_text()


def test_doctor_reports_and_renders_it(tmp_path, monkeypatch):
    home = _isolated(monkeypatch, tmp_path)
    for k in ("VIGIL_CUSTOMER_OIDC_ENABLED", "VIGIL_CUSTOMER_OIDC_HANDOFF", "VIGIL_CUSTOMER_OIDC_CLIENT_ID",
              "VIGIL_CUSTOMER_OIDC_REDIRECT_URI", "VIGIL_CUSTOMER_OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    assert _doc.collect(_REPO)["customer_signin"] == {"configured": False}
    _host(home, cockpit=_ON + _ID + _URI + _SECRET, customer=_ON + _ID + _URI)
    report = _doc.collect(_REPO)
    assert report["customer_signin"]["ok"] is True
    assert any("VIGIL_CUSTOMER_OIDC_HANDOFF is off" in n for n in report["notes"])
    text = _doc.render(report)
    assert "customer Google sign-in: on in the customer edge; on in the cockpit; inside the installed app: OFF" in text


def test_the_founder_flag_without_the_trial_preview_is_a_note(tmp_path):
    _host(tmp_path, cockpit="VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED=1\nVIGIL_TRIAL_PREVIEW_ENABLED=0\n")
    _sec, issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert issues == [] and any(n.startswith("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED is on but") for n in notes)
    _host(tmp_path, cockpit="VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED=1\nVIGIL_TRIAL_PREVIEW_ENABLED=1\n")
    _sec, _issues, notes = dc.customer_signin_report(tmp_path, _REPO)
    assert not any("FOUNDER_TESTER" in n for n in notes)
