"""S5 — the expanded citizen-services surface: profile, messaging, reports, billing, diagnostics.

Each planted sink FIRES in vuln mode and goes QUIET in hardened mode on the SAME route + param — and in
hardened the route still answers (the channel stays live), so the negative is CLOSED, not merely unproven.
Mirrors test_vuln_mode_fires / test_hardened_clean for the S5 screens.

Assertions deliberately avoid any literal that also appears in the always-rendered "Demo attacks" panel
chrome (e.g. the SSTI probe here is {{6661*6661}}, never the panel's {{7*7}}), so a pass means the HANDLER
produced the signal, not the chrome.
"""

from __future__ import annotations


# --- profile: IDOR / BOLA (CWE-639) ----------------------------------------------------------------

def test_profile_idor_reads_any_account(range_client):
    range_client.set_mode("vuln")
    status, body = range_client.get("/profile?id=2")
    assert status == 200 and "LAB-NID-1002" in body  # another account's PII, no ownership check


def test_profile_idor_refused_when_hardened(range_client):
    range_client.set_mode("hardened")
    status, body = range_client.get("/profile?id=2")
    assert status == 403 and "LAB-NID-1002" not in body
    assert range_client.get("/profile?id=1")[0] == 200  # your OWN id still answers → CLOSED negative


# --- profile: mass-assignment privilege escalation (CWE-915 / CWE-269) -----------------------------

def test_profile_mass_assignment_elevates_role(range_client):
    range_client.set_mode("vuln")
    _, body = range_client.post("/profile/update", {"display_name": "Robin", "role": "admin"})
    assert '<b class="mono">admin</b>' in body  # client-supplied role bound → priv-esc


def test_profile_mass_assignment_ignored_when_hardened(range_client):
    range_client.set_mode("hardened")
    _, body = range_client.post("/profile/update", {"display_name": "Robin", "role": "admin"})
    assert '<b class="mono">admin</b>' not in body and '<b class="mono">citizen</b>' in body


# --- profile: reflected XSS (CWE-79) ---------------------------------------------------------------

def test_profile_reflected_xss(range_client):
    payload = "<svg/onload=alert(1)>"
    range_client.set_mode("vuln")
    _, v = range_client.post("/profile/update", {"display_name": payload})
    assert payload in v  # echoed verbatim into an executable position
    range_client.set_mode("hardened")
    _, h = range_client.post("/profile/update", {"display_name": payload})
    assert payload not in h and "&lt;svg" in h


# --- messaging: stored XSS (CWE-79) — send to self so the recipient check is not what suppresses it -

def test_messages_stored_xss_fires_in_vuln(range_client):
    marker = "<script>st0red_msg</script>"
    range_client.set_mode("vuln")
    _, body = range_client.post("/messages/send", {"to": "1", "subject": "x", "body": marker})
    assert marker in body  # POST 302 → view (followed); the stored body is rendered raw


def test_messages_stored_xss_escaped_in_hardened(range_client):
    marker = "<script>st0red_msg</script>"
    range_client.set_mode("hardened")
    _, body = range_client.post("/messages/send", {"to": "1", "subject": "x", "body": marker})
    assert marker not in body and "&lt;script&gt;" in body


# --- messaging: IDOR / BOLA (CWE-639) — message id=3 is addressed to another user ------------------

def test_messages_idor_reads_another_users_message(range_client):
    range_client.set_mode("vuln")
    status, body = range_client.get("/messages/view?id=3")
    assert status == 200 and "OTP-LAB-7Q2X" in body  # another user's secret, no recipient check


def test_messages_idor_refused_when_hardened(range_client):
    range_client.set_mode("hardened")
    status, body = range_client.get("/messages/view?id=3")
    assert status == 403 and "OTP-LAB-7Q2X" not in body
    assert range_client.get("/messages/view?id=1")[0] == 200  # your own message still opens


# --- reports: SSTI (CWE-1336) — evaluation, not reflection -----------------------------------------

def test_reports_ssti_evaluates_in_vuln(range_client):
    range_client.set_mode("vuln")
    _, body = range_client.get("/reports/run?title=" + range_client.q("R {{6661*6661}}"))
    assert "44368921" in body and "{{6661*6661}}" not in body  # computed server-side, raw payload absent


def test_reports_ssti_literal_when_hardened(range_client):
    range_client.set_mode("hardened")
    _, body = range_client.get("/reports/run?title=" + range_client.q("R {{6661*6661}}"))
    assert "44368921" not in body and "{{6661*6661}}" in body  # treated as a literal, nothing evaluated


# --- reports: SQL injection (CWE-89) — error signature + boolean differential ----------------------

def test_reports_sqli_error_and_differential(range_client):
    range_client.set_mode("vuln")
    _, err = range_client.get("/reports/run?status=" + range_client.q("'"))
    assert "SQL error" in err
    _, t = range_client.get("/reports/run?status=" + range_client.q("' OR '1'='1"))
    _, f = range_client.get("/reports/run?status=" + range_client.q("' AND '1'='2"))
    assert t.count("RPT-LAB-0") >= 6 and f.count("RPT-LAB-0") == 0  # TRUE returns all, FALSE returns none


def test_reports_sqli_parameterized_when_hardened(range_client):
    range_client.set_mode("hardened")
    _, err = range_client.get("/reports/run?status=" + range_client.q("'"))
    assert "SQL error" not in err
    _, t = range_client.get("/reports/run?status=" + range_client.q("' OR '1'='1"))
    assert t.count("RPT-LAB-0") == 0  # literal match → no rows, no differential


# --- billing: IDOR / BOLA (CWE-639) — invoice 4802 belongs to another payer ------------------------

def test_billing_idor_reads_any_invoice(range_client):
    range_client.set_mode("vuln")
    status, body = range_client.get("/billing/invoice?id=4802")
    assert status == 200 and "MER-FAKE-0002" in body  # another payer's PII, no ownership check


def test_billing_idor_refused_when_hardened(range_client):
    range_client.set_mode("hardened")
    status, body = range_client.get("/billing/invoice?id=4802")
    assert status == 403 and "MER-FAKE-0002" not in body
    assert range_client.get("/billing/invoice?id=4801")[0] == 200  # your own invoice still opens


# --- billing: payment business-logic (CWE-840) — unbounded client discount -------------------------

def test_billing_business_logic_zero_total_paid(range_client):
    range_client.set_mode("vuln")
    _, body = range_client.post("/billing/checkout", {"id": "4801", "discount": "100"})
    assert "$0.00" in body and "PAID" in body  # 100% discount → $0 total still marked PAID


def test_billing_business_logic_rejected_when_hardened(range_client):
    range_client.set_mode("hardened")
    _, body = range_client.post("/billing/checkout", {"id": "4801", "discount": "100"})
    assert "REJECTED" in body and "$0.00" not in body  # out-of-range discount refused before charging


# --- diagnostics: OS command injection (CWE-78) — confirmable from the reflected output ------------

def test_diagnostics_command_injection_fires(range_client):
    range_client.set_mode("vuln")
    _, body = range_client.get("/diagnostics/ping?host=" + range_client.q("127.0.0.1;id"))
    assert "uid=" in body  # the injected `id` executed and its output is reflected


def test_diagnostics_command_injection_refused_when_hardened(range_client):
    range_client.set_mode("hardened")
    _, body = range_client.get("/diagnostics/ping?host=" + range_client.q("127.0.0.1;id"))
    assert "uid=" not in body and "Refused" in body
    assert range_client.get("/diagnostics/ping?host=127.0.0.1")[0] == 200  # a legit host still probes
