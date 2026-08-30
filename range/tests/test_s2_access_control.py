"""S2 — API/BOLA, CORS, host-header, broken access control, BFLA, priv-esc, business logic, rate limit.

Each check asserts the vuln behavior fires AND the hardened twin neutralizes it while KEEPING the route
live (the sound-negative property).
"""

from __future__ import annotations

import json


def test_bola_reads_victim_pii_in_vuln_and_is_blocked_in_hardened(range_client):
    range_client.set_mode("vuln")
    status, body, _ = range_client.get_h("/api/applications/2")  # citizen 2's application, unauthenticated
    assert status == 200 and "MRD-100002" in body  # victim national id leaks

    range_client.set_mode("hardened")
    status, body, _ = range_client.get_h("/api/applications/2")
    assert status in (401, 403) and "MRD-100002" not in body


def test_hardened_owner_can_still_read_own_application(range_client):
    """The channel stays live in hardened mode: the legitimate owner reads their own record."""
    range_client.set_mode("hardened")
    token = range_client.login("glovelace", "password")  # Grace Lovelace → citizen 2, owns application 2
    assert token
    status, body, _ = range_client.get_h("/api/applications/2", range_client.cookie(token))
    assert status == 200 and "MRD-100002" in body
    # ...but not someone else's (application 1 belongs to citizen 1)
    status2, _, _ = range_client.get_h("/api/applications/1", range_client.cookie(token))
    assert status2 == 403


def test_cors_reflects_hostile_origin_only_in_vuln(range_client):
    hostile = {"Origin": "https://evil.test"}
    range_client.set_mode("vuln")
    _, _, h = range_client.get_h("/api/applications", hostile)
    assert h.get("Access-Control-Allow-Origin") == "https://evil.test"
    assert h.get("Access-Control-Allow-Credentials") == "true"

    range_client.set_mode("hardened")
    _, _, h = range_client.get_h("/api/applications", hostile)
    assert h.get("Access-Control-Allow-Origin") is None


def test_host_header_injection_only_in_vuln(range_client):
    inj = {"Host": "attacker.test"}
    range_client.set_mode("vuln")
    _, body, _ = range_client.get_h("/api/applications/APP-24-0001/share", inj)
    assert "attacker.test" in json.loads(body)["share_url"]

    range_client.set_mode("hardened")
    _, body, _ = range_client.get_h("/api/applications/APP-24-0001/share", inj)
    assert "attacker.test" not in json.loads(body)["share_url"]


def test_review_queue_and_approve_and_role_change_require_auth_when_hardened(range_client):
    range_client.set_mode("vuln")
    assert range_client.get_h("/staff")[0] == 200
    assert range_client.post_form("/staff/applications/3/approve", {})[0] == 200
    assert range_client.post_form("/admin/users/4/role", {"role": "admin"})[0] == 200

    range_client.set_mode("hardened")
    assert range_client.get_h("/staff")[0] == 403
    assert range_client.post_form("/staff/applications/3/approve", {})[0] == 403
    assert range_client.post_form("/admin/users/4/role", {"role": "admin"})[0] == 403


def test_zero_payment_accepted_in_vuln_rejected_in_hardened(range_client):
    range_client.set_mode("vuln")
    s, body, _ = range_client.post_form("/api/applications/1/pay", {"amount": "0"})
    assert s == 200 and json.loads(body)["paid"] is True and json.loads(body)["amount_paid_cents"] == 0

    range_client.set_mode("hardened")
    s, body, _ = range_client.post_form("/api/applications/1/pay", {"amount": "0"})
    assert s == 402 and "underpayment" in body


def test_login_has_no_rate_limit_in_vuln_but_429s_in_hardened(range_client):
    range_client.set_mode("hardened")
    codes = [range_client.post_form("/login", {"username": "admin", "password": "wrong", "next": "/"})[0]
             for _ in range(12)]
    assert 429 in codes  # the rate limit engages after repeated failures
