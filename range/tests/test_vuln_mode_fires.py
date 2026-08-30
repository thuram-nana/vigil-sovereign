"""In VULN mode, every planted S1 sink produces the exact signal its VIGIL oracle needs."""

from __future__ import annotations


def test_sqli_error_signature(range_client):
    range_client.set_mode("vuln")
    status, body = range_client.get("/records/search?q=" + range_client.q("'"))
    assert status == 200
    assert "SQL error" in body
    assert any(sig in body for sig in ("syntax error", "unrecognized token", "OperationalError"))


def test_sqli_boolean_differential(range_client):
    range_client.set_mode("vuln")
    _, true_body = range_client.get("/records/search?q=" + range_client.q("' OR '1'='1"))
    _, false_body = range_client.get("/records/search?q=" + range_client.q("' AND '1'='2"))
    # a TRUE tautology returns the whole register; a FALSE one returns nothing → a material differential
    assert true_body.count("PL-2026") >= 5
    assert false_body.count("PL-2026") == 0


def test_reflected_xss_unescaped(range_client):
    range_client.set_mode("vuln")
    payload = "<svg/onload=alert(1)>"
    _, body = range_client.get("/records/search?q=" + range_client.q(payload))
    assert payload in body  # echoed verbatim into an executable HTML position


def test_stored_xss_in_notes(range_client):
    range_client.set_mode("vuln")
    marker = "<script>st0red_xss</script>"
    _, confirm = range_client.post("/apply", {"name": "X", "permit_type": "Business Licence", "notes": marker})
    ref = confirm.split('class="mono">')[1].split("<")[0]
    _, track = range_client.get("/track?ref=" + range_client.q(ref))
    assert marker in track  # the stored note is rendered unescaped


def test_reflected_xss_on_unknown_ref(range_client):
    range_client.set_mode("vuln")
    payload = "<img src=x onerror=y>"
    _, body = range_client.get("/track?ref=" + range_client.q(payload))
    assert payload in body


def test_path_traversal_returns_decoy(range_client):
    range_client.set_mode("vuln")
    status, body = range_client.get("/documents/download?file=" + range_client.q("../../etc/passwd"))
    assert status == 200 and "root:x:0:0:" in body


def test_open_redirect_to_attacker_host(range_client):
    range_client.set_mode("vuln")
    canary = "https://crucible-redirect-canary.test/pwned"
    status, location = range_client.location_of("/auth/continue?next=" + range_client.q(canary))
    assert status == 302 and location == canary


def test_env_and_actuator_exposure(range_client):
    range_client.set_mode("vuln")
    s1, env = range_client.get("/.env")
    s2, act = range_client.get("/actuator/env")
    assert s1 == 200 and "DB_PASSWORD" in env
    assert s2 == 200 and "propertySources" in act
