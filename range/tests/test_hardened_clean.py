"""In HARDENED mode, every S1 sink is neutralized while KEEPING the same route/param.

This is the sound-negative property VIGIL's posture re-prove depends on: the oracle still has a live channel
(the endpoint answers), it simply does not fire — so the negative is CLOSED, not merely UNPROVEN.
"""

from __future__ import annotations


def test_sqli_is_parameterized_no_error_and_no_differential(range_client):
    range_client.set_mode("hardened")
    _, err_body = range_client.get("/records/search?q=" + range_client.q("'"))
    assert "SQL error" not in err_body  # the DB error is never echoed
    _, tb = range_client.get("/records/search?q=" + range_client.q("' OR '1'='1"))
    _, fb = range_client.get("/records/search?q=" + range_client.q("' AND '1'='2"))
    assert tb.count("PL-2026") == 0 and fb.count("PL-2026") == 0  # literal match on the payload: no rows, no differential


def test_reflected_and_stored_xss_are_escaped(range_client):
    range_client.set_mode("hardened")
    _, r = range_client.get("/records/search?q=" + range_client.q("<svg/onload=alert(1)>"))
    assert "<svg/onload=alert(1)>" not in r and "&lt;svg" in r
    marker = "<script>st0red_xss</script>"
    _, confirm = range_client.post("/apply", {"name": "X", "permit_type": "Business Licence", "notes": marker})
    ref = confirm.split('class="mono">')[1].split("<")[0]
    _, track = range_client.get("/track?ref=" + range_client.q(ref))
    assert marker not in track and "&lt;script&gt;" in track


def test_traversal_is_refused(range_client):
    range_client.set_mode("hardened")
    status, body = range_client.get("/documents/download?file=" + range_client.q("../../etc/passwd"))
    assert status == 404 and "root:x:0:0:" not in body
    # the route still answers for a legitimate document (channel is live → sound negative, not UNPROVEN)
    assert range_client.get("/documents/download?file=readme")[0] == 200


def test_open_redirect_is_refused_but_route_lives(range_client):
    range_client.set_mode("hardened")
    status, location = range_client.location_of(
        "/auth/continue?next=" + range_client.q("https://crucible-redirect-canary.test/pwned"))
    assert status == 400 and location is None
    # a same-origin relative next is still honoured (the channel remains live)
    assert range_client.location_of("/auth/continue?next=/records")[0] == 302


def test_open_redirect_backslash_and_protocol_relative_bypasses_are_refused(range_client):
    """Mutation-sensitive: browsers normalize '\\' to '/', so /\\evil.com and //evil.com must be refused in
    hardened mode (they are external redirects). In vuln mode /\\evil.com IS honoured (the sink exists)."""
    range_client.set_mode("vuln")
    assert range_client.location_of("/auth/continue?next=" + range_client.q("/\\evil.com"))[0] == 302
    range_client.set_mode("hardened")
    for bad in ("/\\evil.com", "//evil.com", "\\/evil.com"):
        status, location = range_client.location_of("/auth/continue?next=" + range_client.q(bad))
        assert status == 400 and location is None, bad


def test_exposure_paths_are_404(range_client):
    range_client.set_mode("hardened")
    assert range_client.get("/.env")[0] == 404
    assert range_client.get("/actuator/env")[0] == 404
