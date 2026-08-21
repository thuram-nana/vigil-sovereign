"""S4 slice 2 — a gated network tool's approval binds to and DISPLAYS its canonical destination.

THE GAP (verified). ``_strix_target`` returned the constant ``"strix:exec"`` for EVERY gated tool, including
``repeat_request`` — which sends attacker-MODIFIED traffic to a URL. So an owner approving a repeat_request
saw ``target: strix:exec``, blind to which HOST they were authorizing an attack against.

FIRST FIX (slice 2 pt1) put the raw URL in the label. The operator's red-pen correctly found that this only
PARTIALLY closes it: a raw URL can (a) spoof the visible host (``https://trusted.example@evil.example/``
connects to ``evil.example``) and (b) smuggle secrets (``user:pass@``, session tokens / signed query
params) into the label and the pending-request UI. This test pins the canonicalisation that closes both:
the label carries only ``scheme://host:port`` with userinfo/path/query/fragment dropped, the host
lowercased / trailing-dot-stripped / IDNA- and numeric-IP-normalised, control chars refused, and a
diverging ``Host`` header surfaced separately.

HONEST BOUND. When repeat_request replays a captured request with NO url override, the true destination is
in the captured request (only ``request_id`` is in the args); fully resolving that id to host+port and
binding the request snapshot with a pre-replay recheck needs Caido at gate time and is the S6/S7 follow-up.
And none of this is a substitute for forcing Strix's real traffic through VIGIL's scope-enforcing egress
(S2/S3) — a human label never enforces scope.
"""
from __future__ import annotations

from vigil_integration.warden_gate import _canonical_destination, _strix_target

R = "repeat_request"


def _t(args):
    return _strix_target(R, args)


# ---- the two HIGH issues: host-spoofing and secret leakage ------------------------------------------

def test_userinfo_host_spoof_resolves_to_the_real_host():
    # connects to different-host.example, NOT authorized.gov.cm (which is userinfo)
    got = _t({"modifications": {"url": "https://authorized.gov.cm@different-host.example/path"}})
    assert got == "strix:repeat_request:https://different-host.example:443"
    assert "authorized.gov.cm" not in got


def test_credentials_in_url_do_not_enter_the_label():
    got = _t({"modifications": {"url": "https://admin:sup3rSecret@host.example/x"}})
    assert "sup3rSecret" not in got and "admin" not in got
    assert got == "strix:repeat_request:https://host.example:443"


def test_query_and_fragment_secrets_do_not_enter_the_label():
    got = _t({"modifications": {"url": "https://h.example/reset?token=abcTOKEN123&x=1#frag=SECRET"}})
    for secret in ("abcTOKEN123", "SECRET", "token=", "frag"):
        assert secret not in got
    assert got == "strix:repeat_request:https://h.example:443"


# ---- canonicalisation edge cases the operator enumerated -------------------------------------------

def test_standard_absolute_url_explicit_port():
    assert _t({"modifications": {"url": "http://ex.example:8080/a"}}) == "strix:repeat_request:http://ex.example:8080"


def test_default_ports_filled():
    assert _t({"modifications": {"url": "http://ex.example/"}}) == "strix:repeat_request:http://ex.example:80"
    assert _t({"modifications": {"url": "https://ex.example/"}}) == "strix:repeat_request:https://ex.example:443"


def test_mixed_case_and_trailing_dot_normalised():
    assert _canonical_destination("HTTPS://ExAmPle.COM./p") == "https://example.com:443"


def test_idna_unicode_homograph_shown_as_punycode():
    # cyrillic 'а' (U+0430) in "аpple.com" must not masquerade as ascii apple.com
    canon = _canonical_destination("https://аpple.com/")
    assert canon is not None and canon.startswith("https://xn--")


def test_ipv4_and_default_port():
    assert _canonical_destination("http://192.0.2.10/") == "http://192.0.2.10:80"


def test_ipv6_is_bracketed():
    assert _canonical_destination("http://[::1]:8080/") == "http://[::1]:8080"


def test_decimal_ip_encoding_canonicalised():
    assert _canonical_destination("http://2130706433/") == "http://127.0.0.1:80"


def test_hex_ip_encoding_canonicalised():
    assert _canonical_destination("http://0x7f000001/") == "http://127.0.0.1:80"


def test_control_characters_refuse_canonicalisation():
    assert _canonical_destination("http://ex.example/\r\nHost: evil") is None
    assert _t({"modifications": {"url": "http://ex.example/\nInjected"}}) == "strix:repeat_request:unparseable-url"


def test_malformed_port_refuses():
    assert _canonical_destination("http://ex.example:notaport/") is None


def test_oversized_host_is_capped():
    huge = "a" * 5000 + ".example"
    canon = _canonical_destination(f"http://{huge}/")
    assert canon is not None and len(canon) < 400 and "truncated" in canon


def test_empty_or_hostless_url_is_unparseable():
    assert _canonical_destination("not a url") is None
    assert _t({"modifications": {"url": "   "}}) == "strix:repeat_request"  # blank url → falls to req/base


# ---- Host header override surfaced separately from the connection destination ----------------------

def test_host_header_override_is_shown_alongside_the_connection_destination():
    got = _t({"modifications": {"url": "https://192.0.2.10/", "headers": {"Host": "app.example"}}})
    assert got == "strix:repeat_request:https://192.0.2.10:443;host=app.example"


def test_host_header_override_case_insensitive_key():
    got = _t({"request_id": "r1", "modifications": {"headers": {"hOsT": "vhost.example"}}})
    assert got == "strix:repeat_request:req=r1;host=vhost.example"


def test_host_header_with_control_chars_is_sanitised():
    got = _t({"modifications": {"url": "https://h.example/", "headers": {"Host": "a.example\r\nX: y"}}})
    assert got.endswith(";host=invalid")


# ---- request_id fallback (honest partial) ----------------------------------------------------------

def test_request_id_only_labels_the_specific_request_not_a_constant():
    assert _t({"request_id": "abc123", "modifications": {"method": "POST"}}) == "strix:repeat_request:req=abc123"


def test_request_id_integer():
    assert _t({"request_id": 42}) == "strix:repeat_request:req=42"


def test_no_destination_info_is_still_a_network_label_not_exec():
    for args in ({}, {"modifications": {}}, "not-a-dict", None):
        assert _t(args) == "strix:repeat_request"


# ---- other tools -----------------------------------------------------------------------------------

def test_web_search_names_the_external_service():
    assert _strix_target("web_search", {"query": "cve poc"}) == "strix:web_search:api.perplexity.ai:443"


def test_exec_tools_keep_the_local_sentinel():
    for name in ("exec_command", "write_stdin"):
        assert _strix_target(name, {"command": "id"}) == "strix:exec"


def test_unknown_tool_name_falls_back_to_the_conservative_sentinel():
    assert _strix_target("some_future_tool", {"x": 1}) == "strix:exec"
    assert _strix_target("", None) == "strix:exec"


# ---- distinctness & negative controls --------------------------------------------------------------

def test_distinct_destinations_get_distinct_labels():
    labels = {
        _t({"request_id": "r1"}),
        _t({"request_id": "r2"}),
        _t({"modifications": {"url": "http://a.example/"}}),
        _t({"modifications": {"url": "http://b.example/"}}),
    }
    assert len(labels) == 4, "distinct destinations collapsed to the same approval label"


def test_negative_control_a_network_tool_no_longer_binds_to_strix_exec():
    """Reverting _strix_target to the constant makes these fail."""
    assert _t({"request_id": "x"}) != "strix:exec"
    assert _strix_target("web_search", {}) != "strix:exec"


def test_negative_control_the_raw_url_is_not_the_label():
    """Proves canonicalisation is live: the raw URL (with its userinfo/query) never appears verbatim."""
    raw = "https://trusted.example@evil.example/p?token=leak"
    got = _t({"modifications": {"url": raw}})
    assert raw not in got and "leak" not in got and "trusted.example" not in got
