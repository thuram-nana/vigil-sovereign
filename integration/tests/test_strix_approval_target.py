"""S4 slice 2 — a gated network tool's approval binds to its real destination, not the "strix:exec" sentinel.

THE GAP (verified). ``_strix_target`` returned the constant ``"strix:exec"`` for EVERY gated tool, including
``repeat_request`` — which sends attacker-MODIFIED traffic to a URL. ``repeat_request(request_id,
modifications)`` resolves its destination from the referenced captured request overlaid with an OPTIONAL
``modifications.url``; when no url override is given, the destination host is not in the args at all — only
the ``request_id`` is. So an owner asked to approve a ``repeat_request`` saw ``target: strix:exec`` and a bare
request-id, blind to which HOST they were authorizing an attack against. (The single-use token was already
bound to the request via the digest over ``args``; the missing piece is the owner SEEING the destination.)

THE FIX. ``_strix_target(tool_name, args)`` resolves a real destination label: the overridden URL, else the
specific request-id, for ``repeat_request``; the external-egress label for ``web_search``; and the honest
local sentinel only for the shell/exec tools that genuinely have no single network destination.
"""
from __future__ import annotations

from vigil_integration.warden_gate import _strix_target


def test_repeat_request_with_a_url_override_binds_to_that_url():
    args = {"request_id": "abc123", "modifications": {"url": "http://target.example/admin"}}
    assert _strix_target("repeat_request", args) == "strix:repeat_request:http://target.example/admin"


def test_repeat_request_without_a_url_binds_to_the_referenced_request_id():
    args = {"request_id": "abc123", "modifications": {"method": "POST"}}
    assert _strix_target("repeat_request", args) == "strix:repeat_request:req=abc123"


def test_repeat_request_with_no_destination_info_is_still_not_the_exec_sentinel():
    # empty / unparseable args must not silently collapse to "strix:exec" (the old bug) — it stays a
    # network-tool label so the owner is never told a network call is a local exec.
    for args in ({}, {"modifications": {}}, "not-a-dict", None, {"modifications": "x"}):
        assert _strix_target("repeat_request", args) == "strix:repeat_request"


def test_repeat_request_integer_request_id():
    assert _strix_target("repeat_request", {"request_id": 42}) == "strix:repeat_request:req=42"


def test_web_search_binds_to_the_external_egress_not_the_target():
    assert _strix_target("web_search", {"query": "cve poc"}) == "strix:web_search"


def test_exec_tools_keep_the_local_sentinel():
    for name in ("exec_command", "write_stdin"):
        assert _strix_target(name, {"command": "id"}) == "strix:exec"


def test_two_different_repeat_request_destinations_get_distinct_labels():
    """The owner must be able to tell two pending repeat_request approvals apart by destination."""
    a = _strix_target("repeat_request", {"request_id": "r1"})
    b = _strix_target("repeat_request", {"request_id": "r2"})
    c = _strix_target("repeat_request", {"modifications": {"url": "http://a.example/"}})
    d = _strix_target("repeat_request", {"modifications": {"url": "http://b.example/"}})
    assert len({a, b, c, d}) == 4, "distinct destinations collapsed to the same approval label"


def test_negative_control_a_network_tool_no_longer_binds_to_strix_exec():
    """Proves the fix is live: reverting _strix_target to the constant makes this assertion fail."""
    assert _strix_target("repeat_request", {"request_id": "x"}) != "strix:exec"
    assert _strix_target("web_search", {}) != "strix:exec"


def test_unknown_gated_name_falls_back_to_the_conservative_sentinel():
    # a name we don't special-case (should not happen for the current gated set, but be safe) still yields a
    # stable non-empty label rather than crashing.
    assert _strix_target("some_future_tool", {"x": 1}) == "strix:exec"
    assert _strix_target("", None) == "strix:exec"
