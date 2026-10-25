"""
Tests for the PLATFORM MCP tool generator (mcp.platform_tools).

The platform tool list is GENERATED from the one authoritative operation registry — ``OFFENSE_ACTION_PERM``
(POST tiers) + the console GET read registries — so it cannot drift from the routes by construction. These
tests pin that, plus the two load-bearing safety invariants:

  * NO DRIFT — the (method, route) pairs the tools cover equal the registry routes EXACTLY (a route with no
    tool, or a tool with no route, fails). Mirrors the W17-14 orphan-route guard; the complementary
    OFFENSE_ACTION_PERM ↔ do_POST completeness is guarded separately by test_offense_rbac.py.
  * THE HINT CANNOT LIE ABOUT THE GATE — every POST tool's declared tier EQUALS the authoritative
    ``offense_perm_for(route)`` that the real console gate turns on, and every POST tool's route actually
    resolves through that gate (never a DEFAULT-DENY unmapped route).
  * FAIL-CLOSED VISIBILITY — the default ``core`` profile never advertises an owner-tier operation.
"""

from __future__ import annotations

import pytest

from vigil_core.rbac import offense_perm_for
from framework.v2.mcp import platform_tools as pt

# A small injected registry fixture — one GET of each kind + one POST of each tier — for deterministic
# logic tests that need no console import.
_FAKE_READ = {"exact": ["/api/status"], "scoped": ["/api/runs"], "prefix": ["/api/report/"]}
_FAKE_PERMS = {
    "/api/instruct": "run_engagement",
    "/api/killswitch/*/trip": "read",
    "/api/terminal/run": "offense_authority",
}


# ---- drift guard (injected + real) ------------------------------------------------------------------

def test_drift_guard_injected() -> None:
    cover = pt.platform_tool_routes(read_routes=_FAKE_READ, action_perms=_FAKE_PERMS)
    decl = pt.registry_routes(read_routes=_FAKE_READ, action_perms=_FAKE_PERMS)
    assert cover == decl
    # explicit: every fixture route is present exactly once, under the right method
    assert cover == {
        ("GET", "/api/status"), ("GET", "/api/runs"), ("GET", "/api/report/"),
        ("POST", "/api/instruct"), ("POST", "/api/killswitch/*/trip"), ("POST", "/api/terminal/run"),
    }


def test_drift_guard_real_registries() -> None:
    """The generator covers EXACTLY the live registry routes — no route silently missing a tool, no tool
    for a route that does not exist. Imports the real console registries + OFFENSE_ACTION_PERM."""
    assert pt.platform_tool_routes() == pt.registry_routes()


# ---- the hint cannot lie about the gate -------------------------------------------------------------

def test_every_post_tool_tier_equals_the_authoritative_gate() -> None:
    """A POST tool's declared tier (which drives its hint + profile) is the SAME permission the real gate
    (offense_perm_for) enforces — so the MCP disclosure can never misrepresent the gate."""
    for t in pt.build_platform_tools("full"):
        meta = t["_meta"]["vigil"]
        if meta["method"] != "POST":
            continue
        route = meta["route"]
        assert pt.resolves_through_gate(route), f"{route} does not resolve through offense_perm_for (unmapped → deny)"
        assert meta["perm"] == offense_perm_for(route), f"{route}: tool tier {meta['perm']!r} != gate {offense_perm_for(route)!r}"


def test_get_tools_are_read_tier() -> None:
    for t in pt.build_platform_tools("full"):
        if t["_meta"]["vigil"]["method"] == "GET":
            assert t["_meta"]["vigil"]["perm"] == "read"


# ---- fail-closed visibility -------------------------------------------------------------------------

def test_core_profile_hides_owner_tier() -> None:
    core = pt.build_platform_tools("core", read_routes=_FAKE_READ, action_perms=_FAKE_PERMS)
    assert all(t["_meta"]["vigil"]["perm"] != "offense_authority" for t in core)
    # the owner-tier terminal/run is present only under full
    full = pt.build_platform_tools("full", read_routes=_FAKE_READ, action_perms=_FAKE_PERMS)
    assert any(t["_meta"]["vigil"]["route"] == "/api/terminal/run" for t in full)
    assert not any(t["_meta"]["vigil"]["route"] == "/api/terminal/run" for t in core)


def test_core_profile_hides_owner_tier_on_real_registries() -> None:
    core = pt.build_platform_tools("core")
    assert all(t["_meta"]["vigil"]["perm"] != "offense_authority" for t in core), \
        "core profile must never advertise an owner-tier (offense_authority) operation"
    # and the real registry DOES have owner-tier ops, exposed only under full (proves the filter does work)
    full = pt.build_platform_tools("full")
    assert any(t["_meta"]["vigil"]["perm"] == "offense_authority" for t in full)


def test_core_is_a_strict_subset_of_full() -> None:
    core = {t["name"] for t in pt.build_platform_tools("core")}
    full = {t["name"] for t in pt.build_platform_tools("full")}
    assert core < full
    assert core == {n for n in full}.intersection(core)  # no core tool absent from full


def test_default_profile_is_core() -> None:
    assert pt.DEFAULT_PROFILE == "core"
    assert {t["name"] for t in pt.build_platform_tools()} == {t["name"] for t in pt.build_platform_tools("core")}


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError):
        pt.build_platform_tools("superuser")


# ---- hint / descriptor shape ------------------------------------------------------------------------

def test_get_tools_are_readonly_idempotent_nondestructive() -> None:
    for t in pt.build_platform_tools("full"):
        if t["_meta"]["vigil"]["method"] == "GET":
            a = t["annotations"]
            assert a["readOnlyHint"] is True
            assert a["idempotentHint"] is True
            assert a["destructiveHint"] is False
            assert a["openWorldHint"] is False


def test_owner_tier_posts_are_destructive_hinted() -> None:
    owner_posts = [t for t in pt.build_platform_tools("full")
                   if t["_meta"]["vigil"]["method"] == "POST" and t["_meta"]["vigil"]["perm"] == "offense_authority"]
    assert owner_posts  # the real registry has some
    for t in owner_posts:
        assert t["annotations"]["destructiveHint"] is True
        assert t["annotations"]["readOnlyHint"] is False


def test_operation_ids_are_unique() -> None:
    names = [t["name"] for t in pt.build_platform_tools("full")]
    assert len(names) == len(set(names)), "operationId collision in the platform tool set"


def test_op_id_scheme() -> None:
    # deterministic method_path tokens; wildcard + /api + /v1 dropped
    assert pt._op_id("GET", "/api/status") == "get_status"
    assert pt._op_id("POST", "/api/run/*/cancel") == "post_run_cancel"
    assert pt._op_id("POST", "/api/remediate/*/apply-local") == "post_remediate_apply_local"
    assert pt._op_id("POST", "/api/v1/tool/invoke") == "post_tool_invoke"
    assert pt._op_id("POST", "/api/killswitch/*/trip") == "post_killswitch_trip"
    # a GET and POST on the same path do not collide
    assert pt._op_id("GET", "/api/token-budgets") != pt._op_id("POST", "/api/token-budgets")


def test_wildcard_path_args_named_by_resource() -> None:
    assert pt._wildcard_path_args("/api/run/*/cancel") == ["run_id"]
    assert pt._wildcard_path_args("/api/remediate/*/apply") == ["remediate_id"]
    assert pt._wildcard_path_args("/api/status") == []


# ---- render_console_request (pure: route+args -> console request; NO /offense here, the server adds it) --

def _desc(name: str) -> dict:
    return {t["name"]: t for t in pt.build_platform_tools("full")}[name]


def test_render_get_exact() -> None:
    assert pt.render_console_request(_desc("get_status"), {}) == {
        "method": "GET", "path": "/api/status", "query": {}, "body": None}


def test_render_get_scoped_slug_to_query() -> None:
    r = pt.render_console_request(_desc("get_runs"), {"slug": "x"})
    assert r["method"] == "GET" and r["path"] == "/api/runs" and r["query"] == {"slug": "x"}
    # absent slug -> no query (the unscoped listing)
    assert pt.render_console_request(_desc("get_runs"), {})["query"] == {}


def test_render_get_prefix_appends_arg() -> None:
    assert pt.render_console_request(_desc("get_report"), {"arg": "run1"})["path"] == "/api/report/run1"


def test_render_post_wildcard_and_body() -> None:
    r = pt.render_console_request(_desc("post_run_cancel"), {"run_id": "r1", "extra": 1})
    assert r["method"] == "POST" and r["path"] == "/api/run/r1/cancel" and r["body"] == {"extra": 1}
    assert "*" not in r["path"]


def test_render_rejects_dotdot_and_dot() -> None:
    for args in ({"run_id": ".."}, {"run_id": "."}):
        with pytest.raises(ValueError):
            pt.render_console_request(_desc("post_run_cancel"), args)
    with pytest.raises(ValueError):
        pt.render_console_request(_desc("get_report"), {"arg": ".."})


def test_render_missing_required_arg_raises() -> None:
    with pytest.raises(ValueError):
        pt.render_console_request(_desc("post_run_cancel"), {})
    with pytest.raises(ValueError):
        pt.render_console_request(_desc("get_report"), {})


def test_descriptor_shape_is_complete() -> None:
    for t in pt.build_platform_tools("full"):
        assert set(t) >= {"name", "description", "inputSchema", "annotations", "_meta"}
        assert t["inputSchema"]["type"] == "object"
        m = t["_meta"]["vigil"]
        assert set(m) >= {"gated", "transport", "method", "route", "perm", "profile", "provenance"}
        assert m["gated"] is True
        assert m["transport"] == "console-hop"
        assert m["method"] in ("GET", "POST")
        assert m["provenance"] == "console-operation"
