"""framework.v2.mcp.platform_tools — generate the PLATFORM MCP tool set from the ONE operation registry.

The *platform* MCP server advertises the CONSOLE/REST operations as role-gated MCP tools — one tool per
console GET read and per mapped POST action. (This is distinct from the capability EXPOSE server in
``server.py``, which advertises the ``agents.tools`` registry.) There is NO OpenAPI; the authoritative,
machine-readable tables are:

  * ``vigil_core.rbac.OFFENSE_ACTION_PERM`` — every state-changing POST route → a permission tier
    (``read`` / ``run_engagement`` / ``offense_authority``); ``offense_route_key``/``offense_perm_for``
    resolve a concrete path, DEFAULT-DENY for an unmapped route.
  * ``console.server._EXACT_ROUTES`` / ``_SCOPED_ROUTES`` / ``_PREFIX_ROUTES`` — the read (GET) registries.

This module is a PURE transform of those tables into MCP ``Tool`` descriptors. **It mints no authority.**
The descriptor's ``readOnly``/``destructive``/``idempotent`` hints are DISCLOSURE derived from the route's
own method and tier (advisory only — the gate, not the hint, enforces). The actual call (a later slice)
routes every invocation through the EXISTING console gate (``role_can(role, offense_perm_for(path))``) over
the authenticated ``vigil up`` proxy hop, so the MCP layer can never widen a role or bypass a gate.

Two invariants this module is built to keep, both asserted in ``tests/test_platform_tools.py`` (mirroring
the W17-14 orphan-route guard):

  1. NO DRIFT — the (method, route) pairs the tool list covers equal the registry routes EXACTLY, so a new
     route added without a tool (or a tool without a route) turns a test red.
  2. FAIL-CLOSED VISIBILITY — the default ``core`` profile NEVER advertises an owner-tier
     (``offense_authority``) operation; those appear only under an explicit ``full`` profile, and even then
     stay gated at owner at invocation. Profile controls visibility, never authority.

Pure stdlib + ``vigil_core.rbac`` (namespace-pure, no sigil/strix import); the read-route source is injected
with a default that imports the console registries lazily, so this module stays importable and unit-testable
without dragging in the whole console.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import quote

from vigil_core.rbac import OFFENSE_ACTION_PERM, offense_perm_for

# Permission tiers (the VALUES in OFFENSE_ACTION_PERM; kept as literals so we do not import rbac's private
# _READ/_RUN/_OWN constants). Reads (GET) are the viewer `read` tier and are NOT in OFFENSE_ACTION_PERM.
_PERM_READ = "read"
_PERM_RUN = "run_engagement"
_PERM_OWN = "offense_authority"

# Profiles → the permission tiers a profile is allowed to ADVERTISE. `core` is the safe default: reads +
# ordinary run actions, never an owner-tier (host-exec / infra / authority / patch-apply) operation. `full`
# adds the owner tier for an operator who deliberately opts in. Visibility only — every call is still gated.
_PROFILE_PERMS: dict[str, frozenset[str]] = {
    "core": frozenset({_PERM_READ, _PERM_RUN}),
    "full": frozenset({_PERM_READ, _PERM_RUN, _PERM_OWN}),
}
PROFILES = tuple(_PROFILE_PERMS)
DEFAULT_PROFILE = "core"

# Operations that are idempotent (repeating the call has the same effect as making it once). ADVISORY
# disclosure only — never a gate input. Authored per-route because neither the RBAC tier nor the WARDEN
# danger class encodes idempotency. Everything not listed defaults to NOT idempotent (the safe default:
# a client must assume a repeat may have an additional effect). All GET reads are idempotent by construction.
_IDEMPOTENT_POST_ROUTES = frozenset({
    "/api/token-budgets",          # sets the budget to a value (not a delta)
    "/api/killswitch/*/trip",      # tripping an already-tripped switch is a no-op
    "/api/emergency-stop",         # enter/status restricted mode (converges)
    "/api/panic",                  # hard-stop converges
    "/api/down",                   # contain converges
    "/api/posture/verify",         # offline re-verify, no state change beyond the report
    "/api/verify",                 # read-recompute
    "/api/verify-cert",            # read-recompute
    "/api/doctor",                 # read-only preflight
    "/api/daemons/status",         # read-only
    "/api/identity",               # read-only export
    "/api/destruction/status",     # read-only shape
    "/api/aegis/mode",             # sets a mode to a value (converges)
})

# Routes whose POST is destructive in the "changes the host / durable governance / infra" sense (the
# owner-tier dangerous class, plus any run-tier route that writes outside the engagement store). ADVISORY
# hint only. Owner-tier routes are destructive by definition; we also list the few run-tier writes that
# delete durable artifacts so the hint is honest. Everything else (ordinary run/launch/read-recompute) is
# non-destructive.
_DESTRUCTIVE_EXTRA_RUN_ROUTES = frozenset({
    "/api/session/delete",
    "/api/chat/delete",
})


def _op_id(method: str, route: str) -> str:
    """Deterministic, collision-resistant operationId: ``<method>_<path tokens>``. Drops the ``/api`` and
    ``/v1`` prefixes and every ``*`` wildcard segment (those become inputSchema path args), lowercases, and
    maps ``-``/``/`` → ``_``. The method prefix disambiguates a GET and a POST on the same path (e.g.
    ``/api/token-budgets`` → ``get_token_budgets`` and ``post_token_budgets``). Uniqueness across the whole
    set is asserted by the drift guard."""
    toks = [t for t in route.strip("/").split("/") if t and t != "*" and t not in ("api", "v1")]
    tail = "_".join(t.replace("-", "_") for t in toks) or "root"
    return f"{method.lower()}_{tail}"


def _wildcard_path_args(route: str) -> list[str]:
    """Name the ``*`` path args of a wildcard POST route by the segment that PRECEDES each (its resource),
    e.g. ``/api/run/*/cancel`` → ``["run_id"]``, ``/api/remediate/*/apply`` → ``["remediate_id"]``. A leading
    ``*`` (none today) would be ``arg``. Deterministic; used only to shape the inputSchema."""
    segs = [s for s in route.strip("/").split("/")]
    args: list[str] = []
    for i, s in enumerate(segs):
        if s == "*":
            prev = segs[i - 1] if i > 0 and segs[i - 1] not in ("api", "v1") else "arg"
            args.append(f"{prev.replace('-', '_')}_id" if prev != "arg" else "arg")
    return args


def _read_input_schema(kind: str) -> dict:
    """inputSchema for a GET read tool. ``exact`` = no args; ``scoped`` = one optional ``slug`` engagement
    filter; ``prefix`` = one required ``arg`` path segment."""
    if kind == "scoped":
        return {"type": "object",
                "properties": {"slug": {"type": "string", "description": "optional engagement slug filter"}},
                "additionalProperties": False}
    if kind == "prefix":
        return {"type": "object",
                "properties": {"arg": {"type": "string", "description": "the path argument (e.g. a run id or slug)"}},
                "required": ["arg"], "additionalProperties": False}
    return {"type": "object", "properties": {}, "additionalProperties": False}


def _post_input_schema(route: str) -> dict:
    """inputSchema for a POST action tool. Wildcard path args are required string properties; the request
    body is left open (``additionalProperties: true``) at this slice — the per-operation body shapes are
    pinned when invocation is wired, and the gate (not the schema) is the authority regardless."""
    props: dict = {}
    required: list[str] = []
    for a in _wildcard_path_args(route):
        props[a] = {"type": "string", "description": f"path argument '{a}'"}
        required.append(a)
    schema: dict = {"type": "object", "properties": props, "additionalProperties": True}
    if required:
        schema["required"] = required
    return schema


def _descriptor(method: str, route: str, perm: str, profile: str, schema_kind: str = "") -> dict:
    """Build one MCP ``Tool`` descriptor for a platform operation, matching the shape the capability EXPOSE
    server emits (``server.py:_descriptor``): name / description / inputSchema / advisory annotations /
    ``_meta.vigil`` gating disclosure. ``method`` is GET|POST; ``perm`` is the RBAC tier string."""
    is_get = method == "GET"
    op = _op_id(method, route)
    destructive = (not is_get) and (perm == _PERM_OWN or route in _DESTRUCTIVE_EXTRA_RUN_ROUTES)
    idempotent = is_get or (route in _IDEMPOTENT_POST_ROUTES)
    if is_get:
        schema = _read_input_schema(schema_kind)
        desc = f"Read the VIGIL console '{route}' resource (GET). Read-only; output is console data."
    else:
        schema = _post_input_schema(route)
        desc = f"Invoke the VIGIL console action '{route}' (POST). Gated at the '{perm}' permission tier."
    return {
        "name": op,
        "description": desc,
        "inputSchema": schema,
        "annotations": {
            "title": op,
            "readOnlyHint": is_get,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            # Platform ops run against the local console over the authenticated loopback hop — no open-world
            # egress of their own (any egress happens downstream inside an already-gated engagement).
            "openWorldHint": False,
        },
        "_meta": {"vigil": {
            "gated": True,
            "transport": "console-hop",
            "method": method,
            "route": route,
            "schema_kind": schema_kind,   # exact|scoped|prefix for GET; "" for POST (wildcard derived from route)
            "perm": perm,
            "profile": profile,
            # A platform operation's result is console data for the operator; it is NOT a confirmed FACT
            # (only a CRUCIBLE oracle mints facts). Kept parallel to the EXPOSE server's provenance note.
            "provenance": "console-operation",
        }},
    }


def _default_read_routes() -> dict[str, list[str]]:
    """Lazily import the console GET registries and return {kind: [routes]}. Imported here (not at module
    top) so ``platform_tools`` stays importable for unit tests without the full console dependency graph."""
    from framework.v2.console import server as _srv  # noqa: PLC0415 — lazy, offense-side only
    return {
        "exact": sorted(_srv._EXACT_ROUTES.keys()),
        "scoped": sorted(_srv._SCOPED_ROUTES.keys()),
        "prefix": sorted(_srv._PREFIX_ROUTES.keys()),
    }


def build_platform_tools(
    profile: str = DEFAULT_PROFILE,
    *,
    read_routes: Optional[dict[str, list[str]]] = None,
    action_perms: Optional[dict[str, str]] = None,
) -> list[dict]:
    """The platform MCP tool list for ``profile`` (default ``core``), sorted by name (deterministic).

    GET read routes (from the three console registries) are ``read``-tier, read-only tools. POST action
    routes (from ``OFFENSE_ACTION_PERM``) carry their mapped tier. A tool is ADVERTISED only if its tier is
    in the profile's permitted set — ``core`` never advertises an owner-tier (``offense_authority``)
    operation. Visibility only: every call is still gated at ``role_can(role, offense_perm_for(route))``.

    ``read_routes``/``action_perms`` are injectable for tests; the defaults read the live registries.
    """
    if profile not in _PROFILE_PERMS:
        raise ValueError(f"unknown profile {profile!r}; one of {PROFILES}")
    allowed = _PROFILE_PERMS[profile]
    routes = read_routes if read_routes is not None else _default_read_routes()
    perms = action_perms if action_perms is not None else OFFENSE_ACTION_PERM

    tools: list[dict] = []
    # GET reads — all `read` tier (so always in-profile), read-only, idempotent.
    for kind in ("exact", "scoped", "prefix"):
        for route in routes.get(kind, []):
            if _PERM_READ in allowed:
                tools.append(_descriptor("GET", route, _PERM_READ, profile, schema_kind=kind))
    # POST actions — carry their mapped tier; advertised only if the tier is in-profile.
    for route, perm in perms.items():
        if perm in allowed:
            tools.append(_descriptor("POST", route, perm, profile))

    tools.sort(key=lambda t: t["name"])
    return tools


def platform_tool_routes(
    *,
    read_routes: Optional[dict[str, list[str]]] = None,
    action_perms: Optional[dict[str, str]] = None,
) -> set[tuple[str, str]]:
    """The complete set of (method, route) pairs the platform tools cover at the WIDEST profile (``full``) —
    the canonical set the drift guard compares against the live registries. (method ∈ {GET, POST}.)"""
    tools = build_platform_tools("full", read_routes=read_routes, action_perms=action_perms)
    return {(t["_meta"]["vigil"]["method"], t["_meta"]["vigil"]["route"]) for t in tools}


def registry_routes(
    *,
    read_routes: Optional[dict[str, list[str]]] = None,
    action_perms: Optional[dict[str, str]] = None,
) -> set[tuple[str, str]]:
    """The (method, route) pairs the SOURCE registries declare — every GET read route + every POST action
    route. The drift guard asserts this equals ``platform_tool_routes()``; any divergence (a route with no
    tool, or a tool with no route) fails the test."""
    routes = read_routes if read_routes is not None else _default_read_routes()
    perms = action_perms if action_perms is not None else OFFENSE_ACTION_PERM
    out: set[tuple[str, str]] = set()
    for kind in ("exact", "scoped", "prefix"):
        for route in routes.get(kind, []):
            out.add(("GET", route))
    for route in perms:
        out.add(("POST", route))
    return out


# Public alias — the server renders wildcard path args from the route.
wildcard_path_args = _wildcard_path_args


def render_console_request(descriptor: dict, arguments: Optional[dict]) -> dict:
    """PURE: map a platform tool descriptor + the caller's ``arguments`` to a concrete console HTTP request
    ``{method, path, query, body}``.

    The ROUTE IS FIXED BY THE DESCRIPTOR (i.e. by the tool name), NEVER by arguments — arguments only fill
    the DECLARED path args (the ``*`` wildcards and the GET prefix/scoped slot) and the POST body. Every
    path arg is URL-encoded with ``safe=""`` so a value like ``../../x`` cannot inject extra path segments
    or escape the route (the server-fixed-scope discipline, mirroring the EXPOSE server's fixed slug). A
    missing required path arg raises ``ValueError`` (fail-closed) — the server turns that into a refusal,
    never a malformed request to the gate.
    """
    meta = descriptor["_meta"]["vigil"]
    method = meta["method"]
    route = meta["route"]
    kind = meta.get("schema_kind", "")
    args = dict(arguments or {})
    query: dict[str, str] = {}
    body: Optional[dict] = None
    name = descriptor.get("name", route)

    if method == "GET":
        if kind == "scoped":
            slug = args.get("slug")
            if slug is not None and str(slug).strip():
                query["slug"] = str(slug)
            path = route
        elif kind == "prefix":
            arg = args.get("arg")
            if arg is None or not str(arg).strip():
                raise ValueError(f"{name}: path argument 'arg' is required")
            path = route + quote(str(arg), safe="")
        else:  # exact
            path = route
    else:  # POST
        path = route
        for argname in wildcard_path_args(route):
            val = args.pop(argname, None)
            if val is None or not str(val).strip():
                raise ValueError(f"{name}: path argument {argname!r} is required")
            path = path.replace("*", quote(str(val), safe=""), 1)
        if "*" in path:  # defensive: an unfilled wildcard must never reach the gate
            raise ValueError(f"{name}: unresolved path wildcard after rendering")
        body = args  # whatever remains is the JSON request body

    return {"method": method, "path": path, "query": query, "body": body}


def resolves_through_gate(route: str) -> bool:
    """True iff a POST ``route`` resolves to a non-None permission via the REAL ``offense_perm_for`` — i.e.
    the existing console gate will recognise and gate it. Used by the conformance test to prove every POST
    tool the platform server advertises lands on the authoritative gate (never a route the gate would
    DEFAULT-DENY as unmapped, which would be an unreachable/mis-declared tool)."""
    return offense_perm_for(route) is not None
