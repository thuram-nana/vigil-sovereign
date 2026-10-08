"""The living UI WIRING GUARD (prod/ui-wiring-guard, slice 1.1).

Makes "every button maps to a live route, every route is UI-driven or intentionally headless" a
durable, drift-failing test. It parses SOURCE AS TEXT (regex over the real files) and imports NOTHING
from ``framework``/``strix``/the sovereign code — it is pure stdlib, so it runs in either venv and
pins nothing it is supposed to be auditing.

What it does:

  (a) EXTRACTS every backend call the unified UI (``packages/vigil-ui/app.js``) makes: every
      ``SOV("...")`` / ``OFF("...")`` path, every bare ``/api/...`` / ``/__vigil/plane/...`` string
      literal (the ceremony helpers pass the path as an argument), and every ``POST /api/action``
      action-name (the sigil action funnel).

  (b) EXTRACTS every registered backend route from the three route tables the uiproxy federates:
        * console  (engine/crucible/framework/v2/console/server.py):  _EXACT_ROUTES / _SCOPED_ROUTES /
          _PREFIX_ROUTES / _CHAT_ATTACH_POST  +  the inline do_GET/do_POST ``path ==`` / ``startswith``
          strings.
        * sigil    (apps/sigil/sigil/ui/server.py):  the inline _do_GET/_do_POST ``path ==`` /
          ``startswith`` / ``path in (...)`` strings, the _BODY_PATHS ceremony set, the local
          _DESTRUCTIVE / _READS ceremony dicts, AND the ``POST /api/action`` funnel's CLOSED verb set
          (apps/sigil/sigil/ui/actions.py ``ACTIONS``).
        * gated-api (engine/crucible/framework/v2/api/server.py):  _EXACT_GET / _PREFIX_GET  +  the
          inline do_GET/do_POST ``f"{_API}/..."`` strings.
      The uiproxy's own plane-local routes (/__vigil/plane/*) are read from
      integration/vigil_integration/uiproxy.py.

  (c) ASSERTS set-containment BOTH WAYS:
        * every UI call resolves to a registered route            (a FAIL here is a DEAD BUTTON)
        * every registered route is either UI-driven OR listed    (a FAIL here is an un-allowlisted
          in an explicit allowlist constant below                  ORPHAN route)
      The same two assertions apply to the action-funnel verb set.

  (d) REGENERATES + DIFFS a matrix artifact (docs/capability-matrix/ui-wiring-matrix.json). A change
      to any button or route changes the artifact, and the diff fails until the artifact is
      regenerated (set ``VIGIL_UIWIRING_REGEN=1`` to rewrite it in place), so the matrix cannot
      silently rot.

  (e) SELF-TEST: feeds the REAL extractors + checkers a PLANTED fixture string containing a dead button
      and an un-allowlisted orphan, and proves the guard FLAGS both (no real edit to any file).

Scope note — what is deliberately EXCLUDED from the route set (not :8770 routes):
  the phone bridge (apps/sigil/sigil/bridge/server.py), the MCP stdio server, and the egress gateway
  are NOT proxied by the uiproxy, so they are not UI-reachable routes and are out of scope here.

Containment is PATH-based (a "route" is a path); HTTP method is recorded in the matrix as advisory
metadata only (best-effort from the fetch wrapper / enclosing handler), never asserted — so a method
mislabel never turns a live wiring into a false DEAD-BUTTON/ORPHAN failure.

Run (static, no stack):
  .venv-offense/bin/python -m pytest -q integration/tests/test_ui_wiring_matrix.py
"""
from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path


# --------------------------------------------------------------------------------------------------
# Repo layout
# --------------------------------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
APP_JS = ROOT / "packages" / "vigil-ui" / "app.js"
UIPROXY = ROOT / "integration" / "vigil_integration" / "uiproxy.py"
CONSOLE = ROOT / "engine" / "crucible" / "framework" / "v2" / "console" / "server.py"
SIGIL = ROOT / "apps" / "sigil" / "sigil" / "ui" / "server.py"
SIGIL_ACTIONS = ROOT / "apps" / "sigil" / "sigil" / "ui" / "actions.py"
GATED = ROOT / "engine" / "crucible" / "framework" / "v2" / "api" / "server.py"
MATRIX = ROOT / "docs" / "capability-matrix" / "ui-wiring-matrix.json"

# Plane labels (the four distinct backends the uiproxy federates).
P_SOV = "sovereign"          # /sovereign/*   -> sigil cockpit  (127.0.0.1:8733)
P_CONSOLE = "offense-console"  # /offense/*      -> console       (127.0.0.1:8787)
P_API = "offense-api"        # /offense/api/v1/* -> gated-api    (127.0.0.1:8799)
P_PLANE = "plane-local"      # /__vigil/plane/* -> proxy-local (never forwarded)

# A string literal is a backend path iff it starts with one of these namespaces.
_NS = ("/api/", "/__vigil/", "/healthz", "/readyz", "/metrics", "/static/")
# Dispatch GUARDS and placeholders that look like routes but are not endpoints.
_NON_ROUTE = {"/api/", "/api", "/", "/sovereign", "/offense", "/static/x"}

GATED_API_PREFIX = "/api/v1"   # the whole gated-api plane lives under this upstream prefix


# ==================================================================================================
# INTENTIONALLY_HEADLESS  — a registered route with NO UI caller, BY DESIGN. One line of reason each.
# A route here is exempt from the "every route is UI-driven" assertion. It is the living ledger of
# "this really has no button, and here is why" — adding a route without a button forces a decision
# HERE rather than letting it rot unnoticed.
# ==================================================================================================
INTENTIONALLY_HEADLESS = {
    # The ENTIRE gated-api :8799 /api/v1/* plane is programmatic (MCP / scripted clients); it has zero
    # UI callers by design. Encoded as a plane rule below (HEADLESS_PLANES), not path-by-path.
    #
    # sigil programmatic cockpit endpoints — documented no-UI (apps/sigil/.../ui/server.py ~546-550,
    # docs/decisions/W17-14): the owner's scripted query/dispatch surface, no affordance in app.js.
    (P_SOV, "/api/ask"): "programmatic cockpit query endpoint (no app.js affordance; W17-14)",
    (P_SOV, "/api/graph"): "programmatic world-graph read (no app.js affordance; W17-14)",
    (P_SOV, "/api/graph/entity"): "programmatic graph-entity read (no app.js affordance; W17-14)",
    (P_SOV, "/api/classify"): "programmatic tool-classify endpoint (no app.js affordance; W17-14)",
    (P_SOV, "/api/record/"): "programmatic per-record spine fetch /api/record/<seq> (documented no-UI)",
    # proxy plane-local owner edge: revoke an authenticated edge by hand; CLI/owner-only, never a button.
    (P_PLANE, "/__vigil/plane/auth/purge"): "owner edge-revoke, CLI/hand only (no UI by design)",
}

# Whole planes that are headless by design (every route on them is exempt).
HEADLESS_PLANES = {
    P_API: "the gated-api :8799 /api/v1/* plane is programmatic/MCP — zero UI callers by design",
}

# Infra probes / static assets served BEFORE auth+routing: liveness, readiness, metrics, static JS/CSS.
# Not buttons; exempt on every plane.
INFRA_PATHS = {"/healthz", "/readyz", "/metrics", "/static/"}

# Action-funnel VERBS (POST /api/action) that are registered server-side but have no app.js caller,
# BY DESIGN — driven from the offense plane / CLI / tests, not the unified cockpit UI.
INTENTIONALLY_HEADLESS_VERBS = {
    "target_add": "live-external target authorization — owner-signed from the offense plane bridge/CLI, no app.js button",
    "target_list": "live-external target listing — programmatic/offense-plane read, no app.js button",
    "target_authority_status": "live-external target authority status — programmatic/offense-plane read, no app.js button",
}

# ==================================================================================================
# PENDING_UI_WIRING  — registered routes/verbs that WILL be UI-driven; slice 1.3 is adding the caller.
# These are NOT headless: they are treated as UI-driven (post-merge). Tracked separately so the ledger
# never mislabels an in-flight wiring as "intentionally no button".
# ==================================================================================================
_SLICE13 = "slice 1.3 adds the UI caller — UI-driven post-merge, not headless"
PENDING_UI_WIRING = {
    (P_SOV, "/api/ceremonies/eval-grant/status"): _SLICE13,
    (P_SOV, "/api/ceremonies/eval-grant/arm"): _SLICE13,
    (P_SOV, "/api/ceremonies/eval-grant/revoke"): _SLICE13,
    (P_SOV, "/api/logout"): _SLICE13,
}
PENDING_UI_WIRING_VERBS = {
    "revoke_webauthn": _SLICE13,
}


# ==================================================================================================
# Extraction — UI (app.js), pure text
# ==================================================================================================
def _strip_query(p: str) -> str:
    return p.split("?", 1)[0]


def _is_backend_path(lit: str) -> bool:
    return any(lit == ns or lit.startswith(ns) for ns in _NS) or lit in ("/healthz", "/readyz", "/metrics")


# A call wrapped directly in a fetch helper: method is inferable.
_WRAPPED = re.compile(r'\b(getJSON|postJSON|sse|authUrl|uploadChunked)\(\s*(SOV|OFF)\(\s*"([^"]+)"')
_SOV = re.compile(r'\bSOV\(\s*"([^"]+)"')
_OFF = re.compile(r'\bOFF\(\s*"([^"]+)"')
_PLANE_LIT = re.compile(r'"(/__vigil/plane[^"]*)"')
_BARE_LIT = re.compile(r'"(/api/[^"]*)"')

_METHOD = {"getJSON": "GET", "sse": "GET", "authUrl": "GET", "postJSON": "POST", "uploadChunked": "POST"}


def extract_ui_calls(src: str):
    """Return a sorted list of {plane, method, path} for every backend call app.js makes.

    SOV("x") -> sovereign; OFF("x") -> offense-console (or offense-api when x is under /api/v1);
    "/__vigil/plane/*" -> plane-local; any other bare "/api/..." literal (the ceremony helpers take
    the path as an argument) -> plane inferred later by resolution (recorded as "?")."""
    calls = {}   # (plane, path) -> method

    def add(plane, path, method):
        path = _strip_query(path)
        if not path or path in _NON_ROUTE:
            return
        key = (plane, path)
        prev = calls.get(key)
        # keep a concrete method over ANY if we learn one
        if prev is None or (prev == "ANY" and method != "ANY"):
            calls[key] = method

    methoded = {}  # (helper-tag, path) already captured with a concrete method
    for m in _WRAPPED.finditer(src):
        helper, wrap, path = m.group(1), m.group(2), m.group(3)
        plane = P_SOV if wrap == "SOV" else (P_API if _strip_query(path).startswith(GATED_API_PREFIX) else P_CONSOLE)
        methoded[(wrap, _strip_query(path))] = _METHOD.get(helper, "ANY")
        add(plane, path, _METHOD.get(helper, "ANY"))

    for m in _SOV.finditer(src):
        path = m.group(1)
        add(P_SOV, path, methoded.get(("SOV", _strip_query(path)), "ANY"))
    for m in _OFF.finditer(src):
        path = m.group(1)
        plane = P_API if _strip_query(path).startswith(GATED_API_PREFIX) else P_CONSOLE
        add(plane, path, methoded.get(("OFF", _strip_query(path)), "ANY"))
    for m in _PLANE_LIT.finditer(src):
        add(P_PLANE, m.group(1), "ANY")

    # Bare "/api/..." literals NOT wrapped in SOV()/OFF() (ceremony/read helpers take the path as an
    # argument). Plane unknown here -> recorded as "?" and resolved against the union at check time.
    wrapped_paths = {_strip_query(p) for (_w, p) in methoded}
    sov_off_paths = {_strip_query(m.group(1)) for m in _SOV.finditer(src)} | {_strip_query(m.group(1)) for m in _OFF.finditer(src)}
    for m in _BARE_LIT.finditer(src):
        path = _strip_query(m.group(1))
        if path in _NON_ROUTE:
            continue
        if path in wrapped_paths or path in sov_off_paths:
            continue
        add("?", path, "ANY")

    return [{"plane": pl, "method": mth, "path": pa} for (pl, pa), mth in sorted(calls.items())]


# --- UI action-funnel verbs -----------------------------------------------------------------------
_SETTINGS_ACT = re.compile(r'settingsAct\(\s*\{\s*action:\s*"([a-z_]+)"')
_ACTION_POST = re.compile(r'postJSON\(\s*SOV\(\s*"/api/action"\s*\)\s*,\s*\{\s*action:\s*"([a-z_]+)"')
_ACTION_CONCAT = re.compile(r'action:\s*"([a-z_]+_)"\s*\+')   # dynamic:  action: "disable_" + name
_ANY_ACTION = re.compile(r'action:\s*"([a-z_]+)"')            # every action: "X" body field in app.js


def extract_ui_action_verbs(src: str):
    """Return (inline_verbs, all_action_literals, prefix_verbs).

    * ``inline_verbs``  — action-names posted to the funnel through an INLINE object literal
      (``settingsAct({action:"X"})`` / ``postJSON(SOV("/api/action"),{action:"X"})``). These are
      DEFINITELY funnel-bound, so the dead-button direction (UI verb must exist in ACTIONS) is checked
      against this narrow, certain set — a non-funnel body field can never create a false DEAD verb.
    * ``all_action_literals`` — EVERY ``action: "X"`` literal in app.js (a superset that also catches
      verbs posted through a payload VARIABLE, e.g. ``var payload = {action:"set_cloud_file_secret"}``;
      used only for the orphan direction, where a literal that equals a real ACTIONS member is strong
      evidence that verb is UI-driven).
    * ``prefix_verbs`` — verbs built at runtime as ``"disable_" + which``; resolve to any ACTIONS
      member that starts with the prefix."""
    inline = set()
    for rx in (_SETTINGS_ACT, _ACTION_POST):
        inline |= set(rx.findall(src))
    prefix = set(_ACTION_CONCAT.findall(src))
    inline -= prefix                # "disable_" is a prefix, not a literal verb
    all_literals = set(_ANY_ACTION.findall(src)) - prefix
    return inline, all_literals, prefix


# ==================================================================================================
# Extraction — backend route tables, pure text
# ==================================================================================================
_DICT_KEY = re.compile(r'"(/(?:api|__vigil)/[^"]*|/healthz|/readyz|/metrics|/static/[^"]*)"\s*:')
_PATH_EQ = re.compile(r'path\s*==\s*"([^"]+)"')
_PATH_SW = re.compile(r'path\.startswith\(\s*"([^"]+)"')
_PATH_IN = re.compile(r'path\s+in\s+\(([^)]*)\)')
_IN_LITS = re.compile(r'"([^"]+)"')
_FAPI = re.compile(r'f"\{_API\}([^"]*)"')
_PLANE_CONST = re.compile(r'PLANE_[A-Z_]+_PATH\s*=\s*PLANE_BASE\s*\+\s*"([^"]+)"')


def _accept(lit: str):
    lit = _strip_query(lit)
    if "<" in lit or not lit:
        return None
    if lit in _NON_ROUTE:
        return None
    if lit.startswith("/static/"):
        return "/static/"            # normalise any static asset to the infra bucket
    if not _is_backend_path(lit):
        return None
    return lit


def _method_for_line(lines, idx, module_dicts):
    """Best-effort HTTP method for a route literal found on line ``idx`` (advisory only)."""
    # module-level route dicts: method decided by the dict's name.
    for (start, end, method) in module_dicts:
        if start <= idx <= end:
            return method
    for j in range(idx, -1, -1):
        s = lines[j].lstrip()
        if s.startswith("def "):
            name = s[4:].split("(", 1)[0].lower()
            if "post" in name:
                return "POST"
            if "get" in name:
                return "GET"
            # a non-dispatch helper: keep scanning outward
    return "GET"


def _module_dict_regions(lines):
    """Spans of module-level route-table dict/tuple literals -> method, by the assigned name."""
    regions = []
    open_name = None
    open_start = None
    depth = 0
    for i, line in enumerate(lines):
        if open_name is None:
            m = re.match(r'\s*([A-Z_][A-Z0-9_]*)\s*=\s*[\{\(]', line)
            if m and ("ROUTE" in m.group(1) or "POST" in m.group(1) or "PATHS" in m.group(1)
                      or m.group(1).endswith("_GET")):
                open_name = m.group(1)
                open_start = i
                depth = line.count("{") + line.count("(") - line.count("}") - line.count(")")
                if depth <= 0:
                    method = "POST" if "POST" in open_name else "GET"
                    regions.append((open_start, i, method))
                    open_name = None
        else:
            depth += line.count("{") + line.count("(") - line.count("}") - line.count(")")
            if depth <= 0:
                method = "POST" if "POST" in open_name else "GET"
                regions.append((open_start, i, method))
                open_name = None
    return regions


def extract_backend_routes(src: str, plane: str):
    """Return (routes, prefix_set). ``routes`` maps path -> {"method": .., "kind": exact|prefix}."""
    lines = src.splitlines()
    module_dicts = _module_dict_regions(lines)
    routes = {}
    prefix_set = set()

    def put(lit, idx, is_prefix):
        acc = _accept(lit)
        if acc is None:
            return
        method = _method_for_line(lines, idx, module_dicts)
        is_pref = is_prefix or acc.endswith("/")
        if is_pref:
            prefix_set.add(acc)
        prev = routes.get(acc)
        kind = "prefix" if is_pref else "exact"
        if prev is None:
            routes[acc] = {"method": method, "kind": kind}
        else:
            if kind == "prefix":
                prev["kind"] = "prefix"

    for i, line in enumerate(lines):
        for m in _DICT_KEY.finditer(line):
            # a _PREFIX_* dict key, or a key that ends in "/", is a prefix route.
            put(m.group(1), i, is_prefix=False)
        for m in _PATH_EQ.finditer(line):
            put(m.group(1), i, is_prefix=False)
        for m in _PATH_SW.finditer(line):
            put(m.group(1), i, is_prefix=True)     # startswith => prefix route
        for m in _PATH_IN.finditer(line):
            for lit in _IN_LITS.findall(m.group(1)):
                put(lit, i, is_prefix=False)
        for m in _FAPI.finditer(line):
            put(GATED_API_PREFIX + m.group(1), i, is_prefix=False)

    # NB: _PREFIX_ROUTES / _PREFIX_GET keys already end in "/", so put()'s endswith check marks them
    # as prefix routes without special-casing the dict name.
    return routes, prefix_set


def extract_plane_routes(src: str):
    base = "/__vigil/plane"
    routes = {base + suf: {"method": "ANY", "kind": "exact"} for suf in _PLANE_CONST.findall(src)}
    return routes


def extract_action_verbs(src: str):
    """The sigil action funnel's CLOSED verb set: the members of the ``ACTIONS`` frozenset union."""
    verbs = set()
    for m in re.finditer(r'frozenset\(\{([^}]*)\}\)', src):
        verbs |= set(re.findall(r'"([a-z_]+)"', m.group(1)))
    return verbs


# ==================================================================================================
# Resolution (PATH-based)
# ==================================================================================================
def _path_match(upath: str, rpath: str, rprefix: bool) -> bool:
    if upath == rpath:
        return True
    if rprefix and upath.startswith(rpath):
        return True
    # the UI passed a prefix literal (ends "/") and the route is a leaf under it
    if upath.endswith("/") and rpath.startswith(upath):
        return True
    return False


def _ui_resolves(call, routes_by_plane, prefix_by_plane):
    """Does one UI call resolve to >=1 registered route? (dead-button check)."""
    up, upath = call["plane"], call["path"]
    planes = routes_by_plane.keys() if up == "?" else [up]
    for pl in planes:
        for rpath, meta in routes_by_plane.get(pl, {}).items():
            if _path_match(upath, rpath, meta["kind"] == "prefix"):
                return True
    return False


def _route_driven(plane, rpath, rprefix, ui_calls):
    """Is a registered route covered by >=1 UI call? (orphan check)."""
    for c in ui_calls:
        if c["plane"] != "?" and c["plane"] != plane:
            continue
        up = c["path"]
        if up == rpath:
            return True
        if rprefix and up.startswith(rpath):
            return True
        if up.endswith("/") and rpath.startswith(up):   # UI prefix drives the leaf below it
            return True
    return False


# ==================================================================================================
# Build the whole model once (used by every test)
# ==================================================================================================
def build_model():
    app_src = APP_JS.read_text(encoding="utf-8", errors="replace")
    ui_calls = extract_ui_calls(app_src)
    ui_inline_verbs, ui_all_verbs, ui_prefix_verbs = extract_ui_action_verbs(app_src)

    console_routes, _cp = extract_backend_routes(CONSOLE.read_text(encoding="utf-8", errors="replace"), P_CONSOLE)
    sigil_routes, _sp = extract_backend_routes(SIGIL.read_text(encoding="utf-8", errors="replace"), P_SOV)
    gated_routes, _gp = extract_backend_routes(GATED.read_text(encoding="utf-8", errors="replace"), P_API)
    plane_routes = extract_plane_routes(UIPROXY.read_text(encoding="utf-8", errors="replace"))
    action_verbs = extract_action_verbs(SIGIL_ACTIONS.read_text(encoding="utf-8", errors="replace"))

    routes_by_plane = {
        P_CONSOLE: console_routes,
        P_SOV: sigil_routes,
        P_API: gated_routes,
        P_PLANE: plane_routes,
    }
    prefix_by_plane = {pl: {p for p, m in r.items() if m["kind"] == "prefix"} for pl, r in routes_by_plane.items()}
    return {
        "ui_calls": ui_calls,
        "ui_inline_verbs": ui_inline_verbs,     # narrow: definitely funnel-bound (dead-button direction)
        "ui_all_verbs": ui_all_verbs,           # broad: every action: literal (orphan direction)
        "ui_prefix_verbs": ui_prefix_verbs,
        "routes_by_plane": routes_by_plane,
        "prefix_by_plane": prefix_by_plane,
        "action_verbs": action_verbs,
    }


def route_status(plane, rpath, rprefix, ui_calls):
    """Classify a route: ui-driven / pending / headless(reason) / INFRA / ORPHAN."""
    if rpath in INFRA_PATHS:
        return "headless", "infra probe / static asset (served before auth+routing; not a button)"
    if plane in HEADLESS_PLANES:
        return "headless", HEADLESS_PLANES[plane]
    if (plane, rpath) in PENDING_UI_WIRING:
        return "pending", PENDING_UI_WIRING[(plane, rpath)]
    if _route_driven(plane, rpath, rprefix, ui_calls):
        return "ui-driven", ""
    if (plane, rpath) in INTENTIONALLY_HEADLESS:
        return "headless", INTENTIONALLY_HEADLESS[(plane, rpath)]
    return "ORPHAN", ""


def verb_status(verb, ui_verbs, ui_prefix):
    if verb in ui_verbs:
        return "ui-driven", ""
    if any(pre and verb.startswith(pre) for pre in ui_prefix):
        return "ui-driven", ""
    if verb in PENDING_UI_WIRING_VERBS:
        return "pending", PENDING_UI_WIRING_VERBS[verb]
    if verb in INTENTIONALLY_HEADLESS_VERBS:
        return "headless", INTENTIONALLY_HEADLESS_VERBS[verb]
    return "ORPHAN", ""


# ==================================================================================================
# Matrix artifact (deliverable b)
# ==================================================================================================
def build_matrix(model):
    ui_calls = model["ui_calls"]
    routes = []
    counts = {"ui-driven": 0, "headless": 0, "pending": 0, "ORPHAN": 0}
    for plane in (P_SOV, P_CONSOLE, P_API, P_PLANE):
        for rpath, meta in sorted(model["routes_by_plane"][plane].items()):
            status, reason = route_status(plane, rpath, meta["kind"] == "prefix", ui_calls)
            counts[status] = counts.get(status, 0) + 1
            routes.append({
                "plane": plane, "path": rpath, "kind": meta["kind"],
                "method": meta["method"], "status": status, "reason": reason,
            })

    funnel = []
    vcounts = {"ui-driven": 0, "headless": 0, "pending": 0, "ORPHAN": 0}
    for verb in sorted(model["action_verbs"]):
        status, reason = verb_status(verb, model["ui_all_verbs"], model["ui_prefix_verbs"])
        vcounts[status] = vcounts.get(status, 0) + 1
        funnel.append({"verb": verb, "status": status, "reason": reason})

    return {
        "_comment": ("Generated by integration/tests/test_ui_wiring_matrix.py — the living UI wiring "
                     "guard. Do not hand-edit; regenerate with VIGIL_UIWIRING_REGEN=1 python -m pytest "
                     "integration/tests/test_ui_wiring_matrix.py."),
        "generated_from": {
            "ui": "packages/vigil-ui/app.js",
            "console": "engine/crucible/framework/v2/console/server.py",
            "sigil": "apps/sigil/sigil/ui/server.py",
            "sigil_actions": "apps/sigil/sigil/ui/actions.py",
            "gated_api": "engine/crucible/framework/v2/api/server.py",
            "plane_local": "integration/vigil_integration/uiproxy.py",
        },
        "counts": {
            "ui_calls": len(ui_calls),
            "routes": len(routes),
            "routes_by_status": counts,
            "funnel_verbs": len(funnel),
            "funnel_verbs_by_status": vcounts,
        },
        "ui_calls": ui_calls,
        "routes": routes,
        "action_funnel": {
            "route": "/api/action (sovereign)",
            "ui_inline_verbs": sorted(model["ui_inline_verbs"]),
            "ui_all_verbs": sorted(model["ui_all_verbs"]),
            "ui_prefix_verbs": sorted(model["ui_prefix_verbs"]),
            "verbs": funnel,
        },
    }


# ==================================================================================================
# TESTS
# ==================================================================================================
class TestSourcesPresent(unittest.TestCase):
    def test_all_sources_exist(self):
        for p in (APP_JS, UIPROXY, CONSOLE, SIGIL, SIGIL_ACTIONS, GATED):
            self.assertTrue(p.is_file(), f"missing source the guard parses: {p}")


class TestExtractionSane(unittest.TestCase):
    def setUp(self):
        self.m = build_model()

    def test_extracted_nonempty(self):
        self.assertGreater(len(self.m["ui_calls"]), 100, "app.js should expose >100 backend calls")
        total_routes = sum(len(r) for r in self.m["routes_by_plane"].values())
        self.assertGreater(total_routes, 100, "the three route tables should register >100 routes")
        self.assertGreater(len(self.m["action_verbs"]), 20, "ACTIONS verb set should be >20")
        # the funnel route itself must be a real registered sovereign route
        self.assertIn("/api/action", self.m["routes_by_plane"][P_SOV])


class TestNoDeadButtons(unittest.TestCase):
    """Every UI call resolves to a registered route — a FAIL here is a DEAD BUTTON."""
    def test_every_ui_call_resolves(self):
        m = build_model()
        dead = [c for c in m["ui_calls"]
                if not _ui_resolves(c, m["routes_by_plane"], m["prefix_by_plane"])]
        self.assertEqual(dead, [], f"DEAD BUTTON(S): UI calls with no registered route: {dead}")

    def test_every_ui_funnel_verb_resolves(self):
        m = build_model()
        verbs = m["action_verbs"]
        dead = []
        # the NARROW, certainly-funnel-bound set: an inline funnel verb absent from ACTIONS is a dead button
        for v in sorted(m["ui_inline_verbs"]):
            if v not in verbs:
                dead.append(v)
        for pre in sorted(m["ui_prefix_verbs"]):
            if not any(x.startswith(pre) for x in verbs):
                dead.append(pre + "*")
        self.assertEqual(dead, [], f"DEAD FUNNEL VERB(S) not in the sigil ACTIONS set: {dead}")


class TestNoOrphanRoutes(unittest.TestCase):
    """Every registered route is UI-driven OR explicitly allowlisted — a FAIL here is an ORPHAN."""
    def test_every_route_driven_or_allowlisted(self):
        m = build_model()
        orphans = []
        for plane in (P_SOV, P_CONSOLE, P_API, P_PLANE):
            for rpath, meta in m["routes_by_plane"][plane].items():
                status, _ = route_status(plane, rpath, meta["kind"] == "prefix", m["ui_calls"])
                if status == "ORPHAN":
                    orphans.append((plane, rpath))
        self.assertEqual(sorted(orphans), [],
                         "ORPHAN route(s) — neither UI-driven nor allowlisted (add a button, or add to "
                         f"INTENTIONALLY_HEADLESS / PENDING_UI_WIRING with a reason): {sorted(orphans)}")

    def test_every_funnel_verb_driven_or_allowlisted(self):
        m = build_model()
        orphans = [v for v in sorted(m["action_verbs"])
                   if verb_status(v, m["ui_all_verbs"], m["ui_prefix_verbs"])[0] == "ORPHAN"]
        self.assertEqual(orphans, [],
                         "ORPHAN funnel verb(s) — add a button or allowlist with a reason: " + str(orphans))

    def test_allowlists_have_no_stale_entries(self):
        """An allowlist entry for a route/verb that no longer exists is drift too — remove it."""
        m = build_model()
        all_routes = {(pl, p) for pl in m["routes_by_plane"] for p in m["routes_by_plane"][pl]}
        for key in INTENTIONALLY_HEADLESS:
            self.assertIn(key, all_routes, f"stale INTENTIONALLY_HEADLESS entry (route gone): {key}")
        for key in PENDING_UI_WIRING:
            self.assertIn(key, all_routes, f"stale PENDING_UI_WIRING entry (route gone): {key}")
        for v in INTENTIONALLY_HEADLESS_VERBS:
            self.assertIn(v, m["action_verbs"], f"stale headless verb (verb gone): {v}")
        for v in PENDING_UI_WIRING_VERBS:
            self.assertIn(v, m["action_verbs"], f"stale pending verb (verb gone): {v}")


class TestMatrixArtifactInSync(unittest.TestCase):
    """The committed matrix artifact must equal what the guard regenerates — a FAIL here is drift."""
    def test_matrix_matches(self):
        m = build_model()
        current = build_matrix(m)
        if os.environ.get("VIGIL_UIWIRING_REGEN"):
            MATRIX.parent.mkdir(parents=True, exist_ok=True)
            MATRIX.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.assertTrue(MATRIX.is_file(),
                        f"missing matrix artifact — regenerate with VIGIL_UIWIRING_REGEN=1: {MATRIX}")
        committed = json.loads(MATRIX.read_text(encoding="utf-8"))
        self.assertEqual(committed, current,
                         "ui-wiring matrix DRIFT — a button/route changed. Review, then regenerate with "
                         "VIGIL_UIWIRING_REGEN=1 python -m pytest integration/tests/test_ui_wiring_matrix.py")


# --------------------------------------------------------------------------------------------------
# SELF-TEST (deliverable e): prove the guard FAILS on a planted dead-button and a planted orphan,
# using FIXTURE STRINGS fed to the REAL extractors + checkers — no real file is edited.
# --------------------------------------------------------------------------------------------------
class TestGuardSelfTest(unittest.TestCase):
    def test_selftest_detects_a_dead_button(self):
        m = build_model()
        # a planted app.js snippet with a button that calls a route NO backend registers
        fixture = 'V.getJSON(SOV("/api/__planted_dead_button__")).then(render);'
        planted = extract_ui_calls(fixture)
        self.assertEqual([c["path"] for c in planted], ["/api/__planted_dead_button__"])
        dead = [c for c in planted
                if not _ui_resolves(c, m["routes_by_plane"], m["prefix_by_plane"])]
        self.assertEqual(len(dead), 1, "guard FAILED to flag a planted dead button")
        self.assertEqual(dead[0]["path"], "/api/__planted_dead_button__")
        # and a REAL call in the same fixture still resolves (the guard is not just rejecting everything)
        ok_fixture = 'V.getJSON(SOV("/api/whoami"));'
        ok = [c for c in extract_ui_calls(ok_fixture)
              if not _ui_resolves(c, m["routes_by_plane"], m["prefix_by_plane"])]
        self.assertEqual(ok, [], "guard wrongly flagged a real, registered button")

    def test_selftest_detects_an_unallowlisted_orphan(self):
        m = build_model()
        # a planted backend snippet registering a sovereign route with no UI caller and no allowlist entry
        fixture = 'if path == "/api/__planted_orphan_route__":\n    return self._json({})\n'
        planted, _pref = extract_backend_routes(fixture, P_SOV)
        self.assertIn("/api/__planted_orphan_route__", planted)
        meta = planted["/api/__planted_orphan_route__"]
        status, _ = route_status(P_SOV, "/api/__planted_orphan_route__", meta["kind"] == "prefix", m["ui_calls"])
        self.assertEqual(status, "ORPHAN", "guard FAILED to flag a planted un-allowlisted orphan route")
        # a planted verb that is in neither the UI nor any allowlist is an ORPHAN verb
        vstatus, _ = verb_status("__planted_orphan_verb__", m["ui_all_verbs"], m["ui_prefix_verbs"])
        self.assertEqual(vstatus, "ORPHAN", "guard FAILED to flag a planted un-allowlisted orphan verb")


if __name__ == "__main__":
    unittest.main()
