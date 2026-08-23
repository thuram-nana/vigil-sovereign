"""W17-14 (#548) — the orphan-route guard: every REGISTERED console read route is either CONSUMED by the
shipped unified UI (`packages/vigil-ui/app.js`) or listed as an intentionally-programmatic route with a
stated reason. A NEW route added to the console's read-route registry with neither a UI consumer nor a
documentation entry turns THIS test — and so the required `CRUCIBLE core on vigil_core` CI job — red.

This is the structural half of the W17-14 cleanup. The other half is the REMOVAL of two genuinely-dead
surfaces, pinned here so the tree without the fix fails:

  * ``GET /api/chat/attachments`` — a read route with ZERO UI consumers (the UI renders attachment chips
    from the chat record's own ``attachments`` field, it never fetched this route). Its provider
    ``chat.attachments_list`` had no internal caller either, so both are gone.
  * ``api.reports_data`` — a provider with NO HTTP route AND no internal caller (unlike ``authority_full`` /
    ``session_detail``, which stay because the dossier/report assembly still calls them). Pure dead code, removed.

The `/api/v1` gated action plane (:8799) is NOT touched: it is a documented, supported, tested programmatic
third-party API (`docs/plain-english/02-the-parts.md`, `docs/plain-english/12-tools-and-what-you-need.md`,
`framework/v2/api/`), so it is KEPT — "documented as a supported API" is a valid resolution, not an orphan.

STDLIB + the console package only; runs inside the `CRUCIBLE core on vigil_core` pytest invocation.
"""
from __future__ import annotations

import ast
import re
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from framework.v2.console import api, chat, server

from .conftest import AUTH_HEADERS


def _repo_root() -> Path:
    p = Path(__file__).resolve()
    for anc in p.parents:
        if (anc / "packages" / "vigil-ui" / "app.js").is_file():
            return anc
    raise AssertionError("could not locate repo root (packages/vigil-ui/app.js)")


APP_JS = (_repo_root() / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
SERVER_SRC = Path(server.__file__).read_text(encoding="utf-8")


# The GET read routes special-cased in ``do_GET`` (matched by name/prefix before the dispatch tables).
# Kept here as an explicit list so a reviewer sees exactly what is enumerated beyond the three registries.
# This hand-list is NO LONGER load-bearing on its own: ``test_special_get_routes_track_the_server_source``
# below re-derives the special-cased set from the server SOURCE (parses ``do_GET``) and fails if this tuple
# and the source ever disagree in EITHER direction — a new special-cased route drifting past the guard, or a
# stale entry lingering after its route was removed. So a NEW ``do_GET`` route cannot be orphaned by omission.
_SPECIAL_GET_ROUTES = (
    "/api/events", "/api/blackboard", "/api/chat/sessions", "/api/chat/session/",
    "/api/chat/hypotheses", "/api/chat/models", "/api/aegis/verdicts", "/api/dossier/",
    "/api/brain/decision", "/api/strix/control",
)


def _do_get_route_literals(src: str) -> set[str]:
    """Every ``/api/...`` path string literal that ``do_GET`` COMPARES against the request path, derived
    from the server SOURCE (not the hand-list) so a new special-cased route cannot silently drift past the
    orphan guard. We collect the string operands of ``path == "..."`` comparisons and of
    ``path.startswith(...)`` / ``path.endswith(...)`` calls inside ``do_GET``, then keep only the ``/api/``
    route shapes — dropping the bare ``/api/`` prefix (the token gate + the catch-all 404, not a route) and
    non-route suffixes like ``.zip``."""
    tree = ast.parse(src)
    do_get = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "do_GET"),
        None,
    )
    assert do_get is not None, "could not locate do_GET in the server source"
    lits: set[str] = set()
    for node in ast.walk(do_get):
        consts: list[str] = []
        if isinstance(node, ast.Compare):
            for operand in (node.left, *node.comparators):
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    consts.append(operand.value)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("startswith", "endswith")):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    consts.append(arg.value)
        for v in consts:
            if v.startswith("/api/") and v != "/api/":
                lits.add(v)
    return lits

# Registered read routes that are DELIBERATELY not consumed by the shipped UI but are kept as a documented,
# programmatic surface. Each entry needs a one-line reason. EMPTY today: after W17-14 every console read
# route has a real UI consumer. A future programmatic-only read route belongs here (with its reason), which
# is itself the documentation entry the acceptance criterion asks for.
_DOCUMENTED_PROGRAMMATIC: dict[str, str] = {}


def _registered_read_routes() -> set[str]:
    routes: set[str] = set()
    for table in (server._EXACT_ROUTES, server._SCOPED_ROUTES, server._PREFIX_ROUTES):
        routes |= set(table.keys())
    routes |= set(_SPECIAL_GET_ROUTES)
    return routes


def _orphans(routes, app_js: str, documented: dict[str, str]) -> list[str]:
    """A route is an ORPHAN when it is neither a literal substring of the shipped UI (the UI fetches it via
    ``OFF("/api/…")``) nor present in the documented-programmatic allowlist."""
    return sorted(r for r in routes if (r not in app_js) and (r not in documented))


# --------------------------------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------------------------------
def test_every_registered_read_route_is_consumed_or_documented():
    orphans = _orphans(_registered_read_routes(), APP_JS, _DOCUMENTED_PROGRAMMATIC)
    assert orphans == [], (
        "console read routes with no UI consumer and no documentation entry (wire them into "
        f"packages/vigil-ui/app.js, add a _DOCUMENTED_PROGRAMMATIC reason, or remove them): {orphans}"
    )


def test_negative_control_the_checker_is_not_a_no_op():
    # A synthetic route that is in neither the UI nor the allowlist MUST be flagged — otherwise the guard
    # above could pass vacuously.
    fake = "/api/__w17_14_definitely_not_a_route__"
    assert _orphans([fake], APP_JS, {}) == [fake]
    # …and documenting it (an allowlist entry) or wiring it (present in the UI text) clears it.
    assert _orphans([fake], APP_JS, {fake: "programmatic only"}) == []
    assert _orphans([fake], APP_JS + f'OFF("{fake}")', {}) == []


# --------------------------------------------------------------------------------------------------
# Drift proof — the special-GET-route set is DERIVED from the server source, not hand-trusted
# --------------------------------------------------------------------------------------------------
def test_special_get_routes_track_the_server_source():
    # Every ``/api/`` route ``do_GET`` special-cases (parsed from the SOURCE) must be accounted for — either
    # enumerated in ``_SPECIAL_GET_ROUTES`` or already a key in one of the dispatch registries. A NEW
    # special-cased ``do_GET`` route added without registering it turns THIS test (and the CI job) red — the
    # exact orphan shape W17-14 removed can no longer recur by omission.
    compared = _do_get_route_literals(SERVER_SRC)
    allowed = _registered_read_routes()  # _SPECIAL_GET_ROUTES ∪ the three dispatch registries
    unregistered = sorted(compared - allowed)
    assert unregistered == [], (
        "do_GET special-cases these /api/ route(s) that are neither in _SPECIAL_GET_ROUTES nor a dispatch "
        f"registry key — add each to _SPECIAL_GET_ROUTES (and wire/document it in the orphan guard): {unregistered}"
    )
    # …and the reverse: no stale hand-list entry that the source no longer compares (bidirectional sync).
    stale = sorted(r for r in _SPECIAL_GET_ROUTES if r not in compared)
    assert stale == [], (
        f"_SPECIAL_GET_ROUTES lists route(s) do_GET no longer special-cases — remove them: {stale}"
    )


def test_route_derivation_catches_a_new_unregistered_do_GET_route():
    # The negative control for the drift guard: a synthetic do_GET that special-cases a brand-new /api/ path
    # MUST be surfaced by the source parser, and that path MUST NOT already be registered — otherwise the
    # guard above could pass vacuously (a no-op parser would find nothing to flag).
    fake_src = (
        "class H:\n"
        "    def do_GET(self):\n"
        "        path = self.path\n"
        "        if path == '/api/__w17_14_new_orphan__':\n"
        "            return self._json({})\n"
        "        if path.startswith('/api/__w17_14_new_prefix__/'):\n"
        "            return self._json({})\n"
        "        if path.startswith('/api/'):\n"
        "            return self._json({}, status=404)\n"
    )
    lits = _do_get_route_literals(fake_src)
    assert lits == {"/api/__w17_14_new_orphan__", "/api/__w17_14_new_prefix__/"}, lits
    # the bare "/api/" prefix is correctly excluded (it is the catch-all, not a route)
    assert "/api/" not in lits
    # and neither synthetic route is registered, so the drift guard WOULD fail on this source
    assert not (lits & _registered_read_routes())
    # the real parser is not a no-op: it recovers exactly the shipped special-cased set
    assert _do_get_route_literals(SERVER_SRC) == set(_SPECIAL_GET_ROUTES)


# --------------------------------------------------------------------------------------------------
# Removal proofs — these FAIL on a tree without the W17-14 fix
# --------------------------------------------------------------------------------------------------
def test_reports_data_dead_code_is_gone():
    assert not hasattr(api, "reports_data"), "api.reports_data is dead code (no route, no caller) — remove it"


def test_attachments_list_provider_and_route_are_gone():
    assert not hasattr(chat, "attachments_list"), "chat.attachments_list had no caller after the route went"
    assert '"/api/chat/attachments"' not in SERVER_SRC, "the orphaned /api/chat/attachments route must be gone"
    # and it is not silently living in one of the dispatch registries either
    assert "/api/chat/attachments" not in _registered_read_routes()


# --------------------------------------------------------------------------------------------------
# Runtime: the removed route 404s while a kept route still serves
# --------------------------------------------------------------------------------------------------
@contextmanager
def _running(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _get_status(url: str) -> int:
    req = urllib.request.Request(url, headers=AUTH_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_removed_route_404s_and_a_kept_route_still_works(tmp_path, monkeypatch):
    with _running(tmp_path, monkeypatch) as base:
        assert _get_status(base + "/api/chat/attachments?chat_id=whatever") == 404
        assert _get_status(base + "/api/status") == 200
