"""WS2a (SOVEREIGN CONSOLE) — read panels surface the REAL backend error, not a blanket "offline".

`offlineEmpty(err)` now distinguishes an HTTP error (the plane is UP but the endpoint failed → show the
server message, which WS0's getJSON attaches on `.status`/`.data`) from a fetch/network failure (the plane
is genuinely down). Every data-read `.catch` routes through it instead of rendering its own inline empty
state that discarded the error. This guards against a regression that re-introduces a masking inline empty.
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APP_JS = REPO / "packages" / "vigil-ui" / "app.js"


def _app() -> str:
    return APP_JS.read_text(encoding="utf-8")


def test_offline_empty_distinguishes_a_backend_error_from_a_down_plane():
    src = _app()
    i = src.index("function offlineEmpty(")
    body = src[i:i + 1000]
    assert "if (err && err.status)" in body, "offlineEmpty must branch on a real HTTP status"
    assert ("err.data && err.data.error" in body) or ("err.message" in body), \
        "the backend-error branch must surface the server message"
    assert "Request failed" in body, "the backend-error state must be visibly distinct from 'offline'"


def test_no_read_catch_discards_the_error_by_calling_offlineEmpty_with_no_arg():
    src = _app()
    # Every catch was threaded from `function ()` to `function (e)` and passes the error: offlineEmpty(e[,hint]).
    assert "offlineEmpty());" not in src, \
        "a catch still calls offlineEmpty() with no error — the real backend error is discarded"


def test_masking_inline_empty_states_survive_only_in_the_helper_and_the_flag_based_panel():
    src = _app()
    # The literal masking markup survives ONLY in offlineEmpty itself and the flag-based Background panel
    # (which renders from a cached offOnline flag and has no error object) — at most 2 occurrences.
    n = src.count('h("div.big", null, "Offense engine offline")')
    assert n <= 2, (f"{n} inline 'Offense engine offline' empty-states remain — read panels should route "
                    "their catch through offlineEmpty(e) so the real backend error is not masked")
