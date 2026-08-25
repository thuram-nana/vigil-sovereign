"""WS2a (SOVEREIGN CONSOLE) — read panels surface the REAL backend error, not a blanket "offline".

`offlineEmpty(err)` now distinguishes an HTTP error (the plane is UP but the endpoint failed → show the
server message, which WS0's getJSON attaches on `.status`/`.data`) from a fetch/network failure (the plane
is genuinely down). Every single-read data `.catch` routes through it — including the Background panel's
runs region, which now captures its poll error into `B.offErr` — so the only surviving inline
"Offense engine offline" literal is the helper itself. (Two multi-source loaders — the Feed/Knowledge
fan-out and the New-Assessment capability catalog — collapse their errors into an "offline" state by a
different, fan-out shape, and are a deliberate boundary for this single-read slice.) This guards against a
regression that re-introduces a masking inline empty.
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
    import re
    src = _app()
    # Every catch passes the error: offlineEmpty(e[, hint]). A BARE offlineEmpty() — any whitespace, any
    # syntactic position — would mean a catch discarded the error. (The definition `function offlineEmpty(
    # err, hint)` never matches this regex.)
    bare = re.findall(r"offlineEmpty\(\s*\)", src)
    assert not bare, f"a catch still calls offlineEmpty() with no error — the real backend error is discarded: {bare}"


def test_the_only_masking_inline_empty_left_is_the_helper_itself():
    src = _app()
    # After threading every single-read catch (incl. the Background runs region) through offlineEmpty(err),
    # the literal masking markup survives ONLY inside offlineEmpty's own fallback branch — one occurrence.
    n = src.count('h("div.big", null, "Offense engine offline")')
    assert n <= 1, (f"{n} inline 'Offense engine offline' empty-states remain — every single-read catch "
                    "should route through offlineEmpty(err) so the real backend error is not masked")
