"""WS0 (SOVEREIGN CONSOLE) — contract guard for the shared UI surfaces the later workstreams depend on.

This is a *contract*/structure guard, not a behavioural JS test (the UI is a no-build static bundle and the
repo has no JS test harness). It fails if a refactor drops:

  * the ``getJSON`` server-error propagation (WS0-a) — the fix that stops read panels masking a real 4xx/5xx
    as a generic "offline/empty" state,
  * the default ``sse`` terminal-failure surface (WS0-b) — so a stream that never connects no longer shows a
    stalled "running…" with no error,
  * the reusable ``progressBar`` / ``streamProgress`` / ``errorBanner`` helpers exported on ``window.VUI``
    (WS0-c) — the surfaces WS1/WS2 build the docker bring-up percentage bar and read-panel errors on.

Behavioural verification lands with the WS2 consumers (the docker bring-up % bar), which exercise these live.
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UI_JS = REPO / "packages" / "vigil-ui" / "ui.js"
COMPONENTS_CSS = REPO / "packages" / "vigil-ui" / "components.css"


def _ui() -> str:
    return UI_JS.read_text(encoding="utf-8")


def _slice(src: str, start_marker: str, end_marker: str) -> str:
    """Return the source between the first start_marker and the next end_marker (the function body)."""
    i = src.index(start_marker)
    j = src.index(end_marker, i + len(start_marker))
    return src[i:j]


def test_getjson_propagates_the_server_error_body():
    # Within the getJSON body specifically (not merely somewhere in the file): it must read the response
    # text and attach the server error + status, exactly as postJSON does.
    body = _slice(_ui(), "async function getJSON(url)", "async function postJSON(url")
    assert "await r.text()" in body, "getJSON must read the response body to recover the server error"
    assert "err.status = r.status" in body and "err.data = data" in body, (
        "getJSON must attach .status/.data so read panels can distinguish a backend 4xx/5xx from 'plane down'")


def test_sse_installs_a_default_terminal_failure_surface():
    # The default onError must fire only on a TERMINAL failure the browser will not retry — gated on
    # readyState === CLOSED so transient reconnects stay silent.
    body = _slice(_ui(), "function sse(url, onEvent, onError)", "function toast(")
    assert "es.onerror = onError ||" in body, "sse must install a default onError when the caller passes none"
    assert "EventSource.CLOSED" in body, "the default sse failure surface must gate on a terminal (CLOSED) state"


def test_shared_helpers_are_exported_on_window_VUI():
    exports = _slice(_ui(), "window.VUI = {", "})();")
    for name in ("errorBanner", "clearErrorBanner", "progressBar", "streamProgress"):
        assert f"{name}: {name}" in exports, f"window.VUI must export {name} — WS1/WS2/WS3 consume it"


def test_progress_bar_styles_are_present():
    css = COMPONENTS_CSS.read_text(encoding="utf-8")
    for sel in (".pbar-track", ".pbar-fill", ".pbar-done .pbar-fill", ".pbar-err .pbar-fill", "#error-banner"):
        assert sel in css, f"missing progress-bar/error-banner style: {sel}"
