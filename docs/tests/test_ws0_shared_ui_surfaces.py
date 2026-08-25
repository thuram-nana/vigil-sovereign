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


def test_sse_stays_minimal_and_offers_an_optin_failure_surface():
    # sse() must NOT install a blanket default onError (that false-alarms on streams which legitimately
    # end or are ambient/optional). The terminal-failure toast is opt-in via sseErrorToast(label), gated
    # on readyState === CLOSED so transient reconnects stay silent.
    sse_body = _slice(_ui(), "function sse(url, onEvent, onError)", "function sseErrorToast(")
    assert "if (onError) es.onerror = onError;" in sse_body, (
        "sse must wire onError ONLY when the caller passes one — no surprising global default")
    assert "es.onerror = onError ||" not in sse_body, "sse must not carry a blanket default onError"
    helper = _slice(_ui(), "function sseErrorToast(", "function toast(")
    assert "EventSource.CLOSED" in helper, "sseErrorToast must gate its toast on a terminal (CLOSED) state"


def test_stream_progress_completes_only_on_an_explicit_done_signal():
    # A sub-phase hitting pct>=100 must NOT terminate the stream and discard later phases (the docker
    # bring-up bar is multi-phase). Completion rides an explicit phase==="done"/done===true only.
    body = _slice(_ui(), "function streamProgress(", "window.VUI = {")
    assert "d.pct >= 100" not in body, "streamProgress must NOT complete on a sub-phase reaching 100%"
    assert 'd.phase === "done" || d.done === true' in body, "streamProgress completes only on an explicit done"


def test_shared_helpers_are_exported_on_window_VUI():
    exports = _slice(_ui(), "window.VUI = {", "})();")
    for name in ("errorBanner", "clearErrorBanner", "progressBar", "streamProgress", "sseErrorToast"):
        assert f"{name}: {name}" in exports, f"window.VUI must export {name} — WS1/WS2/WS3 consume it"


def test_progress_bar_styles_are_present():
    css = COMPONENTS_CSS.read_text(encoding="utf-8")
    for sel in (".pbar-track", ".pbar-fill", ".pbar-done .pbar-fill", ".pbar-err .pbar-fill", "#error-banner"):
        assert sel in css, f"missing progress-bar/error-banner style: {sel}"
