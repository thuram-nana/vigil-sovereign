"""
Request-level checks — CORS-active and host-header injection, confirmed only on
the dangerous behavior, run once per request via the engine's request_checks.
"""

from __future__ import annotations

import contextlib
import http.client
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.checks import CorsActiveCheck, HostHeaderCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest


def _make(kind: str, vulnerable: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            extra: list[tuple[str, str]] = []
            body = b"ok"
            if kind == "cors":
                if vulnerable and origin:
                    extra = [("Access-Control-Allow-Origin", origin),
                             ("Access-Control-Allow-Credentials", "true")]  # reflects any origin
                elif origin:
                    extra = [("Access-Control-Allow-Origin", "https://trusted.example")]  # fixed, safe
            elif kind == "host":
                if vulnerable:
                    body = f'<a href="https://{host}/reset?t=abc">reset</a>'.encode()  # uses Host in a link
                else:
                    body = b'<a href="/reset?t=abc">reset</a>'  # relative, host-independent
            self.send_response(200)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(kind: str, vulnerable: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(kind, vulnerable))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "127.0.0.1", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(host: str, port: int):
    def send(req: HttpRequest) -> dict:
        path = urllib.parse.urlsplit(req.url).path or "/"
        if urllib.parse.urlsplit(req.url).query:
            path += "?" + urllib.parse.urlsplit(req.url).query
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(req.method, path, headers=dict(req.headers))
            resp = conn.getresponse()
            return {"status": resp.status, "headers": resp.getheaders(),
                    "body": resp.read().decode("utf-8", "replace")}
        finally:
            conn.close()
    return send


def test_cors_active_confirmed_and_safe() -> None:
    with _server("cors", vulnerable=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/api")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(CorsActiveCheck(),))
        assert [x for x in f if x.bug_class == "cors"], "CORS reflect-with-credentials not confirmed"
        assert f[0].confirmed_by == "achieved_state"

    with _server("cors", vulnerable=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/api")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(CorsActiveCheck(),))
        assert f == [], "a fixed trusted-origin CORS policy must not be flagged"


def test_host_header_injection_confirmed_and_safe() -> None:
    with _server("host", vulnerable=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/reset")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(HostHeaderCheck(),))
        assert [x for x in f if x.bug_class == "host_header_injection"], "host-header injection not confirmed"

    with _server("host", vulnerable=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/reset")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(HostHeaderCheck(),))
        assert f == [], "an app using relative links must not be flagged for host-header injection"


def test_emitted_url_hosts_counts_emission_not_inert_echo() -> None:
    """The hostile Host counts only when it is the AUTHORITY of a URL the app EMITS (href/src/action, or a
    meta/JS redirect) — a URL a victim's browser would use. A plain-text ECHO of the reconstructed URL back
    to the requester (a 404 message, a <pre> sample, a comment, a JSON error string) is NOT exploitable and
    must NOT count (re-red-pen BLOCK-D). Matching is on the WHOLE authority, so a subdomain reflection does
    not collide with the evil host."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts

    evil = HostHeaderCheck().evil_host
    # EMISSIONS — a link / resource / form target / redirect the app builds from the Host: all must be found
    assert evil in hosts(f'<a href="https://{evil}/reset?t=1">reset</a>')
    assert evil in hosts(f'<a href="//{evil}/reset">reset</a>')          # scheme-relative
    assert evil in hosts(f'<img src="https://{evil}/logo.png">')
    assert evil in hosts(f'<form action="https://{evil}/submit">')
    assert evil in hosts(f'<meta http-equiv="refresh" content="0;url=https://{evil}/x">')  # redirect emission
    assert evil in hosts(f'<meta property="og:url" content="https://{evil}/">')   # canonical URL metadata
    assert evil in hosts(f'<link rel="canonical" href="https://{evil}/">')        # canonical link (href)
    # NON-EMISSIONS — inert echoes shown only to the requester, or not the evil authority at all
    assert evil not in hosts(f'<meta name="description" content="visit https://{evil} today">')  # prose, not URL meta
    # the property name must match the WHOLE allow-listed value: `:alt` sub-properties are TEXT, not URLs,
    # and a name that merely CONTAINS an og token is not og metadata (substring matching would false-FACT)
    assert evil not in hosts(f'<meta name="twitter:image:alt" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="og:image:alt" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="not-og:url" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="x og:url y" content="https://{evil}/x">')
    # ... while every genuinely URL-valued og/twitter property is still counted
    for prop in ("og:url", "og:image", "og:image:secure_url", "twitter:url", "twitter:image:src"):
        assert evil in hosts(f'<meta property="{prop}" content="https://{evil}/x">'), prop


def test_emitted_url_hosts_ignores_inert_markup_contexts() -> None:
    """Markup a browser never PARSES emits nothing: an HTML comment, or the raw-text contents of
    script/style/textarea. An app echoing attacker text that merely LOOKS like a link into one of those must
    not mint a FACT. `<pre>` is deliberately NOT inert — tags inside it are live, clickable links."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts

    evil = HostHeaderCheck().evil_host
    # INERT — never parsed as markup, so nothing is emitted
    assert evil not in hosts(f'<!-- <a href="https://{evil}/">x</a> -->')
    assert evil not in hosts(f"""<script>var t = "<a href='https://{evil}/'>";</script>""")
    assert evil not in hosts(f'<!-- <meta property="og:url" content="https://{evil}/"> -->')
    for el in ("style", "textarea", "title", "xmp", "template", "iframe"):
        assert evil not in hosts(f'<{el}><a href="https://{evil}/">x</a></{el}>'), el
    # `<noscript>` is parsed as LIVE markup when scripting is disabled — a no-JS consumer (link-preview
    # crawler, plain HTTP client) really can follow this link, so it is a genuine emission.
    assert evil in hosts(f'<noscript><a href="https://{evil}/">x</a></noscript>')
    # `<noembed>`/`<noframes>`, despite also being "fallback" elements, are RAWTEXT per the HTML parsing
    # spec — their content is never markup in any configuration — so they stay inert. (An earlier revision
    # of this test lumped all three together; the tokenizer differential caught the over-generalisation.)
    for el in ("noembed", "noframes"):
        assert evil not in hosts(f'<{el}><a href="https://{evil}/">x</a></{el}>'), el
    # an end tag closes only when `</el` is followed by a terminator — `</scriptx>` does not close <script>,
    # so what follows is still inert (treating it as a close would un-mask it and mint a false FACT)
    assert evil not in hosts(f'<script></scriptx><a href="https://{evil}/">x</a></script>')
    assert evil in hosts(f'<script></script ><a href="https://{evil}/">x</a>')   # a real close tag does close
    # the opening tag ends at the first `>` OUTSIDE a quoted attribute, so a `>` inside srcdoc/data-* must
    # not end the tag early and hide the real src (that dropped a genuine <script src>/<iframe src> sink)
    assert evil in hosts(f'<script data-cfg="{{a:1>0}}" src="https://{evil}/app.js"></script>')
    assert evil in hosts(f'<iframe srcdoc="<p>hi</p>" src="https://{evil}/"></iframe>')
    assert evil not in hosts(f'<plaintext><a href="https://{evil}/">x</a>')   # no end tag: literal to EOF
    assert evil not in hosts(f'<template><meta property="og:url" content="https://{evil}/"></template>')
    # LIVE — <pre>/<code> contents ARE parsed, so a link inside them is a real emission
    assert evil in hosts(f'<pre><a href="https://{evil}/">x</a></pre>')
    assert evil in hosts(f'<a href="https://{evil}/reset">reset</a>')
    # ... and an inert element's OPENING TAG still emits: <script src>/<iframe src> load attacker content,
    # the canonical high-severity host-header sink. Masking the whole element dropped this real finding.
    assert evil in hosts(f'<script src="https://{evil}/evil.js"></script>')
    assert evil in hosts(f'<iframe src="https://{evil}/x"></iframe>')
    assert evil in hosts(f'<link rel="stylesheet" href="https://{evil}/x.css">')
    assert evil not in hosts(f'Cannot GET http://{evil}/foo')                    # 404 text echo (BLOCK-D)
    assert evil not in hosts(f'<pre>curl http://{evil}/api</pre>')               # code sample
    assert evil not in hosts(f'<!-- built from host: //{evil}/ -->')            # HTML comment
    assert evil not in hosts(f'{{"error": "unknown path http://{evil}/x"}}')     # JSON error echo
    assert evil not in hosts(f'<img src="https://{evil}.cdn.example.com/l.png">')  # subdomain prefix
    assert evil not in hosts(f"<p>Host: {evil}</p>")                             # bare plain-text echo
    assert evil not in hosts(f'<a href="https://app.example/go?to=//{evil}">x</a>')  # evil in path/query
    assert hosts('<a href="/reset">reset</a>') == []                            # relative link only


def test_emitted_url_hosts_follows_the_html_content_models() -> None:
    """The masker must model what a browser actually parses, in BOTH directions — each of these flipped a
    verdict when it was wrong: an inert element whose opening tag has an unbalanced quote never terminates
    (so the rest of the document is inert, not live); a `<plaintext>` inside an attribute VALUE is not an
    element (so the document after it is still live); `<template>` NESTS (the first `</template>` closes only
    the inner one); and after `<!--<script` the next `</script>` returns to the escaped state instead of
    closing (WHATWG script-data double-escape)."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts

    evil = HostHeaderCheck().evil_host
    # unbalanced quote in an inert opening tag -> the tag never ends -> everything after is inert
    assert evil not in hosts(f'<textarea placeholder="a"b"><a href="https://{evil}/x">')
    # a quote delimits an attribute value only right after `=`; an apostrophe inside an UNQUOTED value
    # (`title=it's` — ordinary English) is a literal, and mis-reading it as a delimiter aborted the scan and
    # left the inert markup after it unmasked
    assert evil not in hosts(
        f"""<a title=it's>t</a><textarea><a href="https://{evil}/r">x</a></textarea>""")
    # `<plaintext>` inside a quoted attribute value is TEXT, not an element -> the page stays live
    assert evil in hosts(f'<input value="<plaintext>"><link rel="canonical" href="https://{evil}/r">')
    # <template> nests: the inner </template> must not un-mask the outer fragment
    assert evil not in hosts(
        f'<template>x<template>y</template><a href="https://{evil}/z"></a></template>')
    assert evil in hosts(f'<template>x</template><a href="https://{evil}/y">z</a>')   # ... and it does close
    # script-data double escape: the FIRST </script> after `<!--<script` does not close the element
    assert evil not in hosts(f'<script><!--<script>q</script><a href="https://{evil}/w"></a></script>')
    assert evil in hosts(f'<script>var a=1</script><a href="https://{evil}/">x</a>')  # ordinary script closes


def test_emitted_url_hosts_models_the_script_data_and_template_state_machines() -> None:
    """The two layers built on top of the tokenizer must follow the SPEC, not a substring guess — each of
    these flipped a verdict when they didn't: the solidus is ignored on a non-void element (so
    ``<template/>`` OPENS an inert fragment); script-data double-escape is entered by a NON-ADJACENT
    ``<!-- … <script`` and requires a terminator after ``<script``; and duplicate attributes are FIRST-wins
    per WHATWG, not last-wins as a dict comprehension yields."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts
    from framework.v2.scanner.checks import _markup_redirect_hosts as redirects

    evil = HostHeaderCheck().evil_host
    # `<template/>` opens an inert fragment — its content is neither rendered nor fetched
    assert hosts(f'<template/><a href="https://{evil}/x">l</a>') == []
    assert redirects(f'<template/><meta http-equiv=refresh content="url=https://{evil}/">') == []
    # double-escape entered NON-adjacently, and re-entered across a would-be close: still script text
    assert redirects(
        f'<script><!-- x <script></script>\n<meta http-equiv=refresh content="url=https://{evil}/">') == []
    assert hosts(f'<script><!--<script></script><script></script><a href="https://{evil}/x"></a>') == []
    # ... but `<script` NOT followed by a terminator does not double-escape, so the next script is LIVE and
    # its sink must still be found (guessing here certified a vulnerable page CLEAN)
    for bad in ("<script<", "<scripting"):
        assert "evil.com" in redirects(
            f"<script><!--{bad}</script>\n<script>location.href='//evil.com/'</script>"), bad
    # duplicate attributes: the FIRST wins, so neither a hostile second nor a benign second changes the verdict
    assert hosts(f'<a href="https://home.example.com/d" href="https://{evil}/x">') == ["home.example.com"]
    assert evil in hosts(f'<a href="https://{evil}/x" href="https://cdn.example.com/x">')


def test_meta_refresh_follows_the_declarative_refresh_steps() -> None:
    """``content`` must be parsed with the HTML Standard's shared declarative-refresh steps. Approximating
    them was wrong in BOTH directions at once: searching for any ``url=`` minted a false FACT on a value
    with NO time component (a browser refreshes nothing) and on one where ``url=`` is not the front token
    (the URL is the whole remainder, so it stays same-origin); requiring a literal ``url=`` simultaneously
    MISSED ``0;https://evil/``, where the keyword is optional and every browser navigates."""
    from framework.v2.scanner.checks import _markup_redirect_hosts as redirects

    evil = "evil.example.test"

    def hosts(content: str) -> list[str]:
        return redirects(f'<meta http-equiv="refresh" content="{content}">')

    # NAVIGATES — all of these send a browser to `evil`
    for content in (f"0; url=https://{evil}/x", f"0;URL=https://{evil}/x", f"0; url = https://{evil}/x",
                    f"0;url https://{evil}/x",          # the `url` keyword takes no `=`
                    f"0;https://{evil}/x",              # ... and is optional entirely
                    f"0, https://{evil}/x",             # `,` is a valid separator
                    f"0.5;url=https://{evil}/x", f".5;url=https://{evil}/x",
                    f"""0;url='https://{evil}/x'"""):
        assert evil in hosts(content), content
    # DOES NOT NAVIGATE (off-site) — none of these may contribute a host
    assert hosts(f"url=https://{evil}/x") == []          # no time component: no refresh at all
    assert hosts(f"0; please wait;url=https://{evil}/x") == []   # URL is the whole remainder -> relative
    assert hosts("5") == []                               # a bare time reloads the same page
    assert hosts("") == []
    assert hosts("0;url=/local") == []                    # same-origin
    # the code point right after the time must be ';', ',' or ASCII whitespace — anything else ends parsing
    assert hosts(f"0url=https://{evil}/x") == []
    assert hosts(f"0https://{evil}/x") == []
    # the URL runs to the end of the value, so a ';' inside the path is not a terminator
    assert "x.test" in hosts("0;url=https://x.test/a;b")


def test_body_navigation_is_ignored_on_a_followed_redirect() -> None:
    """A 3xx carrying a Location is FOLLOWED by the browser, so its body is never rendered — any navigation
    that body describes cannot happen, and counting it would mint a false FACT. The Location disjunct still
    stands on its own, and a body redirect on a page that IS rendered still fires."""
    from framework.v2.verify.oracles import predicate_oracle

    canary = "crucible-redirect-canary.test"

    def fires(status: int, location_host: str, markup_hosts: list[str]) -> bool:
        followed = bool(location_host) and status in (301, 302, 303, 307, 308)
        return predicate_oracle(
            {"status": status, "location_host": location_host, "canary_host": canary, "body": "",
             "followed_redirect": followed, "markup_redirect_hosts": markup_hosts},
            {"any": [
                {"all": [{"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
                         {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]},
                {"all": [{"not": {"eq": [{"var": "followed_redirect"}, True]}},
                         {"min_len": [{"var": "canary_host"}, 1]},
                         {"in": [{"var": "canary_host"}, {"var": "markup_redirect_hosts"}]}]},
            ]}).fired

    assert fires(302, "app.example", [canary]) is False   # redirected somewhere SAFE; body never rendered
    assert fires(200, "", [canary]) is True               # rendered page: the body redirect is real
    assert fires(302, canary, []) is True                 # the Location itself goes to the canary
    assert fires(302, "", [canary]) is True               # a 3xx with no Location is not followed


def test_meta_refresh_url_extraction_is_bounded_and_faithful() -> None:
    """A meta-refresh ``content`` value is attacker-influenced and arrives UNBOUNDED from the tokenizer. The
    previous end-anchored lazy regex took 11 SECONDS on a sub-cap value packed with ``url=`` tokens."""
    import time as _time

    from framework.v2.scanner.checks import _markup_redirect_hosts as redirects

    # Each shape defeated a previous implementation. `url=a;`*N made the old end-anchored lazy regex retry
    # at every token (11s). `urlx`/`url `*N are the NON-matching variants: they never return early, so they
    # are the ones that expose a quadratic scan — a payload that matches on iteration 1 would keep this test
    # green while the slow path stayed open (the red-pen's point about the earlier version of this test).
    for payload in ("url=a;" * 80_000, "urlx" * 200_000, "url " * 200_000, "0;" + "u" * 400_000):
        body = f'<meta http-equiv="refresh" content="{payload}">'
        t0 = _time.perf_counter()
        redirects(body)
        assert (_time.perf_counter() - t0) < 1.0, f"meta-refresh extraction must stay bounded: {payload[:12]!r}"
    # faithful: the URL runs to the end of the value, so a ';' inside the path is NOT a terminator
    assert "x.test" in redirects('<meta http-equiv=refresh content="0; url=https://x.test/a;b">')
    assert "y.test" in redirects("<meta http-equiv=refresh content=0;url=https://y.test/z>")   # unquoted
