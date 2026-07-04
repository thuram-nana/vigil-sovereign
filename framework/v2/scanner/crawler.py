"""
scanner.crawler — the autonomous surface-discovery engine.

The audit engine can scan a request, but something has to *find* the requests.
Burp's coverage starts with a crawler that walks an app and populates a site map;
CRUCIBLE previously had only a static nine-path probe list. This is the real
crawler: from a seed URL it fetches, parses links and forms out of every
response, resolves and scopes them, avoids cycles and parameter-trap explosions,
and emits the discovered endpoints as fuzzable :class:`HttpRequest`s the
``AuditEngine`` consumes directly — closing crawl → scan → confirm with no human.

Design choices that make it correct rather than decorative:

  * **Locations, not URLs.** The visited set is keyed by (method, host, path,
    *sorted parameter names*), so ``?id=1`` and ``?id=2`` are one location — the
    calendar/id trap that drowns naive crawlers is avoided, and each distinct
    parameterised endpoint is still discovered once.
  * **Scope is enforced, egress is contained.** Off-host and non-HTTP links are
    never fetched or enqueued, so a crawl of an authorized target cannot wander
    to a third party (the SSRF-safe default).
  * **Forms become requests.** A ``<form>`` is parsed into method + resolved
    action + auto-filled inputs and rendered as a GET (query) or POST (urlencoded
    body) request, so form-reached surface is scanned too.
  * **Deterministic and bounded.** Breadth-first in document order, no clock, no
    randomness; ``max_pages`` and ``max_depth`` bound the walk.

It performs no I/O itself: a ``send`` callable is injected (the gated executor in
production, a loopback client in tests), so authorization stays enforced.
"""

from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .checks import Send
from .insertion import HttpRequest, _encode_pairs


# ---------------------------------------------------------------------------
# link / form extraction (real HTML parsing, not regex)
# ---------------------------------------------------------------------------

_LINK_ATTR = {"a": "href", "link": "href", "area": "href",
              "script": "src", "img": "src", "iframe": "src", "frame": "src"}


class _Form(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str = "GET"
    action: str = ""
    inputs: list[tuple[str, str, str]] = Field(default_factory=list)  # (name, value, type)


class _Extractor(HTMLParser):
    """Collects hrefs/srcs and forms (with their named inputs) from one page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[_Form] = []
        self._form: _Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        attr = _LINK_ATTR.get(tag)
        if attr and a.get(attr):
            self.links.append(a[attr])
        elif tag == "form":
            self._form = _Form(
                method=(a.get("method") or "GET").upper() or "GET",
                action=a.get("action", ""),
            )
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form.inputs.append((name, a.get("value", ""), a.get("type", "text").lower()))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)  # self-closing <input/>

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:  # type: ignore[override]
        super().close()
        if self._form is not None:  # unterminated <form> — keep what we found
            self.forms.append(self._form)
            self._form = None


# ---------------------------------------------------------------------------
# scope, results
# ---------------------------------------------------------------------------


class Scope(BaseModel):
    """In-scope = same host and path under ``path_prefix`` (HTTP/S only). This
    is the egress boundary: nothing outside it is fetched or enqueued."""

    model_config = ConfigDict(extra="forbid")

    host: str
    path_prefix: str = "/"

    @classmethod
    def from_seed(cls, seed_url: str) -> "Scope":
        sp = urlsplit(seed_url)
        prefix = sp.path.rsplit("/", 1)[0] + "/" if "/" in sp.path else "/"
        return cls(host=sp.netloc, path_prefix=prefix or "/")

    def in_scope(self, url: str) -> bool:
        sp = urlsplit(url)
        if sp.scheme not in ("http", "https"):
            return False
        if sp.netloc != self.host:
            return False
        return sp.path.startswith(self.path_prefix)


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    status: int = 0


class CrawlResult(BaseModel):
    """What a crawl found: the fuzzable requests (ready for ``AuditEngine.audit``),
    the visited pages (site map), and the location count."""

    model_config = ConfigDict(extra="forbid")

    requests: list[HttpRequest] = Field(default_factory=list)
    pages: list[Page] = Field(default_factory=list)
    locations: int = 0


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

# Benign auto-fill values by input type — enough to make a form submit succeed
# without carrying an attack payload (the audit engine fuzzes afterwards).
_FILL = {
    "email": "test@example.com", "number": "1", "tel": "1", "url": "https://example.com",
    "password": "Passw0rd!", "date": "2020-01-01", "checkbox": "on", "radio": "on",
    "hidden": "", "search": "test", "text": "test",
}
_SKIP_INPUT_TYPES = frozenset({"submit", "button", "reset", "image", "file"})


class Crawler:
    """Breadth-first, scope-bounded, cycle-safe crawler. ``send(HttpRequest) ->
    {status, body}`` is injected. Construct with a seed and call :meth:`crawl`."""

    def __init__(
        self,
        send: Send,
        *,
        scope: Scope | None = None,
        max_pages: int = 200,
        max_depth: int = 8,
    ) -> None:
        self._send = send
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth

    def crawl(self, seed_url: str) -> CrawlResult:
        scope = self.scope or Scope.from_seed(seed_url)
        frontier: deque[tuple[str, int]] = deque([(seed_url, 0)])
        visited: set[str] = set()
        pages: list[Page] = []
        requests: list[HttpRequest] = []
        req_keys: set[str] = set()

        while frontier and len(pages) < self.max_pages:
            url, depth = frontier.popleft()
            loc = _location("GET", url)
            if loc in visited:
                continue
            visited.add(loc)

            req = HttpRequest(method="GET", url=url)
            resp = self._send(req)
            status = int(resp.get("status", 0)) if isinstance(resp, dict) else 0
            pages.append(Page(url=url, status=status))
            _add_request(requests, req_keys, req)

            if depth >= self.max_depth:
                continue

            body = resp.get("body", "") if isinstance(resp, dict) else ""
            ex = _Extractor()
            try:
                ex.feed(body)
                ex.close()
            except Exception:  # malformed HTML must never crash a crawl
                pass

            for href in ex.links:
                nxt = urljoin(url, href).split("#", 1)[0]
                if scope.in_scope(nxt) and _location("GET", nxt) not in visited:
                    frontier.append((nxt, depth + 1))

            for form in ex.forms:
                freq = _form_to_request(url, form)
                if freq is None or not scope.in_scope(freq.url):
                    continue
                _add_request(requests, req_keys, freq)
                # A GET form is also a navigable location worth crawling.
                if freq.method == "GET" and _location("GET", freq.url) not in visited:
                    frontier.append((freq.url, depth + 1))

        return CrawlResult(requests=requests, pages=pages, locations=len(visited))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _location(method: str, url: str) -> str:
    """Canonical location key: identical param *names* (not values) collapse, so
    ``?id=1`` and ``?id=2`` are one location — the trap-avoidance rule."""
    sp = urlsplit(url)
    names = sorted(k for k, _ in parse_qsl(sp.query, keep_blank_values=True))
    return f"{method} {sp.scheme}://{sp.netloc}{sp.path}?{'&'.join(names)}"


def _add_request(requests: list[HttpRequest], keys: set[str], req: HttpRequest) -> None:
    key = _location(req.method, req.url) + ("#body" if req.body else "")
    if key in keys:
        return
    keys.add(key)
    requests.append(req)


def _form_to_request(page_url: str, form: _Form) -> HttpRequest | None:
    action = urljoin(page_url, form.action or "").split("#", 1)[0]
    if not action:
        return None
    pairs: list[tuple[str, str]] = []
    for name, value, itype in form.inputs:
        if itype in _SKIP_INPUT_TYPES:
            continue
        pairs.append((name, value if value else _FILL.get(itype, "test")))

    method = form.method if form.method in ("GET", "POST") else "GET"
    if method == "GET":
        sp = urlsplit(action)
        base = f"{sp.scheme}://{sp.netloc}{sp.path}" if sp.scheme else action.split("?", 1)[0]
        existing = parse_qsl(sp.query, keep_blank_values=True)
        query = _encode_pairs(existing + pairs)
        url = f"{base}?{query}" if query else base
        return HttpRequest(method="GET", url=url)

    body = _encode_pairs(pairs)
    return HttpRequest(
        method="POST",
        url=action,
        headers=[("Content-Type", "application/x-www-form-urlencoded"),
                 ("Content-Length", str(len(body.encode("utf-8"))))],
        body=body,
    )
