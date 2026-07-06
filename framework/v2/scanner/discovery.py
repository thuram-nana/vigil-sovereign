"""
scanner.discovery — the attack-surface discovery module.

A scanner can only test what it can find. The :class:`~scanner.crawler.Crawler`
walks the app graph one ``<a href>``/``<form>`` at a time, so it only ever sees
surface an HTML link points at. But the highest-yield bugs live on surface a
link-crawler never reaches: a forgotten ``/.env``, a Spring ``/actuator/env`` heap
dump, an endpoint that only appears as a string inside a bundled JS file, an API
route documented in ``swagger.json`` but linked nowhere, a parameter the server
reads but no form declares. This module finds that surface and hands it back as
concrete seeds and endpoint lists the crawler and audit engine can then drive.

Five capabilities, one boundary:

  * **Content discovery** — probe a curated wordlist of sensitive/common paths and
    report which ones are *reachable* (an interesting status, not a 404). This is
    an existence oracle, not a vulnerability oracle: a reachable ``/.git/config``
    is a lead, and the finding says so.
  * **Robots / sitemap ingestion** — turn the site's own ``robots.txt`` and
    ``sitemap.xml`` into extra crawl seeds (including the paths a site politely
    asks robots *not* to visit — exactly the interesting ones).
  * **JS endpoint + secret mining** — pull URL/path references and high-signal
    secrets out of JavaScript source, so single-page-app routes and leaked keys
    are surfaced without executing anything.
  * **API schema ingestion** — expand a published OpenAPI/Swagger document or a
    GraphQL introspection result into a concrete operation/field list to fuzz.
  * **Parameter mining** — harvest candidate (often hidden) parameter names from
    HTML/JS so the insertion-point engine has names to try.

Boundary and honesty, by construction:

  * It performs **no I/O itself**. Every request goes through an injected
    ``send`` callable — the scope/charter/kill-switch/egress-gated executor in
    production, a loopback client in tests — so authorization stays enforced and
    the whole module is deterministic and loopback-testable.
  * It reports **reachability and references, not exploitability**. A discovered
    path exists; a mined endpoint is referenced; a mined "secret" matched a
    high-signal pattern. Confirmation is the audit engine's and the oracle's job.
  * JS mining is **regex, not a JS parser** — high precision on the patterns it
    knows, blind to obfuscated or dynamically-assembled URLs. Pure stdlib (``re``,
    ``json``, ``urllib.parse``, ``html``); no bs4, no headless browser.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .checks import Send
from .insertion import HttpRequest


# ---------------------------------------------------------------------------
# result models
# ---------------------------------------------------------------------------


class DiscoveredPath(BaseModel):
    """One reachable path found by content discovery. ``status`` is the observed
    HTTP status; ``excerpt`` is a short, whitespace-collapsed body sample kept as
    evidence. This records *existence/reachability*, not a vulnerability."""

    model_config = ConfigDict(extra="forbid")

    path: str
    status: int
    content_type: str = ""
    excerpt: str = ""


class JsSecret(BaseModel):
    """A high-signal secret matched in JS source. ``kind`` names the pattern that
    fired (e.g. ``aws_access_key_id``); ``snippet`` is the surrounding context."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    value: str
    snippet: str = ""


class JsFindings(BaseModel):
    """What JS mining pulled out of one source file: referenced endpoints and
    matched secrets, both deduplicated and in first-seen order."""

    model_config = ConfigDict(extra="forbid")

    endpoints: list[str] = Field(default_factory=list)
    secrets: list[JsSecret] = Field(default_factory=list)


class ApiOperation(BaseModel):
    """One operation lifted from an OpenAPI/Swagger document — a method+path pair
    plus the declared parameter names, ready to render into fuzzable requests."""

    model_config = ConfigDict(extra="forbid")

    method: str
    path: str
    params: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# content discovery
# ---------------------------------------------------------------------------

# A status is "interesting" — evidence the resource exists — when it is anything
# other than a not-found. We list the positive signals explicitly (present /
# auth-gated / forbidden / server-error) rather than "not 404" so a soft-404 that
# returns 200 is still caught by the caller's own diffing, and redirects are
# deliberately excluded (they usually mean "go to the login page", not "exists").
_INTERESTING_STATUSES = frozenset({200, 401, 403, 500})

# The built-in wordlist: ~130 curated sensitive/common paths. Ordered so the
# highest-signal secrets-on-disk entries come first (a tight `max` still probes
# the paths most worth probing). All entries are root-anchored ('/'-prefixed).
CONTENT_WORDLIST: tuple[str, ...] = (
    # secrets / VCS / dotfiles on disk
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore",
    "/.svn/entries", "/.hg/store", "/.bzr/branch-format",
    "/.DS_Store", "/.htaccess", "/.htpasswd", "/.npmrc",
    "/.aws/credentials", "/.ssh/id_rsa", "/.bash_history", "/.dockerignore",
    # config files
    "/config.php", "/config.json", "/config.yml", "/config.yaml",
    "/configuration.php", "/settings.py", "/wp-config.php", "/web.config",
    "/appsettings.json", "/application.properties", "/application.yml",
    "/docker-compose.yml", "/Dockerfile", "/package.json", "/package-lock.json",
    "/composer.json", "/composer.lock", "/yarn.lock", "/Gemfile",
    "/.travis.yml", "/.gitlab-ci.yml", "/Jenkinsfile",
    # spring-boot actuators / runtime introspection
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/loggers",
    "/env", "/health", "/info", "/metrics", "/trace", "/heapdump", "/dump",
    # admin / auth surfaces
    "/admin", "/admin/", "/administrator", "/administrator/", "/admin/login",
    "/admin.php", "/login", "/wp-admin/", "/wp-login.php", "/user/login",
    "/manage", "/management", "/console", "/portal", "/dashboard",
    "/cpanel", "/phpmyadmin/", "/adminer.php", "/pma/",
    # api / docs / schema
    "/api", "/api/", "/api/v1", "/api/v2", "/rest", "/graphql", "/graphiql",
    "/swagger.json", "/openapi.json", "/swagger.yaml", "/swagger-ui.html",
    "/swagger-ui/", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/redoc",
    "/wp-json/", "/xmlrpc.php",
    # server status / debug endpoints
    "/server-status", "/server-info", "/status", "/stats", "/debug",
    "/debug/vars", "/phpinfo.php", "/info.php", "/test.php", "/nginx_status",
    # backups / archives
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/database.sql", "/backup/", "/backups/", "/old/", "/site.tar.gz",
    "/www.zip", "/web.zip",
    # well-known / policy files
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/.well-known/security.txt", "/security.txt",
    "/humans.txt", "/ads.txt", "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json", "/.well-known/change-password",
    # infrastructure-as-code / CI state
    "/terraform.tfstate", "/.terraform/", "/cloud-config.yml",
    "/.circleci/config.yml",
    # common content directories / logs
    "/uploads/", "/files/", "/tmp/", "/logs/", "/error.log", "/access.log",
    "/README.md", "/CHANGELOG.md", "/LICENSE", "/wp-content/", "/favicon.ico",
)


def discover_content(
    base_url: str,
    send: Send,
    *,
    wordlist: tuple[str, ...] | list[str] | None = None,
    extensions: tuple[str, ...] | list[str] = (),
    max: int = 1024,
) -> list[DiscoveredPath]:
    """Probe ``base_url`` for the paths in ``wordlist`` (default
    :data:`CONTENT_WORDLIST`) and return each one that responds with an
    interesting status (present / auth-gated / forbidden / server-error — *not* a
    404). ``extensions`` widens each non-directory word (``('.bak', '.old')`` also
    probes ``/config.php.bak`` …). Candidates are deduplicated and capped at
    ``max`` probes; only ``send`` is called, one GET per candidate, so budget and
    rate are the caller's concern.

    Deterministic given ``send``: candidates are probed in wordlist order and
    results are returned in first-hit order. Reports *reachability*, not a
    vulnerability — a reachable ``/.git/config`` is a lead to confirm, not a
    finding."""
    words = tuple(wordlist) if wordlist is not None else CONTENT_WORDLIST
    exts = [e if e.startswith(".") else f".{e}" for e in extensions]
    candidates = _candidate_paths(words, exts)[: max if max > 0 else 0]

    out: list[DiscoveredPath] = []
    seen: set[str] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        resp = send(HttpRequest(method="GET", url=urljoin(base_url, path)))
        if not isinstance(resp, dict):
            continue
        status = int(resp.get("status", 0) or 0)
        if status not in _INTERESTING_STATUSES:
            continue
        headers = resp.get("headers", []) or []
        body = resp.get("body", "") or ""
        out.append(DiscoveredPath(
            path=path,
            status=status,
            content_type=_content_type(headers),
            excerpt=_excerpt(body if isinstance(body, str) else ""),
        ))
    return out


def _candidate_paths(words: tuple[str, ...], exts: list[str]) -> list[str]:
    """Expand words × extensions into a deduplicated, order-preserving list."""
    seen: set[str] = set()
    out: list[str] = []
    for word in words:
        for cand in _expand_word(word, exts):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


def _expand_word(word: str, exts: list[str]) -> list[str]:
    out = [word]
    if not word.endswith("/"):
        for ext in exts:
            if not word.endswith(ext):
                out.append(word + ext)
    return out


def _content_type(headers: list) -> str:
    for k, v in headers:
        if str(k).lower() == "content-type":
            return str(v).split(";", 1)[0].strip().lower()
    return ""


def _excerpt(body: str, limit: int = 160) -> str:
    text = " ".join(body.split())
    return text[:limit] + ("…" if len(text) > limit else "")


# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml ingestion
# ---------------------------------------------------------------------------


def parse_robots(text: str) -> list[str]:
    """Extract crawl seeds from a ``robots.txt``: every ``Disallow``/``Allow``
    path and every ``Sitemap:`` URL, in document order, deduplicated. The
    Disallow list is a feature, not a courtesy to honour — those are the paths
    the site most wants left alone, and therefore the ones most worth a look."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field in ("disallow", "allow"):
            if value and value not in seen:
                seen.add(value)
                out.append(value)
        elif field == "sitemap":
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


def parse_sitemap(xml: str) -> list[str]:
    """Extract every ``<loc>`` URL from a ``sitemap.xml`` (or a sitemap-index),
    XML-unescaped and deduplicated, in document order."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _LOC.finditer(xml):
        url = html.unescape(m.group(1)).strip()
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


# ---------------------------------------------------------------------------
# JS endpoint + secret mining
# ---------------------------------------------------------------------------

# Every single/double/backtick string literal (with escape handling), captured so
# endpoints and quoted secret values can be examined without a JS parser.
_JS_STRING = re.compile(r"""(['"`])((?:\\.|(?!\1).)*?)\1""", re.S)

# Endpoint-likeness tests applied to a literal's *content*.
_ABS_URL = re.compile(r"""^https?://[^\s'"`<>]+$""", re.I)
_PROTO_REL = re.compile(r"""^//[^\s'"`<>/][^\s'"`<>]*$""")
_ABS_PATH = re.compile(r"""^/[A-Za-z0-9_.~%${}\-][^\s'"`<>]*$""")

# High-signal secret patterns. Each is specific enough that a match is itself the
# signal — no entropy heuristic needed. The generic ``key = "value"`` case is
# handled separately below, behind a plausibility guard, because it is the only
# false-positive-prone one.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
)

_GENERIC_SECRET = re.compile(
    r"""
    \b( api[_-]?key | secret(?:[_-]?key)? | client[_-]?secret |
        access[_-]?token | auth[_-]?token | refresh[_-]?token |
        token | passwd | password )\b
    \s* [:=] \s*
    (['"]) ([^'"\n]{8,128}) \2
    """,
    re.I | re.X,
)

_TOKENISH = re.compile(r"^[A-Za-z0-9_\-./+=~]{8,128}$")
_PLACEHOLDERS = frozenset({
    "null", "undefined", "none", "true", "false", "example", "changeme",
    "test", "password", "secret", "apikey", "your_api_key", "yourapikey",
    "todo", "placeholder", "redacted", "xxxxxxxx",
})
_PLACEHOLDER_SUBSTR = (
    "your_", "yourapi", "example", "changeme", "placeholder", "redacted",
    "xxxxx", "dummy", "sample", "<", "fixme", "fake",
)


def mine_js(js_source: str, *, base_url: str = "") -> JsFindings:
    """Mine one JavaScript source for referenced endpoints and leaked secrets.

    ``endpoints`` are absolute URLs, protocol-relative URLs, and root-anchored
    paths found in string literals (so ``fetch('/api/x')`` and
    ``axios.get('https://…')`` are both caught); when ``base_url`` is given they
    are resolved against it. ``secrets`` are matches of the high-signal patterns
    in :data:`_SECRET_PATTERNS` plus guarded ``key = "value"`` assignments. Both
    lists are deduplicated and in first-seen order.

    Regex, not a parser: precise on the shapes it knows, blind to obfuscated or
    runtime-assembled URLs/keys."""
    return JsFindings(
        endpoints=_mine_endpoints(js_source, base_url),
        secrets=_mine_secrets(js_source),
    )


def _mine_endpoints(js_source: str, base_url: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _JS_STRING.finditer(js_source):
        content = _js_unescape(m.group(2))
        if not (_ABS_URL.match(content) or _PROTO_REL.match(content)
                or _ABS_PATH.match(content)):
            continue
        ep = content
        if base_url and not (content.startswith("http") or content.startswith("//")):
            ep = urljoin(base_url, content)
        if ep not in seen:
            seen.add(ep)
            out.append(ep)
    return out


def _mine_secrets(js_source: str) -> list[JsSecret]:
    out: list[JsSecret] = []
    seen: set[tuple[str, str]] = set()
    structured_values: set[str] = set()

    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(js_source):
            value = m.group(0)
            structured_values.add(value)
            _add_secret(out, seen, kind, value, js_source, m.start(), m.end())

    for m in _GENERIC_SECRET.finditer(js_source):
        value = m.group(3)
        if value in structured_values or not _plausible_secret(value):
            continue
        _add_secret(out, seen, "generic_secret", value, js_source, m.start(3), m.end(3))

    return out


def _add_secret(
    out: list[JsSecret], seen: set[tuple[str, str]], kind: str, value: str,
    source: str, start: int, end: int,
) -> None:
    key = (kind, value)
    if key in seen:
        return
    seen.add(key)
    out.append(JsSecret(kind=kind, value=value, snippet=_snippet(source, start, end)))


def _plausible_secret(value: str) -> bool:
    """Guard the generic ``key = "value"`` match against obvious non-secrets: a
    placeholder, a non-token-shaped value, or a short low-entropy string."""
    v = value.strip()
    low = v.lower()
    if low in _PLACEHOLDERS or any(sub in low for sub in _PLACEHOLDER_SUBSTR):
        return False
    if not _TOKENISH.match(v):
        return False
    if len(v) >= 20:
        return True
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    return has_digit and has_alpha


def _js_unescape(s: str) -> str:
    return s.replace("\\/", "/").replace("\\\\", "\\")


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    lo = start - pad if start - pad > 0 else 0
    hi = end + pad if end + pad < len(text) else len(text)
    return ("…" if lo else "") + text[lo:hi].replace("\n", " ") + ("…" if hi < len(text) else "")


# ---------------------------------------------------------------------------
# API schema ingestion (OpenAPI / Swagger, GraphQL introspection)
# ---------------------------------------------------------------------------

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "options", "head", "trace"})


def parse_openapi(doc: dict | str) -> list[ApiOperation]:
    """Walk an OpenAPI 3 / Swagger 2 document's ``paths`` into a flat list of
    :class:`ApiOperation`s (method + path + declared parameter names). Path-level
    ``parameters`` are merged into every operation under that path. Accepts a
    parsed dict or a JSON string; unparseable input yields an empty list."""
    data = _as_obj(doc)
    paths = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(paths, dict):
        return []
    out: list[ApiOperation] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = _param_names(item.get("parameters"))
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            params = list(shared)
            if isinstance(op, dict):
                for name in _param_names(op.get("parameters")):
                    if name not in params:
                        params.append(name)
            out.append(ApiOperation(method=method.upper(), path=str(path), params=params))
    return out


def _param_names(params: Any) -> list[str]:
    out: list[str] = []
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict):
                name = p.get("name")
                if isinstance(name, str) and name and name not in out:
                    out.append(name)
    return out


def parse_graphql_schema(introspection: dict | str) -> list[str]:
    """Extract type and field names from a GraphQL introspection result (the
    ``{data:{__schema:{types:[…]}}}`` shape, or any inner slice of it). Meta
    (``__``-prefixed) names are skipped. Returns a deduplicated, ordered list —
    a concrete map of the schema's surface to probe."""
    schema = _as_obj(introspection)
    if not isinstance(schema, dict):
        return []
    if isinstance(schema.get("data"), dict):
        schema = schema["data"]
    if isinstance(schema.get("__schema"), dict):
        schema = schema["__schema"]
    types = schema.get("types")
    out: list[str] = []
    seen: set[str] = set()

    def add(name: Any) -> None:
        if isinstance(name, str) and name and not name.startswith("__") and name not in seen:
            seen.add(name)
            out.append(name)

    if isinstance(types, list):
        for t in types:
            if not isinstance(t, dict):
                continue
            add(t.get("name"))
            for coll in ("fields", "inputFields"):
                fields = t.get(coll)
                if isinstance(fields, list):
                    for fld in fields:
                        if isinstance(fld, dict):
                            add(fld.get("name"))
    return out


def _as_obj(doc: dict | str) -> Any:
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except (ValueError, TypeError):
            return {}
    return doc


# ---------------------------------------------------------------------------
# parameter mining
# ---------------------------------------------------------------------------

_PARAM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""\bname\s*=\s*['"]([A-Za-z_][\w\-]*)['"]"""),          # name="x" / <input name=...>
    re.compile(r"""\bid\s*=\s*['"]([A-Za-z_][\w\-]*)['"]"""),           # id="x"
    re.compile(r"""\.get\(\s*['"]([A-Za-z_][\w\-]*)['"]"""),            # params.get('x'), args.get("x")
    re.compile(r"""\b(?:query|body|params|args)\.([A-Za-z_]\w*)"""),    # req.query.x, req.body.x
    re.compile(r"""\[\s*['"]([A-Za-z_][\w\-]*)['"]\s*\]"""),            # data['x'], req.body["x"]
)

# Method/accessor names the dotted/bracket patterns catch that are never
# parameters — dropped so the candidate list stays clean.
_PARAM_STOP = frozenset({
    "get", "post", "put", "set", "has", "map", "filter", "forEach", "then",
    "catch", "json", "length", "push", "pop", "keys", "values", "entries",
    "toString", "hasOwnProperty",
})


def mine_params(html_or_js: str) -> list[str]:
    """Harvest candidate (often hidden) parameter names from HTML or JS: form
    ``name=``/``id=`` attributes, ``params.get('x')`` / ``args.get('x')`` reads,
    ``req.query.x`` / ``req.body.x`` accessors, and ``data['x']`` indexing.
    Deduplicated, in first-seen order, with common accessor method names dropped.
    Candidates for the insertion-point engine to try — not confirmed parameters."""
    out: list[str] = []
    seen: set[str] = set()
    for rx in _PARAM_PATTERNS:
        for m in rx.finditer(html_or_js):
            name = m.group(1)
            if name in _PARAM_STOP or name in seen:
                continue
            seen.add(name)
            out.append(name)
    return out
