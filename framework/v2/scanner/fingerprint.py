"""
scanner.fingerprint — deterministic technology-stack fingerprinting.

A scan is only as good as its aim. Firing a WordPress plugin-enumeration payload
at a Spring service, or a `.aspx` viewstate probe at nginx+PHP, is wasted budget
and needless noise — worse, it is the kind of blind spraying that a defender's
logs flag as a dumb scanner rather than a careful operator. Burp leans on a human
who *reads the response and knows* "this is Rails"; this module is that knowledge
as code. From the responses the crawler already collected it identifies the
server, language, framework, CMS, CDN, WAF and API-gateway in play, and exposes a
flat set of :attr:`Fingerprint.tokens` that the check library gates on — so a
check declares ``applies_when: {"tech": "wordpress"}`` and simply never runs
against a target that isn't WordPress.

Design, matching the rest of the scanner:

  * **Pure and deterministic.** It sends nothing, reads no clock, draws no
    randomness. It takes already-observed responses and returns a fingerprint;
    the same input yields a byte-identical :class:`Fingerprint`.
  * **Declarative signatures.** The evidence base is a flat, auditable table of
    :class:`Signature` rows (one observable signal each: a header regex, a cookie
    name, a body regex, a `<meta generator>`, or a path hint). A small matching
    loop is the whole engine; adding coverage means adding a data row, not code.
  * **Stdlib only.** HTML is parsed with :mod:`html.parser` (no BeautifulSoup),
    hashing with :mod:`hashlib`; there are no third-party dependencies.
  * **Honest about confidence.** Each signal carries a calibrated confidence, and
    duplicate detections merge to the strongest with unioned evidence, so a
    caller can distinguish "the Server banner literally says nginx" (near-certain)
    from "a JSESSIONID cookie suggests Java" (indicative).

Framework/CMS detections also imply their runtime language (WordPress -> PHP,
Django -> Python, Rails -> Ruby, Spring -> Java, ...); the implication is recorded
as its own lower-confidence match so the language token is present for gating even
when no language banner leaked.

Boundary: this module classifies bytes. It never fetches the favicon or any page
itself — callers hand it what the gated executor already retrieved.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..common.errors import CrucibleError
from .passive import Response


# ---------------------------------------------------------------------------
# recoverable errors (CrucibleError subclasses — never an ethics decision)
# ---------------------------------------------------------------------------


class MalformedResponse(CrucibleError):
    """A value handed to :func:`fingerprint` could not be read as an HTTP
    response — it exposes none of url/status/headers/body and is not a mapping.
    Recoverable: the caller passed the wrong shape, not a scope violation."""


class MalformedPredicate(CrucibleError):
    """An ``applies_when`` predicate uses an unrecognised node or a node of the
    wrong shape (e.g. ``any`` whose value is not a list). Recoverable: the check
    library author wrote a bad predicate; surface it, don't silently drop it."""


# ---------------------------------------------------------------------------
# public models
# ---------------------------------------------------------------------------

# The closed set of categories a signature may declare. `other` is the escape
# hatch; everything a check gates on should map to one of the first eight.
CATEGORIES = (
    "server", "language", "framework", "cms",
    "cdn", "waf", "api_gateway", "analytics", "other",
)


class TechMatch(BaseModel):
    """One detected technology and the concrete signal that betrayed it.

    ``name`` is lowercased and stable (``"nginx"``, ``"php"``, ``"wordpress"``);
    ``category`` is one of :data:`CATEGORIES`; ``confidence`` is calibrated per
    signal (a literal Server banner scores near 1.0, a renameable cookie lower);
    ``evidence`` is human-readable and points at the observed bytes (``"Server:
    nginx/1.24"``, ``'meta generator "WordPress 6.4"'``, ``'"/wp-content" path'``)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""


class Fingerprint(BaseModel):
    """The merged technology fingerprint of a target: one :class:`TechMatch` per
    (name, category), strongest-confidence kept, evidence unioned.

    The integration contract other M1 modules depend on is :attr:`tokens` — the
    lowercased union of technology names and their categories. A check's
    ``applies_when`` predicate is evaluated against exactly this set, so gating is
    a set-membership test and nothing more (see :func:`matches_predicate`).

    Matches are held in a canonical order (by category then name), so two
    fingerprints of the same input serialise identically."""

    model_config = ConfigDict(extra="forbid")

    matches: list[TechMatch] = Field(default_factory=list)

    @model_validator(mode="after")
    def _canonicalise(self) -> "Fingerprint":
        # Canonical, deterministic ordering regardless of how the model was
        # built, so model_dump() is stable input-for-input.
        self.matches = sorted(
            self.matches,
            key=lambda t: (t.category, t.name, -t.confidence, t.evidence),
        )
        return self

    @property
    def technologies(self) -> set[str]:
        """The lowercased technology names present (e.g. ``{"nginx", "php"}``)."""
        return {m.name for m in self.matches}

    @property
    def categories(self) -> set[str]:
        """The categories present (e.g. ``{"server", "language", "cms"}``)."""
        return {m.category for m in self.matches}

    @property
    def tokens(self) -> set[str]:
        """The union of :attr:`technologies` and :attr:`categories` — THE gating
        contract. A check runs iff its predicate is satisfied by this set."""
        return self.technologies | self.categories

    def has(self, name: str) -> bool:
        """True if ``name`` (a tech name or a category) is in :attr:`tokens`."""
        return name.lower() in self.tokens

    def best(self, name: str) -> TechMatch | None:
        """The highest-confidence match for a technology name, or ``None``."""
        cands = [m for m in self.matches if m.name == name.lower()]
        return max(cands, key=lambda m: m.confidence) if cands else None

    def describe(self) -> str:
        """A one-line, deterministic summary grouped by category, e.g.
        ``"server: nginx | language: php | cms: wordpress"``."""
        if not self.matches:
            return "no technologies fingerprinted"
        by_cat: dict[str, list[str]] = {}
        for m in self.matches:  # already sorted by (category, name)
            names = by_cat.setdefault(m.category, [])
            if m.name not in names:
                names.append(m.name)
        return " | ".join(f"{cat}: {', '.join(names)}" for cat, names in by_cat.items())


# ---------------------------------------------------------------------------
# signature model — one observable signal per row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    """A single detection rule: it fires on exactly one observable, producing a
    :class:`TechMatch` for ``name``/``category`` at ``confidence``.

    Exactly one matcher field is set per row (checked at import), which keeps
    every confidence value attributable to one concrete signal:

      * ``header`` — ``(name, value_regex)``; ``value_regex=""`` means presence
        alone is enough. Matched case-insensitively against every header of that
        name (so repeated Set-Cookie / Link headers are all considered).
      * ``cookie`` — a regex matched against Set-Cookie / Cookie *names*.
      * ``generator`` — a regex matched against ``<meta name=generator>`` content.
      * ``path`` — a literal substring expected in the body or a header value
        (e.g. ``/wp-content``); the cheap "this app references X" hint.
      * ``body`` — a regex matched against the raw body.

    ``note`` is an optional analyst annotation (e.g. why a signal is weak)."""

    name: str
    category: str
    confidence: float
    header: tuple[str, str] | None = None
    cookie: str | None = None
    generator: str | None = None
    path: str | None = None
    body: str | None = None
    note: str = ""

    def matchers(self) -> tuple[str, ...]:
        return tuple(
            k for k in ("header", "cookie", "generator", "path", "body")
            if getattr(self, k) is not None
        )


# ---------------------------------------------------------------------------
# the signature library (declarative data)
# ---------------------------------------------------------------------------

# fmt: off
SIGNATURES: tuple[Signature, ...] = (
    # --- servers ---------------------------------------------------------
    Signature("nginx",     "server", 0.98, header=("Server", r"nginx")),
    Signature("openresty", "server", 0.97, header=("Server", r"openresty")),
    Signature("apache",    "server", 0.97, header=("Server", r"apache")),
    Signature("iis",       "server", 0.97, header=("Server", r"microsoft-iis")),
    Signature("litespeed", "server", 0.97, header=("Server", r"litespeed")),
    Signature("caddy",     "server", 0.95, header=("Server", r"caddy")),
    Signature("tomcat",    "server", 0.9,  header=("Server", r"tomcat|coyote")),
    Signature("jetty",     "server", 0.9,  header=("Server", r"jetty")),

    # --- languages -------------------------------------------------------
    Signature("php",     "language", 0.98, header=("X-Powered-By", r"php")),
    Signature("php",     "language", 0.75, cookie=r"^PHPSESSID$",
              note="default session cookie name; renameable"),
    Signature("asp.net", "language", 0.95, header=("X-Powered-By", r"asp\.net")),
    Signature("asp.net", "language", 0.9,  header=("X-AspNet-Version", r"")),
    Signature("asp.net", "language", 0.85, cookie=r"^ASP\.NET_SessionId$"),
    Signature("java",    "language", 0.8,  cookie=r"^JSESSIONID$",
              note="servlet-container session; also Tomcat/Jetty"),
    Signature("python",  "language", 0.7,  header=("Server", r"python|werkzeug|gunicorn|uvicorn|waitress|wsgiserver"),
              note="WSGI/ASGI server banners imply Python"),
    Signature("ruby",    "language", 0.85, header=("X-Powered-By", r"phusion passenger")),
    Signature("ruby",    "language", 0.6,  header=("Server", r"passenger|puma|webrick|thin|unicorn")),

    # --- frameworks ------------------------------------------------------
    Signature("express",     "framework", 0.9,  header=("X-Powered-By", r"express")),
    Signature("django",      "framework", 0.85, cookie=r"^csrftoken$"),
    Signature("django",      "framework", 0.9,  body=r"csrfmiddlewaretoken"),
    Signature("rails",       "framework", 0.85, cookie=r"^_[A-Za-z0-9]+_session$"),
    Signature("rails",       "framework", 0.85, body=r'name=["\']?authenticity_token'),
    Signature("rails",       "framework", 0.55, header=("X-Runtime", r""),
              note="Rack timing header; Rails default but any Rack app can set it"),
    Signature("laravel",     "framework", 0.9,  cookie=r"^laravel_session$"),
    Signature("laravel",     "framework", 0.6,  cookie=r"^XSRF-TOKEN$",
              note="also emitted by Angular clients"),
    Signature("laravel",     "framework", 0.9,  cookie=r"^laravel_token$"),
    Signature("spring",      "framework", 0.9,  header=("X-Application-Context", r"")),
    Signature("spring",      "framework", 0.85, body=r"Whitelabel Error Page"),
    Signature("flask",       "framework", 0.6,  header=("Server", r"werkzeug"),
              note="Werkzeug is Flask's dev server; absent behind a real front end"),
    Signature("asp.net-mvc", "framework", 0.9,  header=("X-AspNetMvc-Version", r"")),
    Signature("symfony",     "framework", 0.8,  header=("X-Debug-Token", r"")),
    Signature("angular",     "framework", 0.8,  body=r"ng-version=|\sng-app[=\s>]"),
    Signature("next.js",     "framework", 0.85, body=r'id=["\']__NEXT_DATA__'),

    # --- CMS -------------------------------------------------------------
    Signature("wordpress", "cms", 0.85, path="/wp-content"),
    Signature("wordpress", "cms", 0.85, path="/wp-includes"),
    Signature("wordpress", "cms", 0.8,  path="/wp-json"),
    Signature("wordpress", "cms", 0.95, generator=r"WordPress"),
    Signature("wordpress", "cms", 0.75, cookie=r"^(wordpress_|wp-settings)"),
    Signature("drupal",    "cms", 0.9,  header=("X-Generator", r"Drupal")),
    Signature("drupal",    "cms", 0.95, generator=r"Drupal"),
    Signature("drupal",    "cms", 0.8,  path="/sites/default"),
    Signature("drupal",    "cms", 0.9,  header=("X-Drupal-Cache", r"")),
    Signature("joomla",    "cms", 0.85, path="/media/jui"),
    Signature("joomla",    "cms", 0.95, generator=r"Joomla"),
    Signature("joomla",    "cms", 0.8,  body=r"option=com_|/media/system/js"),
    Signature("magento",   "cms", 0.85, body=r"Mage\.Cookies|/skin/frontend/|/static/(?:version\d+/)?frontend/"),
    Signature("magento",   "cms", 0.9,  header=("X-Magento-Cache-Debug", r"")),
    Signature("ghost",     "cms", 0.9,  generator=r"Ghost"),

    # --- CDN / edge ------------------------------------------------------
    Signature("cloudflare", "cdn", 0.97, header=("CF-RAY", r"")),
    Signature("cloudflare", "cdn", 0.9,  header=("Server", r"cloudflare")),
    Signature("akamai",     "cdn", 0.9,  header=("Server", r"akamaighost")),
    Signature("akamai",     "cdn", 0.85, header=("X-Akamai-Transformed", r"")),
    Signature("fastly",     "cdn", 0.75, header=("X-Served-By", r"cache-|fastly"),
              note="Fastly's Varnish edge tag; some non-Fastly Varnish also emits it"),
    Signature("fastly",     "cdn", 0.9,  header=("X-Fastly-Request-ID", r"")),
    Signature("cloudfront", "cdn", 0.95, header=("X-Amz-Cf-Id", r"")),
    Signature("cloudfront", "cdn", 0.9,  header=("Via", r"cloudfront")),

    # --- WAF -------------------------------------------------------------
    Signature("cloudflare",  "waf", 0.5,  header=("CF-RAY", r""),
              note="Cloudflare in path implies WAF capability, not that rules are on"),
    Signature("akamai",      "waf", 0.5,  header=("Server", r"akamaighost"),
              note="Kona/App-&-API-Protector capability, not confirmed enabled"),
    Signature("imperva",     "waf", 0.9,  cookie=r"^visid_incap"),
    Signature("imperva",     "waf", 0.9,  cookie=r"^incap_ses"),
    Signature("imperva",     "waf", 0.85, header=("X-Iinfo", r"")),
    Signature("f5-big-ip",   "waf", 0.85, cookie=r"^BIGipServer"),
    Signature("f5-big-ip",   "waf", 0.6,  cookie=r"^TS[0-9a-fA-F]{6,}$",
              note="BIG-IP ASM cookie; heuristic, can collide"),
    Signature("mod_security", "waf", 0.8, body=r"Mod_?Security|This error was generated by Mod_Security|blocked by mod_security"),
    Signature("aws-waf",     "waf", 0.5,  header=("X-Amzn-Waf-Action", r""),
              note="rarely surfaced; AWS WAF is usually invisible in headers"),
    Signature("sucuri",      "waf", 0.9,  header=("X-Sucuri-ID", r"")),

    # --- API gateways ----------------------------------------------------
    Signature("kong",            "api_gateway", 0.85, header=("Via", r"kong")),
    Signature("kong",            "api_gateway", 0.9,  header=("X-Kong-Upstream-Latency", r"")),
    Signature("aws-api-gateway", "api_gateway", 0.75, header=("x-amzn-RequestId", r""),
              note="also set by other AWS services fronted by API Gateway"),
    Signature("aws-api-gateway", "api_gateway", 0.85, header=("x-amz-apigw-id", r"")),
    Signature("apigee",          "api_gateway", 0.85, header=("X-Apigee-mplb-nonprod-target", r"")),

    # --- analytics / third-party client tags -----------------------------
    Signature("google-analytics", "analytics", 0.85,
              body=r"google-analytics\.com|googletagmanager\.com/gtag|GoogleAnalyticsObject|gtag\("),
    Signature("hotjar",           "analytics", 0.85, body=r"static\.hotjar\.com|hj\(\s*['\"]"),
)
# fmt: on


# Framework/CMS -> its runtime stack. A confirmed framework detection implies the
# language/runtime it is written in even when no language banner leaked, so the
# gating token is present. The implied match is recorded at a discounted
# confidence and clearly labelled as inferred, never as an observed signal.
IMPLICATIONS: tuple[tuple[str, str, str], ...] = (
    ("wordpress", "php", "language"),
    ("drupal", "php", "language"),
    ("joomla", "php", "language"),
    ("magento", "php", "language"),
    ("laravel", "php", "language"),
    ("symfony", "php", "language"),
    ("django", "python", "language"),
    ("flask", "python", "language"),
    ("rails", "ruby", "language"),
    ("express", "node", "language"),
    ("next.js", "node", "language"),
    ("ghost", "node", "language"),
    ("spring", "java", "language"),
    ("tomcat", "java", "language"),
    ("jetty", "java", "language"),
)


# Validate the library shape once, at import: every row names a known category and
# carries exactly one matcher. A malformed signature is a bug in *our* data, so it
# should fail loud on import, not silently mis-detect at scan time.
def _validate_library() -> None:
    for sig in SIGNATURES:
        if sig.category not in CATEGORIES:
            raise CrucibleError(f"signature {sig.name!r} has unknown category {sig.category!r}")
        ms = sig.matchers()
        if len(ms) != 1:
            raise CrucibleError(
                f"signature {sig.name!r}/{sig.category} must set exactly one matcher, got {ms}"
            )
        if sig.name != sig.name.lower():
            raise CrucibleError(f"signature name {sig.name!r} must be lowercase")


_validate_library()


# ---------------------------------------------------------------------------
# favicon fingerprinting (stub table — see docstring)
# ---------------------------------------------------------------------------

# Illustrative fixtures only. A production build would hash the favicons of real
# products (the classic mmh3-of-the-base64 trick, here a stdlib md5 of the raw
# bytes) into this table from a crawled corpus; that corpus is future work. These
# entries exist so the code path is real and deterministically testable. Because
# the table is a stub, favicon matches are scored conservatively.
_KNOWN_FAVICONS: tuple[tuple[bytes, str, str, float], ...] = (
    (b"CRUCIBLE-FIXTURE:wordpress-favicon", "wordpress", "cms", 0.6),
    (b"CRUCIBLE-FIXTURE:gravatar-favicon", "gravatar", "analytics", 0.6),
    (b"CRUCIBLE-FIXTURE:django-admin-favicon", "django", "framework", 0.6),
)
_FAVICON_TABLE: dict[str, tuple[str, str, float]] = {
    hashlib.md5(raw).hexdigest(): (name, category, conf)
    for raw, name, category, conf in _KNOWN_FAVICONS
}


def fingerprint_favicon(favicon_bytes: bytes) -> TechMatch | None:
    """Identify a technology from its favicon by exact content hash.

    The favicon is hashed (md5 hex of the raw bytes — no mmh3 dependency) and
    looked up in a small known-favicon table. Returns a :class:`TechMatch` on a
    hit, ``None`` otherwise. The table is deliberately tiny (a stub); populating
    it from a real corpus of product favicons is future work, so a miss here is
    the common case and never authoritative — favicon evidence supplements the
    header/body signatures, it does not replace them."""
    if not favicon_bytes:
        return None
    digest = hashlib.md5(favicon_bytes).hexdigest()
    hit = _FAVICON_TABLE.get(digest)
    if hit is None:
        return None
    name, category, conf = hit
    return TechMatch(name=name, category=category, confidence=conf,
                     evidence=f"favicon hash md5:{digest}")


# ---------------------------------------------------------------------------
# predicate evaluation (the check library's `applies_when` grammar)
# ---------------------------------------------------------------------------


def matches_predicate(predicate: Mapping | None, tokens: set[str]) -> bool:
    """Evaluate an ``applies_when`` predicate against a token set.

    This is the exact grammar the check library uses to decide whether a check is
    relevant to a target. Because :attr:`Fingerprint.tokens` unions technology
    names and their categories, ``tech`` and ``category`` are both plain
    membership tests over ``tokens`` — the distinction documents intent.

    Grammar (all supported):

      * ``None`` / ``{}``            → always true (no constraint).
      * ``{"always": bool}``         → the literal boolean.
      * ``{"tech": "wordpress"}``    → token present.
      * ``{"category": "cms"}``      → token present.
      * ``{"any": [pred, ...]}``     → logical OR (empty ⇒ false).
      * ``{"all": [pred, ...]}``     → logical AND (empty ⇒ true).
      * ``{"not": pred}``            → negation.

    Raises :class:`MalformedPredicate` on an unrecognised node or a mis-shaped
    ``any``/``all`` — a broken predicate is surfaced, never silently treated as
    false (which would quietly disable a check)."""
    if predicate is None:
        return True
    if not isinstance(predicate, Mapping):
        raise MalformedPredicate(f"predicate must be a mapping or None, got {type(predicate).__name__}")
    if len(predicate) == 0:
        return True

    if "always" in predicate:
        return bool(predicate["always"])
    if "not" in predicate:
        return not matches_predicate(predicate["not"], tokens)
    if "any" in predicate:
        subs = predicate["any"]
        if not isinstance(subs, (list, tuple)):
            raise MalformedPredicate("'any' takes a list of predicates")
        return any(matches_predicate(p, tokens) for p in subs)
    if "all" in predicate:
        subs = predicate["all"]
        if not isinstance(subs, (list, tuple)):
            raise MalformedPredicate("'all' takes a list of predicates")
        return all(matches_predicate(p, tokens) for p in subs)
    if "tech" in predicate:
        return str(predicate["tech"]).lower() in tokens
    if "category" in predicate:
        return str(predicate["category"]).lower() in tokens

    raise MalformedPredicate(f"unrecognised predicate node: {sorted(predicate)}")


# ---------------------------------------------------------------------------
# HTML meta-generator extraction (stdlib parser, not regex-over-HTML)
# ---------------------------------------------------------------------------


class _MetaExtractor(HTMLParser):
    """Collects the content of every ``<meta name="generator">`` on a page —
    attribute order-independent, unlike a naive regex."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("name", "").strip().lower() == "generator" and a.get("content"):
            self.generators.append(a["content"].strip())

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)  # self-closing <meta/>


def _extract_generators(body: str) -> list[str]:
    if not body or "generator" not in body.lower():
        return []
    ex = _MetaExtractor()
    try:
        ex.feed(body)
        ex.close()
    except Exception:  # malformed HTML must never crash a fingerprint
        pass
    return ex.generators


# ---------------------------------------------------------------------------
# response coercion — accept Response / dict / duck-typed object
# ---------------------------------------------------------------------------

_COOKIE_NAME = re.compile(r"^\s*([^=;]+)=")


def _as_int(v: object) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _as_str(v: object) -> str:
    return "" if v is None else str(v)


def _norm_headers(h: object) -> list[tuple[str, str]]:
    """Normalise headers to an ordered list of (name, value) pairs, accepting a
    dict or an iterable of pairs (the two shapes callers hand us)."""
    if h is None:
        return []
    if isinstance(h, Mapping):
        return [(str(k), str(v)) for k, v in h.items()]
    out: list[tuple[str, str]] = []
    try:
        for item in h:  # type: ignore[union-attr]
            if isinstance(item, (tuple, list)) and len(item) >= 2:
                out.append((str(item[0]), str(item[1])))
    except TypeError:
        return []
    return out


def _coerce(obj: object) -> Response:
    """Read one arbitrary response-like value into a :class:`Response`. Missing
    fields default; a value that exposes none of the expected fields (a bare int,
    a stray string) is rejected as :class:`MalformedResponse`."""
    if isinstance(obj, Response):
        return obj
    if isinstance(obj, Mapping):
        return Response(
            url=_as_str(obj.get("url", "")),
            status=_as_int(obj.get("status", 0)),
            headers=_norm_headers(obj.get("headers")),
            body=_as_str(obj.get("body", "")),
        )
    if isinstance(obj, (str, bytes, bytearray, int, float, bool)) or obj is None:
        raise MalformedResponse(f"cannot read a response from {type(obj).__name__}")
    if not any(hasattr(obj, a) for a in ("url", "status", "headers", "body")):
        raise MalformedResponse(f"object exposes no url/status/headers/body: {type(obj).__name__}")
    return Response(
        url=_as_str(getattr(obj, "url", "")),
        status=_as_int(getattr(obj, "status", 0)),
        headers=_norm_headers(getattr(obj, "headers", None)),
        body=_as_str(getattr(obj, "body", "")),
    )


def _iter_responses(responses: object) -> list[object]:
    """Accept a single response or an iterable of them. A mapping or a
    :class:`Response` is a single response (both are also iterable, so they must
    be caught first)."""
    if responses is None:
        return []
    if isinstance(responses, (Response, Mapping, str, bytes, bytearray)):
        return [responses]
    if isinstance(responses, Iterable):
        return list(responses)
    return [responses]


def _cookie_names(resp: Response) -> list[str]:
    names: list[str] = []
    for raw in resp.headers_all("set-cookie") + resp.headers_all("cookie"):
        m = _COOKIE_NAME.match(raw)
        if m:
            names.append(m.group(1).strip())
    return names


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------


def _match_signature(
    sig: Signature,
    resp: Response,
    *,
    generators: list[str],
    cookie_names: list[str],
    body_lower: str,
) -> TechMatch | None:
    """Test one signature against one response; return a :class:`TechMatch` with
    concrete evidence on a hit, else ``None``."""
    if sig.header is not None:
        hname, value_re = sig.header
        for value in resp.headers_all(hname):
            if value_re == "" or re.search(value_re, value, re.I):
                return _mk(sig, f"{hname}: {value.strip()[:80]}")
        return None

    if sig.cookie is not None:
        for cn in cookie_names:
            if re.search(sig.cookie, cn, re.I):
                return _mk(sig, f'cookie "{cn}"')
        return None

    if sig.generator is not None:
        for g in generators:
            if re.search(sig.generator, g, re.I):
                return _mk(sig, f'meta generator "{g[:80]}"')
        return None

    if sig.path is not None:
        needle = sig.path.lower()
        if needle in body_lower or any(needle in v.lower() for _, v in resp.headers):
            return _mk(sig, f'"{sig.path}" path')
        return None

    if sig.body is not None:
        m = re.search(sig.body, resp.body, re.I)
        if m:
            snippet = m.group(0).strip().replace("\n", " ")
            return _mk(sig, f'body: "{snippet[:60]}"')
        return None

    return None


def _mk(sig: Signature, evidence: str) -> TechMatch:
    return TechMatch(name=sig.name, category=sig.category,
                     confidence=sig.confidence, evidence=evidence)


def _apply_implications(raw: list[TechMatch]) -> list[TechMatch]:
    """For every detected framework/CMS, add the language/runtime it implies (if
    not already directly detected at higher confidence). Deterministic: iterates
    the fixed :data:`IMPLICATIONS` table in order."""
    best_conf: dict[str, float] = {}
    for m in raw:
        best_conf[m.name] = max(best_conf.get(m.name, 0.0), m.confidence)

    extra: list[TechMatch] = []
    for src, implied, category in IMPLICATIONS:
        if src not in best_conf:
            continue
        conf = round(min(0.9, best_conf[src]) * 0.9, 3)
        conf = max(conf, 0.5)  # an implication is still a firm signal
        extra.append(TechMatch(name=implied, category=category, confidence=conf,
                               evidence=f"implied by {src}"))
    return extra


def _merge(matches: list[TechMatch]) -> list[TechMatch]:
    """Collapse to one match per (name, category): keep the strongest confidence,
    union evidence in first-seen order (deterministic given deterministic input
    iteration)."""
    best: dict[tuple[str, str], TechMatch] = {}
    evidence: dict[tuple[str, str], list[str]] = {}
    for m in matches:
        key = (m.name, m.category)
        ev = evidence.setdefault(key, [])
        if m.evidence and m.evidence not in ev:
            ev.append(m.evidence)
        cur = best.get(key)
        if cur is None or m.confidence > cur.confidence:
            best[key] = m
    return [
        TechMatch(name=name, category=category,
                  confidence=best[(name, category)].confidence,
                  evidence="; ".join(evidence[(name, category)]))
        for (name, category) in best
    ]


def fingerprint(responses: object) -> Fingerprint:
    """Fingerprint a target's technology stack from observed responses.

    ``responses`` is a single response or an iterable of them; each may be a
    :class:`~framework.v2.scanner.passive.Response`, a mapping with
    ``url``/``status``/``headers``/``body`` keys, or any object exposing those as
    attributes (e.g. a crawler ``Page``). Headers may be a dict or a list of
    pairs. Every signature is tested against every response; detections are merged
    to the strongest confidence per (name, category) with unioned evidence, and
    framework/CMS detections contribute their implied runtime language.

    Pure and deterministic: no I/O, no clock, no randomness. Raises
    :class:`MalformedResponse` if a value cannot be read as a response."""
    raw: list[TechMatch] = []
    for obj in _iter_responses(responses):
        resp = _coerce(obj)
        generators = _extract_generators(resp.body)
        cookie_names = _cookie_names(resp)
        body_lower = resp.body.lower()
        for sig in SIGNATURES:
            hit = _match_signature(
                sig, resp,
                generators=generators, cookie_names=cookie_names, body_lower=body_lower,
            )
            if hit is not None:
                raw.append(hit)

    raw.extend(_apply_implications(raw))
    return Fingerprint(matches=_merge(raw))


__all__ = [
    "TechMatch",
    "Fingerprint",
    "Signature",
    "SIGNATURES",
    "IMPLICATIONS",
    "CATEGORIES",
    "fingerprint",
    "fingerprint_favicon",
    "matches_predicate",
    "MalformedResponse",
    "MalformedPredicate",
]
