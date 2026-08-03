"""
eval.benchmark_app — a labelled, deliberately-vulnerable benchmark target.

The comparative spine (`eval.validation`) can score any tool against a labelled
`CorpusTarget`, but a *public* benchmark needs a target whose ground truth is
known exactly — otherwise a "false positive" count is guesswork. This module is
that target: a self-contained :class:`ThreadingHTTPServer` handler that plants a
SPREAD of real, distinct, deterministic web bugs, each at a known location, plus
:func:`benchmark_corpus` — the ground-truth manifest every tool is scored against.

Design rules that make the numbers trustworthy:

  * **Every planted bug is real.** The XSS reflects an attacker payload verbatim
    into executable HTML; the boolean SQLi dumps every row for a tautology and
    none for a benign term; the error-based SQLi echoes a real MySQL parser error
    on a quote; the open redirect reflects a parameter into a 302 ``Location``;
    the CORS endpoint reflects a hostile ``Origin`` with credentials; ``.git/config``,
    ``.env`` and the Spring ``/actuator/env`` leak their signature secrets.
  * **Every planted bug is single-class.** Each vulnerable endpoint is engineered
    to trip exactly ONE of CRUCIBLE's oracle-anchored checks, so the manifest is
    honest (no endpoint is silently also SSTI/traversal). Concretely: a reflecting
    sink is only exercised for markup-shaped input (so the marker-reflection
    side-effect checks for SSTI / path-traversal / error-based do not co-fire on a
    pure XSS sink), and the error page embeds its DB error inside a large static
    body so the boolean differential stays below threshold.
  * **The SAFE endpoints take input and handle it correctly** — a parameterised
    profile lookup, a constant health endpoint, an allow-listed download, an
    auto-escaping template, and an ordinary benign page — so a tool that flags them
    is measurably wrong. They are the false-positive ruler for the param-level
    checks. The two HOST-level classes (CORS, host-header) are anchored on the seed
    ``/`` alone: those checks probe only the first request per host, so the
    misconfiguration is planted there and every other route emits a clean
    CORS/host response — **no safe endpoint carries either bug**, which is what
    makes "anything reported on a safe endpoint is a false positive" honest for
    every class, not just the param-level ones.

The handler binds to loopback only and is served via :func:`serve`. It sends the
``Server: Jetty`` banner so the technology fingerprinter marks the stack ``java``
and the Spring-actuator check applies (that check is stack-gated by design).

Boundary: this is a target we own and run in-process for measurement. It is not a
probe, an exploit, or anything aimed at a third party.
"""

from __future__ import annotations

import contextlib
import html
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from .validation import CorpusTarget, ExpectedFinding

# ---------------------------------------------------------------------------
# The boolean-blind SQLi model (a faithful reuse of the vulnerable matcher from
# verify.confirmation): user input is string-built into ``name = '<q>'`` and split
# on `` OR ``, so an `` ' OR '1'='1`` tautology breaks out and selects every row,
# while any benign term selects none. This is a REAL, observable differential.
# ---------------------------------------------------------------------------

_ROWS: tuple[dict[str, object], ...] = (
    {"id": 1, "name": "alice", "role": "user", "email": "alice@corp.example"},
    {"id": 2, "name": "bob", "role": "admin", "email": "bob@corp.example"},
    {"id": 3, "name": "carol", "role": "user", "email": "carol@corp.example"},
)

_CLAUSE_NAME = re.compile(r"name = '(.*)'")
_CLAUSE_TAUTOLOGY = re.compile(r"'(.*)'\s*=\s*'(.*)'")


def _clause_true(clause: str, name: str) -> bool:
    m = _CLAUSE_NAME.fullmatch(clause)
    if m:
        return name == m.group(1)
    m = _CLAUSE_TAUTOLOGY.fullmatch(clause)
    if m:
        return m.group(1) == m.group(2)
    return False


def _vulnerable_match(q: str) -> list[dict[str, object]]:
    """Deliberately flawed: builds ``name = '<q>'`` by concatenation, so a
    `` ' OR '1'='1`` clause is an always-true tautology that returns every row."""
    stmt = "name = '" + q + "'"
    clauses = [c.strip() for c in stmt.split(" OR ")]
    return [row for row in _ROWS if any(_clause_true(c, row["name"]) for c in clauses)]


def _safe_match(q: str) -> list[dict[str, object]]:
    """The parameterised twin: ``q`` is bound as a literal value, never structure,
    so no tautology can widen the result set (the SAFE control)."""
    return [row for row in _ROWS if row["name"] == q]


# ---------------------------------------------------------------------------
# Static bodies. The product page is deliberately large so the error variant
# (page + a short MySQL error line) stays under the boolean-differential's 5%
# length / 10% lexical thresholds — the error-based endpoint must NOT also read
# as a boolean-blind differential.
# ---------------------------------------------------------------------------

# ~4.5 KB of neutral product copy (no SQL/error/exposure signature strings).
_PRODUCT_FILLER = (
    "The Aurora field kit is a compact, weather-sealed carrier built for long "
    "shifts outdoors. Its modular internal dividers reshape to fit a laptop, a "
    "tablet, and a full change of layers without crushing anything soft. The "
    "outer shell is a recycled ripstop weave that sheds a passing shower and "
    "wipes clean, and the base panel is reinforced so the bag stands on its own "
    "when you set it down. Padded, breathable straps spread the load across the "
    "shoulders, a sternum clip keeps everything stable on the move, and a hidden "
    "back panel pocket keeps documents flat and close. Reviewers consistently "
    "call out the balance of capacity and comfort: enough room for a two-day "
    "trip, light enough to carry all day, and organised enough that nothing "
    "rattles loose. Thoughtful touches abound, from the quiet magnetic closures "
    "to the loop that parks a water bottle, to the soft-lined sleeve that keeps a "
    "screen from scuffing. It ships flat-packed in fully recyclable materials and "
    "is covered by a straightforward multi-year guarantee against manufacturing "
    "defects. Customers who bought this also considered the matching pouch set, "
    "the rain cover, and the compact travel organiser, each designed to slot into "
    "the same interior without adding bulk. In short, a dependable everyday "
    "companion that keeps its shape, protects what matters, and looks the part. "
) * 3

# A genuine MySQL parser error string (matches the error-signature oracle). It is
# fixed and never echoes the raw payload, so it cannot become an XSS/SSTI sink.
_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near ''' at line 1"
)

# ---------------------------------------------------------------------------
# The server-side template-evaluation model (the SSTI planted bug). A naive
# renderer EVALUATES an injected ``{{N*M}}`` / ``${N*M}`` expression and emits
# only the computed RESULT — the raw template text is consumed, never reflected.
# That is exactly what the evaluation oracle demands (result present, raw absent),
# and it keeps the sink single-class: only a template-shaped arithmetic expression
# is ever acted on, so an XSS marker, a SQL tautology, a traversal, or a quote all
# fall through to a constant render and cannot co-fire.
# ---------------------------------------------------------------------------

_SSTI_BRACES = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")
_SSTI_DOLLAR = re.compile(r"\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}")


def _eval_template(raw: str) -> str | None:
    """The deliberately-flawed template evaluator: if ``raw`` is a bare ``{{N*M}}``
    or ``${N*M}`` expression, COMPUTE it and return the product as a string (server-
    side evaluation). Anything else returns None — the caller renders a constant, so
    non-expression input is never reflected and the sink stays single-class SSTI."""
    m = _SSTI_BRACES.fullmatch(raw) or _SSTI_DOLLAR.fullmatch(raw)
    if m:
        return str(int(m.group(1)) * int(m.group(2)))
    return None


def _page(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body>{body}</body></html>"
    ).encode("utf-8")


class BenchmarkHandler(BaseHTTPRequestHandler):
    """The deliberately-vulnerable benchmark app. One route per planted bug plus
    the SAFE controls; unknown paths 404 so the many path-signature exposure
    checks that were NOT planted cannot fire."""

    # Advertise a Java app-server so the fingerprinter marks the stack ``java`` and
    # the (stack-gated) Spring-actuator exposure check runs. sys_version="" keeps
    # the banner from also leaking "Python".
    server_version = "Jetty(9.4.z-SNAPSHOT)"
    sys_version = ""

    # -- plumbing ----------------------------------------------------------

    def log_message(self, *args: object) -> None:  # keep the target quiet
        return

    def _query(self, key: str) -> str:
        qs = urlsplit(self.path).query
        return parse_qs(qs, keep_blank_values=True).get(key, [""])[0]

    def _respond(
        self,
        status: int,
        body: bytes,
        *,
        ctype: str = "text/html; charset=utf-8",
        location: str | None = None,
        cors_reflect: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if location is not None:
            self.send_header("Location", location)
        # PLANTED BUG (CORS) — scoped to the ONE anchor the check probes. CORS is a
        # host-ANCHOR-level check: it sends a hostile Origin against the seed request
        # (`/`) ONLY, so the misconfiguration is planted there and nowhere else. Only
        # the index route passes ``cors_reflect=True``; every other route — in
        # particular the SAFE controls — emits NO Access-Control-Allow-Origin at all,
        # so a per-endpoint CORS report on a safe route would be flagging a bug that
        # genuinely is not there, and "anything reported on a safe endpoint is a false
        # positive by construction" holds for the CORS class too. When reflected, a
        # hostile Origin is echoed AND credentials allowed — the exact combination
        # that lets an attacker page read authenticated responses.
        if cors_reflect:
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path.rstrip("/") or "/"
        route = _ROUTES.get(path)
        if route is None:
            self._respond(404, _page("404", "<h1>Not Found</h1>"))
            return
        route(self)

    # -- planted-bug routes ------------------------------------------------

    def _index(self) -> None:
        # Links carry a query so the crawler discovers each endpoint's parameter.
        links = "".join(
            f'<li><a href="{href}">{label}</a></li>'
            for href, label in (
                ("/search?q=widgets", "Search"),
                ("/users?name=guest", "User lookup"),
                ("/product?id=1", "Product"),
                ("/redirect?url=/", "Continue"),
                ("/file?name=manual.txt", "Docs"),
                ("/render?name=guest", "Dashboard"),
                ("/profile?name=guest", "Profile (safe)"),
                ("/api/health?check=all", "Health (safe)"),
                ("/download?file=manual.pdf", "Download (safe)"),
                ("/greeting?name=guest", "Greeting (safe)"),
                ("/support", "Support (safe)"),
            )
        )
        # PLANTED BUG (host-header injection): the landing page derives its canonical
        # Open-Graph URL from the incoming Host header with no allow-list, so a
        # poisoned ``Host`` becomes an absolute ``//attacker`` URL — the primitive
        # behind web-cache poisoning and password-reset-link hijacking. It is
        # confirmed by HostHeaderCheck, which is a HOST-ANCHOR-level check (it runs
        # once, against the first request seen for the host — the seed ``/``), which
        # is exactly why the sink lives on the index. It reflects only the Host header
        # (never a query value), so it cannot co-fire as XSS or open redirect, and the
        # og:url meta is not a navigable link, so the crawler does not chase it.
        host = self.headers.get("Host", "localhost")
        page = (
            "<!doctype html><html><head><title>Acme Store</title>"
            f'<meta property="og:url" content="https://{host}/">'
            "</head>"
            f"<body><h1>Acme Store</h1><ul>{links}</ul></body></html>"
        ).encode("utf-8")
        # The seed `/` is the sole anchor for the two HOST-level checks: it carries
        # both the host-header sink (og:url above) and the CORS misconfiguration
        # (cors_reflect=True) — the only route that reflects a hostile Origin. Every
        # other route leaves cors_reflect at its default False and is CORS-clean.
        self._respond(200, page, cors_reflect=True)

    def _search(self) -> None:
        # PLANTED BUG (reflected XSS): a markup-shaped search term is reflected
        # VERBATIM into an executable HTML position. The sink is only exercised for
        # values that look like markup, which keeps this a single-class XSS bug:
        # the bare-marker reflection probes (SSTI / path-traversal / error-based)
        # carry no '<', so they never reach the sink and cannot co-fire here.
        q = self._query("q")
        if "<" in q:
            body = f"<h2>Results for: {q}</h2><p>No products matched.</p>"
        else:
            body = f"<h2>Search</h2><p>Showing results for the term <b>widgets</b>.</p>"
        self._respond(200, _page("Search", body))

    def _users(self) -> None:
        # PLANTED BUG (boolean-blind SQLi): a tautology dumps every row, a benign
        # term dumps none — an observable status/length/lexical differential.
        rows = _vulnerable_match(self._query("name"))
        if not rows:
            body = "<h2>User lookup</h2><p>No results found.</p>"
        else:
            items = "".join(
                f"<li>id={r['id']} name={r['name']} role={r['role']} email={r['email']}</li>"
                for r in rows
            )
            body = f"<h2>User lookup</h2><ul>{items}</ul>"
        self._respond(200, _page("Users", body))

    def _product(self) -> None:
        # PLANTED BUG (error-based SQLi): a quote/backtick provokes a real MySQL
        # parser error. The error is embedded in the large static product page and
        # never echoes the raw input, so (a) the boolean differential stays sub-
        # threshold and (b) the page can never become an XSS/SSTI sink.
        raw = self._query("id")
        page = f"<h1>Aurora Field Kit</h1><p>{_PRODUCT_FILLER}</p>"
        if any(c in raw for c in "'\"`"):
            page += f"<!-- {_MYSQL_ERROR} -->"
        self._respond(200, _page("Product", page))

    def _redirect(self) -> None:
        # PLANTED BUG (open redirect): the `url` parameter is reflected verbatim
        # into a 302 Location with no allow-list, so an attacker can bounce a
        # victim to any external site.
        target = self._query("url") or "/"
        self._respond(302, b"", location=target)

    def _render(self) -> None:
        # PLANTED BUG (SSTI): a naive template renderer EVALUATES an injected
        # expression server-side. ``{{N*M}}`` / ``${N*M}`` is computed and only the
        # RESULT is rendered (the raw template text is consumed, not echoed), so the
        # evaluation oracle confirms a real evaluation — result present, raw absent.
        # Non-expression input renders a constant "guest", so nothing is reflected:
        # the XSS marker / SQL tautology / traversal / quote probes all fall through
        # to the same constant and cannot co-fire. Single-class SSTI by construction.
        rendered = _eval_template(self._query("name")) or "guest"
        body = f"<h1>Dashboard</h1><p>Welcome back, {rendered}.</p>"
        self._respond(200, _page("Dashboard", body))

    # -- SAFE controls (must NEVER be flagged) -----------------------------

    def _profile(self) -> None:
        # SAFE: parameterised lookup — input is bound as a literal, never reflected.
        # A tautology returns the same "Unknown user." as any other miss, and no
        # input is ever echoed, so no differential / reflection / injection fires.
        rows = _safe_match(self._query("name"))
        if not rows:
            body = "<h2>Profile</h2><p>Unknown user.</p>"
        else:
            r = rows[0]
            body = f"<h2>Profile</h2><p>Role: {r['role']}. Member in good standing.</p>"
        self._respond(200, _page("Profile", body))

    def _health(self) -> None:
        # SAFE: constant response, input ignored.
        self._respond(
            200,
            b'{"status":"ok","checks":{"db":"ok","cache":"ok"},"uptime_s":86400}',
            ctype="application/json",
        )

    def _download(self) -> None:
        # SAFE: allow-listed file names only; a traversal payload resolves to a
        # miss, and the requested name is never reflected into the response.
        allowed = {"manual.pdf", "spec-sheet.pdf", "warranty.pdf"}
        if self._query("file") in allowed:
            body = b"%PDF-1.4 (binary content elided for the benchmark)"
            self._respond(200, body, ctype="application/pdf")
        else:
            self._respond(404, _page("Download", "<h2>Download</h2><p>File not found.</p>"))

    def _greeting(self) -> None:
        # SAFE (SSTI twin): an auto-escaping template — the user value is rendered
        # as DATA, never evaluated. It echoes the input HTML-escaped inside a large
        # static page, so ``{{7331*7331}}`` appears VERBATIM (the evaluation oracle's
        # rule #2: raw present -> not evaluation) and its computed value 53743561
        # never appears. The escaped echo cannot become an XSS sink (inert, encoded)
        # and the constant filler keeps benign-vs-probe length/lexical deltas below
        # the boolean-differential thresholds. The false-positive ruler for SSTI.
        name = html.escape(self._query("name"))
        body = f"<h1>Greeting</h1><p>Hello, {name}.</p><p>{_PRODUCT_FILLER}</p>"
        self._respond(200, _page("Greeting", body))

    def _support(self) -> None:
        # SAFE (ordinary benign page): a static page whose single absolute link points
        # at a FIXED, configured host. Its false-positive value is for the PARAM-LEVEL
        # checks — a clean crawled route with an absolute URL that a tool must not flag
        # as open-redirect, XSS, or injection. It is deliberately NOT called a
        # host-header "twin": host-header (like CORS) is a host-ANCHOR check that
        # probes ONLY the seed `/`, so it never re-probes this route and a per-endpoint
        # safe twin for it would carry no measured signal. The correct fixed-host
        # handling shown here is documentation of the safe pattern, not a discriminator.
        body = (
            "<h2>Support</h2>"
            '<p>Contact us at <a href="https://acme.example/support">support</a>.</p>'
        )
        self._respond(200, _page("Support", body))

    def _file(self) -> None:
        # PLANTED BUG (path traversal): a traversal escapes the document directory
        # and reads an arbitrary file. It returns the FILE CONTENT and never
        # reflects the raw path, so ONLY a real file-content signature
        # (``root:x:0:0:``) confirms it — a marker-reflection probe learns nothing
        # here (which is why the content-signature check is the one that catches
        # it). A benign name yields an ordinary document with no reflection.
        name = self._query("name")
        # A pure path-traversal sink joins the name onto a base dir and opens it, so
        # a filesystem traversal reads the file but a scheme wrapper (file://, php://)
        # does NOT — the benchmark plants exactly one traversal bug, not a scheme LFI.
        if "://" not in name and ("etc/passwd" in name or name.rstrip("/").endswith("passwd")):
            body = (
                b"root:x:0:0:root:/root:/bin/bash\n"
                b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            )
            self._respond(200, body, ctype="text/plain; charset=utf-8")
        else:
            self._respond(200, _page("Document", "<h2>Document</h2><p>The requested manual page.</p>"))

    # -- exposure routes (leak their signature) ----------------------------

    def _git_config(self) -> None:
        # PLANTED BUG (exposure): a deployed .git/config exposes repo metadata.
        body = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "[remote \"origin\"]\n"
            "\turl = https://git.internal.example/acme/store.git\n"
        ).encode("utf-8")
        self._respond(200, body, ctype="text/plain; charset=utf-8")

    def _env(self) -> None:
        # PLANTED BUG (exposure): a served .env leaks database credentials. It
        # carries DB_PASSWORD but NOT APP_KEY, so exactly one .env signature check
        # (m5-fw-env-dbpass) fires — the manifest counts one .env exposure.
        body = (
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=10.0.3.12\n"
            "DB_DATABASE=acme_store\n"
            "DB_USERNAME=acme\n"
            "DB_PASSWORD=s3cr3t-prod-db-pw\n"
        ).encode("utf-8")
        self._respond(200, body, ctype="text/plain; charset=utf-8")

    def _actuator_env(self) -> None:
        # PLANTED BUG (exposure): an unauthenticated Spring Actuator /env dumps the
        # property sources (secrets). Signature: "propertySources". Stack-gated on
        # java, satisfied by the Jetty Server banner above.
        body = json.dumps({
            "activeProfiles": ["production"],
            "propertySources": [
                {"name": "systemEnvironment",
                 "properties": {"DB_PASSWORD": {"value": "s3cr3t-prod-db-pw"}}},
                {"name": "applicationConfig",
                 "properties": {"spring.datasource.url": {"value": "jdbc:mysql://10.0.3.12/acme"}}},
            ],
        }).encode("utf-8")
        self._respond(200, body, ctype="application/json")


# Path -> handler method. Everything else 404s (so the un-planted path-signature
# exposure checks — /.git/HEAD, /actuator/health, /swagger.json, ... — do not fire).
_ROUTES = {
    "/": BenchmarkHandler._index,
    "/search": BenchmarkHandler._search,
    "/users": BenchmarkHandler._users,
    "/product": BenchmarkHandler._product,
    "/redirect": BenchmarkHandler._redirect,
    "/render": BenchmarkHandler._render,
    "/profile": BenchmarkHandler._profile,
    "/api/health": BenchmarkHandler._health,
    "/download": BenchmarkHandler._download,
    "/greeting": BenchmarkHandler._greeting,
    "/support": BenchmarkHandler._support,
    "/file": BenchmarkHandler._file,
    "/.git/config": BenchmarkHandler._git_config,
    "/.env": BenchmarkHandler._env,
    "/actuator/env": BenchmarkHandler._actuator_env,
}


# ---------------------------------------------------------------------------
# Ground-truth manifest
# ---------------------------------------------------------------------------


def benchmark_corpus(base_url: str) -> CorpusTarget:
    """The complete, honest ground truth for the benchmark app.

    Locations are written in CRUCIBLE's vocabulary so the comparative scorer lines
    a produced finding up with its label: param-level bugs as ``path?param`` (the
    scorer's path+param fallback matches CRUCIBLE's param-level location), and the
    two host/endpoint-level classes (CORS, exposures) as the ``request:<check-id>``
    token CRUCIBLE emits for a request-level finding.

    Eleven planted bugs; the five SAFE endpoints (``/profile``, ``/api/health``,
    ``/download``, ``/greeting``, ``/support``) are intentionally absent — anything a
    tool reports on them is a false positive by construction."""
    expected = [
        ExpectedFinding(bug_class="xss", location="/search?q"),
        ExpectedFinding(bug_class="boolean_sqli", location="/users?name"),
        ExpectedFinding(bug_class="error_based_sqli", location="/product?id"),
        ExpectedFinding(bug_class="open_redirect", location="/redirect?url"),
        ExpectedFinding(bug_class="path_traversal", location="/file?name"),
        ExpectedFinding(bug_class="ssti", location="/render?name"),
        ExpectedFinding(bug_class="host_header_injection", location="request:host-header"),
        ExpectedFinding(bug_class="cors", location="request:cors-active"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-git-config"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-env-dbpass"),
        ExpectedFinding(bug_class="exposure", location="request:m5-fw-spring-actuator-env"),
    ]
    return CorpusTarget(
        name="crucible-benchmark-app",
        base_url=base_url,
        expected=expected,
        notes=(
            "Self-contained labelled benchmark: reflected XSS, boolean-blind SQLi, "
            "error-based SQLi, open redirect, path traversal, SSTI (server-side "
            "template evaluation), host-header injection, CORS-with-credentials, and "
            "three exposures (.git/config, .env, Spring /actuator/env), plus five SAFE "
            "controls (/profile, /api/health, /download, /greeting, /support) that "
            "must not be flagged."
        ),
    )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def serve() -> Iterator[str]:
    """Run the benchmark app on ``127.0.0.1:<ephemeral>`` for the duration of the
    block, yielding its base URL and shutting it down cleanly on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="benchmark-app", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
