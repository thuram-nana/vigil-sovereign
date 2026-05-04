"""framework_detection — identify the back-end / front-end web framework."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # ----- PHP server-side -----
    c.cookie("laravel",   "laravel_session", 0.9,  "laravel_session cookie set"),
    c.cookie("laravel",   "XSRF-TOKEN",      0.6,  "XSRF-TOKEN cookie (Laravel default)"),
    c.body  ("laravel",   c.re_(r"vendor/laravel/"),                 0.85, "Laravel vendor path leaked"),
    c.body  ("laravel",   c.re_(r'<meta name="csrf-token"'),         0.4,  "CSRF token meta (Laravel pattern)"),

    c.body  ("symfony",   c.re_(r"app_dev\.php|/_profiler/|/_wdt/"), 0.9,  "Symfony profiler/dev path"),
    c.hdr   ("symfony",   "X-Debug-Token", "",                       0.95, "X-Debug-Token header"),
    c.cookie("symfony",   "PHPSESSID",                               0.3,  "PHPSESSID (PHP family)"),

    c.hdr   ("php",       "X-Powered-By", c.re_(r"PHP/"),            0.8,  "X-Powered-By: PHP/*"),
    c.body  ("php",       c.re_(r"<\?php"),                          0.9,  "raw PHP tags in response"),

    c.body  ("wordpress", c.re_(r"<meta name=\"generator\" content=\"WordPress"), 0.95, "<meta generator> WordPress"),
    c.path  ("wordpress", c.re_(r"/wp-(content|includes|admin|json)/"), 0.85, "/wp-* path returned"),
    c.body  ("wordpress", c.re_(r"wp-content/(themes|plugins)/"),    0.7,  "wp-content asset path in HTML"),
    c.body  ("wordpress", c.re_(r"wp-includes/"),                    0.6,  "wp-includes path in HTML"),

    # ----- Python -----
    c.cookie("django",    "csrftoken",                                0.9,  "csrftoken cookie"),
    c.cookie("django",    "sessionid",                                0.7,  "sessionid cookie (Django default)"),
    c.body  ("django",    c.re_(r"<input[^>]*name=\"csrfmiddlewaretoken\""), 0.95, "csrfmiddlewaretoken input"),
    c.body  ("django",    c.re_(r"DEBUG = True"),                    0.6,  "Django debug config leaked"),

    c.body  ("flask",     c.re_(r"Werkzeug.*Debugger|_pin_.*flask"), 0.95, "Flask Werkzeug debugger"),
    c.body  ("fastapi",   c.re_(r'"docs_url":\s*"/docs"'),           0.6,  "FastAPI docs_url config"),
    c.path  ("fastapi",   c.re_(r"/docs|/redoc|/openapi\.json"),     0.4,  "FastAPI default routes"),

    # ----- Node / JS -----
    c.hdr   ("express",   "X-Powered-By", "Express",                  0.95, "X-Powered-By: Express"),
    c.cookie("express",   "connect.sid",                              0.9,  "connect.sid cookie"),

    c.hdr   ("nextjs",    "X-Powered-By", "Next.js",                  0.95, "X-Powered-By: Next.js"),
    c.body  ("nextjs",    c.re_(r"__NEXT_DATA__"),                   0.95, "__NEXT_DATA__ script"),
    c.body  ("nextjs",    c.re_(r"/_next/static/"),                  0.85, "/_next/static asset path"),
    c.body  ("react",     c.re_(r"<div id=\"root\"></div>"),         0.5,  "<div id=root> (React shell)"),
    c.body  ("react",     c.re_(r"react-dom\.production"),           0.7,  "react-dom build artifact"),
    c.body  ("vue",       c.re_(r"id=\"app\"|<vue"),                 0.4,  "Vue app shell"),
    c.body  ("nuxt",      c.re_(r"window\.__NUXT__|/_nuxt/"),        0.9,  "__NUXT__ globals or /_nuxt/ path"),
    c.body  ("svelte",    c.re_(r"__svelte_meta|svelte-kit"),        0.85, "Svelte/SvelteKit markers"),
    c.body  ("gatsby",    c.re_(r"gatsby-(esm|chunk|focus)"),        0.85, "Gatsby chunk artifact"),

    # ----- Ruby -----
    c.cookie("rails",     "_session_id",                              0.7,  "_session_id cookie"),
    c.body  ("rails",     c.re_(r"<meta name=\"csrf-param\""),       0.9,  "Rails csrf-param meta"),
    c.hdr   ("rails",     "X-Runtime", "",                            0.5,  "X-Runtime header (Rails default)"),
    c.hdr   ("phusion",   "X-Powered-By", "Phusion Passenger",        0.85, "X-Powered-By: Phusion Passenger"),

    # ----- JVM -----
    c.cookie("javaee",    "JSESSIONID",                               0.85, "JSESSIONID cookie"),
    c.hdr   ("spring",    "X-Application-Context", "",                0.95, "X-Application-Context (Spring Boot)"),
    c.body  ("spring",    c.re_(r"Whitelabel Error Page"),            0.95, "Spring whitelabel error"),
    c.body  ("spring",    c.re_(r"\"actuator\""),                    0.7,  "Spring Actuator references"),

    # ----- .NET -----
    c.hdr   ("aspnet",    "X-AspNet-Version", "",                     0.95, "X-AspNet-Version header"),
    c.hdr   ("aspnet",    "X-Powered-By", c.re_(r"ASP\.NET"),         0.95, "X-Powered-By: ASP.NET"),
    c.cookie("aspnet",    "ASP.NET_SessionId",                        0.9,  "ASP.NET_SessionId cookie"),

    # ----- Elixir -----
    c.cookie("phoenix",   "_phoenix_key",                             0.95, "_phoenix_key cookie"),

    # ----- Go (often less identifiable) -----
    c.body  ("gin",       c.re_(r"<a href=\"https://github.com/gin-gonic/gin"), 0.9, "Gin error page link"),

    # ----- panel-specific -----
    c.body  ("smarty",    c.re_(r"\{[\$#][\w]"),                      0.4,  "Smarty-style {$var} markers in HTML"),
    c.body  ("perfect-panel", c.re_(r"perfectcdn\.com|cdn\.glycon\.net"), 0.9, "Perfect Panel CDN reference"),
    c.body  ("perfect-panel", c.re_(r"/api/v2/.*action=", ),          0.7,  "Perfect Panel /api/v2/ action= pattern"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("framework_detection", SIGNATURES, exchanges, category="framework")
