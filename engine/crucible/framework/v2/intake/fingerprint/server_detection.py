"""server_detection — identify the HTTP server software."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    c.hdr("nginx",      "Server", c.re_(r"^nginx"),                   0.95, "Server: nginx"),
    c.hdr("apache",     "Server", c.re_(r"^Apache"),                  0.95, "Server: Apache"),
    c.hdr("iis",        "Server", c.re_(r"Microsoft-IIS"),            0.95, "Server: Microsoft-IIS"),
    c.hdr("caddy",      "Server", c.re_(r"^Caddy"),                   0.9,  "Server: Caddy"),
    c.hdr("openresty",  "Server", c.re_(r"^openresty"),               0.9,  "Server: openresty"),
    c.hdr("traefik",    "Server", c.re_(r"^Traefik"),                 0.9,  "Server: Traefik"),
    c.hdr("envoy",      "Server", c.re_(r"^envoy"),                   0.85, "Server: envoy"),
    c.hdr("litespeed",  "Server", c.re_(r"LiteSpeed"),                0.9,  "Server: LiteSpeed"),
    c.hdr("nodejs",     "Server", c.re_(r"^node\.js"),                0.85, "Server: node.js"),
    c.hdr("kestrel",    "Server", c.re_(r"^Kestrel"),                 0.85, "Server: Kestrel (.NET)"),
    c.hdr("gunicorn",   "Server", c.re_(r"^gunicorn"),                0.9,  "Server: gunicorn"),
    c.hdr("werkzeug",   "Server", c.re_(r"^Werkzeug"),                0.9,  "Server: Werkzeug (Flask)"),
    c.hdr("uvicorn",    "Server", c.re_(r"^uvicorn"),                 0.9,  "Server: uvicorn"),
    c.hdr("puma",       "Server", c.re_(r"^Puma"),                    0.9,  "Server: Puma (Ruby)"),
    c.hdr("unicorn",    "Server", c.re_(r"^Unicorn"),                 0.85, "Server: Unicorn (Ruby)"),

    # version-leak signals (lower confidence for server identity but useful)
    c.hdr("apache-version", "Server", c.re_(r"Apache/[0-9]"),          0.6,  "Apache version exposed"),
    c.hdr("nginx-version",  "Server", c.re_(r"nginx/[0-9]"),           0.6,  "nginx version exposed"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("server_detection", SIGNATURES, exchanges, category="server")
