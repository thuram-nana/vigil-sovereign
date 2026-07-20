"""cdn_waf_detection — identify CDN, WAF, and edge-protection layers."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # ----- CDNs / edge -----
    c.hdr   ("cloudflare", "Server",      c.re_(r"cloudflare"),     0.95, "Server: cloudflare"),
    c.hdr   ("cloudflare", "CF-Ray",      "",                       0.95, "CF-Ray header present"),
    c.cookie("cloudflare", "__cf_bm",                                0.9,  "__cf_bm cookie"),
    c.cookie("cloudflare", "cf_clearance",                           0.9,  "cf_clearance cookie"),
    c.body  ("cloudflare", c.re_(r"Cloudflare Ray ID"),             0.85, "Cloudflare error page"),

    c.hdr   ("akamai",     "Server",      c.re_(r"AkamaiGHost"),    0.95, "Server: AkamaiGHost"),
    c.cookie("akamai",     "_abck",                                  0.9,  "_abck (Akamai BM) cookie"),
    c.hdr   ("akamai",     "X-Akamai-Transformed", "",               0.95, "X-Akamai-Transformed header"),

    c.hdr   ("fastly",     "X-Served-By", c.re_(r"cache-"),          0.85, "X-Served-By: cache-* (Fastly)"),
    c.hdr   ("fastly",     "X-Fastly-Request-ID", "",                0.95, "X-Fastly-Request-ID header"),
    c.hdr   ("fastly",     "Fastly-Debug-Path", "",                  0.95, "Fastly-Debug-Path header"),

    c.hdr   ("cloudfront", "Via", c.re_(r"CloudFront"),              0.95, "Via: ... CloudFront"),
    c.hdr   ("cloudfront", "X-Amz-Cf-Id", "",                        0.95, "X-Amz-Cf-Id header"),

    c.hdr   ("google-edge", "Via",        c.re_(r"google"),          0.7,  "Via: ... google"),
    c.hdr   ("google-edge", "Server",     c.re_(r"^gws"),            0.85, "Server: gws"),

    c.hdr   ("azure-cdn",  "X-Cache",     c.re_(r"frontdoor"),       0.85, "X-Cache: ... frontdoor"),

    c.hdr   ("vercel",     "Server",      c.re_(r"^Vercel"),         0.95, "Server: Vercel"),
    c.hdr   ("vercel",     "X-Vercel-Id", "",                        0.95, "X-Vercel-Id header"),
    c.hdr   ("netlify",    "Server",      c.re_(r"^Netlify"),        0.95, "Server: Netlify"),

    # ----- WAFs -----
    c.hdr   ("incapsula",  "X-Iinfo",     "",                        0.95, "X-Iinfo (Imperva/Incapsula)"),
    c.cookie("incapsula",  "incap_ses",                               0.95, "incap_ses cookie (Incapsula)"),
    c.cookie("incapsula",  "visid_incap",                             0.9,  "visid_incap cookie"),

    c.hdr   ("sucuri",     "X-Sucuri-ID", "",                         0.95, "X-Sucuri-ID header"),
    c.hdr   ("sucuri",     "Server",      c.re_(r"Sucuri/Cloudproxy"), 0.95, "Server: Sucuri/Cloudproxy"),

    c.body  ("modsecurity", c.re_(r"Mod_?Security|mod_security"),     0.85, "ModSecurity error page"),
    c.body  ("modsecurity", c.re_(r"Reference\s*#\d+\.[\da-f]+\.\d+"), 0.7, "OWASP CRS reference id pattern"),

    c.hdr   ("aws-waf",    "x-amzn-RequestId", "",                    0.7,  "x-amzn-RequestId (AWS API GW / WAF)"),
    c.body  ("aws-waf",    c.re_(r"<H1>403 ERROR</H1>.*Request blocked"), 0.7, "AWS WAF 403 page"),

    c.hdr   ("f5-bigip",   "Set-Cookie", c.re_(r"BIGipServer"),       0.9, "BIGipServer cookie"),

    c.hdr   ("barracuda",  "Server",     c.re_(r"^Barracuda"),        0.85, "Server: Barracuda"),

    c.hdr   ("wordfence",  "X-Powered-By", c.re_(r"Wordfence"),       0.85, "X-Powered-By: Wordfence"),
    c.body  ("wordfence",  c.re_(r"Wordfence Security"),              0.85, "Wordfence error / banner"),

    # ----- security headers (informational, treated as confidence-1.0 if present) -----
    c.hdr("hsts",  "Strict-Transport-Security", "", 1.0, "HSTS enabled"),
    c.hdr("csp",   "Content-Security-Policy",   "", 1.0, "CSP enabled"),
    c.hdr("xfo",   "X-Frame-Options",           "", 1.0, "X-Frame-Options set"),
    c.hdr("xcto",  "X-Content-Type-Options",    "", 1.0, "X-Content-Type-Options set"),
    c.hdr("rp",    "Referrer-Policy",           "", 1.0, "Referrer-Policy set"),
    c.hdr("pp",    "Permissions-Policy",        "", 1.0, "Permissions-Policy set"),
    c.hdr("coop",  "Cross-Origin-Opener-Policy", "", 1.0, "COOP set"),
    c.hdr("corp",  "Cross-Origin-Resource-Policy", "", 1.0, "CORP set"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("cdn_waf_detection", SIGNATURES, exchanges, category="cdn_waf")
