"""auth_detection — identify the authentication scheme(s)."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # Basic / Bearer at the protocol layer
    c.hdr("basic-auth",  "WWW-Authenticate", c.re_(r"^Basic"),  0.95, "WWW-Authenticate: Basic"),
    c.hdr("bearer-auth", "WWW-Authenticate", c.re_(r"Bearer"),  0.95, "WWW-Authenticate: Bearer"),

    # Form-based login (heuristic — body inspected on /login or /)
    c.body("form-login",
           c.re_(r"<form[^>]*action[^>]*(login|signin|authentication)[^>]*>", ), 0.7,
           "<form action=login> in body"),
    c.body("form-login",
           c.re_(r"<input[^>]*type=\"password\""),                     0.6,
           "<input type=password> in body"),

    # Classic session cookies
    c.cookie("php-session",     "PHPSESSID",                            0.85, "PHPSESSID cookie"),
    c.cookie("java-session",    "JSESSIONID",                           0.85, "JSESSIONID cookie"),
    c.cookie("aspnet-session",  "ASP.NET_SessionId",                    0.85, "ASP.NET_SessionId cookie"),
    c.cookie("rails-session",   "_session_id",                          0.6,  "Rails _session_id cookie"),
    c.cookie("connect-session", "connect.sid",                          0.85, "connect.sid (Express) cookie"),
    c.cookie("django-session",  "sessionid",                            0.7,  "Django sessionid cookie"),
    c.cookie("laravel-session", "laravel_session",                      0.85, "laravel_session cookie"),

    # JWT signatures (typically 3 base64url segments)
    c.body  ("jwt", c.re_(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
             0.85, "JWT-shaped token in body"),
    c.hdr   ("jwt", "Set-Cookie", c.re_(r"=eyJ[A-Za-z0-9_-]{10,}\."), 0.85, "JWT in Set-Cookie"),

    # OAuth / OIDC
    c.path  ("oidc", c.re_(r"/\.well-known/openid-configuration"),     0.95, "/.well-known/openid-configuration"),
    c.body  ("oidc", c.re_(r'"authorization_endpoint"'),               0.95, "OIDC discovery doc"),
    c.body  ("oauth", c.re_(r"<a[^>]*href=\"[^\"]*/oauth/(authorize|token)"),
             0.7, "OAuth endpoint reference"),
    c.path  ("oauth", c.re_(r"/oauth/(authorize|token|callback)"),     0.7, "OAuth path"),

    # SAML
    c.body("saml", c.re_(r"urn:oasis:names:tc:SAML"),                 0.95, "SAML namespace"),
    c.path("saml", c.re_(r"/saml/(login|metadata|sso|acs)"),         0.85, "SAML endpoint path"),

    # API keys
    c.hdr("api-key", "WWW-Authenticate", c.re_(r"X-API-Key"),         0.85, "WWW-Authenticate: X-API-Key"),
    c.body("api-key", c.re_(r"X-Api-Key|X-Auth-Token"),               0.5, "API key header referenced"),

    # MFA hints (often visible in login error)
    c.body("mfa",  c.re_(r"two-factor|2FA|verification code"),         0.5, "MFA-related copy"),

    # Magic-link / passwordless
    c.body("magic-link", c.re_(r"send (you )?a (magic )?login link"), 0.5, "magic-link login copy"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("auth_detection", SIGNATURES, exchanges, category="auth")
