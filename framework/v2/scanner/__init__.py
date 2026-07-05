"""
scanner — CRUCIBLE's autonomous web-audit engine (Burp-parity track).

Burp Suite is an *engine plus a human operator*. CRUCIBLE already has the
confirmation brain (``verify`` oracles, ``worldmodel``, ``planner``,
``calibration``); this package builds the missing *hands* — the crawl →
insertion-point → check → confirm pipeline — and drives it with the planner
instead of a human, so it runs zero-manual.

Foundational layer first: the **insertion-point engine**. Every active check
Burp runs is an (insertion-point × payload × response-analyzer) triple; without
a way to mark an arbitrary position in a request and render a payload into it,
there is no scanner and no Intruder. ``RequestTemplate`` provides exactly that,
as pure, deterministic parsing/rendering (no network, no clock) — the substrate
the check library and the fuzzing engine ride on.

Public surface:

    from framework.v2.scanner import (
        HttpRequest, InsertionKind, InsertionPoint, RequestTemplate,
    )

Boundary: this module only *shapes* requests. It sends nothing itself — the
audit engine (a later increment) issues rendered requests through the existing
``agents.http_executor`` safety stack (charter/scope/kill-switch/egress/rate),
so scope and authorization stay enforced.
"""

from __future__ import annotations

from .campaign import ScanReport, WebScanCampaign, populate_worldmodel
from .checks import (
    DEFAULT_CHECKS,
    Check,
    CorsActiveCheck,
    DifferentialCheck,
    HostHeaderCheck,
    IdorCheck,
    MarkerReflectionCheck,
    OOBCheck,
    OpenRedirectCheck,
    RequestCheck,
)
from .crawler import CrawlResult, Crawler, Page, Scope
from .engine import AuditEngine, AuditFinding
from .passive import PASSIVE_CHECKS, PassiveFinding, Response, scan_passive
from .targeting import likely_classes, select_checks
from . import browser, browser_crawler, domxss, graphql, jwt, smuggling
from .browser import find_browser, render_dom, scan_dom_xss
from .browser_crawler import BrowserCrawler, browser_send
from .domxss import DomXssCandidate, analyze_html, analyze_js
from .graphql import GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
from .insertion import (
    HttpRequest,
    InsertionKind,
    InsertionPoint,
    RequestTemplate,
)
from .jwt import JwtNoneCheck

__all__ = [
    # insertion
    "HttpRequest",
    "InsertionKind",
    "InsertionPoint",
    "RequestTemplate",
    # checks
    "Check",
    "DifferentialCheck",
    "MarkerReflectionCheck",
    "OOBCheck",
    "IdorCheck",
    "OpenRedirectCheck",
    "RequestCheck",
    "CorsActiveCheck",
    "HostHeaderCheck",
    "JwtNoneCheck",
    "jwt",
    "GraphQLIntrospectionCheck",
    "GraphQLSuggestionsCheck",
    "graphql",
    "smuggling",
    "domxss",
    "DomXssCandidate",
    "analyze_html",
    "analyze_js",
    "browser",
    "find_browser",
    "render_dom",
    "scan_dom_xss",
    "browser_crawler",
    "BrowserCrawler",
    "browser_send",
    "DEFAULT_CHECKS",
    # engine
    "AuditEngine",
    "AuditFinding",
    # crawler
    "Crawler",
    "Scope",
    "CrawlResult",
    "Page",
    # passive
    "Response",
    "PassiveFinding",
    "scan_passive",
    "PASSIVE_CHECKS",
    # campaign
    "WebScanCampaign",
    "ScanReport",
    "populate_worldmodel",
    # targeting
    "select_checks",
    "likely_classes",
]
