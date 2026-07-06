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
    BooleanInferenceCheck,
    MarkerReflectionCheck,
    OOBCheck,
    OpenRedirectCheck,
    PathProbeCheck,
    RequestCheck,
    TimingCheck,
)
from .crawler import CrawlResult, Crawler, Page, Scope
from .engine import AuditEngine, AuditFinding
from .orchestrator import AttackPath, AutonomousCampaign, AutonomousResult, ChainedConclusion
from .passive import PASSIVE_CHECKS, PassiveFinding, Response, scan_passive
from .targeting import likely_classes, select_checks
from . import (
    adaptive,
    benchmark,
    browser,
    browser_crawler,
    browser_xss,
    cdp,
    check_synthesis,
    constraints,
    detection_cost,
    discovery,
    domxss,
    fingerprint,
    fitness,
    graphql,
    grammar,
    jwt,
    learning,
    library,
    quantum_era,
    race,
    report,
    self_improve,
    sequencer,
    smuggling,
    spa_crawler,
    websocket,
)
from .report import build_report, render, to_html, to_json, to_sarif
from .check_synthesis import CheckEval, evaluate_check, synthesize_check
from .constraints import InferenceResult, InferredConstraint, infer_predicate
from .fitness import differential_proximity, reflection_proximity, unblocked_gate
from .grammar import RequestGrammar, infer_grammar
from .cdp import CdpBrowser, CdpSession, cdp_available
from .browser_xss import DomXssResult, confirm_dom_xss
from .spa_crawler import SpaCrawlResult, crawl_spa, detect_framework
from .discovery import (
    ApiOperation,
    DiscoveredPath,
    JsFindings,
    discover_content,
    mine_js,
    mine_params,
    parse_openapi,
    parse_robots,
    parse_sitemap,
)
from .fingerprint import Fingerprint, fingerprint
from .library import LibraryEntry, compile_entry, load_library, select_entries, split_checks
from .adaptive import AdaptResult, EvolveResult, evolve, waf_adapt
from .benchmark import BenchmarkReport, run_benchmark
from .detection_cost import detection_cost_of_technique, path_detection_cost, rank_paths
from .learning import ContextualBandit, arm_key, context_key
from .quantum_era import PqcReport, anneal_path_portfolio, classify_kex, classify_signature, pqc_scan
from .race import RaceResult, race_burst, race_check, raw_race
from .self_improve import CapabilityGap, CapabilityProposal, MergeGate, analyze_gaps, draft_proposals
from .sequencer import SequencerResult, analyze as analyze_tokens, collect_tokens
from .websocket import CswshCheck, WsMessageInjectionCheck
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
    "TimingCheck",
    "BooleanInferenceCheck",
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
    "websocket",
    "CswshCheck",
    "WsMessageInjectionCheck",
    "sequencer",
    "SequencerResult",
    "analyze_tokens",
    "collect_tokens",
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
    # autonomous orchestration (scanner -> world-model -> knowledge chaining)
    "AutonomousCampaign",
    "AutonomousResult",
    "ChainedConclusion",
    "AttackPath",
    # single-packet race
    "race",
    "raw_race",
    "race_burst",
    "race_check",
    "RaceResult",
    # detection-cost / stealth ranking
    "detection_cost",
    "detection_cost_of_technique",
    "path_detection_cost",
    "rank_paths",
    # benchmark harness
    "benchmark",
    "run_benchmark",
    "BenchmarkReport",
    # self-learning bandit
    "learning",
    "ContextualBandit",
    "arm_key",
    "context_key",
    # evolving payloads + WAF-adaptive bypass
    "adaptive",
    "evolve",
    "waf_adapt",
    "EvolveResult",
    "AdaptResult",
    # membership-query constraint inference + oracle-proximity fitness
    "constraints",
    "infer_predicate",
    "InferenceResult",
    "InferredConstraint",
    "fitness",
    "reflection_proximity",
    "differential_proximity",
    "unblocked_gate",
    "grammar",
    "infer_grammar",
    "RequestGrammar",
    # quantum-era: PQC exposure + quantum-inspired optimizer
    "quantum_era",
    "classify_kex",
    "classify_signature",
    "pqc_scan",
    "PqcReport",
    "anneal_path_portfolio",
    # self-improvement (proposes, never self-applies)
    "self_improve",
    "analyze_gaps",
    "draft_proposals",
    "MergeGate",
    "CapabilityGap",
    "CapabilityProposal",
    # guarded, eval-gated declarative check synthesis
    "check_synthesis",
    "synthesize_check",
    "evaluate_check",
    "CheckEval",
    # targeting
    "select_checks",
    "likely_classes",
]
