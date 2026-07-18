"""SCRIBE (Phase 8, WS-E) — a grounded web-research/scraper engine. Crawls PUBLIC content only,
SSRF-gated + IP-pinned on every hop, RESPECTS robots.txt + per-host rate limits, scope-gates to
owner-authorized domains, and grounds every served fact to a verbatim source span cited to the spine
(the same demote-only veracity gate that governs memory). Correlatable (never evasive), GET-only,
never an attack tool. Offense-free by doctrine."""
from ..reuse import assert_no_offense

assert_no_offense()

from .extract import entities, links, main_text, tables  # noqa: E402
from .ratelimit import RateLimiter  # noqa: E402
from .robots import RobotsCache  # noqa: E402
from .scope import ScrapeScope  # noqa: E402

__all__ = ["ScrapeScope", "RateLimiter", "RobotsCache", "links", "tables", "main_text", "entities"]
