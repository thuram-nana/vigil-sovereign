"""SIGIL Phase 8 WS-E — SCRIBE grounded scraper: SSRF-gated fetch, deny-all scope, per-host rate
limit, robots RESPECTED, structured extraction, VOI frontier, and serve-the-quote grounding.
Run: ~/.sigil/venv/bin/python tests/test_scrape.py"""
import tempfile
from pathlib import Path

import sigil.scrape.scope as scope_mod
from sigil.agents.sources import FetchResult, fetch_raw, read_source
from sigil.scrape import RateLimiter, RobotsCache, ScrapeScope
from sigil.scrape import extract
from sigil.scrape.frontier import FetchedPage, Frontier
from sigil.scrape.researcher import WebResearcher
from sigil.spine.store import SpineStore


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _fetch_table(pages):
    """A fake `fetch` over a canned {url: (status, body)} table (bypasses the SSRF gate for logic tests)."""
    def _f(url, **kw):
        if url in pages:
            st, body = pages[url]
            return FetchResult(200 <= st < 300, st, body, url, reason=("" if 200 <= st < 300 else f"http-{st}"))
        return FetchResult(False, 404, "", url, reason="http-404")
    return _f


# ---- E1 fetch_raw: SSRF gate ---------------------------------------------------------------------
def test_fetch_raw_refuses_internal_hosts():
    for u in ("http://127.0.0.1:9/x", "http://169.254.169.254/latest", "http://10.0.0.1/", "http://localhost:80/"):
        r = fetch_raw(u)
        assert r.ok is False and r.status == 0 and r.reason == "ssrf-refused", f"{u} must be refused before any socket"
    assert read_source("http://127.0.0.1:9/secret") == "", "read_source stays empty on a refused fetch"


def test_fetch_raw_surfaces_status_and_preserves_newlines(monkeypatch=None):
    # patch the vetting to allow a loopback test server, proving status-surfacing + newline preservation
    import http.server
    import threading

    import sigil.agents.sources as S

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"line one\nline two\nDisallow: /x\n")
        def log_message(self, *a): pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    orig = S._vetted_ip
    S._vetted_ip = lambda host: "127.0.0.1"
    try:
        r = fetch_raw(f"http://127.0.0.1:{port}/robots.txt")
        assert r.ok and r.status == 200
        assert "\n" in r.raw and r.raw.count("\n") >= 3, "newlines preserved (robots/extraction need them)"
    finally:
        S._vetted_ip = orig; srv.shutdown()


# ---- E2 scope: deny-all + allowlist + public-only ------------------------------------------------
def test_scope_deny_all_and_allowlist():
    orig = scope_mod.is_public_host
    scope_mod.is_public_host = lambda h: True                 # isolate allowlist logic from DNS
    try:
        assert ScrapeScope([]).admit("https://example.com/x") is None, "empty allowlist = deny-all"
        sc = ScrapeScope(["example.com"])
        assert sc.admit("https://example.com/page") == "example.com"
        assert sc.admit("https://evil.com/page") is None, "a non-allowlisted domain is refused"
        assert sc.admit("https://sub.example.com/x") is None, "subdomains excluded by default"
        assert ScrapeScope(["example.com"], include_subdomains=True).admit("https://sub.example.com/x") == "sub.example.com"
        assert sc.admit("ftp://example.com/x") is None, "non-http scheme refused"
    finally:
        scope_mod.is_public_host = orig


def test_scope_refuses_loopback_via_ssrf():
    assert ScrapeScope(["localhost"]).admit("http://localhost/x") is None, "a loopback host is never in scope"


# ---- E3 rate limiter -----------------------------------------------------------------------------
def test_rate_limiter_min_interval_and_crawl_delay():
    t = {"now": 100.0}
    waited = []
    rl = RateLimiter(min_interval=2.0, clock=lambda: t["now"], sleep=lambda s: waited.append(s))
    assert rl.acquire("a.com") == 0.0, "first request to a host waits nothing"
    t["now"] = 100.5
    assert rl.acquire("a.com") == 1.5, "a 2.0s interval, 0.5s elapsed → wait 1.5s"
    assert rl.acquire("b.com") == 0.0, "a different host has its own bucket"
    t["now"] = 200.0
    assert abs(rl.acquire("a.com", host_min=5.0) - 0.0) < 1e-9, "long-idle → no wait"
    t["now"] = 200.1
    assert abs(rl.acquire("a.com", host_min=5.0) - 4.9) < 1e-6, "site crawl-delay raises the floor to 5.0s"


# ---- E4 robots: respected + fail-closed ----------------------------------------------------------
def test_robots_respected_and_fail_closed():
    robo = "User-agent: *\nDisallow: /private\nCrawl-delay: 3\n"
    rc = RobotsCache(fetch=_fetch_table({"https://x.com/robots.txt": (200, robo)}))
    assert rc.can_fetch("https://x.com/public") is True
    assert rc.can_fetch("https://x.com/private/secret") is False, "a Disallowed path is never fetched"
    assert rc.crawl_delay("https://x.com/") == 3.0, "site crawl-delay is surfaced"
    # 5xx robots → disallow-all (fail-closed); 404 → allow-all (standard)
    assert RobotsCache(fetch=_fetch_table({"https://y.com/robots.txt": (503, "")})).can_fetch("https://y.com/z") is False
    assert RobotsCache(fetch=_fetch_table({})).can_fetch("https://z.com/anything") is True


# ---- E5 extraction -------------------------------------------------------------------------------
def test_extract_links_tables_entities():
    html = ('<a href="/a">Alpha</a><a href="https://x.com/b">Beta</a>'
            '<table><tr><td>r1c1</td><td>r1c2</td></tr></table> Barack Obama visited Paris.')
    lk = extract.links("https://x.com/base", html)
    assert {l["url"] for l in lk} == {"https://x.com/a", "https://x.com/b"}, "relative link resolved to absolute"
    assert extract.tables(html)[0] == [["r1c1", "r1c2"]]
    ents = extract.entities(html)
    assert "Barack Obama" in ents and "Paris" in ents, "capitalized entities surfaced (advisory)"


# ---- E6 frontier: scope + robots + skips ---------------------------------------------------------
def test_frontier_crawls_in_scope_respects_robots_and_records_skips():
    orig = scope_mod.is_public_host
    scope_mod.is_public_host = lambda h: True
    try:
        pages = {
            "https://site.test/": (200, '<a href="/a">A</a><a href="/private">P</a><a href="https://evil.test/x">E</a>'),
            "https://site.test/a": (200, "the answer is 42"),
        }
        robo = RobotsCache(fetch=_fetch_table({"https://site.test/robots.txt": (200, "User-agent: *\nDisallow: /private\n"),
                                               "https://evil.test/robots.txt": (200, "")}))
        fr = Frontier(ScrapeScope(["site.test"]), fetch=_fetch_table(pages), robots=robo, max_pages=10)
        got = fr.crawl("what is the answer", ["https://site.test/"])
        urls = {p.url for p in got}
        assert "https://site.test/" in urls and "https://site.test/a" in urls
        assert "https://site.test/private" not in urls, "robots-disallowed page is never fetched"
        assert "https://evil.test/x" not in urls, "an out-of-scope link is never fetched"
        skips = {why for _, why in fr.skips}
        assert "robots-disallow" in skips and "out-of-scope" in skips, "drops are honestly recorded"
    finally:
        scope_mod.is_public_host = orig


# ---- E8 grounding: serve the verbatim span, flag fabrication --------------------------------------
class _FakeFrontier:
    def __init__(self, pages):
        self._pages = pages
        self.skips = []
    def crawl(self, question, seeds):
        return self._pages


class _MockSynth:
    def synthesize(self, question, docs):
        seq = next(iter(docs))
        return [
            {"claim": "the sky is blue today", "source": seq, "quote": "the sky is blue", "confidence": 0.9},
            {"claim": "FABRICATED: rockets are made of cheese", "source": seq,
             "quote": "this exact phrase is absent from the page", "confidence": 0.8},
        ]


def test_grounding_serves_verbatim_and_flags_fabrication():
    s = _store()
    page = FetchedPage(url="https://site.test/a", status=200, text="Observing: the sky is blue over the bay.",
                       raw="", content_hash="h", depth=0, links=[])
    res = WebResearcher(s).research_web("what colour is the sky?", ["https://site.test/a"],
                                        ScrapeScope(["site.test"]), synthesizer=_MockSynth(),
                                        frontier=_FakeFrontier([page]))
    text = s.get(res.applied[0]).payload["text"]
    assert "the sky is blue" in text, "the verbatim grounded span is served"
    lines = text.splitlines()
    adv_i = next(i for i, ln in enumerate(lines) if "Advisory" in ln)
    grounded_block, advisory_block = "\n".join(lines[:adv_i]), "\n".join(lines[adv_i:])
    assert "cheese" not in grounded_block, "a fabricated claim is NOT served as grounded"
    assert "cheese" in advisory_block, "the fabrication is demoted to advisory, not dropped"


def test_web_page_records_are_persisted_and_cited():
    s = _store()
    page = FetchedPage(url="https://site.test/a", status=200, text="the answer is 42", raw="", content_hash="h", depth=0, links=[])
    WebResearcher(s).research_web("q", ["https://site.test/a"], ScrapeScope(["site.test"]),
                                  synthesizer=_MockSynth(), frontier=_FakeFrontier([page]))
    webpages = [r for r in s.iter_records() if r.kind == "web_page"]
    assert webpages and webpages[0].payload["url"] == "https://site.test/a" and webpages[0].payload["robots_allowed"] is True


# ---- red-pen negative controls (BLOCK-1 / BLOCK-2) -----------------------------------------------
def test_ssrf_refuses_cgnat_shared_space():                       # BLOCK-1
    import sigil.agents.sources as S
    orig = S.socket.getaddrinfo
    S.socket.getaddrinfo = lambda host, *a, **k: [(2, 1, 6, "", ("100.100.100.200", 0))]  # Alibaba metadata / CGNAT
    try:
        assert S.is_public_host("metadata.attacker.test") is False, "RFC-6598 shared space is not globally routable → refused"
        assert S._vetted_ip("metadata.attacker.test") is None
    finally:
        S.socket.getaddrinfo = orig
    S.socket.getaddrinfo = lambda host, *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))]
    try:
        assert S.is_public_host("dns.test") is True, "a genuinely-global public IP still passes"
    finally:
        S.socket.getaddrinfo = orig


def test_frontier_budget_truncation_is_recorded():                # BLOCK-2
    orig = scope_mod.is_public_host
    scope_mod.is_public_host = lambda h: True
    try:
        pages = {f"https://site.test/{i}": (200, "".join(f'<a href="/{j}">L</a>' for j in range(6))) for i in range(6)}
        pages["https://site.test/"] = (200, "".join(f'<a href="/{j}">L</a>' for j in range(6)))
        robo = RobotsCache(fetch=_fetch_table({"https://site.test/robots.txt": (200, "")}))
        fr = Frontier(ScrapeScope(["site.test"]), fetch=_fetch_table(pages), robots=robo, max_pages=3)
        got = fr.crawl("q", ["https://site.test/"])
        assert len(got) == 3, "max_pages caps fetched pages"
        assert any(why == "max-pages-budget" for _, why in fr.skips), "budget-truncated URLs are recorded, not silently dropped"
    finally:
        scope_mod.is_public_host = orig


# ---- E0 WARDEN guard-lock ------------------------------------------------------------------------
def test_warden_locks_scrape_verbs_a3():
    from sigil.agents.base import Tier
    from sigil.agents.kernel_classify import KernelClassifier
    k = Path("/home/kali/sigil/kernel/target/release/sigil-kernel")
    if not k.exists():
        print("    (skip — kernel not built)")
        return
    kc = KernelClassifier(kernel_bin=str(k))
    assert kc.classify("scrape.fetch") == Tier.A3 and kc.classify("web.fetch") == Tier.A3, "generic scrape/fetch fail-closed A3"
    assert kc.classify("http.get") == Tier.A0, "a clean read-verb is A0"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-8 WS-E (SCRIBE scraper) guarantees hold")
