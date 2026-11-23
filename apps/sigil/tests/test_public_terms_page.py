"""The public Terms of Service page (https://vigilguard.net/terms) — served, linked, self-contained, and owner-complete.

Load-bearing invariants:
  * ``public_site/terms/index.html`` exists and pubui serves it at ``/terms`` with the strict public headers and no
    cookie, like every other public page;
  * every public-site footer that links Privacy also links Terms, and the sitemap lists ``/terms``;
  * the page loads nothing off-site (no script, no external stylesheet or image), every internal link it names is
    served by pubui, and its only off-site links are the public source repository's licensing / acceptable-use
    documents, the company site and the legal contact mailbox;
  * the page carries the visible "reviewed on" notice at the top and no "draft" banner;
  * ``test_terms_page_has_no_owner_placeholders`` FAILS while any ``[[OWNER: ...]]`` marker remains. It is meant to
    keep the page un-mergeable until the owner supplies the facts only the owner can supply (registered address,
    registration number, tax id, governing law and courts, legal contact email, effective date). The detector it
    uses is itself tested, so a marker hidden in a comment, an attribute or behind HTML entities is still caught.
"""
from __future__ import annotations

import html
import re
import threading
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

from sigil.ui.pubui import build_public_server

ROOT = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
TERMS = ROOT / "terms" / "index.html"
REPO_DOCS = "https://github.com/thuram-nana/vigil-sovereign/blob/main/"
COMPANY_SITE = "https://sigilsovereign.com"
LEGAL_MAILTO = "mailto:info@sigilsovereign.com"

# An owner placeholder: "[[OWNER:" in any case, with any whitespace inside the brackets.
_OWNER_MARKER = re.compile(r"\[\[\s*owner\s*:[^\]]*\]\]|\[\[\s*owner\s*:", re.IGNORECASE)


def owner_markers(text: str) -> list[str]:
    """Every ``[[OWNER: ...]]`` marker in ``text``: in the raw source (comments and attributes included) and again
    after HTML entities are decoded, so ``&#91;&#91;OWNER:`` cannot hide one. De-duplicated, in order."""
    found: list[str] = []
    for variant in (text, html.unescape(text)):
        for m in _OWNER_MARKER.finditer(variant):
            s = re.sub(r"\s+", " ", m.group(0))
            if s not in found:
                found.append(s)
    return found


def _serve():
    srv = build_public_server(host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _get(port: int, path: str):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class _Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[str] = []          # <a href>
        self.loads: list[tuple[str, str]] = []  # (tag, url) of everything the page LOADS
        self.ids: set[str] = set()
        self.scripts = 0
        self.inline_styles = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        if a.get("style") is not None:
            self.inline_styles += 1
        if tag == "script":
            self.scripts += 1
        if tag == "a" and a.get("href"):
            self.anchors.append(a["href"])
        elif tag == "link" and a.get("href"):
            self.loads.append((tag, a["href"]))
        for k in ("src", "srcset", "data", "poster"):
            if a.get(k):
                self.loads.append((tag, a[k]))


def _refs(text: str) -> _Refs:
    p = _Refs()
    p.feed(text)
    p.close()
    return p


def _footers(text: str) -> list[str]:
    return re.findall(r"<footer\b.*?</footer>", text, re.S | re.I)


# --- the page exists and is served ---------------------------------------------------------------------------------

def test_terms_page_is_served_with_strict_headers_and_no_cookie():
    assert TERMS.is_file()
    srv, port = _serve()
    try:
        code, hdrs, body = _get(port, "/terms")
        assert code == 200 and hdrs.get("Content-Type", "").startswith("text/html")
        assert b"<h1>Terms of Service</h1>" in body and b"SIGIL SARL" in body
        assert "default-src 'self'" in hdrs.get("Content-Security-Policy", "")
        assert hdrs.get("X-Frame-Options") == "DENY"
        assert "Set-Cookie" not in hdrs
    finally:
        srv.shutdown()


def test_every_footer_that_links_privacy_also_links_terms():
    linked = []
    for page in sorted(ROOT.rglob("*.html")):
        for footer in _footers(page.read_text(encoding="utf-8")):
            if 'href="/privacy"' in footer:
                assert 'href="/terms"' in footer, f"{page.relative_to(ROOT)}: footer links Privacy but not Terms"
                linked.append(page.relative_to(ROOT))
    assert Path("index.html") in linked, "the home page footer must link Terms"


def test_terms_is_in_the_sitemap():
    sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
    locs = re.findall(r"<loc>([^<]+)</loc>", sitemap)
    assert any(loc.endswith("/terms") for loc in locs), locs
    assert any(loc.endswith("/privacy") for loc in locs)        # the same host pattern as its sibling legal page


# --- self-contained and every link resolves ------------------------------------------------------------------------

def test_terms_page_loads_nothing_off_site_and_runs_no_script():
    refs = _refs(TERMS.read_text(encoding="utf-8"))
    assert refs.scripts == 0
    assert refs.inline_styles == 0                    # the strict CSP blocks inline styles; use site.css classes
    for tag, url in refs.loads:
        assert url.startswith("/") and not url.startswith("//"), f"<{tag}> loads an off-site resource: {url}"


def test_terms_page_links_resolve():
    refs = _refs(TERMS.read_text(encoding="utf-8"))
    off_site = [h for h in refs.anchors if re.match(r"(?i)[a-z][a-z0-9+.-]*:|//", h)]
    repo_links = [h for h in off_site if h.startswith(REPO_DOCS)]
    assert sorted(set(repo_links)) == [REPO_DOCS + "ACCEPTABLE-USE.md", REPO_DOCS + "LICENSING.md"], repo_links
    for h in off_site:
        assert h in (REPO_DOCS + "LICENSING.md", REPO_DOCS + "ACCEPTABLE-USE.md", COMPANY_SITE, LEGAL_MAILTO), \
            f"unexpected off-site link {h}"
    assert LEGAL_MAILTO in off_site and COMPANY_SITE in off_site
    # the repository documents those links name exist in this repository
    repo = Path(__file__).resolve().parents[3]
    for h in repo_links:
        assert (repo / h[len(REPO_DOCS):]).is_file(), h
    # in-page anchors point at an element of the page
    for h in refs.anchors:
        if h.startswith("#"):
            assert h[1:] in refs.ids, f"dangling in-page link {h}"
    # every same-site link is served by pubui
    internal = sorted({h.split("#", 1)[0] for h in refs.anchors if h.startswith("/") and not h.startswith("//")})
    assert {"/privacy", "/cookies"} <= set(internal)
    srv, port = _serve()
    try:
        for h in internal:
            assert _get(port, h)[0] == 200, f"{h} is linked from /terms but not served"
    finally:
        srv.shutdown()


# --- content shape -------------------------------------------------------------------------------------------------

def test_terms_page_covers_the_required_subjects():
    ids = _refs(TERMS.read_text(encoding="utf-8")).ids
    for section in ("parties", "eligibility", "authorization", "acceptable-use", "account", "credits", "renewal",
                    "refunds", "service", "results", "ai", "data", "ip", "termination", "disclaimers", "liability",
                    "indemnity", "changes", "law", "contact"):
        assert section in ids, f"missing section #{section}"


def test_terms_page_states_the_decided_billing_behaviour():
    text = re.sub(r"\s+", " ", TERMS.read_text(encoding="utf-8"))
    # disputes: removed when the dispute opens, restored automatically when won
    assert "removed when the dispute opens" in text and "restored automatically" in text
    # refunds are discretionary, never promised beyond the law
    assert "any refund is at SIGIL SARL's discretion" in text and "Except where the law requires otherwise" in text
    # a cancelled plan runs to the end of the paid period
    assert "runs to the end of the period you have already paid for" in text
    # USD pricing plus taxes, and the seat
    assert "US dollars (USD)" in text and "USD 25 per month plus applicable taxes" in text
    # partial results during a trial; no SLA unless agreed in writing
    assert "may be shown in part" in text
    assert "no service-level agreement" in text and "signed written agreement" in text


def test_terms_page_has_the_reviewed_notice_and_no_draft_banner():
    text = TERMS.read_text(encoding="utf-8")
    main = text[text.index("<main"):]
    notice = re.search(r'<p class="muted" id="reviewed">(.*?)</p>', main, re.S)
    assert notice and "reviewed on" in notice.group(1)
    assert notice.start() < main.index("<h2"), "the reviewed-on notice belongs at the top, before the first section"
    assert not re.search(r"\bdraft\b", text, re.I), "no draft banner or wording on the published terms"


def test_terms_page_makes_no_overclaim():
    text = re.sub(r"\s+", " ", TERMS.read_text(encoding="utf-8")).lower()
    for phrase in ("guarantee", "fully protected", "zero false positive", "100% secure", "unhackable",
                   "bank-grade", "military-grade"):
        assert phrase not in text, phrase


# --- the owner-placeholder gate ------------------------------------------------------------------------------------

def test_owner_marker_check_catches_every_form():
    assert owner_markers("<p>All facts supplied.</p>") == []
    assert owner_markers("[[OWNER: registered address]]") == ["[[OWNER: registered address]]"]
    assert owner_markers("<!-- [[OWNER: effective date]] -->")                      # hidden in a comment
    assert owner_markers('<meta content="[[OWNER: tax id]]">')                       # hidden in an attribute
    assert owner_markers("&#91;&#91;OWNER: governing law&#93;&#93;")                 # hidden behind entities
    assert owner_markers("&lsqb;&lsqb;OWNER: courts&rsqb;&rsqb;")
    assert owner_markers("[[ owner :contact]]")                                      # case / spacing variants
    assert owner_markers("[[OWNER: an unterminated marker")                          # a broken marker still counts
    # the detector finds every marker in the shipped page as it stands (whatever their number)
    raw = TERMS.read_text(encoding="utf-8")
    assert len(owner_markers(raw)) == len(set(re.findall(r"\[\[OWNER:[^\]]*\]\]", raw)))


def test_terms_page_has_no_owner_placeholders():
    """FAILS until the owner replaces every ``[[OWNER: ...]]`` marker in public_site/terms/index.html with the real
    fact. Deliberate: the page must not go live with a placeholder in a legal document."""
    left = owner_markers(TERMS.read_text(encoding="utf-8"))
    assert not left, ("the Terms of Service still carry owner placeholders — the owner must supply:\n  "
                      + "\n  ".join(left))
