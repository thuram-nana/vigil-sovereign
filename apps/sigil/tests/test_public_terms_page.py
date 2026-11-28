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
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from sigil.ui.pubui import build_public_server

ROOT = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "public_site"
TERMS = ROOT / "terms" / "index.html"
PRIVACY = ROOT / "privacy" / "index.html"
COOKIES = ROOT / "cookies" / "index.html"
SUPPORT = ROOT / "support" / "index.html"
SECURITY_TXT = ROOT / ".well-known" / "security.txt"
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

def test_legal_pages_load_nothing_off_site_and_run_no_script():
    # the terms, the privacy, cookie and support pages: no script, no inline style, nothing loaded off-site
    for page in (TERMS, PRIVACY, COOKIES, SUPPORT):
        name = page.parent.name
        refs = _refs(page.read_text(encoding="utf-8"))
        assert refs.scripts == 0, f"/{name} runs a script"
        assert refs.inline_styles == 0, f"/{name} has an inline style (the strict CSP blocks it; use site.css)"
        for tag, url in refs.loads:
            assert url.startswith("/") and not url.startswith("//"), f"/{name}: <{tag}> loads off-site: {url}"


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
    # refunds are discretionary beyond the law and the one stated case: discontinuation, or closing the account over
    # a material change the customer does not accept, refunds unused purchased credits on request
    assert "any other refund is at SIGIL SARL's discretion" in text and "Except where the law requires otherwise" in text
    assert ("If we discontinue the Service, or you close your account because you do not accept a material change, "
            "we will refund unused purchased credits on request.") in text
    # a cancelled plan runs to the end of the paid period
    assert "runs to the end of the period you have already paid for" in text
    # USD pricing plus taxes; no seat price, because no seat is sold (governor/catalog.py has no seat entry)
    assert "US dollars (USD)" in text
    assert "USD 25" not in text and "a seat will not include credits" in text
    # partial results during a trial; no SLA unless agreed in writing
    assert "may be shown in part" in text
    assert "no service-level agreement" in text and "signed written agreement" in text


def test_terms_page_admits_individuals_and_states_the_consumer_right_of_withdrawal():
    # Owner, 2026-11-24: VIGIL is for businesses AND individuals. The terms must not restrict use to business purposes,
    # must keep the 18+ rule, and must state the consumer's 14-day right of withdrawal with the immediate-supply
    # acknowledgement (unused credits refunded in proportion; the right ends once a purchase's credits are all used).
    text = re.sub(r"\s+", " ", TERMS.read_text(encoding="utf-8"))
    assert "for businesses, professionals and individuals" in text and "at least 18 years old" in text
    assert "business and professional use" not in text and "internal business purposes" not in text
    assert "for your own business or personal purposes" in text
    # §1: a workspace is an individual's account too, consistent with §2 admitting individuals
    assert 'A "workspace" is the account of one person or organisation on the Service' in text
    assert "the account of one organisation" not in text
    assert "Right of withdrawal (consumers)" in text and "within 14 days" in text
    assert "ask us to start supplying it immediately" in text
    assert "we refund the price of that purchase's credits you have not used, in proportion" in text
    assert "you lose the right of withdrawal for a purchase once all of its credits have been used" in text

def test_terms_page_pins_the_consumer_refund_window_and_protection_sentences():
    # D3/D4/D5 (P1218 round-2 mutation review): the sentences the owner/counsel settled for consumers. Pinned verbatim
    # so deleting or inverting any of them fails CI. The generic "within 14 days" assertions above are also satisfied
    # by the earlier "within 14 days of it", so these three are asserted in full rather than by a shared fragment.
    text = re.sub(r"\s+", " ", TERMS.read_text(encoding="utf-8"))
    # §8 refunds: the refund window and method
    assert "We refund within 14 days of receiving your withdrawal, to the payment method you used." in text   # D3
    # §8 refunds: a plan's 14 days run from its first purchase, and a withdrawn plan does not renew
    assert ("For a plan, the 14 days run from its first purchase, and a plan you withdraw from does not renew."
            in text)                                                                                           # D4
    # §2 eligibility: the consumer-protection bullet (the law's non-excludable protection still applies)
    assert ("the points of these terms marked for consumers apply to you, and so does the consumer protection that "
            "the law of the country where you live gives you and that cannot be excluded by contract.") in text  # D5


def test_terms_page_never_claims_the_checkout_computes_or_shows_tax():
    # Owner, 2026-11-24: no tax or VAT computation at launch (no checkout asks the processor to compute one). §6 keeps
    # the wording of the reviewed terms: prices exclude taxes, which are added where the law requires and are the
    # customer's responsibility. It must not promise that the checkout adds or shows a tax line.
    text = re.sub(r"\s+", " ", TERMS.read_text(encoding="utf-8"))
    assert ("Prices are in US dollars (USD) and are shown on the Service and on the checkout page before you pay. "
            "They exclude taxes. Applicable taxes, such as VAT, GST or sales tax, are added where the law requires "
            "and are your responsibility.") in text
    low = text.lower()
    assert "checkout page shows them" not in low and "shows the tax" not in low and "shows taxes" not in low


def test_terms_page_has_the_reviewed_notice_and_no_draft_banner():
    text = TERMS.read_text(encoding="utf-8")
    main = text[text.index("<main"):]
    notice = re.search(r'<p class="muted" id="reviewed">(.*?)</p>', main, re.S)
    assert notice and "reviewed on" in notice.group(1)
    assert notice.start() < main.index("<h2"), "the reviewed-on notice belongs at the top, before the first section"
    assert not re.search(r"\bdraft\b", text, re.I), "no draft banner or wording on the published terms"


# Phrases a legal page must never use. "protected" and "secure" are checked as whole words after removing the
# few uses that describe a duty or a third party's page rather than a promise about the Service.
_OVERCLAIM_PHRASES = ("guarantee", "fully protected", "zero false positive", "100% secure", "unhackable",
                      "bank-grade", "military-grade")
_OVERCLAIM_WORDS = re.compile(r"\b(protected|secure)\b")
_OVERCLAIM_ALLOWED = (
    re.compile(r"data-protection"),                       # the name of a body of law / an authority
    re.compile(r"secure checkout page"),                  # Stripe's page, not ours
    re.compile(r"keep your sign-in credentials and authenticator app secure"),   # the customer's duty
    re.compile(r"work to keep the service available and secure"),               # an effort, with no SLA (section 9)
    re.compile(r"not a statement that a system is secure"),   # the disclaimer that DENIES the claim
    re.compile(r"provide, secure, support"),              # "secure" the verb, in the list of permitted purposes
)


def overclaims(text: str) -> list[str]:
    """Every overclaim in ``text`` (HTML): a banned phrase, or "protected" / "secure" outside the allowances."""
    flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).lower()
    found = [p for p in _OVERCLAIM_PHRASES if p in flat]
    for allowed in _OVERCLAIM_ALLOWED:
        flat = allowed.sub(" ", flat)
    found += _OVERCLAIM_WORDS.findall(flat)
    return found


def test_overclaim_check_catches_protected_and_secure_but_allows_duties():
    assert overclaims("<p>Your data is protected.</p>") == ["protected"]
    assert overclaims("<p>The Service is secure.</p>") == ["secure"]
    assert overclaims("<p>We guarantee results.</p>") == ["guarantee"]
    assert overclaims("<p>Keep your sign-in credentials and authenticator app secure.</p>") == []
    assert overclaims("<p>We work to keep the Service available and secure.</p>") == []
    assert overclaims("<p>We keep your data secure.</p>") == ["secure"]     # only the two exact phrases are allowed
    assert overclaims("<p>on its own secure checkout page</p>") == []
    assert overclaims("<p>applicable data-protection laws</p>") == []
    assert overclaims("<p>We keep the logs. Our systems are secure.</p>") == ["secure"]   # a bare claim is still caught
    assert overclaims("<p>It is a statement that a system is secure.</p>") == ["secure"]  # only the denial is allowed


def test_terms_page_makes_no_overclaim():
    assert overclaims(TERMS.read_text(encoding="utf-8")) == []


def test_privacy_page_makes_no_overclaim():
    assert overclaims(PRIVACY.read_text(encoding="utf-8")) == []


# --- the terms, the privacy notice and security.txt agree ----------------------------------------------------------

# The production processors and providers of the hosted service (owner-supplied; Flutterwave is paused in code and
# is not a current processor). Both legal pages must name every one, and the same contact. The AI subprocessor is
# disclosed GENERICALLY ("a third-party AI processor") rather than by provider name, per the consumer no-model rule
# (the customer never sees the AI provider); the disclosure itself is kept, only the name is withheld.
PROVIDERS = ("AWS", "Amazon SES", "Cloudflare", "Stripe", "Google", "GitHub", "third-party AI processor")
CONTACT = "info@sigilsovereign.com"


def _flat_text(path: Path) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", path.read_text(encoding="utf-8"))))


def test_privacy_page_names_the_production_providers_and_contact():
    text = _flat_text(PRIVACY)
    for name in PROVIDERS:
        assert name in text, f"/privacy does not name the provider {name}"
    assert CONTACT in text
    assert "Flutterwave" not in text, "Flutterwave is paused; it is not a current processor"
    assert "in development" not in text.lower() and "finalised with counsel" not in text.lower()
    assert "Republic of Cameroon" in text and "OHADA" in text          # the same governing law as the terms


def test_terms_and_privacy_name_the_same_providers_and_contact():
    terms, privacy = _flat_text(TERMS), _flat_text(PRIVACY)
    for name in PROVIDERS:
        assert name in terms, f"/terms does not name the provider {name}"
        assert name in privacy, f"/privacy does not name the provider {name}"
    assert "Flutterwave" not in terms
    assert "third-party AI processors we use to run the Service, which are listed in our Privacy notice" in terms
    assert CONTACT in terms and CONTACT in privacy


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def test_no_personal_mailbox_or_placeholder_domain_on_the_legal_pages():
    for path in (TERMS, PRIVACY, SECURITY_TXT, ROOT / "sitemap.xml", ROOT / "robots.txt"):
        raw = path.read_text(encoding="utf-8")
        mailboxes = set(_EMAIL.findall(raw))
        assert mailboxes <= {CONTACT}, f"{path.name} names a mailbox other than {CONTACT}"
        assert "vigil.example" not in raw, f"{path.name} still uses the placeholder domain"
    sec = SECURITY_TXT.read_text(encoding="utf-8")
    assert f"Contact: mailto:{CONTACT}" in sec
    assert "Canonical: https://vigilguard.net/.well-known/security.txt" in sec


def test_security_txt_has_an_rfc9116_expires_in_the_future():
    """RFC 9116 section 2.5.5: exactly one ``Expires`` field, an RFC 3339 timestamp, not yet passed. When this fails
    because the date has passed, renew the field (at most a year ahead) rather than weakening the test."""
    lines = [ln for ln in SECURITY_TXT.read_text(encoding="utf-8").splitlines() if ln.lower().startswith("expires:")]
    assert len(lines) == 1, f"security.txt must carry exactly one Expires field, found {len(lines)}"
    value = lines[0].split(":", 1)[1].strip()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", value), value
    expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert expires > datetime.now(timezone.utc), f"security.txt expired on {value}"


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


def test_the_support_page_describes_the_hosted_service_and_the_owners_support_commitment():
    # Owner, 2026-11-24 (decision 4): support goes to info@sigilsovereign.com with a 2-business-day reply TARGET (no
    # SLA). The page must describe the live hosted service, never the old "self-hosted only / hosted in development"
    # story, and must not contradict the privacy notice (data does go to the model provider in hosted mode).
    text = re.sub(r"\s+", " ", SUPPORT.read_text(encoding="utf-8"))
    assert "mailto:info@sigilsovereign.com" in text and "within <strong>2 business days</strong>" in text
    assert "a target, not a promised response time" in text and "no service-level agreement" in text
    for stale in ("in development", "VIGIL is self-hosted", "There's no telemetry", "Request access or a walkthrough"):
        assert stale not in text, stale
    assert "We answer deletion requests within 30 days" in text      # the approved retention schedule (decision 3)
    assert "never ask for one" in text                              # no password / code / secret by email


def test_support_page_states_the_corrected_customer_facing_facts():
    """The three review objections on #1219 — each pinned to the shipped behaviour so a regression reds.

    1. The password-reset email carries a 6-digit CODE and a single-use TOKEN and NO link (provision.py
       _RECOVER_CODE_EMAIL / "Reset: token {token}") — the page must not claim a reset "link".
    2. A credit-paused assessment is resumed from Assessments WITHIN 7 DAYS (credit_pause_ttl_s default 604800 s),
       else it closes and is charged only for what it used (provision.py _CREDIT_PAUSE_BODY).
    3. Closing an account: cancel any plan first so it does not renew, download reports, unused credits lapse
       (Terms §14); purchased credits never expire WHILE YOUR ACCOUNT STAYS OPEN (Terms §6, not an absolute)."""
    text = re.sub(r"\s+", " ", SUPPORT.read_text(encoding="utf-8"))
    # 1 — reset: a code and a token, never a link
    assert "6-digit code and a single-use" in text and "there is no link to click" in text
    assert "single-use link" not in text, "the reset email has no link; the page must not claim one"
    # 2 — paused assessment: resume within 7 days, else close and charge for what it used
    assert "resume it from Assessments within 7 days" in text
    assert "it closes and is charged only for what it used" in text
    # 3 — credits never expire WHILE the account is open, and the close-account steps
    assert "purchased credits never expire while your account stays open" in text
    assert "never expire while your account stays open" in text and "never expire." not in text
    assert "cancel any plan first so it does not renew" in text
    assert "unused credits lapse" in text
    # the owner-asked pointers: the public security policy and a 'Get started' link to the real customer sign-up
    assert "https://github.com/thuram-nana/vigil-sovereign/blob/main/SECURITY.md" in text
    assert text.count("https://app.vigilguard.net/") >= 1 and "Get started" in text


def test_support_pack_range_and_plan_names_are_derived_from_the_owner_catalog():
    """The /support "credits and plans" copy is DERIVED from the owner catalog (governor/catalog.py), never pinned
    to a hand-typed number: the pack PRICE RANGE, the "$1 = 100 credits" no-bonus rate, and the plan NAMES are
    exactly the OFFERED, NON-RETIRED catalog. Change a price, a plan name, or add a bonus pack in the catalog and
    this reds until the page is brought back into agreement — the page can never drift from what is on sale."""
    from sigil.governor import catalog
    from sigil.governor.billing import EVENT_TOPUP
    text = re.sub(r"\s+", " ", SUPPORT.read_text(encoding="utf-8"))
    # offered (non-retired) top-ups = the credit packs on sale. plans() already drops retired entries.
    packs = [p for p in catalog.plans() if p["kind"] == EVENT_TOPUP]
    assert packs, "no credit pack is on sale in the owner catalog"
    amounts = sorted(p["amount_minor"] for p in packs)
    lo, hi = amounts[0], amounts[-1]
    assert lo % 100 == 0 and hi % 100 == 0, (lo, hi)        # whole-dollar packs, the way the page states them
    assert f"from ${lo // 100} to ${hi // 100}" in text, \
        f"/support pack range must be 'from ${lo // 100} to ${hi // 100}' (the offered catalog)"
    # every offered pack is exactly $1 = 100 credits (amount_minor cents == credits): the no-volume-bonus rate the
    # page claims. The retired bonus pack is excluded by plans(); re-introducing one would red this.
    assert all(p["credits"] == p["amount_minor"] for p in packs), \
        "an offered pack is not $1 = 100 credits, but /support claims that rate"
    assert "$1 = 100 credits" in text
    # the offered CREDIT plan names (never a top-up, never an AEGIS monitoring plan), in catalog order, exactly as
    # the page lists them — "(Starter, Pro or Team)".
    names = [e.display_name.split(" (")[0] for e in catalog.credit_plan_entries(offered_only=True)]
    assert len(names) >= 2, names
    listed = ", ".join(names[:-1]) + " or " + names[-1]
    assert f"({listed})" in text, f"/support must name the offered plans as ({listed})"
    for name in names:
        assert name in text, f"/support does not name the offered plan {name!r}"


def test_support_withdrawal_mention_requires_the_consumer_withdrawal_clause_in_terms():
    """A /support summary must never outlive the binding clause it points to: whenever the page mentions a right of
    withdrawal, the Terms must still carry the exact "Right of withdrawal (consumers)" clause (Terms §8) that the
    summary stands on. Drop the clause from /terms and this reds."""
    support = re.sub(r"\s+", " ", SUPPORT.read_text(encoding="utf-8")).lower()
    if "withdrawal" in support:
        terms = TERMS.read_text(encoding="utf-8")
        assert "Right of withdrawal (consumers)" in terms, \
            "/support mentions withdrawal but /terms no longer carries the 'Right of withdrawal (consumers)' clause"


def test_support_page_makes_no_overclaim():
    """The same overclaim lint the legal pages pass, run on /support: no "guarantee", no "100% secure", no bare
    "protected" / "secure" claim about the Service."""
    assert overclaims(SUPPORT.read_text(encoding="utf-8")) == []
