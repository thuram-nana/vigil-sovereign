"""privacy_center_store — the published privacy facts the customer Privacy centre (VIGIL_CUSTOMER_PRIVACY_CENTER)
surfaces, read from the ONE canonical source: the packaged public pages.

The Privacy centre (legal/governance S2) is a pure display screen. It must never show a reworded or invented copy of the
privacy wording — it renders the text this deployment has ALREADY published. So the facts it shows are read, at request
time, from the packaged ``public_site`` pages that ARE that published wording:

  * the strictly-necessary cookie inventory — the cookie table of ``public_site/cookies/index.html`` (three cookies,
    every one strictly necessary, zero optional, nothing to consent to);
  * the subprocessor list — the providers list of ``public_site/privacy/index.html`` (AWS, Cloudflare, Stripe, Google,
    GitHub, and a third-party AI processor — the AI subprocessor is disclosed but deliberately NOT named, so a
    customer never sees the AI provider), each rendered as the canonical page words it;
  * links to the full published pages (``/cookies``, ``/privacy``, ``/trust``), the same paths the public site uses.

There is no second copy of this wording to drift: edit the public page and the Privacy centre follows on the next read.
This is a read of published, org-INDEPENDENT facts (the same for every workspace) — never money, never authority, never a
signed-spine record, and nothing here is ever written. If a section's expected structure is not found, that section
reads as empty (the screen still shows the links): the safe direction is to show less, never a guessed value.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

from ..reuse import assert_no_offense

assert_no_offense()

#: the packaged public pages that ARE the canonical published wording (served by ``pubui`` at ``/cookies`` and
#: ``/privacy``); read here, never forked.
_PUBLIC_ROOT = Path(__file__).resolve().parent / "public_site"
_COOKIES_PAGE = _PUBLIC_ROOT / "cookies" / "index.html"
_PRIVACY_PAGE = _PUBLIC_ROOT / "privacy" / "index.html"

#: the canonical paths of the published pages (the same paths the public site links between its own pages).
LINKS = {"cookies": "/cookies", "privacy": "/privacy", "trust": "/trust"}

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_TR = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.I | re.S)
_TH = re.compile(r"<th\b[^>]*>(.*?)</th>", re.I | re.S)
_TD = re.compile(r"<td\b[^>]*>(.*?)</td>", re.I | re.S)
_LI = re.compile(r"<li\b[^>]*>(.*?)</li>", re.I | re.S)
_STRONG = re.compile(r"<strong\b[^>]*>(.*?)</strong>", re.I | re.S)


def _text(fragment: str) -> str:
    """The visible text of an HTML fragment: tags removed, entities unescaped, whitespace collapsed."""
    return _WS.sub(" ", html.unescape(_TAG.sub("", fragment))).strip()


def _read(path: Path) -> str:
    """The page's text, or ``""`` if it cannot be read (the section then reads as empty — never a raised error on a
    display path)."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _between(doc: str, start: str, end: str) -> str:
    """The slice of ``doc`` from the first ``start`` to the next ``end`` (empty if either marker is absent)."""
    i = doc.find(start)
    if i < 0:
        return ""
    j = doc.find(end, i + len(start))
    return doc[i + len(start):j] if j >= 0 else ""


def _cookies(doc: str) -> list:
    """The cookie inventory from the cookies page's matrix table: one ``{name, purpose, category}`` per body row."""
    body = _between(doc, "<tbody>", "</tbody>")
    rows = []
    for tr in _TR.findall(body):
        th = _TH.search(tr)
        tds = _TD.findall(tr)
        if not th or len(tds) < 2:
            continue
        rows.append({"name": _text(th.group(1)), "purpose": _text(tds[0]), "category": _text(tds[1])})
    return rows


def _cookie_note(doc: str) -> str:
    """The cookies page's own short-version summary (the ``<p class="muted">`` under the heading)."""
    m = re.search(r'<p class="muted">(.*?)</p>', doc, re.I | re.S)
    return _text(m.group(1)) if m else ""


def _subprocessors(doc: str) -> list:
    """The subprocessor list from the privacy page's providers section: one ``{name, detail}`` per list item, rendered
    as the canonical page words it (name = the bolded provider, detail = the whole published line)."""
    section = _between(doc, '<h3 id="providers">', "</ul>")
    ul = section[section.find("<ul>"):] if "<ul>" in section else ""
    out = []
    for li in _LI.findall(ul):
        strong = _STRONG.search(li)
        if not strong:
            continue
        out.append({"name": _text(strong.group(1)), "detail": _text(li)})
    return out


def read_privacy_center() -> dict:
    """The published privacy facts the Privacy centre surfaces, read from the canonical public pages: the cookie
    inventory and its strictly-necessary/optional counts, the subprocessor list, and the links to the full pages.
    Org-INDEPENDENT (the same for every workspace) and read-only — nothing here is ever written."""
    cookies_doc = _read(_COOKIES_PAGE)
    privacy_doc = _read(_PRIVACY_PAGE)
    cookies = _cookies(cookies_doc)
    strictly = sum(1 for c in cookies if "strictly" in c["category"].lower())
    return {
        "cookies": cookies,
        "cookie_summary": {"strictly_necessary": strictly, "optional": len(cookies) - strictly,
                           "note": _cookie_note(cookies_doc)},
        "subprocessors": _subprocessors(privacy_doc),
        "links": dict(LINKS),
    }
