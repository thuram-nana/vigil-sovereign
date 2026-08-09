"""Differential test: VIGIL's inert-markup masker vs. a REAL HTML tokenizer (stdlib ``html.parser``).

The masker in ``scanner/checks.py`` decides whether a URL in a response body is something the app EMITS (a
link/resource a victim's browser would actually use) or merely inert text. That decision is load-bearing:
counting inert text mints a signed FALSE FACT, and masking live markup DROPS a real vulnerability. Both
directions have happened repeatedly, each time on a fresh HTML tokenizer edge case found by hand.

So stop guessing: assert the masker against an independent tokenizer over a generated corpus. Every case is
an ``href`` placed inside a context whose liveness ``html.parser`` decides for us, so a disagreement is
either a false-FACT surface or a dropped sink — and CI reports it without anyone having to think of the
edge case first.

Scope note: ``html.parser`` is not a full WHATWG implementation, so the corpus is restricted to constructs
it tokenizes faithfully. Two documented, deliberate divergences are excluded and covered by explicit tests
elsewhere: fallback elements (``noscript``/``noembed``/``noframes``, which VIGIL treats as LIVE because they
are parsed as markup whenever the corresponding feature is off) and the WHATWG script-data double-escape.
"""

from __future__ import annotations

from html.parser import HTMLParser

import pytest

from framework.v2.scanner.checks import _emitted_url_hosts

_HOST = "diff-probe.test"
_URL = f"https://{_HOST}/x"


class _LiveUrlCollector(HTMLParser):
    """Collects url-ish attribute values from tags the tokenizer actually reports as tags. Anything the
    tokenizer hands back as DATA (raw text, comments, rcdata) never becomes a tag, so it is inert."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in ("href", "src", "action") and value:
                self.urls.append(value)

    handle_startendtag = handle_starttag


def _browser_says_live(body: str) -> bool:
    parser = _LiveUrlCollector()
    try:
        parser.feed(body)
        parser.close()
    except Exception:                      # noqa: BLE001 — a tokenizer error means "not a clean live tag"
        pass
    return any(_HOST in u for u in parser.urls)


def _vigil_says_live(body: str) -> bool:
    return _HOST in _emitted_url_hosts(body)


# Contexts that WRAP the probe link. Each is a real construct whose liveness the tokenizer decides.
_WRAPPERS = [
    ("bare", "{probe}"),
    ("div", "<div>{probe}</div>"),
    ("pre", "<pre>{probe}</pre>"),                       # live: tags inside <pre> are parsed
    ("code", "<code>{probe}</code>"),
    ("comment", "<!-- {probe} -->"),                     # inert
    ("script", "<script>{probe}</script>"),              # inert (raw text)
    ("style", "<style>{probe}</style>"),                 # inert (raw text)
    ("textarea", "<textarea>{probe}</textarea>"),        # inert (escapable raw text)
    ("title", "<title>{probe}</title>"),                 # inert (escapable raw text)
    ("closed_script_then", "<script>var a=1</script>{probe}"),
    ("closed_textarea_then", "<textarea>x</textarea>{probe}"),
    ("comment_then", "<!-- c -->{probe}"),
    ("attr_gt", '<div title="a>b"></div>{probe}'),       # a '>' inside a quoted value
    ("attr_apostrophe", "<div title=it's></div>{probe}"),  # literal quote in an UNQUOTED value
    ("attr_quoted_apostrophe", "<div title=\"it's\"></div>{probe}"),
    ("attr_lt", '<div title="a<b"></div>{probe}'),
    ("input_value_taglike", '<input value="<textarea>">{probe}'),
    ("meta_charset_then", '<meta charset="utf-8">{probe}'),
    ("nested_div", "<div><span>{probe}</span></div>"),
    ("script_after_close", "<script>x</script ><div>{probe}</div>"),
]

# The probe itself: several spellings of a link, all of which a tokenizer reports as a start tag.
_PROBES = [
    ("a_double", f'<a href="{_URL}">t</a>'),
    ("a_single", f"<a href='{_URL}'>t</a>"),
    ("img_src", f'<img src="{_URL}">'),
    ("form_action", f'<form action="{_URL}"></form>'),
    ("link_href", f'<link rel="canonical" href="{_URL}">'),
    ("iframe_src", f'<iframe src="{_URL}"></iframe>'),
    ("a_extra_attrs", f'<a class="x" href="{_URL}" data-y="1">t</a>'),
]

_CASES = [
    pytest.param(w_tpl.format(probe=p_body), id=f"{w_id}-{p_id}")
    for w_id, w_tpl in _WRAPPERS
    for p_id, p_body in _PROBES
]


@pytest.mark.parametrize("body", _CASES)
def test_masker_agrees_with_a_real_tokenizer_on_liveness(body: str) -> None:
    """VIGIL must count a URL as emitted exactly when a real tokenizer reports it as a live tag attribute.

    Disagreement in one direction is a FALSE-FACT surface (inert text counted as an emission); in the other
    it is a DROPPED sink (a real link masked away). Both are defects, so this asserts equality."""
    browser = _browser_says_live(body)
    vigil = _vigil_says_live(body)
    assert vigil == browser, (
        f"masker/tokenizer disagree (vigil={vigil}, tokenizer={browser}) on: {body!r}\n"
        f"{'inert text counted as an emission (false-FACT surface)' if vigil else 'live link masked away (dropped sink)'}"
    )


def test_the_differential_corpus_actually_exercises_both_outcomes() -> None:
    """Guard against a vacuous corpus: it must contain cases the tokenizer calls live AND cases it calls
    inert. A corpus that is all-live (or all-inert) would pass while testing nothing."""
    live = sum(1 for c in _CASES if _browser_says_live(c.values[0]))
    assert live > 0, "corpus has no LIVE cases — it cannot catch a dropped sink"
    assert live < len(_CASES), "corpus has no INERT cases — it cannot catch a false-FACT surface"
