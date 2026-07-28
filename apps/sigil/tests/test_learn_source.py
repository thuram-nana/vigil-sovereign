"""K4 — point-at-a-URL learning (`scrape.learn_source` + the `start_learn` action).

Doctrine under test:
  * NOTHING a page asserts becomes a fact — every synthesized claim goes through the demote-only
    `consolidate.gate.admit`: only a VERBATIM span from the re-fetched page grounds; a fabricated quote OR a
    citation outside the fetched window is demoted to advisory;
  * SCOPE is fail-closed + SSRF-safe — the crawl is bounded to the URL's host, and an internal/metadata/
    off-scope host is refused (`is_public_host`);
  * STOP-able — a kill-switch `cancel` hook aborts the crawl between hops (recorded honestly);
  * the `start_learn` action is FAIL-CLOSED — refused when the kill-switch is engaged or autolearn is off.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest tests/test_learn_source.py -q
"""

import tempfile
from types import SimpleNamespace

import pytest

from sigil.scrape.frontier import Frontier
from sigil.scrape.learn_source import TRUSTED_LEARN_SOURCES, learn_from_url
from sigil.scrape.researcher import WebResearcher
from sigil.scrape.scope import ScrapeScope
from sigil.spine.store import SpineStore
from sigil.ui import actions

_PAGE = "<html><body>SQL injection occurs when untrusted input reaches a query.</body></html>"


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


class _Robots:
    def can_fetch(self, url):
        return True

    def crawl_delay(self, url):
        return 0.0


class _Rate:
    def acquire(self, host, host_min=0.0):
        return None


def _fetch(url):
    return SimpleNamespace(ok=True, status=200, raw=_PAGE, reason="ok")


class _Synth:
    """Returns three claims: one verbatim (grounds), one fabricated, one citing outside the window."""

    def synthesize(self, question, docs):
        seq = list(docs.keys())[0]
        return [
            {"claim": "grounded", "source": seq, "quote": "SQL injection occurs when untrusted input",
             "confidence": 0.9},
            {"claim": "FABRICATED", "source": seq, "quote": "this text is nowhere in the page", "confidence": 0.99},
            {"claim": "outside-window", "source": "99999", "quote": "SQL injection occurs", "confidence": 0.9},
        ]


def _frontier(**kw):
    return Frontier(ScrapeScope(["owasp.org"]), fetch=_fetch, robots=_Robots(), rate=_Rate(), **kw)


@pytest.fixture
def public(monkeypatch):
    # `is_public_host` resolves DNS for a hostname (flaky offline); stub it so the crawl runs deterministically
    # for owasp.org while STILL rejecting internal/metadata hosts (the SSRF-relevant IP literals).
    import sigil.scrape.scope as scope_mod
    monkeypatch.setattr(scope_mod, "is_public_host",
                        lambda h: bool(h) and h not in ("127.0.0.1", "169.254.169.254", "localhost", "::1"))


# ---- scope: fail-closed + SSRF-safe (IP-literal checks are offline-safe) ----

def test_scope_is_fail_closed_and_ssrf_safe():
    sc = ScrapeScope(["owasp.org"])
    assert sc.admit("http://127.0.0.1/x") is None                # loopback SSRF (real is_public_host)
    assert sc.admit("http://169.254.169.254/") is None           # cloud-metadata SSRF
    assert ScrapeScope([]).admit("http://8.8.8.8/x") is None     # empty allowlist = deny-all
    assert all("*" not in h and "/" not in h for h in TRUSTED_LEARN_SOURCES)   # concrete apex hosts


def test_scope_admits_in_scope_and_refuses_off_scope(public):
    sc = ScrapeScope(["owasp.org"])
    assert sc.admit("https://owasp.org/x") == "owasp.org"        # in scope
    assert sc.admit("https://evil.com/x") is None                # off-scope host (not in the allowlist)


# ---- the load-bearing gate: nothing a page asserts becomes a fact ----------

def test_grounding_demotes_ungrounded_and_rejects_outside_window(public):
    s = _store()
    fr = _frontier(max_pages=2, max_depth=0)
    res = WebResearcher(s).research_web(
        "sqli", ["https://owasp.org/sqli"], ScrapeScope(["owasp.org"]), synthesizer=_Synth(), frontier=fr)
    rep = s.get(res.applied[-1]).payload
    assert rep["grounded"] == 1                                  # ONLY the verbatim claim grounds
    assert rep["advisory"] == 2                                  # fabricated + outside-window both demoted
    assert "SQL injection occurs" in rep["text"] and "NOT relied upon" in rep["text"]


def test_frontier_cancel_hook_aborts_between_hops(public):
    fr = _frontier(max_pages=5, cancel=lambda: True)
    pages = fr.crawl("q", ["https://owasp.org/a", "https://owasp.org/b"])
    assert pages == [] and any(why == "stopped" for _, why in fr.skips)


def test_frontier_without_cancel_is_unchanged(public):
    fr = _frontier(max_pages=2, max_depth=0)                     # default cancel=None → byte-identical crawl
    assert len(fr.crawl("q", ["https://owasp.org/a"])) == 1


def test_learn_from_url_rejects_non_http():
    for bad in ("ftp://x/y", "file:///etc/passwd", "not a url", "javascript:alert(1)"):
        with pytest.raises(ValueError, match="http"):
            learn_from_url(_store(), bad)


# ---- the start_learn action: fail-closed --------------------------------------

@pytest.fixture
def owner(monkeypatch):
    from sigil.reuse import generate_keypair
    kp = generate_keypair()
    import sigil.governor.identity as idmod
    monkeypatch.setattr(idmod, "ensure_owner_keypair", lambda: kp)
    monkeypatch.setattr(idmod, "owner_keypair", lambda: kp)
    monkeypatch.setattr(idmod, "owner_pubkey", lambda: kp.public_key_b64)
    return kp


def test_start_learn_refused_when_killswitch_engaged(owner):
    from sigil.governor import KillSwitch
    s = _store()
    KillSwitch(s, owner_key=owner).engage(reason="stop")
    with pytest.raises(ValueError, match="kill-switch"):
        actions.do_action("start_learn", {"url": "https://owasp.org/x"}, store=s)


def test_start_learn_refused_when_autolearn_disabled(owner):
    from sigil.governor import CapabilityGate
    s = _store()
    CapabilityGate(s, owner_key=owner).disable("autolearn", reason="off")
    with pytest.raises(ValueError, match="autolearn"):
        actions.do_action("start_learn", {"url": "https://owasp.org/x"}, store=s)


def test_start_learn_requires_url_or_topic(owner):
    with pytest.raises(ValueError, match="url or a topic"):
        actions.do_action("start_learn", {}, store=_store())
