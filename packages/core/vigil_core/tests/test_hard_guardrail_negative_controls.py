"""hard_guardrail — mutation/negative controls for the deterministic scope floor (audit F-11).

The existing acceptance suite (``integration/tests/test_safety_guardrail.py`` +
``test_protected_guard_corpus.py``) runs in the INTEGRATION / offense CI legs and is skipped in the
sovereign leg. This file is pure ``vigil_core`` (stdlib only) so the floor is also protected in the
required "vigil_core — shared integrity substrate" job — and it is written as MUTATION CONTROLS: each
test pins a specific branch so a plausible edit (an anchor dropped, a quantifier widened, the fail-safe
polarity flipped, one client-reading dropped) turns a row red instead of passing silently.

Nothing here mutates the real process env except through a scoped ``monkeypatch``.
"""
from __future__ import annotations

import pytest

from vigil_core.hard_guardrail import (
    _ALLOW_ENV,
    candidate_hosts,
    is_hard_blocked,
    protected_guard_enabled,
)


# ── protected_guard_enabled — the fail-safe truth table (no pure-core test pins this today) ────────────
# Polarity is deliberately ALLOW: the guard is ON (protected) unless an explicit affirmative disables it.
# A single inverted comparison (``in`` for ``not in``) or a dropped token would flip this — every row is a
# mutation killer.

@pytest.mark.parametrize("value", ["1", "true", "yes", "on",
                                   "TRUE", "Yes", "  on  ", "ON", "  1"])
def test_only_an_explicit_affirmative_disables_the_guard(monkeypatch, value):
    """The ONLY OFF state is an owner-written affirmative (case/space-insensitive)."""
    monkeypatch.setenv(_ALLOW_ENV, value)
    assert protected_guard_enabled() is False, value


@pytest.mark.parametrize("value", ["", "   ", "0", "false", "no", "off", "maybe",
                                   "enabled", "protected", "2", "yes please", "true!"])
def test_unset_empty_or_any_non_affirmative_is_fail_safe_protected(monkeypatch, value):
    """Empty / whitespace / a negative / junk / a near-miss all fail SAFE (guard stays ON)."""
    monkeypatch.setenv(_ALLOW_ENV, value)
    assert protected_guard_enabled() is True, value


def test_unset_env_is_protected(monkeypatch):
    monkeypatch.delenv(_ALLOW_ENV, raising=False)
    assert protected_guard_enabled() is True


# ── every TLD pattern fires, and each is ANCHORED — the $ / quantifier mutation killers ────────────────
# One positive per pattern (the pattern must fire) paired with a near-miss NEGATIVE that would only pass
# if the end-anchor or the length quantifier were dropped/widened.

@pytest.mark.parametrize("host", [
    "whitehouse.gov",          # \.gov$
    "example.gov.uk",          # \.gov\.[a-z]{2,3}$
    "site.gob.mx",             # \.gob\.[a-z]{2,3}$
    "site.gouv.fr",            # \.gouv\.[a-z]{2,3}$
    "police.govt.nz",          # \.govt\.[a-z]{2,3}$
    "cabinet.go.jp",           # \.go\.[a-z]{2}$
    "amt.gv.at",               # \.gv\.[a-z]{2}$
    "portal.government.uk",    # \.government\.[a-z]{2,3}$
    "army.mil",                # \.mil$
    "base.mil.br",             # \.mil\.[a-z]{2,3}$
    "mit.edu",                 # \.edu$
    "uni.edu.au",              # \.edu\.[a-z]{2,3}$
    "ox.ac.uk",                # \.ac\.[a-z]{2,3}$
    "nato.int",                # \.int$
])
def test_each_protected_tld_pattern_fires(host):
    assert is_hard_blocked(host)[0] is True, host


@pytest.mark.parametrize("host", [
    # $-anchor killers: a protected label MID-string (a real subdomain of an attacker domain) must NOT
    # block — only a plain `\.gov` without the end anchor would false-positive here.
    "budget.gov.attacker.com",
    "army.mil.evil.example",
    "student.edu.phish.io",
    "nato.int.not-real.net",
    # quantifier killers for the 2-letter ccTLD patterns: Disney's go.com and a 3-letter .go.* must NOT
    # match `\.go\.[a-z]{2}$` — widening the quantifier to {2,3} would wrongly block these.
    "blog.go.com",
    "cabinet.go.jpn",
    "amt.gv.com",
    # ordinary hosts whose text merely contains a protected token
    "governance.io", "mygov.com", "education.example.com", "sprint.com", "internal.example.com",
])
def test_near_miss_hosts_are_not_over_blocked(host):
    assert is_hard_blocked(host)[0] is False, host


# ── candidate_hosts must return BOTH client readings — the client-independence killer ──────────────────
# A deny-only floor is client-independent: it evaluates the requests/WHATWG reading (fold \->/) AND the
# httpx reading (keep \ in the authority). A mutation that returns only one reading would let the other
# client bypass the floor; these pin that both survive.

def test_candidate_hosts_yields_both_backslash_readings():
    hosts = candidate_hosts("https://x\\@un.org/")
    assert "un.org" in hosts, hosts     # httpx reading (\ kept, split on @) reaches the protected host
    assert "x" in hosts, hosts          # requests/WHATWG reading (\->/) reaches the userinfo host


def test_backslash_confusion_blocks_under_either_reading():
    # both directions of the disagreement must block: protected host reachable under requests OR under httpx
    assert is_hard_blocked("https://un.org\\@evil.com/")[0] is True   # requests reading -> un.org
    assert is_hard_blocked("https://x\\@army.mil/")[0] is True        # httpx reading   -> army.mil
