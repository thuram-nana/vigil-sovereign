"""F1 — hard_guardrail: the deterministic, non-disableable scope floor (pre-charter)."""

from __future__ import annotations

import pytest

from vigil_integration.safety.hard_guardrail import (
    HardBlockError,
    assert_not_hard_blocked,
    is_hard_blocked,
    normalize_domain,
)


def test_sensitive_tlds_are_blocked():
    for d in ("whitehouse.gov", "army.mil", "mit.edu", "nato.int", "example.gov.uk",
              "police.govt.nz", "cabinet.go.jp", "site.gob.mx", "site.gouv.fr", "ox.ac.uk"):
        blocked, reason = is_hard_blocked(d)
        assert blocked is True, d
        assert "blocked" in reason


def test_intergovernmental_orgs_and_subdomains_are_blocked():
    assert is_hard_blocked("un.org")[0] is True
    assert is_hard_blocked("data.un.org")[0] is True  # subdomain of a blocked domain
    assert is_hard_blocked("europa.eu")[0] is True
    assert is_hard_blocked("ec.europa.eu")[0] is True
    assert is_hard_blocked("icrc.org")[0] is True
    assert is_hard_blocked("iso.org")[0] is True


def test_ordinary_targets_are_not_blocked():
    for d in ("example.com", "shop.acme.io", "app.startup.dev", "test.co", "my-bank.com",
              "go.dev", "notgov.com", "education.example.com"):
        assert is_hard_blocked(d)[0] is False, d


def test_ip_targets_are_not_hard_blocked_here():
    # IPs have no meaningful TLD; they are gated by the charter + egress denylist, not here
    assert is_hard_blocked("10.0.0.1")[0] is False
    assert is_hard_blocked("93.184.216.34")[0] is False


def test_normalize_strips_scheme_path_port_and_case():
    assert normalize_domain("HTTPS://Example.GOV.UK:443/path?q=1") == "example.gov.uk"
    assert normalize_domain("http://un.org/") == "un.org"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("") == "" and normalize_domain(None) == ""  # type: ignore[arg-type]


def test_normalization_defeats_evasion():
    # scheme/case/port/trailing-dot must not smuggle a blocked target past the check
    for evasion in ("HTTPS://WhiteHouse.GOV", "army.mil:8443", "https://nato.int/", "un.org."):
        assert is_hard_blocked(evasion)[0] is True, evasion


def test_assert_raises_on_blocked_and_passes_on_allowed():
    with pytest.raises(HardBlockError):
        assert_not_hard_blocked("defense.gov")
    assert_not_hard_blocked("example.com")  # no raise


def test_empty_input_is_not_blocked():
    assert is_hard_blocked("")[0] is False and is_hard_blocked(None)[0] is False  # type: ignore[arg-type]
