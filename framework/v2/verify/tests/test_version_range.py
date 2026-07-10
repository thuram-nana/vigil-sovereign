"""
Tests for Wave 5b — the version-range-membership oracle (supply-chain prove-don't-guess).

A scanner's "package @ version is affected by CVE-Y" is a LEAD; it becomes a FACT only when the
concrete version PROVABLY falls in the advisory's affected range. These cover the pure comparator, the
oracle (fires in-range, fail-closed otherwise), the FindingContext carrier + offline re-verification.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.verify import (
    OracleVerifier,
    confirm_vulnerable_dependency,
    version_in_affected,
    version_range_oracle,
    vulnerable_dependency_context,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.reverify import reverify_context


@pytest.mark.parametrize("version,affected,expect", [
    ("2.14.1", [{"introduced": "2.0", "fixed": "2.15.0"}], True),      # log4shell in [2.0, 2.15.0)
    ("2.15.0", [{"introduced": "2.0", "fixed": "2.15.0"}], False),     # fixed boundary exclusive
    ("1.9", [{"introduced": "2.0", "fixed": "2.15.0"}], False),        # below introduced
    ("2.17.0", [{"introduced": "2.0", "fixed": "2.15.0"}], False),     # at/above fixed
    ("1.2.3", [">=1.0.0,<2.0.0"], True),                               # comparator string
    ("2.0.0", [">=1.0.0,<2.0.0"], False),
    ("1.2.0-rc1", [{"introduced": "1.0", "fixed": "1.2.0"}], True),    # prerelease sorts below release
    ("1.2.0", [{"introduced": "1.0", "fixed": "1.2.0"}], False),
    ("1.5", [{"introduced": "1.0", "last_affected": "1.5"}], True),    # last_affected inclusive
    ("1.6", [{"introduced": "1.0", "last_affected": "1.5"}], False),
    # fail-closed: unparseable version / range / open-ended / empty / wrong type
    ("garbage", [{"introduced": "1.0", "fixed": "2.0"}], False),
    ("1.5", [{"introduced": "1.0"}], False),                           # open-ended (no upper bound)
    ("1.5", [{"introduced": "bad", "fixed": "worse"}], False),         # unparseable range
    ("1.0.0", [], False),
    ("1.2.3", "not-a-range", False),
])
def test_version_in_affected(version, affected, expect) -> None:
    assert version_in_affected(version, affected) is expect


def test_oracle_confirms_in_range_and_fail_closes_otherwise() -> None:
    adv = {"package": "log4j-core", "version": "2.14.1", "vuln_id": "CVE-2021-44228",
           "affected": [{"introduced": "2.0", "fixed": "2.15.0"}]}
    sig = version_range_oracle(adv)
    assert sig.fired and sig.confidence >= 0.7 and "affected range" in sig.evidence
    # a patched version does NOT fire
    assert not version_range_oracle({**adv, "version": "2.16.0"}).fired
    # missing version / empty affected / non-mapping -> no fire
    assert not version_range_oracle({**adv, "version": ""}).fired
    assert not version_range_oracle({**adv, "affected": []}).fired
    assert not version_range_oracle("nope").fired


def test_scanner_match_is_a_lead_until_the_version_proves_membership() -> None:
    # the whole prove-don't-guess point: a grype match with a version OUTSIDE the range is NOT confirmed
    patched = {"package": "log4j-core", "version": "2.17.1", "vuln_id": "CVE-2021-44228",
               "affected": [{"introduced": "2.0", "fixed": "2.15.0"}]}
    assert not confirm_vulnerable_dependency(patched).confirmed
    vulnerable = {**patched, "version": "2.14.1"}
    assert confirm_vulnerable_dependency(vulnerable).confirmed


def test_routes_and_reverifies_offline() -> None:
    adv = {"package": "openssl", "version": "3.0.1", "vuln_id": "CVE-2022-3602",
           "affected": [{"introduced": "3.0.0", "fixed": "3.0.7"}]}
    res = OracleVerifier().confirm(vulnerable_dependency_context(adv))
    assert res.confirmed and res.bug_class == "vulnerable_dependency"
    ctx = vulnerable_dependency_context(adv)
    json.dumps(ctx)                                              # JSON-safe -> offline re-verifiable
    r = reverify_context(ctx, bug_class="vulnerable_dependency")
    assert r.reproduced and r.ok


def test_finding_context_carrier() -> None:
    ctx = FindingContext.from_version_advisory(
        {"package": "p", "version": "1.0", "affected": [">=0,<2"]})
    assert ctx.to_verifier_context()["version_advisory"]["version"] == "1.0"
