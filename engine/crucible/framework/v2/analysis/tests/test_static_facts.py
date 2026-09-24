"""
Wave-5.1 SAST bridge — the static-FACT oracle mints ONLY a proven code property, and re-verifies offline.

Each tier is exercised with a PLANTED positive (the property genuinely holds → MINTS) and its SAFE TWIN
(the correct primitive / an absent flag / a sanitized flow → must NOT mint). Soundness is the whole point:
an honest LEAD beats a false FACT, so every twin that does not carry the property must fail to confirm, a
tamper of the retained bytes must be rejected at re-verification, and a region the oracle cannot re-parse
(or a non-Python region) must REFUSE rather than assert.
"""

from __future__ import annotations

import pytest

from ..static_facts import (
    STATIC_RULE_IDS,
    bug_class_for_rule,
    confirm_code_region,
    from_code_region,
    static_fact_finding,
)
from ...evidence.certify import build_certificate
from ...verify import oracles
from ...verify.reverify import reverify_finding

# --------------------------------------------------------------------------------------------
# PLANTED (mints) / SAFE TWIN (must not mint) corpus — one pair per sound tier.
# --------------------------------------------------------------------------------------------

# (a) broken-crypto invocation
_A_PLANTED = "import hashlib\ndef sign(x):\n    return hashlib.md5(x).hexdigest()\n"
_A_SAFE = "import hashlib\ndef sign(x):\n    return hashlib.sha256(x).hexdigest()\n"

# (b) insecure randomness feeding a security sink
_B_PLANTED = "import random\ndef mk():\n    token = random.randint(0, 999999)\n    return token\n"
_B_SAFE = "import secrets\ndef mk():\n    token = secrets.token_hex(16)\n    return token\n"

# (c) explicitly-disabled security flag literal
_C_PLANTED = "import requests\ndef fetch(u):\n    return requests.get(u, verify=False)\n"
_C_SAFE = "import requests\ndef fetch(u):\n    return requests.get(u)\n"   # flag ABSENT -> default-dependent -> REFUSE

# (d) direct intra-procedural unsanitized taint
_D_PLANTED = "import os\ndef run():\n    cmd = request.args.get('c')\n    os.system(cmd)\n"
_D_SAFE = "import os, shlex\ndef run():\n    cmd = request.args.get('c')\n    os.system(shlex.quote(cmd))\n"

_TIERS = [
    ("broken-crypto-invocation", "static_broken_crypto", _A_PLANTED, _A_SAFE),
    ("insecure-randomness-sink", "static_insecure_randomness", _B_PLANTED, _B_SAFE),
    ("insecure-flag-literal", "static_insecure_flag", _C_PLANTED, _C_SAFE),
    ("direct-taint", "static_taint", _D_PLANTED, _D_SAFE),
]


def test_closed_vocabulary_agrees_with_the_oracle() -> None:
    """The bridge's closed rule-id set is the SAME as the oracle's own — they can never drift."""
    assert STATIC_RULE_IDS == oracles._STATIC_RULE_IDS
    assert STATIC_RULE_IDS == {
        "broken-crypto-invocation", "insecure-randomness-sink",
        "insecure-flag-literal", "direct-taint",
    }


@pytest.mark.parametrize("rule_id,bug_class,planted,safe", _TIERS)
def test_planted_case_mints_and_safe_twin_does_not(rule_id, bug_class, planted, safe) -> None:
    fact = confirm_code_region("app/mod.py", 3, planted, rule_id)
    assert fact.confirmed, f"{rule_id}: planted case must MINT"
    assert fact.bug_class == bug_class
    assert fact.confirmed_by == "static_rule"
    assert fact.confidence >= 0.7
    # the safe twin carries no property -> must NOT mint (an honest LEAD, never a false FACT).
    twin = confirm_code_region("app/mod.py", 3, safe, rule_id)
    assert not twin.confirmed, f"{rule_id}: safe twin must NOT mint"


def test_bug_class_derived_from_rule_id() -> None:
    assert bug_class_for_rule("broken-crypto-invocation") == "static_broken_crypto"
    assert bug_class_for_rule("direct-taint") == "static_taint"
    assert bug_class_for_rule("not-a-rule") == ""


@pytest.mark.parametrize("rule_id,bug_class,planted,safe", _TIERS)
def test_confirmed_fact_mints_via_standard_certify_path_and_reverifies(rule_id, bug_class, planted, safe) -> None:
    """A confirmed static fact serialises into the STANDARD certify path (build_certificate binds the
    oracle_version) and re-verifies OFFLINE by re-running the pure oracle over the retained bytes."""
    fact = confirm_code_region("app/mod.py", 3, planted, rule_id)
    finding = static_fact_finding(fact)
    cert = build_certificate(finding, engagement_slug="wave5-test")
    assert cert.bug_class == bug_class
    assert cert.confirmed_by == "static_rule"
    assert cert.oracle_version.startswith("sha256:"), "the certificate must bind a resolvable oracle_version"
    r = reverify_finding(finding)
    assert r.ok and r.reproduced, f"{rule_id}: the retained static fact must re-verify offline"


def test_a_tamper_of_the_retained_bytes_is_rejected() -> None:
    """Editing the retained source so the property no longer holds must make offline re-verify REFUSE."""
    fact = confirm_code_region("app/mod.py", 3, _A_PLANTED, "broken-crypto-invocation")
    finding = static_fact_finding(fact)
    # tamper: swap md5 for sha256 in the retained bytes.
    finding["oracle_context"]["static_rule"]["source"] = _A_SAFE
    r = reverify_finding(finding)
    assert not r.reproduced, "a tampered retained region must NOT re-confirm"


def test_unparseable_region_refuses_never_mints() -> None:
    fact = confirm_code_region("app/mod.py", 3, "def (:: not valid python", "broken-crypto-invocation")
    assert not fact.confirmed


def test_non_python_region_refuses_never_mints() -> None:
    # a JS snippet that textually contains md5( must still REFUSE (Python-only re-parse).
    fact = confirm_code_region("app/x.js", 3, "const h = md5(x);", "broken-crypto-invocation", language="javascript")
    assert not fact.confirmed


def test_unknown_rule_id_has_no_bug_class_and_never_mints() -> None:
    ctx = from_code_region("app/mod.py", 3, "x = 1\n", "totally-made-up-rule")
    assert ctx.bug_class == ""
    fact = confirm_code_region("app/mod.py", 3, "x = 1\n", "totally-made-up-rule")
    assert not fact.confirmed


def test_static_fact_finding_refuses_to_serialise_a_lead() -> None:
    lead = confirm_code_region("app/mod.py", 3, _A_SAFE, "broken-crypto-invocation")
    assert not lead.confirmed
    with pytest.raises(ValueError):
        static_fact_finding(lead)
