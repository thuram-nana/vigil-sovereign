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

# (b) insecure randomness feeding a GENUINE SECRET-MATERIAL sink — a non-crypto PRNG passed as the `key=` of a
# RESOLVED crypto-module call (`hmac.new`, provenance resolved via the import, NOT a name pattern). This is the
# sound positive: the PRNG value IS the key material. (A bare `token = random.randint(...)` assignment is a
# security-ISH NAME only and is a LEAD; a PRNG in a CONTROL parameter — length/iterations — is a LEAD; see the
# negative controls below.)
_B_PLANTED = "import random, hmac\ndef mk(msg):\n    return hmac.new(key=random.randbytes(16), msg=msg).hexdigest()\n"
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

# --------------------------------------------------------------------------------------------
# STRUCTURALLY-BENIGN-BUT-FIRING negative controls — code that a NAME/pattern rule (the tool's own
# false-positive class) would flag, but which carries NO proven property. Each MUST stay a LEAD: a
# STATIC_RULE FACT re-derives the property SEMANTICALLY (provenance + genuine use), it does not re-run the
# tool's syntactic pattern. An honest LEAD beats a false FACT.
# --------------------------------------------------------------------------------------------
_NEG_CONTROLS = [
    # (a) a DEFENSIVE rejection of ECB — a comparison / raise, never a construction. Not "use".
    ("broken-crypto-invocation",
     "from Crypto.Cipher import AES\ndef guard(mode):\n    if mode == AES.MODE_ECB:\n        raise ValueError('ECB is banned')\n"),
    # (a) a bare, IMPORT-FREE md5(...) — no crypto provenance to resolve.
    ("broken-crypto-invocation", "def sign(x):\n    return md5(x)\n"),
    # (a) a LOCALLY-SHADOWED md5 — the call resolves to the local def, not hashlib.
    ("broken-crypto-invocation", "def md5(x):\n    return 0\ndef sign(x):\n    return md5(x)\n"),
    # (b) a PRNG assigned to a security-ISH variable NAME, with NO flow into a sink (benign lexer / caller).
    ("insecure-randomness-sink", "import random\ndef mk(tokens):\n    token = random.choice(tokens)\n    return token\n"),
    # (b) same, a `nonce` name — still a name-only assignment, no security sink.
    ("insecure-randomness-sink", "import random\ndef mk():\n    nonce = random.randint(0, 999999)\n    return nonce\n"),
    # (b) `key=` is a COMPARISON-key function on sorted/min/max/heapq/itertools/groupby — NOT a crypto key. The
    # receiving callee does not resolve to a security API, so a PRNG comparison key is a LEAD, never a FACT.
    ("insecure-randomness-sink", "import random\ndef pick(items, fns):\n    return sorted(items, key=random.choice(fns))\n"),
    ("insecure-randomness-sink", "import random\ndef shuf(items):\n    return sorted(items, key=lambda x: random.random())\n"),
    # (b) `numpy.sign(...)` is the MATH sign function — a bare/aliased verb with no crypto-module provenance.
    ("insecure-randomness-sink", "import numpy as np\nimport random\ndef s():\n    return np.sign(random.random())\n"),
    # (b) a security-named `token=` kwarg on a LOGGER — `logging.info` does not resolve to a security API.
    ("insecure-randomness-sink", "import random, logging\ndef log():\n    logging.info('x', token=random.random())\n"),
    # (b) a security-named `salt=` kwarg on an UNRESOLVED builder — no crypto/security provenance to resolve.
    ("insecure-randomness-sink", "import random\ndef b(cfg):\n    return build(cfg, salt=random.random())\n"),
    # (b) NAME-ONLY FP: `make_key(random.choice(shards))` is a SHARDED CACHE key — `make_key` is an AMBIGUOUS
    # descriptive constructor that resolves to NOTHING (no crypto-module provenance, DROPPED from the closed
    # allowlist), so it no longer mints a durable false FACT.
    ("insecure-randomness-sink", "import random\ndef mk(shards):\n    return make_key(random.choice(shards))\n"),
    # (b) `new_key` / `create_key` — the same ambiguous generic-constructor class (a dict / DB / partition
    # key), no provenance to resolve => a LEAD.
    ("insecure-randomness-sink", "import random\ndef mk():\n    return new_key(random.random())\n"),
    ("insecure-randomness-sink", "import random\ndef mk():\n    return create_key(random.random())\n"),
    # (b) CONTROL-PARAMETER FP on a RESOLVED callee: `generate_token` resolves, but `length=` is a CONTROL
    # parameter — a random token LENGTH is a benign control value, not secret material => a LEAD.
    ("insecure-randomness-sink", "import random\ndef mk():\n    return generate_token(length=random.randint(8, 16))\n"),
    # (b) CONTROL-PARAMETER FP on a RESOLVED KDF: `derive_key` resolves, but `iterations=` is a work-factor
    # CONTROL parameter — a random iteration COUNT is not key material => a LEAD.
    ("insecure-randomness-sink", "import random\ndef mk(pw, salt):\n    return derive_key(pw, salt, iterations=random.randint(1000, 2000))\n"),
    # (c) verify=False on a NON-security callee (a chart renderer) — does not resolve to an HTTP/TLS API.
    ("insecure-flag-literal", "import chartlib\ndef draw(chart):\n    return chart.render(verify=False)\n"),
    # (c) secure=False on a NON-security callee (a UI widget builder) — not a cookie / request.
    ("insecure-flag-literal", "import ui\ndef draw(widget):\n    return widget.build(secure=False)\n"),
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


@pytest.mark.parametrize("rule_id,src", _NEG_CONTROLS)
def test_benign_but_pattern_firing_controls_stay_a_lead(rule_id, src) -> None:
    """The FP surface the old name/pattern rules minted on. A STATIC_RULE FACT must ESTABLISH the property
    SEMANTICALLY (resolved provenance + genuine use), so each of these MUST stay a LEAD — never a FACT."""
    lead = confirm_code_region("app/mod.py", 3, src, rule_id)
    assert not lead.confirmed, f"{rule_id}: a benign-but-pattern-firing control must NOT mint"
    # ... and it therefore cannot be serialised into a certificate.
    with pytest.raises(ValueError):
        static_fact_finding(lead)


# Extra GENUINE positives (beyond the one-per-tier corpus) — the semantic fix must not lose real recall.
_EXTRA_POSITIVES = [
    # (a) a broken CIPHER resolved from Crypto.Cipher, constructed via .new.
    ("broken-crypto-invocation", "from Crypto.Cipher import DES\ndef e(k, d):\n    return DES.new(k, DES.MODE_ECB).encrypt(d)\n"),
    # (a) pycryptodome AES-ECB constructed into a cipher.
    ("broken-crypto-invocation", "from Crypto.Cipher import AES\ndef e(k, d):\n    return AES.new(k, AES.MODE_ECB).encrypt(d)\n"),
    # (a) the cryptography library's modes.ECB() constructed into a Cipher(...).
    ("broken-crypto-invocation",
     "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ndef c(k):\n    return Cipher(algorithms.AES(k), modes.ECB())\n"),
    # (b) a PRNG feeding a SECRET-MATERIAL keyword parameter (`salt=`) of a RESOLVED descriptive security API
    # (`derive_key` is a KDF — the name IS the resolved operation). A random salt from a NON-crypto PRNG is the
    # weakness; the CONTROL parameter `iterations=` on the SAME callee is a LEAD (see the negative controls).
    ("insecure-randomness-sink", "import random\ndef mk(m):\n    return derive_key(m, salt=random.random())\n"),
    # (b) a PRNG feeding a SECRET-MATERIAL keyword parameter (`key=`) of a RESOLVED crypto-module call
    # (`hmac.new`, provenance via the import).
    ("insecure-randomness-sink", "import random, hmac\ndef mk(m):\n    return hmac.new(m, key=random.random())\n"),
    # (b) a PRNG (single-hop alias `k`) feeding the SECRET-MATERIAL `key=` of a resolved crypto call — the
    # alias source is re-derived within the function.
    ("insecure-randomness-sink",
     "import random, hmac, hashlib\ndef mk(m):\n    k = str(random.randint(0, 1 << 32)).encode()\n    return hmac.new(key=k, msg=m, digestmod=hashlib.sha256).hexdigest()\n"),
    # (c) verify=False on a requests Session (base-var resolved).
    ("insecure-flag-literal", "import requests\ndef f(u):\n    s = requests.Session()\n    return s.post(u, verify=False)\n"),
    # (c) TLS verification disabled via ssl.wrap_socket(cert_reqs=ssl.CERT_NONE).
    ("insecure-flag-literal", "import ssl, socket\ndef w(sock):\n    return ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n"),
]


@pytest.mark.parametrize("rule_id,src", _EXTRA_POSITIVES)
def test_extra_genuine_positives_still_mint(rule_id, src) -> None:
    fact = confirm_code_region("app/mod.py", 3, src, rule_id)
    assert fact.confirmed, f"{rule_id}: a genuine positive must MINT"
    assert fact.confirmed_by == "static_rule"


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
