"""
Wave-5.1 SAST bridge — the static-FACT oracle mints ONLY a proven code property, and re-verifies offline.

Each FACT-capable tier (a broken-crypto invocation, an insecure-flag literal, a direct intra-procedural taint)
is exercised with a PLANTED positive (the property genuinely holds → MINTS) and its SAFE TWIN (the correct
primitive / an absent flag / a sanitized flow → must NOT mint). Tier (b) insecure-randomness is LEAD-only: the
oracle is FAIL-CLOSED for it and never mints a FACT, for ANY input — an honest LEAD beats a false FACT, and a
sound FACT would need crypto-provenance dataflow that a single-region re-parse cannot do. Soundness is the
whole point: every twin that does not carry the property must fail to confirm, a tamper of the retained bytes
must be rejected at re-verification, and a region the oracle cannot re-parse (or a non-Python region) must
REFUSE rather than assert.
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

# (b) insecure randomness is LEAD-only (Wave-5.1 round-4 DOWNGRADE). The STATIC_RULE oracle is FAIL-CLOSED for
# insecure-randomness: it NEVER mints a FACT, for ANY input, live or offline. A sound FACT needs real
# crypto-provenance dataflow (a provenance-resolved PRNG source + flow-sensitive dataflow + a resolved
# secret-material sink), out of scope for a single-region offline re-parse — four red-pen rounds each found a
# NEW benign-but-firing shape on secure/benign code. So tier (b) is NOT in `_TIERS` (which drives the "planted
# MINTS" assertion). The shapes below — including the previously-"genuine" hmac.new(key=random...) positives —
# are now LEADs, asserted in `test_insecure_randomness_is_lead_only_and_never_mints`.
_B_FORMER_POSITIVES = [
    # the previously-"genuine" positives — a PRNG feeding a SECRET-MATERIAL kwarg of a RESOLVED crypto/security
    # API. Each is now a LEAD.
    "import random, hmac\ndef mk(msg):\n    return hmac.new(key=random.randbytes(16), msg=msg).hexdigest()\n",
    "import random\ndef mk(m):\n    return derive_key(m, salt=random.random())\n",
    "import random, hmac\ndef mk(m):\n    return hmac.new(m, key=random.random())\n",
    "import random, hmac, hashlib\ndef mk(m):\n    k = str(random.randint(0, 1 << 32)).encode()\n    return hmac.new(key=k, msg=m, digestmod=hashlib.sha256).hexdigest()\n",
    # a crypto SystemRandom source (the name-only exclusion was one of the FP holes) — must never mint.
    "import random, hmac\ndef mk(m):\n    return hmac.new(key=random.SystemRandom().randbytes(16), msg=m).hexdigest()\n",
    # FLOW-REASSIGNMENT: a PRNG is bound, then REASSIGNED to a secure value BEFORE the sink — a flow-insensitive
    # heuristic mis-fires; a sound flow-sensitive analysis would not. Fail-closed => LEAD.
    "import random, secrets, hmac\ndef mk(m):\n    k = random.randbytes(16)\n    k = secrets.token_bytes(16)\n    return hmac.new(key=k, msg=m).hexdigest()\n",
]

# (c) explicitly-disabled security flag literal
_C_PLANTED = "import requests\ndef fetch(u):\n    return requests.get(u, verify=False)\n"
_C_SAFE = "import requests\ndef fetch(u):\n    return requests.get(u)\n"   # flag ABSENT -> default-dependent -> REFUSE

# (d) direct intra-procedural unsanitized taint
_D_PLANTED = "import os\ndef run():\n    cmd = request.args.get('c')\n    os.system(cmd)\n"
_D_SAFE = "import os, shlex\ndef run():\n    cmd = request.args.get('c')\n    os.system(shlex.quote(cmd))\n"

# Only the THREE FACT-capable tiers drive the "planted MINTS" assertion; tier (b) is LEAD-only (above).
_TIERS = [
    ("broken-crypto-invocation", "static_broken_crypto", _A_PLANTED, _A_SAFE),
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
    # (d) FLOW-SENSITIVITY — a REASSIGNMENT KILL: the tainted binding is overwritten by a constant BEFORE the
    # sink, so the value AT the sink is the constant. A flow-INSENSITIVE rule mints a durable FALSE FACT here
    # ("a taint source reaches the sink" is false); the flow-sensitive rule stays a LEAD. (red-pen HIGH)
    ("direct-taint", 'import os\ndef run():\n    cmd = request.args["c"]\n    cmd = "ls -la"\n    os.system(cmd)\n'),
    # (d) reassignment to a non-tainted CALL result (not a constant) also kills — the value at the sink is not
    # provably the source, so a LEAD.
    ("direct-taint", 'import os\ndef run():\n    cmd = request.args["c"]\n    cmd = safe_default()\n    os.system(cmd)\n'),
    # (d) NON-STRAIGHT-LINE — the source binding is inside an `if` branch: a branch could alter the binding, so
    # we do NOT guess. Conservative LEAD.
    ("direct-taint", 'import os\ndef run():\n    if flag:\n        cmd = request.args["c"]\n    os.system(cmd)\n'),
    # (d) NON-STRAIGHT-LINE — the source binding is inside a loop. Conservative LEAD.
    ("direct-taint", 'import os\ndef run():\n    for x in xs:\n        cmd = request.args["c"]\n    os.system(cmd)\n'),
    # (d) SANITIZED flow — a sanitizer between source and sink; fail-closed to a LEAD.
    ("direct-taint", "import os, shlex\ndef run():\n    cmd = request.args.get('c')\n    os.system(shlex.quote(cmd))\n"),
    # (d) ALIASING BEYOND ONE HOP — a=source; b=a; c=b; sink(c). Only single-hop aliasing is followed; a
    # second hop is not proven tainted => conservative LEAD.
    ("direct-taint", 'import os\ndef run():\n    a = request.args["c"]\n    b = a\n    c = b\n    os.system(c)\n'),
    # (a) NOISE CARVE-OUT — an EXPLICIT `usedforsecurity=False` is Python's opt-out declaring this md5 is NOT
    # for security (a checksum). No FACT; a genuine md5 WITHOUT the opt-out still fires (see _EXTRA_POSITIVES).
    ("broken-crypto-invocation", "import hashlib\ndef digest(x):\n    return hashlib.md5(x, usedforsecurity=False).hexdigest()\n"),
    # (a) same carve-out via hashlib.new('md5', ..., usedforsecurity=False).
    ("broken-crypto-invocation", "import hashlib\ndef digest(x):\n    return hashlib.new('md5', x, usedforsecurity=False).hexdigest()\n"),
]


def test_closed_vocabulary_agrees_with_the_oracle() -> None:
    """The bridge's closed rule-id set is the SAME as the oracle's own — they can never drift. All four rule
    ids are RECOGNISED (a detection pointer at least); only the three in `_FACT_RULE_IDS` are FACT-capable,
    and insecure-randomness is LEAD-only."""
    assert STATIC_RULE_IDS == oracles._STATIC_RULE_IDS
    assert STATIC_RULE_IDS == {
        "broken-crypto-invocation", "insecure-randomness-sink",
        "insecure-flag-literal", "direct-taint",
    }
    # The FACT/LEAD split: insecure-randomness is recognised but never FACT-capable.
    assert oracles._LEAD_ONLY_RULE_IDS == {"insecure-randomness-sink"}
    assert oracles._FACT_RULE_IDS == {
        "broken-crypto-invocation", "insecure-flag-literal", "direct-taint",
    }
    assert oracles._FACT_RULE_IDS.isdisjoint(oracles._LEAD_ONLY_RULE_IDS)
    assert oracles._FACT_RULE_IDS | oracles._LEAD_ONLY_RULE_IDS == oracles._STATIC_RULE_IDS
    # the confidence map is keyed by FACT-capable tiers only — insecure-randomness is deliberately absent.
    assert set(oracles._STATIC_TIER_CONF) == oracles._FACT_RULE_IDS


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


# --------------------------------------------------------------------------------------------
# Tier (b) insecure-randomness is LEAD-only (Wave-5.1 round-4 DOWNGRADE): the STATIC_RULE oracle is FAIL-CLOSED
# for insecure-randomness and NEVER mints a FACT, for ANY input, live or offline. An honest LEAD beats a false
# FACT; a sound FACT needs crypto-provenance dataflow, out of scope for this single-region re-parse.
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("src", _B_FORMER_POSITIVES)
def test_insecure_randomness_is_lead_only_and_never_mints(src) -> None:
    """The shapes that USED to mint (the previously-'genuine' hmac.new(key=random...) / derive_key(salt=random)
    positives, a SystemRandom source, a flow-reassignment) are now LEADs — never FACTs — and cannot be
    serialised into a certificate."""
    lead = confirm_code_region("app/mod.py", 3, src, "insecure-randomness-sink")
    assert not lead.confirmed, "insecure-randomness must NOT mint — it is LEAD-only (fail-closed)"
    assert lead.bug_class == "static_insecure_randomness", "the class stays registered (a detection pointer)"
    with pytest.raises(ValueError):
        static_fact_finding(lead)


def test_insecure_randomness_oracle_is_fail_closed_for_any_input() -> None:
    """The fail-closed GUARANTEE at the oracle boundary: `static_rule_oracle` returns a NON-firing signal for
    the insecure-randomness rule_id on EVERY input — a firing-shaped positive, a SystemRandom source, a
    flow-reassignment, an unparseable/empty/non-Python region, and a malformed observation. No input can
    make it assert a FACT."""
    firing_shaped = [
        {"rule_id": "insecure-randomness-sink",
         "source": "import random, hmac\ndef mk(m):\n    return hmac.new(key=random.randbytes(16), msg=m).hexdigest()\n",
         "language": "python", "path": "a.py", "line": 1},
        {"rule_id": "insecure-randomness-sink",
         "source": "import random\ndef mk(m):\n    return derive_key(m, salt=random.random())\n",
         "language": "python", "path": "a.py", "line": 1},
        {"rule_id": "insecure-randomness-sink",
         "source": "import random, hmac\ndef mk(m):\n    return hmac.new(key=random.SystemRandom().randbytes(16), msg=m)\n",
         "language": "python", "path": "a.py", "line": 1},
        {"rule_id": "insecure-randomness-sink",
         "source": "import random, secrets, hmac\ndef mk(m):\n    k = random.randbytes(16)\n    k = secrets.token_bytes(16)\n    return hmac.new(key=k, msg=m)\n",
         "language": "python", "path": "a.py", "line": 1},
    ]
    edge = [
        {"rule_id": "insecure-randomness-sink", "source": "def (:: not python", "language": "python"},
        {"rule_id": "insecure-randomness-sink", "source": "", "language": "python"},
        {"rule_id": "insecure-randomness-sink", "source": "const h = rand();", "language": "javascript"},
        {"rule_id": "insecure-randomness-sink", "source": "x = 1\n", "language": "python"},
        {"rule_id": "insecure-randomness-sink"},   # no source at all
        "not even a mapping",
    ]
    for observed in firing_shaped + edge:
        sig = oracles.static_rule_oracle(observed)
        assert sig.kind == oracles.OracleKind.STATIC_RULE
        assert sig.fired is False, f"insecure-randomness fired for {observed!r} — it must be fail-closed"
        assert sig.confidence == 0.0
    # and the rule_id is registered but explicitly LEAD-only (never in the FACT-capable path).
    assert "insecure-randomness-sink" in oracles._STATIC_RULE_IDS
    assert "insecure-randomness-sink" in oracles._LEAD_ONLY_RULE_IDS
    assert "insecure-randomness-sink" not in oracles._FACT_RULE_IDS
    assert "insecure-randomness-sink" not in oracles._STATIC_TIER_CONF


# Extra GENUINE positives (beyond the one-per-tier corpus) — the semantic fix must not lose real recall.
_EXTRA_POSITIVES = [
    # (a) a broken CIPHER resolved from Crypto.Cipher, constructed via .new.
    ("broken-crypto-invocation", "from Crypto.Cipher import DES\ndef e(k, d):\n    return DES.new(k, DES.MODE_ECB).encrypt(d)\n"),
    # (a) pycryptodome AES-ECB constructed into a cipher.
    ("broken-crypto-invocation", "from Crypto.Cipher import AES\ndef e(k, d):\n    return AES.new(k, AES.MODE_ECB).encrypt(d)\n"),
    # (a) the cryptography library's modes.ECB() constructed into a Cipher(...).
    ("broken-crypto-invocation",
     "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ndef c(k):\n    return Cipher(algorithms.AES(k), modes.ECB())\n"),
    # NOTE: tier (b) insecure-randomness has NO genuine positive here any more — it is LEAD-only and never mints
    # (see `test_insecure_randomness_is_lead_only_and_never_mints`).
    # (c) verify=False on a requests Session (base-var resolved).
    ("insecure-flag-literal", "import requests\ndef f(u):\n    s = requests.Session()\n    return s.post(u, verify=False)\n"),
    # (c) TLS verification disabled via ssl.wrap_socket(cert_reqs=ssl.CERT_NONE).
    ("insecure-flag-literal", "import ssl, socket\ndef w(sock):\n    return ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n"),
    # (d) DIRECT source -> sink with NO variable at all: request.args['c'] passed straight into os.system. The
    # genuine positive the flow-sensitive fix must keep minting.
    ("direct-taint", 'import os\ndef run():\n    os.system(request.args["c"])\n'),
    # (d) SINGLE-HOP alias: a = source; os.system(a). Still a direct straight-line flow => mints.
    ("direct-taint", 'import os\ndef run():\n    a = request.args["c"]\n    b = a\n    os.system(b)\n'),
    # (d) reassignment source->source (a benign var reused, rebound to a taint source) then sink => mints.
    ("direct-taint", 'import os\ndef run():\n    cmd = "default"\n    cmd = request.args["c"]\n    os.system(cmd)\n'),
    # (a) a genuine md5 WITH usedforsecurity=True is still for security => still mints (the carve-out is False-only).
    ("broken-crypto-invocation", "import hashlib\ndef sign(x):\n    return hashlib.md5(x, usedforsecurity=True).hexdigest()\n"),
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


# --------------------------------------------------------------------------------------------
# Tier (d) FLOW-SENSITIVITY (red-pen HIGH). The direct-taint tier is now flow-sensitive on reassignment
# kills: a taint binding overwritten by a non-tainted value before the sink KILLS the taint (the value AT the
# sink is the constant), so it must NOT mint. A genuine straight-line source->sink still mints and re-verifies.
# --------------------------------------------------------------------------------------------

def test_reassignment_kill_is_a_lead_not_a_durable_false_fact() -> None:
    """`cmd = request.args["c"]; cmd = "ls -la"; os.system(cmd)` — the value at the sink is a CONSTANT, so the
    evidence claim 'a taint source reaches the sink' is FALSE. It must stay a LEAD (never a signed FACT that
    would re-verify offline on benign code)."""
    src = 'import os\ndef run():\n    cmd = request.args["c"]\n    cmd = "ls -la"\n    os.system(cmd)\n'
    lead = confirm_code_region("app/mod.py", 3, src, "direct-taint")
    assert not lead.confirmed, "a reassignment-killed flow must NOT mint a FACT"
    with pytest.raises(ValueError):
        static_fact_finding(lead)


def test_non_straight_line_source_to_sink_is_conservative_lead() -> None:
    """A source bound inside a branch / loop is NOT straight-line: the binding could be altered, so the oracle
    does NOT guess — it stays a LEAD (soundness over recall)."""
    for src in (
        'import os\ndef run():\n    if flag:\n        cmd = request.args["c"]\n    os.system(cmd)\n',
        'import os\ndef run():\n    for x in xs:\n        cmd = request.args["c"]\n    os.system(cmd)\n',
    ):
        lead = confirm_code_region("app/mod.py", 3, src, "direct-taint")
        assert not lead.confirmed, "a non-straight-line source->sink must stay a LEAD"


def test_genuine_direct_taint_still_mints_and_reverifies() -> None:
    """The genuine positive the fix must KEEP: a direct source -> sink with no reassignment/sanitizer mints a
    FACT and re-verifies OFFLINE over the retained bytes."""
    src = 'import os\ndef run():\n    os.system(request.args["c"])\n'
    fact = confirm_code_region("app/mod.py", 3, src, "direct-taint")
    assert fact.confirmed and fact.confirmed_by == "static_rule"
    finding = static_fact_finding(fact)
    cert = build_certificate(finding, engagement_slug="wave5-test")
    assert cert.bug_class == "static_taint"
    r = reverify_finding(finding)
    assert r.ok and r.reproduced


# --------------------------------------------------------------------------------------------
# Tier (a) NOISE CARVE-OUT (red-pen LOW). `hashlib.md5(x, usedforsecurity=False)` is Python's explicit
# opt-out that this md5 is NOT for security (a checksum). It must NOT mint; a genuine md5 without the opt-out
# still mints.
# --------------------------------------------------------------------------------------------

def test_usedforsecurity_false_is_a_lead_but_genuine_md5_still_mints() -> None:
    optout = "import hashlib\ndef digest(x):\n    return hashlib.md5(x, usedforsecurity=False).hexdigest()\n"
    lead = confirm_code_region("app/mod.py", 3, optout, "broken-crypto-invocation")
    assert not lead.confirmed, "usedforsecurity=False is the explicit non-security opt-out — must NOT mint"
    with pytest.raises(ValueError):
        static_fact_finding(lead)
    # a genuine md5 WITHOUT the opt-out is still flagged.
    genuine = "import hashlib\ndef sign(x):\n    return hashlib.md5(x).hexdigest()\n"
    fact = confirm_code_region("app/mod.py", 3, genuine, "broken-crypto-invocation")
    assert fact.confirmed and fact.bug_class == "static_broken_crypto"


# --------------------------------------------------------------------------------------------
# Tier (d) + tier (c) FLOW-INSENSITIVITY on KILL/REBIND forms (red-pen BLOCK, rounds 5->6->7). The straight-
# line binding tracker used by BOTH tiers was INVERTED: it advances the binding map ONLY through a closed
# allowlist of fully-modeled statement forms (a simple `Name = <modeled-expr>` assignment whose RHS is a taint
# source / a single-hop alias / a resolved Session() ctor / a plainly-non-tainted literal that KILLS the
# binding). ANY other statement form — a walrus, an import / from-import that rebinds the name, an augmented /
# tuple / attribute / subscript assignment target, a for / with target, a del, a nested def, or an assignment
# whose RHS is not fully modeled — ENDS the straight-line region, so from that point every construct is a LEAD.
# Because the DEFAULT for anything unmodeled is 'bail to LEAD', no unmodeled form can leave a stale binding
# that mints a false FACT on benign code. Each negative control below is a benign snippet where the value AT
# the sink is provably NOT the taint source / NOT a session — it MUST be a LEAD, never a durable false FACT.
# --------------------------------------------------------------------------------------------

# (d) direct-taint: a taint SOURCE is bound, then the tracked name is KILLED/REBOUND by an UNMODELED form
# before the sink. The value at the sink is provably a constant / module / loop-or-context value / deleted /
# unpacked literal — the evidence claim "a taint source reaches the sink" would be FALSE, so each is a LEAD.
_D_FLOW_INSENSITIVITY_LEADS = [
    # walrus / NamedExpr rebinds `cmd` to a constant (round-6 missed NamedExpr entirely -> a durable false FACT).
    ("walrus-kill",
     'import os\ndef run():\n    cmd = request.args["c"]\n    (cmd := "safe")\n    os.system(cmd)\n'),
    # `import cmd` rebinds `cmd` to a module (round-6 treated Import as flow-neutral -> a durable false FACT).
    ("import-rebind-kill",
     'import os\ndef run():\n    cmd = request.args["c"]\n    import cmd\n    os.system(cmd)\n'),
    # `from os import getcwd as cmd` rebinds `cmd` to a function (round-6 treated ImportFrom as flow-neutral).
    ("from-import-rebind-kill",
     'import os\ndef run():\n    cmd = request.args["c"]\n    from os import getcwd as cmd\n    os.system(cmd)\n'),
    # AugAssign is not a modeled form -> the tracker refuses to guess the concatenation is still tainted (LEAD).
    ("aug-assign",
     'import os\ndef run():\n    cmd = request.args["c"]\n    cmd += "_suffix"\n    os.system(cmd)\n'),
    # a `for` target rebinds `cmd` to the loop variable (a non-straight-line, non-modeled binding).
    ("for-target-rebind",
     'import os\ndef run():\n    cmd = request.args["c"]\n    for cmd in items:\n        pass\n    os.system(cmd)\n'),
    # a `with ... as` target rebinds `cmd` to the context manager value.
    ("with-target-rebind",
     'import os\ndef run():\n    cmd = request.args["c"]\n    with open("f") as cmd:\n        pass\n    os.system(cmd)\n'),
    # `del cmd` removes the binding entirely; using it after is a NameError at runtime, never the source.
    ("del-then-use",
     'import os\ndef run():\n    cmd = request.args["c"]\n    del cmd\n    os.system(cmd)\n'),
    # a tuple-unpack target rebinds `cmd` to a literal (a multi-target assignment, not the modeled Name = ...).
    ("tuple-unpack-rebind",
     'import os\ndef run():\n    cmd = request.args["c"]\n    cmd, other = "safe", "x"\n    os.system(cmd)\n'),
]


@pytest.mark.parametrize("label,src", _D_FLOW_INSENSITIVITY_LEADS)
def test_tier_d_kill_and_rebind_forms_are_leads_not_durable_false_facts(label, src) -> None:
    """Each snippet binds a taint source then KILLS/REBINDS the tracked name via a form the tracker does not
    model. The value at the sink is provably NOT the source, so it MUST stay a LEAD (never a signed FACT that
    would re-verify offline on benign code)."""
    lead = confirm_code_region("app/mod.py", 3, src, "direct-taint")
    assert not lead.confirmed, f"tier-d {label}: a killed/rebound taint must NOT mint a FACT"
    with pytest.raises(ValueError):
        static_fact_finding(lead)


# (c) insecure-flag: a session VARIABLE resolved by the cross-statement binding tracker, then REASSIGNED to a
# non-session before the flagged call. The value at the call is provably not a session, so it is a LEAD.
_C_SESSION_KILL_LEADS = [
    # `s` rebound to an int — the flow-INSENSITIVE round-6 collector minted a false FACT on this benign code.
    ("session-reassigned-to-int",
     "import requests\ndef f(u):\n    s = requests.Session()\n    s = 123\n    s.get(u, verify=False)\n"),
    # `s` rebound by an import (the same class of miss the tier-d import-rebind control covers).
    ("session-import-rebind",
     "import requests\ndef f(u):\n    s = requests.Session()\n    import s\n    s.get(u, verify=False)\n"),
    # `s` rebound to a plainly-non-session literal string.
    ("session-reassigned-to-str",
     "import requests\ndef f(u):\n    s = requests.Session()\n    s = 'closed'\n    s.get(u, verify=False)\n"),
]


@pytest.mark.parametrize("label,src", _C_SESSION_KILL_LEADS)
def test_tier_c_session_var_reassigned_to_non_session_is_a_lead(label, src) -> None:
    """A session variable REASSIGNED to a non-session before the flagged call is no longer a session at the
    call. `s.get(..., verify=False)` on the reassigned `s` carries no proven HTTP/TLS property, so it MUST
    stay a LEAD — the flow-INSENSITIVE session collector minted a false FACT here."""
    lead = confirm_code_region("app/mod.py", 3, src, "insecure-flag-literal")
    assert not lead.confirmed, f"tier-c {label}: a reassigned session var must NOT mint a FACT"
    with pytest.raises(ValueError):
        static_fact_finding(lead)


def test_flow_sensitive_fix_keeps_the_genuine_positives_minting() -> None:
    """The inverted (soundness-first) tracker keeps every genuine positive the task requires minting: a direct
    source->sink, a `cmd = source; sink(cmd)`, a single-hop alias (tier d); and a session-var
    `requests.Session().get(verify=False)`, a call-site-direct `requests.get(verify=False)`, and
    `ssl.wrap_socket(cert_reqs=CERT_NONE)` (tier c)."""
    positives = [
        ("direct-taint", 'import os\ndef run():\n    os.system(request.args["c"])\n'),
        ("direct-taint", 'import os\ndef run():\n    cmd = request.args["c"]\n    os.system(cmd)\n'),
        ("direct-taint", 'import os\ndef run():\n    a = request.args["c"]\n    b = a\n    os.system(b)\n'),
        ("insecure-flag-literal",
         "import requests\ndef f(u):\n    s = requests.Session()\n    return s.get(u, verify=False)\n"),
        ("insecure-flag-literal", "import requests\ndef fetch(u):\n    return requests.get(u, verify=False)\n"),
        ("insecure-flag-literal",
         "import ssl, socket\ndef w(sock):\n    return ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n"),
    ]
    for rule_id, src in positives:
        fact = confirm_code_region("app/mod.py", 3, src, rule_id)
        assert fact.confirmed and fact.confirmed_by == "static_rule", f"{rule_id}: genuine positive must MINT"
        # a genuine positive serialises + re-verifies offline over the retained bytes.
        r = reverify_finding(static_fact_finding(fact))
        assert r.ok and r.reproduced, f"{rule_id}: the genuine positive must re-verify offline"
