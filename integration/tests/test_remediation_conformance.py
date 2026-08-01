"""VF — the adversarial CONFORMANCE corpus for the RemediationCertificate.

A conformant verifier is DEFINED by its verdicts on this labeled matrix: exactly one MUST-ACCEPT vector (a
well-formed controlled certificate) and a set of MUST-REJECT vectors, each a single targeted mutation that
should trip a specific fail-closed layer. This is the corpus a second, independent (VIGIL-free) verifier must
agree with — the differential harness in VF-1d imports and re-runs these SAME vectors, and any disagreement is
a spec ambiguity or a bug.

Needs framework (reverify + the oracle) → PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import copy

from vigil_core import generate_keypair
from vigil_integration.remediation.remediation_cert import (
    mint_remediation_certificate,
    verify_remediation_certificate,
)

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
PUBKEYS = {"root0": SIGNER.public_key_b64}
_ATTACKER = generate_keypair()

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class="error_based_sqli", resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def _valid_cert() -> dict:
    return mint_remediation_certificate(
        finding_ref="errsqli-1", bug_class="error_based_sqli",
        patched_oracle_context=_context(_BENIGN), positive_control_context=_context(_SQL_ERROR),
        engagement_slug="acme", signers=SIGNERS, surface="GET /search?q=")


# Each vector: (name, mutate(cert)->cert, pubkeys, must_accept). A mutation of None means "unchanged".
def _m(fn):
    def apply(c):
        c = copy.deepcopy(c)
        fn(c)
        return c
    return apply


def _swap_patched(body):
    return _m(lambda c: c.__setitem__("patched_oracle_context", _context(body)))


CORPUS = [
    ("valid",                     _m(lambda c: None),                                   PUBKEYS,        True),
    ("wrong-schema",              _m(lambda c: c.__setitem__("schema", "x")),           PUBKEYS,        False),
    ("still-vulnerable-patched",  _swap_patched(_SQL_ERROR),                            PUBKEYS,        False),
    ("non-firing-positive-control", _m(lambda c: c.__setitem__("positive_control_context", _context(_BENIGN))), PUBKEYS, False),
    ("unreachable-patched",       _m(lambda c: c.__setitem__("patched_oracle_context", {"bug_class": "error_based_sqli"})), PUBKEYS, False),
    ("tampered-patched-context",  _m(lambda c: c["patched_oracle_context"].__setitem__("_t", "x")), PUBKEYS, False),
    ("tampered-control-context",  _m(lambda c: c["positive_control_context"].__setitem__("_t", "x")), PUBKEYS, False),
    ("flipped-control-claim",     _m(lambda c: c["controls"].__setitem__("positive_control", False)), PUBKEYS, False),
    ("stripped-signature",        _m(lambda c: c.pop("signature", None)),               PUBKEYS,        False),
    ("malformed-signature",       _m(lambda c: c["signature"].__setitem__("sig", "AAAA")), PUBKEYS,     False),
    ("wrong-pinned-key",          _m(lambda c: None),                                   {"root0": _ATTACKER.public_key_b64}, False),
    ("empty-pinned-keys",         _m(lambda c: None),                                   {},             False),
    ("swapped-digest",            _m(lambda c: c.__setitem__("patched_context_sha256", "0" * 64)), PUBKEYS, False),
]


def test_conformance_corpus_verdicts_match_labels():
    base = _valid_cert()
    failures = []
    for name, mutate, pubkeys, must_accept in CORPUS:
        v = verify_remediation_certificate(mutate(base), signer_pubkeys=pubkeys)
        if v.ok != must_accept:
            failures.append(f"{name}: verdict ok={v.ok}, expected {must_accept} ({v.reason})")
    assert not failures, "conformance verdicts disagree with labels:\n" + "\n".join(failures)


def test_corpus_has_exactly_one_must_accept():
    # a corpus that accepts everything (or nothing) is not adversarial — pin the shape.
    accepts = [n for n, _, _, ok in CORPUS if ok]
    assert accepts == ["valid"], accepts
    assert len(CORPUS) >= 10, "the MUST-REJECT set must cover every fail-closed layer"
