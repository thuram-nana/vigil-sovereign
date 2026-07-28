"""B2/B3 — the Proof Studio content-gate + reproduce-from-raw mint (proof.content_gate + proof.engine).

Doctrine under test:
  * the content gate DENIES detection-evasion / persistence / destructive / self-propagating / exfil poc
    code BEFORE any mint — even when the oracle would fire;
  * a REPRODUCING captured exchange mints a signed FACT (provenance is FIXED to "reproduced", never
    relaxable by a caller);
  * a non-reproducing exchange is a LEAD (no signed cert), and a LEAD never spools;
  * empty governance signers are refused fail-closed.

Needs framework (context_from_exchanges + the oracle) → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import pytest

from vigil_core import generate_keypair
from vigil_integration.proof.content_gate import screen_poc_content
from vigil_integration.proof.engine import mint_proof

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]


class _Ex:
    """A duck-typed CapturedExchange — the engine/translator read attributes, not the pydantic type."""

    def __init__(self, channel, role="", request_bytes_ref="", response_bytes_ref="", bug_class=""):
        self.channel = channel
        self.role = role
        self.request_bytes_ref = request_bytes_ref
        self.response_bytes_ref = response_bytes_ref
        self.bug_class = bug_class
        self.status = None
        self.exit_code = None


def _sqli_exchange(ref="req", role="q"):
    """One request-payload exchange whose decoded value the SQLi-breakout oracle judges."""
    return [_Ex(channel="request_payload", role=role, request_bytes_ref=ref, bug_class="sqli_attempt")]


def _resolve(value: bytes):
    return lambda ref: value if ref == "req" else None


# ---- content gate --------------------------------------------------------------

def test_content_gate_allows_benign_and_denies_each_danger_class():
    assert not screen_poc_content("print('reproduce the finding via a GET to the target')").denied
    assert screen_poc_content("rm -rf / --no-preserve-root").denied                 # destructive
    assert screen_poc_content("echo '@reboot /tmp/implant' | crontab -").denied      # persistence
    assert screen_poc_content(12345).denied                                          # non-str fail-closed
    assert screen_poc_content("x" * 5_000_000).denied                                # oversized fail-closed


# ---- the mint ------------------------------------------------------------------

def test_reproducing_exchange_mints_a_signed_fact():
    res = mint_proof(
        finding={"check_id": "sqli-001", "bug_class": "sqli_attempt",
                 "poc_script_code": "print('benign reproduction')"},
        exchanges=_sqli_exchange(), resolve=_resolve(b"' OR '1'='1"),
        engagement_slug="acme", signers=SIGNERS)
    assert res.is_fact and res.signed is not None and res.reproduced


def test_non_reproducing_exchange_is_a_lead():
    res = mint_proof(
        finding={"check_id": "x", "bug_class": "sqli_attempt", "poc_script_code": "print('x')"},
        exchanges=_sqli_exchange(), resolve=_resolve(b"O'Brien"),      # a benign value the oracle won't fire on
        engagement_slug="acme", signers=SIGNERS)
    assert res.status == "lead" and res.signed is None


def test_content_gate_deny_blocks_the_mint_even_when_the_oracle_would_fire():
    res = mint_proof(
        finding={"check_id": "x", "bug_class": "sqli_attempt",
                 "poc_script_code": "rm -rf / --no-preserve-root"},   # would fire, but the code is destructive
        exchanges=_sqli_exchange(), resolve=_resolve(b"' OR '1'='1"),
        engagement_slug="acme", signers=SIGNERS)
    assert res.status == "denied" and res.signed is None and res.gate_category


def test_empty_signers_is_refused_fail_closed():
    with pytest.raises(ValueError, match="signers"):
        mint_proof(finding={"check_id": "x", "bug_class": "sqli_attempt", "poc_script_code": "ok"},
                   exchanges=_sqli_exchange(), resolve=_resolve(b"' OR '1'='1"),
                   engagement_slug="acme", signers=[])


def test_a_fact_crosses_the_spine_and_a_lead_never_does(tmp_path):
    spool = tmp_path / "spool"
    fact = mint_proof(
        finding={"check_id": "s", "bug_class": "sqli_attempt", "poc_script_code": "ok"},
        exchanges=_sqli_exchange(), resolve=_resolve(b"' OR '1'='1"),
        engagement_slug="acme", signers=SIGNERS, spool_dir=str(spool))
    assert fact.is_fact and fact.envelope_path                        # a signed FACT crossed the seam
    lead = mint_proof(
        finding={"check_id": "l", "bug_class": "sqli_attempt", "poc_script_code": "ok"},
        exchanges=_sqli_exchange(), resolve=_resolve(b"O'Brien"),
        engagement_slug="acme", signers=SIGNERS, spool_dir=str(spool))
    assert lead.status == "lead" and not lead.envelope_path           # a LEAD never spools


# ---- red-pen BLOCK-1: the certificate actually binds the captured raw bytes ----

def test_a_fact_binds_the_captured_bytes_and_a_tamper_breaks_verification(tmp_path):
    from framework.v2.evidence.certify import verify_certificate
    from framework.v2.verify.poc_translate import context_from_exchanges
    from vigil_core import AuthorizerKey, TrustRoot

    trust = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="root0", name="root0", public_key_b64=SIGNER.public_key_b64)])
    er = tmp_path / "ev"
    res = mint_proof(
        finding={"check_id": "sqli-bind", "bug_class": "sqli_attempt", "poc_script_code": "ok"},
        exchanges=_sqli_exchange(), resolve=_resolve(b"' OR '1'='1"),
        engagement_slug="acme", signers=SIGNERS, evidence_root=str(er), action_id="act-1")
    assert res.is_fact
    # the raw bytes were materialised UNDER the manifested dir (evidence_root/action_id/<ref>)
    assert (er / "act-1" / "req").read_bytes() == b"' OR '1'='1"
    # the certificate binds them: it verifies now…
    octx = context_from_exchanges(_sqli_exchange(), bug_class="sqli_attempt",
                                  resolve=_resolve(b"' OR '1'='1")).model_dump(mode="json")
    # verify_certificate needs the evidence_root to RE-HASH the bound artifacts (fail-closed: "CLAIMED but
    # NOT checked" is a refusal). It passes now because the manifest matches the on-disk bytes…
    assert verify_certificate(res.signed, oracle_context=octx, trust_root=trust, evidence_root=str(er)).ok is True
    # …and a one-byte tamper of the retained artifact breaks ARTIFACT INTEGRITY (the binding is real).
    (er / "act-1" / "req").write_bytes(b"' OR '1'='2")
    assert verify_certificate(res.signed, oracle_context=octx, trust_root=trust, evidence_root=str(er)).ok is False


def test_replay_demotes_when_the_retained_bytes_do_not_reproduce(tmp_path):
    # The from-disk replay is a REAL guard: a resolve that returns firing bytes for the initial confirm but
    # benign bytes when materialising (so the RETAINED on-disk evidence no longer fires) → the signed FACT is
    # demoted to a LEAD. Removing the demote branch would let this pass as a "fact" — so the guard is covered.
    calls = {"n": 0}

    def flaky(ref):
        calls["n"] += 1
        return b"' OR '1'='1" if calls["n"] == 1 else b"O'Brien"      # fires once, then benign on disk

    res = mint_proof(
        finding={"check_id": "flaky", "bug_class": "sqli_attempt", "poc_script_code": "ok"},
        exchanges=_sqli_exchange(), resolve=flaky, engagement_slug="acme", signers=SIGNERS,
        evidence_root=str(tmp_path / "ev"), action_id="act-2")
    assert res.status == "lead" and "did not re-confirm on replay" in res.reason


# ---- red-pen BLOCK-2: an alias bug_class is not spuriously demoted --------------

def test_an_alias_bug_class_still_mints_a_fact():
    # nosqli_attempt is an alias of nosql_injection_attempt; the post-confirm replay must re-fire with the
    # ORIGINAL class (not the normalized one), so an alias FACT is NOT demoted to a LEAD.
    res = mint_proof(
        finding={"check_id": "nosql-1", "bug_class": "nosqli_attempt", "poc_script_code": "ok"},
        exchanges=[_Ex(channel="request_payload", role="username", request_bytes_ref="req",
                       bug_class="nosqli_attempt")],
        resolve=_resolve(b'{"$ne": null}'), engagement_slug="acme", signers=SIGNERS)
    assert res.is_fact and res.signed is not None


# ---- minimization (B6) ---------------------------------------------------------

def test_minimize_keeps_only_a_still_reproducing_subset():
    from vigil_integration.proof.minimize import minimize_payload

    # a candidate "reproduces" iff it still contains the SENTINEL; ddmin should strip the padding.
    def still(candidate: bytes) -> bool:
        return b"SENTINEL" in candidate

    res = minimize_payload(b"AAAAAAAA SENTINEL BBBBBBBB", still_reproduces=still)
    assert res.reduced and b"SENTINEL" in res.minimized and res.minimized_len < res.original_len


def test_minimize_is_fail_closed_when_the_original_does_not_reproduce():
    from vigil_integration.proof.minimize import minimize_payload

    res = minimize_payload(b"nothing here", still_reproduces=lambda c: False)
    assert res.reduced is False and res.minimized == b"nothing here"
