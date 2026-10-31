"""Slice G0 — customer ASSET-OWNERSHIP PROOF (the billing != testing linchpin).

Load-bearing invariants (a false-green here would let a customer forge proof of owning a host they do not
control — the exact shortcut that would let payment masquerade as testing authority):
  * a proof is recorded ONLY when the deterministic verdict fires over the TRUSTED observation against the
    CURRENT challenge token; a wrong/absent/superseded token records NOTHING (fail-closed);
  * challenge + proof are the DANGEROUS direction: OWNER-signed + strictly-increasing issued_at; a forged
    (attacker-signed) grant is inert in the fold;
  * revoke is the SAFE direction (honored even unsigned, fixed issued_at 0.0);
  * ANTI-REPLAY: a revoked proof cannot be resurrected by re-appending a captured owner-signed active proof
    (per-(org_id, host) LWW high-water); a tampered owner-signed field (e.g. a stretched expires_at) breaks
    the signature and is inert;
  * EXPIRY is owner-signed: has_current_proof is time-aware and default-deny;
  * PER-(org_id, host) scoping: org A's proof of host H gives org B nothing (tenant isolation);
  * NOT SUFFICIENT: this module mints no EngagementAuthority and grants no testing capability — it only
    records the ownership half the separate owner-signed authority will later require;
  * fail-closed host floor: IP literals, URLs/paths/ports, and the categorical .gov/.mil/.edu/.int floor are
    refused at challenge time;
  * FATAL-2 + lockstep: imports no framework/strix; the replicated hostname / tenant regexes match source.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor import asset_ownership as ao
from sigil.governor.asset_ownership import (
    METHOD_DNS_TXT,
    METHOD_WELL_KNOWN,
    AssetOwnershipRegistry,
    expected_marker,
    observation_proves,
)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store):
    return AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OP)


def _dns(marker: str):
    """A realistic TXT value set a resolver would return at the dedicated name (unrelated records + ours)."""
    return ["some-other-verification=abc", "v=spf1 include:_spf.example.com ~all", marker]


# --- happy paths ------------------------------------------------------------------------------------

def test_dns_txt_roundtrip():
    s = _store()
    reg = _reg(s)
    ch = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    assert ch.host == "apme.cm" and ch.token and ch.marker == expected_marker(ch.token)
    assert ch.dns_name == "_vigil-challenge.apme.cm"
    now = 1000.0
    proof = reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                                  observed=_dns(ch.marker), now=now, ttl_seconds=3600.0)
    assert proof.method == METHOD_DNS_TXT and proof.verified_at == now
    assert reg.has_current_proof("acme", "apme.cm", now=now)
    assert reg.proven_hosts("acme", now=now) == ["apme.cm"]


def test_well_known_roundtrip_tolerates_trailing_newline():
    s = _store()
    reg = _reg(s)
    ch = reg.issue_challenge("acme", "shop.example.net", issued_at=_issue())
    body = ch.marker + "\n"                                   # a web server commonly adds a trailing newline
    proof = reg.verify_and_record("acme", "shop.example.net", method=METHOD_WELL_KNOWN,
                                  observed=body, now=2000.0, ttl_seconds=3600.0)
    assert proof.method == METHOD_WELL_KNOWN
    assert reg.proof("acme", "shop.example.net") is not None


# --- the verdict is the gate: a proof is NEVER recorded without it firing ---------------------------

def test_wrong_token_records_nothing():
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                              observed=_dns("vigil-site-verification=WRONG"), now=1000.0)
    assert reg.proof("acme", "apme.cm") is None                 # fail-closed: nothing recorded


def test_verify_without_challenge_refused():
    s = _store()
    reg = _reg(s)
    with pytest.raises(ValueError):
        reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                              observed=_dns(expected_marker("anything")), now=1000.0)


def test_superseded_token_refused_current_token_accepted():
    """A re-issued challenge supersedes the prior one (LWW): only the CURRENT token's marker verifies."""
    s = _store()
    reg = _reg(s)
    ch1 = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    ch2 = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())   # supersedes ch1
    assert ch1.token != ch2.token
    with pytest.raises(ValueError):                                    # publishing the OLD token no longer works
        reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                              observed=_dns(ch1.marker), now=1000.0)
    proof = reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                                  observed=_dns(ch2.marker), now=1001.0, ttl_seconds=3600.0)
    assert proof is not None


def test_well_known_reflected_extra_content_refused():
    """An exact match (after trim): a page that WRAPS/echoes the marker plus attacker text does not satisfy."""
    s = _store()
    reg = _reg(s)
    ch = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.verify_and_record("acme", "apme.cm", method=METHOD_WELL_KNOWN,
                              observed=f"<html>{ch.marker} and more</html>", now=1000.0)


# --- asymmetric auth: forged grants inert, revoke safe-direction -----------------------------------

def test_forged_challenge_is_ignored():
    s = _store()
    forged = AssetOwnershipRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP)
    forged.issue_challenge("acme", "apme.cm", issued_at=_issue())     # signed by the WRONG key
    assert _reg(s).challenge("acme", "apme.cm") is None               # inert in the fold


def test_forged_proof_is_ignored():
    """A hand-crafted attacker-signed active proof record never folds active (the elevation an attacker wants)."""
    s = _store()
    from sigil.governor.asset_ownership import PROOF_SIGNAL
    from sigil.governor.authn import signed_payload
    core = {"signal": PROOF_SIGNAL, "org_id": "acme", "host": "apme.cm", "method": METHOD_DNS_TXT,
            "token_sha256": "x", "verified_at": 1.0, "expires_at": 1e18, "state": "active", "issued_at": 1.0}
    s.append(kind="event", source="governor", actor="WARDEN",
             payload={**signed_payload(core, ATTACKER), "by": "owner"})
    assert _reg(s).proof("acme", "apme.cm") is None
    assert not _reg(s).has_current_proof("acme", "apme.cm", now=2.0)


def test_proof_revoke_survives_replay_resurrection():
    """A revoked proof cannot be resurrected by re-appending the captured genuine owner-signed active proof."""
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=_issue(),
                          ttl_seconds=1e18)
    captured = next(r.payload for r in s.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == ao.PROOF_SIGNAL
                    and r.payload.get("state") == "active")
    reg.revoke_proof("acme", "apme.cm")
    assert reg.proof("acme", "apme.cm") is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay the genuine grant
    assert reg.proof("acme", "apme.cm") is None                                    # stays revoked (high-water)


def test_tampered_expiry_breaks_signature():
    """expires_at is owner-signed: re-appending a captured proof with a stretched expiry is inert (bad sig)."""
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=100.0, ttl_seconds=10.0)
    s2 = _store()                                                 # fresh spine, replay only the tampered record
    reg2 = _reg(s2)
    captured = next(dict(r.payload) for r in s.iter_records()
                    if isinstance(r.payload, dict) and r.payload.get("signal") == ao.PROOF_SIGNAL
                    and r.payload.get("state") == "active")
    captured["expires_at"] = 1e18                                 # stretch the window — breaks the signature
    s2.append(kind="event", source="governor", actor="WARDEN", payload=captured)
    assert reg2.proof("acme", "apme.cm") is None


# --- expiry + tenant isolation ----------------------------------------------------------------------

def test_proof_expires():
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=100.0, ttl_seconds=50.0)
    assert reg.has_current_proof("acme", "apme.cm", now=149.0)
    assert not reg.has_current_proof("acme", "apme.cm", now=151.0)      # past expires_at (owner-signed)
    assert reg.proven_hosts("acme", now=151.0) == []


def test_proof_is_per_org_host():
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=100.0, ttl_seconds=1e9)
    assert reg.has_current_proof("acme", "apme.cm", now=200.0)
    assert not reg.has_current_proof("evilcorp", "apme.cm", now=200.0)  # another org gets NOTHING from acme's proof
    assert not reg.has_current_proof("acme", "other.example.com", now=200.0)


def test_revoke_then_reprove():
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=100.0, ttl_seconds=1e9)
    reg.revoke_proof("acme", "apme.cm")
    assert reg.proof("acme", "apme.cm") is None
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())          # fresh challenge
    reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                          observed=_dns(reg.challenge("acme", "apme.cm").marker), now=500.0, ttl_seconds=1e9)
    assert reg.has_current_proof("acme", "apme.cm", now=600.0)          # re-proving works after revoke


# --- fail-closed host floor -------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "https://apme.cm", "apme.cm/path", "apme.cm:8080", "a b.cm", "", "whitehouse.gov",
    "army.mil", "mit.edu", "203.0.113.5",
])
def test_bad_host_refused_at_challenge(bad):
    s = _store()
    reg = _reg(s)
    with pytest.raises(ValueError):
        reg.issue_challenge("acme", bad, issued_at=_issue())


def test_bad_org_id_refused():
    s = _store()
    reg = _reg(s)
    with pytest.raises(ValueError):
        reg.issue_challenge("../escape", "apme.cm", issued_at=_issue())


# --- the pure verdict function ----------------------------------------------------------------------

def test_observation_proves_pure():
    tok = "abc123"
    m = expected_marker(tok)
    # dns-txt: a list; any value (trimmed) must equal the marker
    assert observation_proves(METHOD_DNS_TXT, tok, ["x", m, "y"])
    assert observation_proves(METHOD_DNS_TXT, tok, [f"  {m}  "])          # whitespace tolerated
    assert not observation_proves(METHOD_DNS_TXT, tok, ["x", "y"])
    assert not observation_proves(METHOD_DNS_TXT, tok, m)                 # a bare string is NOT a TXT set
    # well-known: an exact body match (trimmed)
    assert observation_proves(METHOD_WELL_KNOWN, tok, m)
    assert observation_proves(METHOD_WELL_KNOWN, tok, m + "\n")
    assert not observation_proves(METHOD_WELL_KNOWN, tok, m + " extra")
    assert not observation_proves(METHOD_WELL_KNOWN, tok, ["list"])       # body must be a string
    # fail-closed: unknown method / empty token
    assert not observation_proves("bogus", tok, [m])
    assert not observation_proves(METHOD_DNS_TXT, "", [expected_marker("")])


def test_ttl_must_be_positive():
    s = _store()
    reg = _reg(s)
    reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    with pytest.raises(ValueError):
        reg.verify_and_record("acme", "apme.cm", method=METHOD_DNS_TXT,
                              observed=_dns(reg.challenge("acme", "apme.cm").marker), now=1.0, ttl_seconds=0.0)


# --- non-ASCII observations fail CLOSED, never raise (red-pen fold) ---------------------------------

@pytest.mark.parametrize("body", ["﻿x", "café", "�", "\U0001f600"])
def test_non_ascii_well_known_body_never_raises(body):
    # observation_proves is contractually fail-closed: a customer-controlled non-ASCII body (BOM / accented /
    # invalid-UTF-8 U+FFFD / emoji) returns False, NEVER a TypeError — the comparison is over bytes, not str.
    assert observation_proves(METHOD_WELL_KNOWN, "tok", body) is False


def test_dns_non_ascii_sibling_does_not_break_match():
    tok = "tok"; marker = expected_marker(tok)
    assert observation_proves(METHOD_DNS_TXT, tok, ["café", marker]) is True   # the good value still matches
    assert observation_proves(METHOD_DNS_TXT, tok, ["café", "�"]) is False


def test_bom_prefixed_marker_is_clean_refusal_not_a_crash():
    s = _store(); reg = _reg(s)
    ch = reg.issue_challenge("acme", "apme.cm", issued_at=_issue())
    with pytest.raises(ValueError):            # a clean ValueError (mappable to a 4xx), NOT a TypeError → 500
        reg.verify_and_record("acme", "apme.cm", method=METHOD_WELL_KNOWN,
                              observed="﻿" + ch.marker, now=1000.0)
    assert reg.proof("acme", "apme.cm") is None   # fail-closed: nothing recorded


# --- FATAL-2 + lockstep -----------------------------------------------------------------------------

def test_no_offense_imported():
    import sys
    assert not any(m == "framework" or m.startswith("framework.")
                   or m == "strix" or m.startswith("strix.") for m in sys.modules)


def test_hostname_re_matches_target_authorization_literal():
    """The replicated hostname regex stays byte-identical to its ui.target_authorization source of truth."""
    from sigil.ui import target_authorization as ta
    assert ao._HOSTNAME_RE.pattern == ta._HOSTNAME_RE.pattern


def test_tenant_re_matches_orgs_literal():
    from sigil.governor import orgs as og
    assert ao._TENANT_RE.pattern == og._TENANT_RE.pattern
