"""W8-5 (#471) — the shared-owner-key-across-HA-passives residual, pinned; per-host keys with delegation
evaluated and DEFERRED (recorded, not half-built).

THE RESIDUAL. Every HA passive that can become the sovereign spine writer must hold the OWNER signing key:
the spine head is signed by a single owner key at a 1-of-1 trust root (`checkpoint.trust_root` ->
`sign_head`/`verify_head`). So every passive holds the SAME key, and every host that holds it can sign a
fork — the HA story (keep passives hot) and the key story (one key everywhere) contradict each other.

WHAT THIS SUITE PROVES.
  * the residual is STATED in the HA doc (`docs/architecture/HA-PROFILE.md` §4) — the sharpened, load-bearing
    concession + the "per-host keys with delegation evaluated and NOT implemented" decision. FAILS on a tree
    without W8-5 (those exact sentences and the decision record do not exist there);
  * the concession is TRUE OF THE CODE — an owner-signed head verifies under the 1-of-1 owner root, and a
    passive holding only its OWN per-host key is NOT a valid writer (the head path admits no per-host key);
  * `checkpoint.trust_root` really is 1-of-1 single-owner, with a NEGATIVE CONTROL proving the "single-owner
    head root" predicate is not a no-op (a synthetic 2-of-2 per-host head root — what a silently-introduced
    per-host multi-key head would look like — is rejected by the predicate);
  * the delegation machinery we EVALUATED as the reuse candidate bounds a signer to its grant (AC3 negative
    control: a host signing outside its delegation is refused) — on the OFFENSE surface it governs, which is
    exactly why it is not a drop-in for the head (see docs/decisions/W8-5-per-host-keys-with-delegation.md).

The decision to DEFER (not half-build) per-host head delegation is recorded in the design note; this suite
pins the residual, per the issue: "a test asserts the concession text is present and true of the code."
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import sigil.spine.checkpoint as C
from sigil.config import OWNER_KEY_ID
from sigil.reuse import (
    AuthorizerKey,
    TrustRoot,
    build_chain,
    digest_payload,
    generate_keypair,
)
from sigil.reuse.chain import sign_head, verify_head
from vigil_core.delegation import (
    OFFENSE_GOVERNANCE_ROLE,
    OFFENSE_SPINE_ROLE,
    DelegationError,
    sign_delegation,
    verify_delegation,
)

_REPO = Path(__file__).resolve().parents[3]
_HA_DOC = _REPO / "docs" / "architecture" / "HA-PROFILE.md"
_DECISION = _REPO / "docs" / "decisions" / "W8-5-per-host-keys-with-delegation.md"
_SCOPE = "sigil"

# The load-bearing, verbatim (whitespace-collapsed) concession sentences the HA doc MUST carry. Neither
# exists on a pre-W8-5 tree, so the doc assertion below goes RED without this change.
_HA_CONCESSION = "every passive holds the SAME owner signing key, and every host that holds it can sign a fork"
_HA_DECISION = ("Per-host keys with delegation were evaluated (W8-5, #471) and deliberately NOT implemented "
                "for the head surface")


def _collapsed(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _single_owner_head_root(tr: TrustRoot) -> bool:
    """The predicate that makes the concession TRUE of the code: the head trust root admits exactly ONE
    distinct owner key at threshold 1. A per-host multi-key head (what a delegated per-host head signer would
    require) makes this False — see the negative control below."""
    return tr.threshold == 1 and len({a.public_key_b64 for a in tr.authorizers}) == 1


def _chain(n: int):
    return build_chain([digest_payload({"i": i}) for i in range(n)])


# --------------------------------------------------------------- the residual is STATED in the HA doc (RED w/o fix)

def test_ha_profile_states_the_shared_owner_key_concession():
    """FAILS WITHOUT THE FIX: the sharpened concession + the per-host-delegation decision, and the link to the
    design note, do not exist in HA-PROFILE.md on a pre-W8-5 tree."""
    doc = _collapsed(_HA_DOC.read_text(encoding="utf-8"))
    assert _HA_CONCESSION in doc, "HA-PROFILE §4 must state the sharpened shared-owner-key concession"
    assert _HA_DECISION in doc, "HA-PROFILE §4 must record that per-host delegation was evaluated and NOT implemented"
    assert "W8-5-per-host-keys-with-delegation.md" in doc, "HA-PROFILE §4 must link the W8-5 design note"


def test_design_note_records_the_evaluation_and_decision():
    """FAILS WITHOUT THE FIX: the design note does not exist pre-W8-5. It must evaluate per-host keys with
    delegation against the existing machinery and record the DECISION to defer (not half-build)."""
    assert _DECISION.is_file(), f"missing W8-5 design note at {_DECISION}"
    text = _DECISION.read_text(encoding="utf-8")
    low = text.lower()
    # evaluates per-host keys with delegation against the three existing primitives
    assert "#434" in text and "#438" in text, "must evaluate against #434 succession and #438 co-signer enrolment"
    assert "delegationcert" in low or "delegation cert" in low, "must evaluate the S4 delegation certificate"
    assert "per-host" in low and "delegation" in low
    # records the DECISION: defer / not implemented (not half-built)
    assert "not implemented" in low or "defer" in low, "must record the decision to defer per-host head delegation"
    assert "half-buil" in low, "must state it is recorded, not half-built (the issue's own constraint)"
    # the registered claim marker (the registry source)
    assert "<!-- CLAIM:W8-5 -->" in text, "the design note must carry the registered-claim marker"


# --------------------------------------------------------------- the concession is TRUE OF THE CODE

def test_head_path_is_single_owner_and_admits_no_per_host_key():
    """The concession is true of the code: an owner-signed head verifies under the 1-of-1 OWNER root
    (a passive holding the owner key is a valid writer), and — the NEGATIVE CONTROL — a passive holding ONLY
    its own per-host key is NOT a valid writer: the head path admits no per-host key. This is precisely why
    every passive must hold the SAME owner key (the residual), and why a per-host delegation is not wired in."""
    owner = generate_keypair()
    passive = generate_keypair()                    # a passive host's OWN key (what per-host delegation would use)
    entries = _chain(3)
    head = sign_head(entries, engagement_slug=_SCOPE, signers=[(OWNER_KEY_ID, owner.private_key_b64)])

    tr_owner = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id=OWNER_KEY_ID, name="owner", public_key_b64=owner.public_key_b64)])
    ok_owner, _ = verify_head(head, entries, tr_owner, genesis_prev=head.base_prev_hash)
    assert ok_owner, "a passive holding the OWNER key is a valid writer (the shared-key concession)"

    # NEGATIVE CONTROL: only the per-host key -> NOT admitted by the head path.
    tr_passive = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="host2", name="passive-host", public_key_b64=passive.public_key_b64)])
    ok_passive, msg = verify_head(head, entries, tr_passive, genesis_prev=head.base_prev_hash)
    assert not ok_passive, ("the head path must NOT admit a passive's own per-host key — if it did, per-host "
                            "delegation would already be implemented and the concession would be false")
    assert "signature" in msg.lower()


def test_checkpoint_trust_root_is_1of1_single_owner(monkeypatch, tmp_path):
    """`checkpoint.trust_root` yields a 1-of-1 single-owner head root (hermetic: monkeypatched owner keys +
    an empty fake store, so no SIGIL_HOME/genesis state leaks in). Plus the NEGATIVE CONTROL that the
    single-owner predicate is not a no-op — a synthetic 2-of-2 per-host head root is REJECTED by it, so a
    silently-introduced per-host multi-key head (which would falsify the concession) would be caught."""
    owner = generate_keypair()
    monkeypatch.setattr(C, "_owner_keys", lambda: (owner.private_key_b64, owner.public_key_b64))
    monkeypatch.setattr(C, "_PUB", tmp_path / "owner.pub")   # no genesis pin beside it -> current key is genesis

    class _FakeStore:
        def iter_records(self):
            return []

        def change_token(self):
            return "w8-5"

    tr = C.trust_root(_FakeStore())
    assert tr.threshold == 1 and len(tr.authorizers) == 1
    assert tr.authorizers[0].name == "owner" and tr.authorizers[0].public_key_b64 == owner.public_key_b64
    assert _single_owner_head_root(tr) is True

    # NEGATIVE CONTROL: what a per-host multi-key head would look like -> the predicate rejects it (not a no-op).
    h1, h2 = generate_keypair(), generate_keypair()
    fake_multi = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="host-a", public_key_b64=h1.public_key_b64),
        AuthorizerKey(key_id="b", name="host-b", public_key_b64=h2.public_key_b64)])
    assert _single_owner_head_root(fake_multi) is False


# --------------------------------------------------------------- the EVALUATED machinery bounds a signer to its grant

def test_evaluated_delegation_machinery_bounds_a_signer_to_its_grant():
    """The design note evaluates the S4 delegation cert as the reuse candidate. It DOES enforce "a signer may
    sign only what it is delegated" (AC3's property): in-grant returns the delegated root; an out-of-scope,
    out-of-role, expired, or wrong-owner delegation is REFUSED fail-closed. This is on the OFFENSE surface it
    governs (domain-tagged `vigil-delegation-v1`), NOT the spine head — which is exactly why it is not a
    drop-in for per-host head signing (a head-trust-model change would be required; see the design note)."""
    owner = generate_keypair()
    host = generate_keypair()
    auth = AuthorizerKey(key_id="h1", name="host1", public_key_b64=host.public_key_b64)
    cert = sign_delegation(owner, role=OFFENSE_GOVERNANCE_ROLE, scope="engagement-A",
                           authorizers=[auth], threshold=1, not_after=2000)

    # in-grant -> the delegated root
    tr = verify_delegation(cert, trusted_owner_pubkey=owner.public_key_b64, now=1000,
                           role=OFFENSE_GOVERNANCE_ROLE, scope="engagement-A")
    assert tr.threshold == 1 and tr.authorizers[0].public_key_b64 == host.public_key_b64

    # NEGATIVE CONTROLS: a host signing OUTSIDE its delegation is refused.
    with pytest.raises(DelegationError):                    # out of scope
        verify_delegation(cert, trusted_owner_pubkey=owner.public_key_b64, now=1000,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="engagement-B")
    with pytest.raises(DelegationError):                    # out of role
        verify_delegation(cert, trusted_owner_pubkey=owner.public_key_b64, now=1000,
                          role=OFFENSE_SPINE_ROLE, scope="engagement-A")
    with pytest.raises(DelegationError):                    # expired
        verify_delegation(cert, trusted_owner_pubkey=owner.public_key_b64, now=9999,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="engagement-A")
    with pytest.raises(DelegationError):                    # not the trusted owner
        verify_delegation(cert, trusted_owner_pubkey=generate_keypair().public_key_b64, now=1000,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="engagement-A")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
