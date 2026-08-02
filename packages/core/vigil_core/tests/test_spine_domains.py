"""S5 — the spine-domain registry (`vigil_core.spine_domains`).

Proves the registry is internally consistent and honest: every segment names a known role/trust-domain,
the roles are single-sourced from delegation, owner-rooted vs file-backed are queryable, and the registry
does NOT overclaim (the non-delegated operator ledger is not marked owner-rooted; the DB-projection chain is
not marked file-backed).

Run: pytest packages/core/vigil_core/tests/test_spine_domains.py -q
"""
from vigil_core import spine_domains as sd
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, OFFENSE_SPINE_ROLE


def test_registration_is_self_consistent():
    sd.verify_registration()   # raises on any inconsistency


def test_roles_are_single_sourced_from_delegation():
    # The registry must reuse delegation's role strings, not re-spell them (the F3 one-vocabulary lesson).
    assert sd.OFFENSE_GOVERNANCE_ROLE is OFFENSE_GOVERNANCE_ROLE
    assert sd.OFFENSE_SPINE_ROLE is OFFENSE_SPINE_ROLE
    assert OFFENSE_SPINE_ROLE == "offense-spine" and OFFENSE_GOVERNANCE_ROLE == "offense-governance"


def test_every_segment_has_a_known_role_and_trust_domain():
    for d in sd.DOMAINS:
        assert d.signer_role in sd._ALL_ROLES
        assert d.trust_domain in (sd.SOVEREIGN, sd.OFFENSE)


def test_lookup_and_helpers():
    assert sd.signer_role("offense-spine") == OFFENSE_SPINE_ROLE
    assert sd.domain("offense-spine").trust_domain == sd.OFFENSE
    owner_rooted = set(sd.owner_rooted_segments())
    # sovereign spine (owner key directly), the finding anchor-1 (from_delegation consumer), the offense SPINE
    # (S5b's verify_offense_spine consumer), and — as of T3 — the CRUCIBLE blackboard chain (its persisted
    # head is rooted by verify_blackboard_chain -> verify_delegation(OFFENSE_GOVERNANCE_ROLE)) are owner-rooted.
    # The usage ledger (operator key, not owner-delegated) is honestly NOT owner-rooted (S7).
    assert "sovereign-spine" in owner_rooted
    assert "offense-finding-anchor1" in owner_rooted
    assert "offense-spine" in owner_rooted
    assert "crucible-blackboard-chain" in owner_rooted
    assert "offense-usage-ledger" not in owner_rooted
    # both the offense spine and — as of T3 — the persisted CRUCIBLE blackboard chain are file-backed
    # (offline-verifiable from inert bytes by a public-key-only reader).
    file_backed = set(sd.offline_verifiable_segments())
    assert "offense-spine" in file_backed
    assert "crucible-blackboard-chain" in file_backed


def test_owner_rooted_iff_named_consumer():
    # The invariant the guard enforces, asserted directly: a segment is owner_rooted EXACTLY when it names a
    # specific owner-tie consumer. (This is the whole-class property; the mutation test below proves teeth.)
    for d in sd.DOMAINS:
        assert d.owner_rooted == bool(d.owner_tie_consumer.strip()), d.name


def test_registration_guard_catches_the_whole_class_not_just_one_instance():
    # Per-SEGMENT guard: ANY segment flipped to owner_rooted=True without naming a consumer is refused —
    # including `continuous-attestation-log`, which SHARES OFFENSE_GOVERNANCE_ROLE with the genuinely
    # owner-rooted `offense-finding-anchor1` and (as of T3) `crucible-blackboard-chain`. A role-granular guard
    # would have let it ride in on a sibling's role (the exact S5a re-check MED); the segment-granular guard
    # does not.
    import dataclasses

    import pytest

    def _patched_raises(victim, **over):
        overclaim = dataclasses.replace(sd.domain(victim), **over)
        patched = tuple(overclaim if d.name == victim else d for d in sd.DOMAINS)
        original = sd.DOMAINS
        try:
            sd.DOMAINS = patched                   # type: ignore[misc]
            with pytest.raises(ValueError, match="refused"):
                sd.verify_registration()
        finally:
            sd.DOMAINS = original                  # type: ignore[misc]

    # overclaim: owner_rooted=True with no consumer — for the consumer-LESS segments, crucially including
    # `continuous-attestation-log`, which SHARES OFFENSE_GOVERNANCE_ROLE with the owner-rooted
    # offense-finding-anchor1 (and T3's crucible-blackboard-chain). A role-granular guard would let it ride in
    # on a sibling's role; this one doesn't (it binds the claim to each segment's OWN named consumer).
    for victim in ("continuous-attestation-log", "offense-usage-ledger"):
        _patched_raises(victim, owner_rooted=True)
    # under-claim: a real consumer named but owner_rooted=False is ALSO refused (would leave it unroutable) —
    # assert it for BOTH the offense spine and (T3) the now-consumer-bearing crucible-blackboard-chain.
    _patched_raises("offense-spine", owner_rooted=False)
    _patched_raises("crucible-blackboard-chain", owner_rooted=False)


def test_unknown_segment_is_fail_closed():
    import pytest
    with pytest.raises(KeyError):
        sd.domain("no-such-segment")


def test_offense_spine_is_a_distinct_role_from_governance():
    # The stable spine identity and the m-of-n finding authority must be different roles so delegating one
    # never widens the other's signing surface.
    assert sd.domain("offense-spine").signer_role != sd.domain("offense-finding-anchor1").signer_role


def test_domain_tags_are_distinct_prefixes():
    tags = list(sd.DOMAIN_TAGS.values())
    assert len(set(tags)) == len(tags)                       # no two purposes share a prefix
    assert all(t.endswith(b"\x00") for t in tags)           # each is a NUL-terminated domain separator
