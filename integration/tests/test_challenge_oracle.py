"""I1 — per-run randomized-challenge oracles + kernel-minted Verified|Abstain.

The load-bearing properties: a recorded/hallucinated response CANNOT satisfy a fresh per-run
challenge (replay is structurally impossible, not merely improbable), and only the oracle key can
MINT a verifiable 'Verified' verdict (an LLM/critic cannot forge it)."""

from __future__ import annotations

from vigil_integration.challenge_oracle import (
    CanaryLeakOracle,
    Challenge,
    MintedVerdict,
    NonceEchoOracle,
    OOBTokenOracle,
    ValueControlOracle,
    Verdict,
    challenge_kinds,
    confirm_with_challenge,
    mint,
    oracle_for,
    verify_minted,
)

KEY = b"vigil-i1-oracle-key"
OTHER_KEY = b"attacker-key"


def test_issued_tokens_are_fresh_and_unpredictable():
    o = NonceEchoOracle()
    toks = {o.issue().token for _ in range(50)}
    assert len(toks) == 50               # fresh every time
    assert all(len(t) >= 32 for t in toks)  # 128-bit hex


def test_nonce_echo_verified_only_when_the_exact_token_is_echoed():
    o = NonceEchoOracle()
    ch = o.issue()
    assert o.verify(ch, f"...id={ch.token}...") is Verdict.VERIFIED
    assert o.verify(ch, "no echo here") is Verdict.ABSTAIN
    assert o.verify(ch, None) is Verdict.ABSTAIN


def test_replay_is_structurally_impossible():
    # a response captured for challenge C1 does NOT verify against a FRESH challenge C2
    o = NonceEchoOracle()
    c1 = o.issue()
    response_for_c1 = f"echoed {c1.token} back"
    assert o.verify(c1, response_for_c1) is Verdict.VERIFIED
    c2 = o.issue()
    assert c2.token != c1.token
    assert o.verify(c2, response_for_c1) is Verdict.ABSTAIN  # the old response can't satisfy the new token


def test_oob_token_checks_set_membership():
    o = OOBTokenOracle()
    ch = o.issue()
    assert o.verify(ch, {ch.token, "other"}) is Verdict.VERIFIED
    assert o.verify(ch, [ch.token]) is Verdict.VERIFIED
    assert o.verify(ch, ["other-token"]) is Verdict.ABSTAIN
    assert o.verify(ch, []) is Verdict.ABSTAIN


def test_canary_leak_needs_the_exact_canary():
    o = CanaryLeakOracle()
    ch = o.issue()
    assert o.verify(ch, f"secret={ch.token}") is Verdict.VERIFIED
    assert o.verify(ch, "some other data leaked") is Verdict.ABSTAIN


def test_value_control_requires_exact_match():
    o = ValueControlOracle()
    ch = o.issue()
    assert o.verify(ch, ch.token) is Verdict.VERIFIED
    assert o.verify(ch, ch.token + "0") is Verdict.ABSTAIN


def test_wrong_kind_challenge_abstains():
    o = NonceEchoOracle()
    assert o.verify(Challenge(kind="oob-token", token="x"), "x") is Verdict.ABSTAIN
    assert o.verify(Challenge(kind="nonce-echo", token=""), "x") is Verdict.ABSTAIN  # empty token


def test_only_the_oracle_key_mints_a_verifiable_verified():
    o = NonceEchoOracle()
    ch = o.issue()
    good = mint(Verdict.VERIFIED, ch, oracle_key=KEY)
    assert good.is_verified and verify_minted(good, oracle_key=KEY)
    assert not verify_minted(good, oracle_key=OTHER_KEY)             # wrong key can't validate
    forged = MintedVerdict(verdict=Verdict.VERIFIED, challenge=ch, mac="deadbeef")
    assert not verify_minted(forged, oracle_key=KEY)                 # forged MAC rejected
    tampered = MintedVerdict(verdict=Verdict.VERIFIED, challenge=Challenge("nonce-echo", ch.token + "x"),
                             mac=good.mac)
    assert not verify_minted(tampered, oracle_key=KEY)               # MAC bound to the exact token
    ab = mint(Verdict.ABSTAIN, ch, oracle_key=KEY)
    assert not ab.is_verified and not verify_minted(ab, oracle_key=KEY)


def test_confirm_with_a_real_prober_verifies_and_mints():
    o = NonceEchoOracle()
    mv = confirm_with_challenge(o, lambda ch: f"result: {ch.token}", oracle_key=KEY)
    assert mv.is_verified and verify_minted(mv, oracle_key=KEY)


def test_confirm_with_a_hallucinating_prober_abstains():
    o = NonceEchoOracle()
    # a convincing-looking canned response that ignores the challenge → cannot satisfy the fresh token
    canned = "SQL injection confirmed! dumped id=1,2,3 admin=true"
    mv = confirm_with_challenge(o, lambda ch: canned, oracle_key=KEY)
    assert not mv.is_verified and not verify_minted(mv, oracle_key=KEY)


def test_confirm_with_a_replaying_prober_abstains():
    o = NonceEchoOracle()
    old = o.issue()
    recorded = f"echoed {old.token}"  # a recorded response from a PRIOR challenge
    mv = confirm_with_challenge(o, lambda ch: recorded, oracle_key=KEY)  # ignores the fresh challenge
    assert not mv.is_verified


def test_bug_class_to_challenge_mapping():
    assert isinstance(oracle_for("sqli"), NonceEchoOracle)
    assert isinstance(oracle_for("ssrf"), OOBTokenOracle)
    assert isinstance(oracle_for("idor"), CanaryLeakOracle)
    assert isinstance(oracle_for("memory_safety"), ValueControlOracle)
    assert oracle_for("unknown-class") is None
    assert set(challenge_kinds()) == {"nonce-echo", "canary-leak", "oob-token", "value-control"}
