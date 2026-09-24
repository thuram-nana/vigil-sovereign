"""
Password-reset / account-recovery token-invariant oracle (Wave 4.3) — the pure predicate's FACT / CLEAN /
LEAD discipline over its OWN OracleKind.PASSWORD_RESET_INVARIANT (CWE-640/613/330), plus offline re-verify
through the OracleVerifier dispatch and the FindingContext round-trip.

The invariant this file guards (the Wave-3 lesson applied): an achieved CHANGED state (a reset token that was
consumed still re-changes the credential on replay) CANNOT be proven from response CONTENT / a bare 200 — it is
proven by the SAME PRIVATE-READ REDUCTION Wave-3.1 IDOR/BOLA + Wave-3.2 session fixation use (a victim-PRIVATE
datum reached by authenticating with the replay-set secret, present in the owner's read yet absent from a
substantive SAME-SHAPE unauthorized read and a no-session baseline). The deterministic COLLISION FACT is an
EXACT-ARITHMETIC predictable-counter collision ONLY; a BYTE-IDENTICAL token — same account LABEL or across
DIFFERENT account LABELS — is a LEAD, never a FACT (labels are never proven distinct principals — a
case-normalizing generator maps 'alice'/'Alice' to ONE principal), and genuine cross-principal exploitation is
minted only by the password_reset_cross_user private-read differential. ENTROPY is never scored (a distinct token
is CLEAN). A benign single-use / expiring token and a distinct-token generator mint NOTHING — live AND under
offline re-verify.
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import password_reset_invariant_oracle
from framework.v2.verify.verifier import OracleVerifier

_D = "RESET-PRIVATE-victim-9931-2050"
_CHROME = "<html><nav>Home</nav><main>{extra}</main><footer>Acme Corp support portal</footer></html>"


def _authed(extra: str) -> dict:
    return {"status": 200, "body": _CHROME.format(extra=extra)}


_P1 = "OBSIDIAN-TEST-consume-secret-1000"
_P2 = "OBSIDIAN-TEST-replay-secret-2000"


def _reuse_record(**over):
    rec = dict(
        reset_token="rt_deadbeefcafebabe0011",
        private_discriminator=_D,
        # the replay-set secret's authenticated read reaches the victim-private datum
        authorized_view=_authed(_D),
        # owner's authoritative read (D present — proves D is real private content)
        owner_view=_authed(_D),
        # OTHER unauthorized identity's SUBSTANTIVE SAME-SHAPE read (same shell, D absent)
        unauth_ref=_authed("record owner=victim status=(restricted) — no access"),
        # no-session gating baseline (a genuine denial with a real body)
        logged_out_ref={"status": 403, "body": "login required to view this account page"},
        logged_out_markers=("You are logged out",),
        logged_out_statuses=(401, 403),
        # P2-binding: the consumed P1, the replay-set P2 (distinct), and P2 as the credential the authorized
        # read was reached with — so the achieved state is attributable to the REPLAY, not the first consume.
        consumed_secret=_P1,
        replay_secret=_P2,
        authorized_secret=_P2,
    )
    rec.update(over)
    return rec


def _reuse_sig(**over):
    """Build the retained token-reuse record via the FindingContext factory (so ``mode`` and the view-coercion
    match the real minting path) and run the oracle over it."""
    ctx = FindingContext.from_password_reset_reuse(**_reuse_record(**over))
    return password_reset_invariant_oracle(ctx.password_reset_invariant)


# ---------------------------------------------------------------------------
# token REUSE / NON-EXPIRY — the private-read reduction
# ---------------------------------------------------------------------------

def test_reuse_fires_when_replay_set_secret_reaches_the_private_datum() -> None:
    sig = _reuse_sig()
    assert sig.kind is OracleKind.PASSWORD_RESET_INVARIANT
    assert sig.fired and sig.conclusive and sig.confidence >= 0.9


def test_reuse_single_use_expiring_token_is_channel_confirmed_clean() -> None:
    # BENIGN TWIN: the token expired on first use, so the replay set nothing; authenticating with the second
    # secret fails and the read is a logged-out page — D absent ⇒ NOT a reuse, a confirmed CLEAN.
    sig = _reuse_sig(authorized_view=_authed("Please log in — you are logged out"))
    assert not sig.fired and sig.conclusive   # channel-confirmed clean, never a false FACT


def test_reuse_without_references_is_a_lead_not_a_fact() -> None:
    sig = _reuse_sig(owner_view=None, unauth_ref=None, logged_out_ref=None)
    assert not sig.fired and not sig.conclusive   # undecidable ⇒ LEAD


def test_reuse_datum_present_in_unauth_reference_is_a_lead() -> None:
    # D present for an OTHER identity ⇒ chrome / shared / not victim-private ⇒ undecidable (LEAD), never a FACT.
    sig = _reuse_sig(unauth_ref=_authed(_D))
    assert not sig.fired and not sig.conclusive


def test_reuse_reflected_token_datum_is_a_lead() -> None:
    # A discriminator that IS the reset token (a token echo, not access-gated content) cannot mint.
    tok = "rt_deadbeefcafebabe0011"
    sig = _reuse_sig(private_discriminator=tok, authorized_view=_authed(tok), owner_view=_authed(tok))
    assert not sig.fired and not sig.conclusive


def test_reuse_non_substantive_unauth_reference_is_a_lead() -> None:
    # A denial / empty / different-shape negative reference is REFUSED (its absent D is vacuous) ⇒ LEAD.
    sig = _reuse_sig(unauth_ref={"status": 403, "body": "forbidden"})
    assert not sig.fired and not sig.conclusive


# ---------------------------------------------------------------------------
# token REUSE — P2-binding (the achieved read must be reached with the REPLAY-set secret, not the consumed P1)
# ---------------------------------------------------------------------------

def test_reuse_wrong_secret_authorized_view_is_a_lead() -> None:
    # The authenticated read was reached with the CONSUMED secret P1 (or any secret != the replay-set P2), so a
    # success cannot be attributed to the REPLAY — a single-use token whose replay set nothing could still read D
    # via the first consume. The P2-binding refuses this ⇒ LEAD, never a FACT.
    sig = _reuse_sig(authorized_secret=_P1)
    assert not sig.fired and not sig.conclusive


def test_reuse_replay_secret_equal_to_consumed_is_a_lead() -> None:
    # P2 == P1 ⇒ a successful read cannot be attributed to the REPLAY rather than the first consume ⇒ LEAD.
    sig = _reuse_sig(replay_secret=_P1, authorized_secret=_P1)
    assert not sig.fired and not sig.conclusive


def test_reuse_missing_replay_secret_is_a_lead() -> None:
    # No replay-set secret recorded ⇒ the achieved read cannot be bound to the replayed token ⇒ LEAD.
    sig = _reuse_sig(replay_secret=None, authorized_secret=None)
    assert not sig.fired and not sig.conclusive


def test_reuse_discriminator_echoing_replay_secret_is_a_lead() -> None:
    # D that is a substring of the replay-set secret P2 is a credential echo, not access-gated content ⇒ LEAD.
    secret = "OBSIDIAN-TEST-replay-" + _D + "-tail"
    sig = _reuse_sig(replay_secret=secret, authorized_secret=secret,
                     authorized_view=_authed(secret), owner_view=_authed(_D))
    assert not sig.fired and not sig.conclusive


# ---------------------------------------------------------------------------
# deterministic COLLISION
# ---------------------------------------------------------------------------

def test_collision_cross_label_identical_is_a_lead_not_a_fact() -> None:
    # RETIRED FACT PATH (round-3 soundness fix): the SAME token for two DIFFERENT account LABELS is NO LONGER a
    # FACT. Account labels are opaque strings NEVER proven to be distinct PRINCIPALS — a case-normalizing
    # generator maps 'victim'/'Victim' to ONE principal — so a byte-identical token across labels FAILS CLOSED to
    # a LEAD (a stronger LEAD to escalate via the cross-user private-read differential), never a cross-user FACT.
    sig = password_reset_invariant_oracle({"mode": "token_collision", "samples": [
        {"token": "a1b2c3d4e5", "account": "victim"}, {"token": "a1b2c3d4e5", "account": "attacker"}]})
    assert not sig.fired and not sig.conclusive          # LEAD — never a FACT
    assert sig.observed.get("identical_lead") is True and sig.observed.get("cross_label") is True


def test_collision_case_normalizing_generator_alice_Alice_is_a_lead() -> None:
    # THE round-3 SOUNDNESS CASE: a benign per-user-DETERMINISTIC, identifier-NORMALIZING generator
    # (case-insensitive email/username) returns the BYTE-IDENTICAL token for 'alice' and 'Alice' — which are the
    # SAME principal, not two. The old label-collision FACT path would MINT A FALSE cross-user FACT here; the fix
    # fails closed to a LEAD. Genuine cross-principal exploitation is proven only by the private-read differential.
    sig = password_reset_invariant_oracle({"mode": "token_collision", "samples": [
        {"token": "a1b2c3d4e5", "account": "alice"}, {"token": "a1b2c3d4e5", "account": "Alice"}]})
    assert not sig.fired and not sig.conclusive          # LEAD — never a FACT
    assert sig.observed.get("identical_lead") is True and sig.observed.get("cross_label") is True


def test_collision_same_user_byte_identical_is_a_lead() -> None:
    # BENIGN CONTROL: byte-identical tokens for the SAME account label are exactly what a cryptographically-secure
    # DETERMINISTIC generator (Django default_token_generator within a timestamp bucket, a cache-one-token-per-
    # account app) returns — NOT an exploitable collision ⇒ LEAD, never a FACT.
    sig = password_reset_invariant_oracle({"mode": "token_collision", "samples": [
        {"token": "a1b2c3d4e5", "account": "victim"}, {"token": "a1b2c3d4e5", "account": "victim"}]})
    assert not sig.fired and not sig.conclusive
    assert sig.observed.get("identical_lead") is True and sig.observed.get("cross_label") is False


def test_collision_byte_identical_unknown_accounts_is_a_lead() -> None:
    # A flat token list carries NO account label, so a byte-identical pair cannot even be examined for cross-label
    # ⇒ LEAD (fails closed): the old byte-identical-alone FACT is downgraded.
    sig = password_reset_invariant_oracle({"mode": "token_collision", "tokens": ["a1b2c3d4e5", "a1b2c3d4e5"]})
    assert not sig.fired and not sig.conclusive
    assert sig.observed.get("identical_lead") is True and sig.observed.get("cross_label") is False


def test_collision_exact_arithmetic_progression_fires() -> None:
    sig = password_reset_invariant_oracle(
        {"mode": "token_collision", "tokens": ["00001001", "00001002", "00001003"]})
    assert sig.fired and sig.conclusive
    assert sig.observed.get("arithmetic") is True and sig.observed.get("step") == 1


def test_collision_distinct_high_entropy_tokens_are_clean() -> None:
    # BENIGN TWIN: distinct random tokens — a channel-confirmed clean, never a FACT (entropy is not scored).
    sig = password_reset_invariant_oracle(
        {"mode": "token_collision", "tokens": ["9f3a1c77bd", "2e88d0114a", "c50177ffde"]})
    assert not sig.fired and sig.conclusive


def test_collision_two_distinct_non_arithmetic_tokens_are_clean() -> None:
    sig = password_reset_invariant_oracle({"mode": "token_collision", "tokens": ["ab12cd34ef", "zz98yy76xx"]})
    assert not sig.fired and sig.conclusive


def test_collision_too_few_samples_is_a_lead() -> None:
    sig = password_reset_invariant_oracle({"mode": "token_collision", "tokens": ["a1b2c3d4e5"]})
    assert not sig.fired and not sig.conclusive


def test_collision_too_short_token_is_a_lead() -> None:
    sig = password_reset_invariant_oracle({"mode": "token_collision", "tokens": ["abc", "abc"]})
    assert not sig.fired and not sig.conclusive


def test_collision_close_but_non_constant_step_does_not_fire() -> None:
    # near-adjacent but NOT a constant step (1002-1001=1, 1004-1002=2) ⇒ not a deterministic progression ⇒ clean.
    sig = password_reset_invariant_oracle(
        {"mode": "token_collision", "tokens": ["00001001", "00001002", "00001004"]})
    assert not sig.fired and sig.conclusive


def test_unknown_mode_is_inconclusive() -> None:
    sig = password_reset_invariant_oracle({"mode": "something_else"})
    assert not sig.fired and not sig.conclusive


# ---------------------------------------------------------------------------
# offline re-verify through the OracleVerifier dispatch + FindingContext round-trip
# ---------------------------------------------------------------------------

def _confirm_offline(ctx: FindingContext) -> bool:
    rebuilt = FindingContext.model_validate(ctx.model_dump())
    return OracleVerifier().confirm(rebuilt.to_verifier_context()).confirmed


def test_reuse_fact_confirms_through_the_verifier_and_reroundtrips() -> None:
    ctx = FindingContext.from_password_reset_reuse(**_reuse_record())
    assert OracleVerifier().confirm(ctx.to_verifier_context()).confirmed
    assert _confirm_offline(ctx)   # durable-certificate path re-fires from the serialized record


def test_collision_fact_confirms_through_the_verifier() -> None:
    ctx = FindingContext.from_password_reset_collision(tokens=["00001001", "00001002", "00001003"])
    assert OracleVerifier().confirm(ctx.to_verifier_context()).confirmed
    assert _confirm_offline(ctx)


def test_benign_twins_never_confirm_through_the_verifier() -> None:
    # single-use expiring token (reuse twin) + distinct-token generator (collision twin) — neither confirms.
    reuse_twin = FindingContext.from_password_reset_reuse(
        **_reuse_record(authorized_view=_authed("Please log in — you are logged out")))
    coll_twin = FindingContext.from_password_reset_collision(tokens=["9f3a1c77bd", "2e88d0114a", "c50177ffde"])
    assert not OracleVerifier().confirm(reuse_twin.to_verifier_context()).confirmed
    assert not OracleVerifier().confirm(coll_twin.to_verifier_context()).confirmed
