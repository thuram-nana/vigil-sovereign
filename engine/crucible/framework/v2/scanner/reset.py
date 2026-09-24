"""
scanner.reset — password-reset / account-recovery token-invariant confirmation (Wave 4.3, gated-workflow,
opt-in). CWE-640 (weak recovery) / CWE-613 (insufficient token expiration) / CWE-330 (insufficiently random).

These are GATED-WORKFLOW probes over the recovery flow the operator declares, driven ENTIRELY by the RUNNER
(never a tool / an LLM): the RUNNER wires each primitive (request a reset, consume/replay a token, read the
protected account as a given credential, read as the owner / an other identity / no-session) to a concrete
request through the scope/charter/kill-switch-gated executor, and this module orchestrates the ceremony and
hands the RAW captured bytes to the deterministic ``password_reset_invariant_oracle``. The scanner makes NO
accept/expiry/collision DECISION — the pure oracle re-derives every one from the retained bytes, and the
retained ``oracle_context`` re-verifies offline.

Two invariant-FREE sub-properties are FACT-capable here (no operator intent needed to know they are wrong):

  * token REUSE / NON-EXPIRY (:func:`confirm_password_reset_reuse`) — VIGIL drives its OWN test account: it
    CONSUMES a reset token (sets the password to a first unique secret P1), REPLAYS the identical token to set
    a SECOND unique secret P2, then AUTHENTICATES with P2 and reads the account. Adjudicated by the PRIVATE-READ
    REDUCTION (the same machinery Wave-3.1 IDOR/BOLA + Wave-3.2 session fixation use), with the achieved read
    BOUND to P2 (recorded ``authorized_secret`` == P2, DISTINCT from P1): a fire proves the REPLAY GENUINELY
    changed the credential (P2 reaches a victim-PRIVATE datum absent from a same-shape unauthorized read + a
    no-session baseline), never a bare 200 and never a leftover consume-session. A single-use / expiring token
    (the benign twin) leaves P2 unset — the P2 login fails, the datum is absent, and NOTHING mints.

  * deterministic COLLISION (:func:`confirm_password_reset_collision`) — VIGIL issues independent reset requests
    across one or more accounts and captures each ``{token, account}`` pair in order. A FACT is a genuinely
    EXPLOITABLE collision only: a CROSS-USER identical token (same token for two DIFFERENT accounts) or a
    PREDICTABLE counter (>=3 tokens forming an exact arithmetic progression). Byte-identical tokens for the SAME
    account (a deterministic-but-secure generator — Django default_token_generator within a timestamp bucket, a
    cache-one-token-per-account app) are NOT a FACT — they degrade to a LEAD. Distinct tokens (the benign twin)
    mint nothing; ENTROPY is never scored — a distinct-but-weak token stays a probabilistic LEAD, never a FACT.

The CROSS-USER reset-token sub-property REUSES the Wave-3.1 IdorCheck same-shape private-read differential
(``scanner.checks.IdorCheck`` → the achieved_state predicate oracle) UNCHANGED; the reset-link HOST-POISONING
sub-property routes to the EXISTING host_header_injection FACT — neither lives here.

Nothing here weakens the boundary: every request rides the RUNNER's injected gated send; the credentials and
the test account are operator-supplied for an authorized target.
"""

from __future__ import annotations

from typing import Any, Callable

from ..verify.adapter import FindingContext

# A reset token below this length is too short to reason about a collision soundly (mirrors
# oracles._PRT_MIN_TOKEN — the oracle re-checks it, this is the scanner-side documentation of the contract).
MIN_RESET_TOKEN = 8


def _view(resp: Any) -> "dict | None":
    """The retained ``{status, body}`` of a captured response the oracle re-runs its differential over. A
    non-dict (no channel on that leg) becomes ``None`` — a missing reference the oracle treats as undecidable
    (fails closed to a LEAD), never as a satisfied differential."""
    if isinstance(resp, dict):
        return {"status": resp.get("status"), "body": str(resp.get("body", ""))}
    return None


def confirm_password_reset_reuse(
    *,
    reset_token: str,
    private_discriminator: str,
    first_secret: str,
    second_secret: str,
    consume: Callable[[str, str], Any],
    replay: Callable[[str, str], Any],
    read_as_secret: Callable[[str], Any],
    owner_read: Callable[[], Any],
    unauth_read: Callable[[], Any],
    nocred_read: Callable[[], Any],
    logged_out_markers: "tuple[str, ...]" = (),
    logged_out_statuses: "tuple[int, ...]" = (401, 403),
) -> FindingContext | None:
    """Token-REUSE / NON-EXPIRY gated-workflow probe (CWE-640/613) over a VIGIL-OWNED test account.

    The RUNNER supplies the primitives, each wired to the gated send:

      * ``consume(token, first_secret)`` — the FIRST use of the reset token, setting the account password to the
        unique VIGIL secret ``first_secret`` (P1). Its response is captured only for the audit trail.
      * ``replay(token, second_secret)`` — the SECOND submit of the SAME ``reset_token``, attempting to set a
        DIFFERENT unique VIGIL secret ``second_secret`` (P2). A single-use / expiring token rejects this; a
        reusable / non-expiring token accepts it.
      * ``read_as_secret(second_secret)`` — authenticate with P2 and read the protected account URL (S's read).
      * ``owner_read()`` — read the SAME URL authoritatively as the owner (the POSITIVE reference — D present).
      * ``unauth_read()`` — read the SAME URL as an OTHER unauthorized identity (the DECISIVE SAME-SHAPE
        negative reference — a substantive 2xx from which D must be ABSENT).
      * ``nocred_read()`` — read the SAME URL with NO session (the no-session gating baseline).

    ``private_discriminator`` (D) is the operator's genuine victim-PRIVATE datum. The captured RAW views — plus
    the P2-binding fields (the consumed P1, the replay-set P2, and P2 as the credential the authorized read was
    reached with) — are handed to :func:`~verify.oracles.password_reset_invariant_oracle`, which BINDS the
    achieved read to P2 (P2 present + non-trivial + DISTINCT from P1, the read reached WITH P2) and then fires
    ONLY when D is PRESENT in the P2-authenticated read AND the owner's read yet PROVABLY ABSENT from the
    same-shape unauthorized read and the no-session baseline — proving the REPLAY GENUINELY re-changed the
    credential (not a bare 200, not a leftover consume-session). The benign twin (a single-use / expiring token)
    leaves P2 unset ⇒ the P2 login fails ⇒ D absent ⇒ channel-confirmed CLEAN. Returns ``None`` only when the
    first consume established no channel (a non-dict response); every other outcome is adjudicated by the oracle.
    The scanner scores nothing."""
    consume_resp = consume(reset_token, first_secret)
    if not isinstance(consume_resp, dict):
        return None   # no channel established on the consume leg — INCONCLUSIVE, never a CLEAN

    # The SECOND submit of the SAME token (the replay). Its own response is not scored — the achieved changed
    # state is proven only by authenticating with the replay-set secret and reaching the private datum.
    replay(reset_token, second_secret)

    # The authenticated read is reached WITH the replay-set secret P2 (=``second_secret``) — recorded as
    # ``authorized_secret`` so the oracle can BIND the achieved state to the REPLAY (P2), not the consumed P1 /
    # a leftover consume-session (mirrors session-fixation's sentinel-binding). A single-use / expiring token
    # rejects the replay, so a P2 login fails and the datum is absent ⇒ channel-confirmed clean.
    authorized_resp = read_as_secret(second_secret)
    owner_resp = owner_read()
    unauth_resp = unauth_read()
    nocred_resp = nocred_read()

    return FindingContext.from_password_reset_reuse(
        reset_token=reset_token,
        private_discriminator=private_discriminator,
        authorized_view=_view(authorized_resp),
        owner_view=_view(owner_resp),
        unauth_ref=_view(unauth_resp),
        logged_out_ref=_view(nocred_resp),
        logged_out_markers=logged_out_markers,
        logged_out_statuses=logged_out_statuses,
        consumed_secret=first_secret,
        replay_secret=second_secret,
        authorized_secret=second_secret,
    )


def confirm_password_reset_collision(
    *,
    request_reset_token: Callable[[str], Any],
    accounts: "tuple[str, ...]",
    repeats: int = 1,
) -> FindingContext | None:
    """Deterministic token-COLLISION gated-workflow probe (CWE-640/330), account-aware.

    ``request_reset_token(account)`` performs ONE reset request for ``account`` through the gated send and
    returns the freshly-issued reset token (a string), or a falsy value if none was issued. This requests a
    token for EACH account in ``accounts``, ``repeats`` times, IN ORDER, and captures each ``{token, account}``
    pair. The captures are handed to :func:`~verify.oracles.password_reset_invariant_oracle`, which mints a FACT
    ONLY on a genuinely-EXPLOITABLE collision:

      * a CROSS-USER identical token — the SAME token issued to two DIFFERENT accounts (pass >=2 distinct
        ``accounts``); an attacker who resets their own account then receives the victim's token; OR
      * a PREDICTABLE counter — >=3 tokens forming an EXACT arithmetic progression (pass >=3 total captures, e.g.
        ``repeats>=3`` on one account or >=3 accounts).

    Byte-identical tokens for the SAME account (a cryptographically-secure DETERMINISTIC generator — stock Django
    default_token_generator within a timestamp bucket, a cache-one-token-per-account app) are NOT a FACT — they
    degrade to a LEAD. DISTINCT tokens (the benign twin) mint nothing; ENTROPY is never scored. Returns ``None``
    only when fewer than 2 captures were established (no channel / no tokens — INCONCLUSIVE, never a CLEAN);
    every sufficient sample is adjudicated by the oracle."""
    if not accounts:
        return None
    reps = max(int(repeats), 1)
    samples: list[dict] = []
    for _ in range(reps):
        for account in accounts:
            tok = request_reset_token(account)
            if isinstance(tok, str) and tok:
                samples.append({"token": tok, "account": str(account)})
    if len(samples) < 2:
        return None   # no channel / too few tokens issued — INCONCLUSIVE, never a CLEAN
    return FindingContext.from_password_reset_collision(samples=samples)


def password_reset_finding(
    ctx: "FindingContext", *, check_id: str, insertion_point: str = ""
) -> dict:
    """Wrap a confirmed :class:`~verify.adapter.FindingContext` (from a reuse or collision probe) into the
    finding dict the admission / minting choke reads — ``{check_id, bug_class, insertion_point,
    oracle_context}``. The retained ``oracle_context`` is the JSON-safe record, so the signed certificate
    re-verifies offline (the pure ``password_reset_invariant_oracle`` re-fires over the retained bytes). This
    helper never mints; the runner mints ONLY via ``oracle_adapter.certify_admitted(provenance="live_redrive")``
    against the class's registered evidence branch."""
    return {
        "check_id": check_id,
        "bug_class": ctx.bug_class,
        "insertion_point": insertion_point,
        "oracle_context": ctx.to_verifier_context(),
    }
