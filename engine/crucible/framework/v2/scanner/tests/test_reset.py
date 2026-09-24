"""
Password-reset token-invariant confirmation (Wave 4.3, gated-workflow) — end-to-end over the in-process
benchmark app, without a browser: VIGIL drives its OWN test account through the reset flow and hands the RAW
captured bytes to the deterministic ``password_reset_invariant_oracle``, which adjudicates by the PRIVATE-READ
REDUCTION (reuse/non-expiry) or a DETERMINISTIC collision.

Proves:
  * token REUSE / NON-EXPIRY is a FACT on the PLANTED vulnerable flow (``/reset/consume`` never invalidates the
    token, so REPLAYING it re-sets the password — authenticating with the replay-set secret reaches the
    victim's PRIVATE datum, present in the owner's read and absent from an OTHER identity's same-shape read);
  * SILENCE on the reuse BENIGN TWIN (``/reset/safe/consume`` is single-use — the replay sets nothing, so the
    replay-set secret never authenticates and the datum is absent);
  * deterministic COLLISION is a FACT on the PLANTED vulnerable flow (``/reset/request`` returns a monotonic
    counter token — an exact arithmetic progression across independent requests);
  * SILENCE on the collision BENIGN TWIN (``/reset/safe/request`` returns distinct random tokens);
  * the oracle NEVER trusts a bare 200 nor scores entropy;
  * the default GET-only crawl never touches the POST reset routes / the unlinked account page (the fixture is
    deep-only), so ``make gate`` is unaffected.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from framework.v2.eval.benchmark_app import _reset_private, serve
from framework.v2.scanner.insertion import HttpRequest
from framework.v2.scanner.reset import confirm_password_reset_collision, confirm_password_reset_reuse
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import OracleVerifier

_TOKEN_RE = re.compile(r"reset token: (\S+?)<")
_RESET_COOKIE = "RESET_SESSION"


def _send(req: HttpRequest) -> dict:
    body = req.body.encode("utf-8") if req.body is not None else None
    r = urllib.request.Request(req.url, data=body, method=req.method)
    for k, v in req.headers:
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:   # noqa: S310 (loopback benchmark app)
            return {"status": resp.status, "headers": list(resp.getheaders()),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:                       # pragma: no cover
        return {"status": e.code, "headers": list(e.headers.items()),
                "body": e.read().decode("utf-8", "replace")}


def _post(url: str, body: str) -> dict:
    return _send(HttpRequest(method="POST", url=url,
                             headers=[("Content-Type", "application/x-www-form-urlencoded")], body=body))


def _request_token(base: str, user: str, *, safe: bool = False, route: str = "") -> str:
    if not route:
        route = "/reset/safe/request" if safe else "/reset/request"
    resp = _post(f"{base}{route}", f"user={user}")
    m = _TOKEN_RE.search(resp["body"])
    return m.group(1) if m else ""


def _consume(base: str, token: str, pw: str, *, safe: bool = False) -> dict:
    route = "/reset/safe/consume" if safe else "/reset/consume"
    return _post(f"{base}{route}", f"token={token}&password={pw}")


def _login_sid(base: str, user: str, pw: str) -> str | None:
    resp = _post(f"{base}/reset/login", f"user={user}&password={pw}")
    for k, v in resp["headers"]:
        if str(k).lower() == "set-cookie" and f"{_RESET_COOKIE}=" in v:
            return v.split(f"{_RESET_COOKIE}=", 1)[1].split(";", 1)[0]
    return None


def _read_account(base: str, sid: str | None) -> dict:
    headers = [("Cookie", f"{_RESET_COOKIE}={sid}")] if sid else []
    return _send(HttpRequest(method="GET", url=f"{base}/reset/account", headers=headers, body=None))


def _confirm(ctx: FindingContext) -> bool:
    return OracleVerifier().confirm(ctx.to_verifier_context()).confirmed


def _reuse_ctx(base: str, *, safe: bool) -> FindingContext | None:
    """Drive the full reuse ceremony against the benchmark. An OWNER session is established up front (bound to
    the user, so it survives the later password changes) to serve as the authoritative positive reference; an
    OTHER identity's session is the same-shape negative reference."""
    victim, attacker = "victim43", "attacker43"
    D = _reset_private(victim)
    # owner session: set the victim's password once and log in (the session persists through later changes).
    _consume(base, _request_token(base, victim, safe=safe), "OBSIDIAN-TEST-owner-pw", safe=safe)
    owner_sid = _login_sid(base, victim, "OBSIDIAN-TEST-owner-pw")
    # a distinct OTHER identity's session (its account renders ITS private datum, not the victim's).
    _consume(base, _request_token(base, attacker, safe=safe), "OBSIDIAN-TEST-attacker-pw", safe=safe)
    attacker_sid = _login_sid(base, attacker, "OBSIDIAN-TEST-attacker-pw")
    # the token under test
    token = _request_token(base, victim, safe=safe)
    p2 = "OBSIDIAN-TEST-replay-secret-2"
    return confirm_password_reset_reuse(
        reset_token=token, private_discriminator=D,
        first_secret="OBSIDIAN-TEST-consume-secret-1", second_secret=p2,
        consume=lambda tok, pw: _consume(base, tok, pw, safe=safe),
        replay=lambda tok, pw: _consume(base, tok, pw, safe=safe),
        read_as_secret=lambda pw: _read_account(base, _login_sid(base, victim, pw)),
        owner_read=lambda: _read_account(base, owner_sid),
        unauth_read=lambda: _read_account(base, attacker_sid),
        nocred_read=lambda: _read_account(base, None),
        logged_out_markers=("You are logged out",))


# ---------------------------------------------------------------------------
# token REUSE / NON-EXPIRY
# ---------------------------------------------------------------------------

def test_planted_reuse_flow_confirms_a_fact() -> None:
    with serve() as base:
        ctx = _reuse_ctx(base, safe=False)
    assert ctx is not None
    rec = ctx.password_reset_invariant
    assert rec["mode"] == "token_reuse"
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(rec)
    assert sig.kind is OracleKind.PASSWORD_RESET_INVARIANT
    assert sig.fired and sig.conclusive
    assert _confirm(ctx)


def test_single_use_token_is_the_benign_twin_no_reuse_fact() -> None:
    with serve() as base:
        ctx = _reuse_ctx(base, safe=True)
    assert ctx is not None
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(ctx.password_reset_invariant)
    assert not sig.fired and sig.conclusive   # the correct defense — channel-confirmed clean
    assert not _confirm(ctx)


# ---------------------------------------------------------------------------
# deterministic COLLISION
# ---------------------------------------------------------------------------

def test_planted_deterministic_collision_confirms_a_fact() -> None:
    # VULNERABLE /reset/request is a global monotonic counter — independent requests form an exact arithmetic
    # progression (a predictable counter), the deterministic-collision FACT.
    with serve() as base:
        ctx = confirm_password_reset_collision(
            request_reset_token=lambda acct: _request_token(base, acct), accounts=("collide",), repeats=3)
    assert ctx is not None
    rec = ctx.password_reset_invariant
    assert rec["mode"] == "token_collision" and len(rec["samples"]) == 3
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(rec)
    assert sig.fired and sig.conclusive and sig.observed.get("arithmetic") is True
    assert _confirm(ctx)


def test_cross_user_identical_token_confirms_a_fact() -> None:
    # VULNERABLE /reset/crossuser/request fails to bind the token to the user — two DIFFERENT accounts receive
    # the BYTE-IDENTICAL token (a genuine cross-user collision), the deterministic-collision FACT.
    with serve() as base:
        ctx = confirm_password_reset_collision(
            request_reset_token=lambda acct: _request_token(base, acct, route="/reset/crossuser/request"),
            accounts=("cu-victim43", "cu-attacker43"))
    assert ctx is not None
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(ctx.password_reset_invariant)
    assert sig.fired and sig.conclusive and sig.observed.get("cross_user") is True
    assert _confirm(ctx)


def test_deterministic_secure_same_user_token_is_a_lead_not_a_fact() -> None:
    # BENIGN CONTROL: /reset/deterministic/request is a cryptographically-secure per-user deterministic
    # generator (byte-identical for the SAME user, distinct across users). Requesting repeatedly for ONE user
    # returns byte-identical tokens — but same-account identity is NOT an exploitable collision ⇒ a LEAD, never
    # a FACT (this is exactly the Django default_token_generator / cache-one-token case the red-pen flagged).
    with serve() as base:
        ctx = confirm_password_reset_collision(
            request_reset_token=lambda acct: _request_token(base, acct, route="/reset/deterministic/request"),
            accounts=("du-same43",), repeats=3)
    assert ctx is not None
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(ctx.password_reset_invariant)
    assert not sig.fired and not sig.conclusive   # same-user byte-identical ⇒ LEAD, not a false FACT nor a CLEAN
    assert not _confirm(ctx)


def test_deterministic_secure_distinct_across_users_is_clean() -> None:
    # The same secure per-user generator across DIFFERENT users returns DISTINCT tokens ⇒ channel-confirmed clean.
    with serve() as base:
        ctx = confirm_password_reset_collision(
            request_reset_token=lambda acct: _request_token(base, acct, route="/reset/deterministic/request"),
            accounts=("du-a43", "du-b43", "du-c43"))
    assert ctx is not None
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(ctx.password_reset_invariant)
    assert not sig.fired and sig.conclusive   # distinct per-user tokens — clean
    assert not _confirm(ctx)


def test_random_token_generator_is_the_benign_twin_no_collision_fact() -> None:
    with serve() as base:
        ctx = confirm_password_reset_collision(
            request_reset_token=lambda acct: _request_token(base, acct, safe=True), accounts=("collide",), repeats=3)
    assert ctx is not None
    from framework.v2.verify.oracles import password_reset_invariant_oracle
    sig = password_reset_invariant_oracle(ctx.password_reset_invariant)
    assert not sig.fired and sig.conclusive   # distinct random tokens — channel-confirmed clean
    assert not _confirm(ctx)
