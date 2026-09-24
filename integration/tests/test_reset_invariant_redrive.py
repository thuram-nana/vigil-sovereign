"""
Password-reset token invariants — STD-WIRING (Wave 4.3): admission -> certify_admitted -> offline re-verify
-> tamper reject, over the registered password_reset.token_reuse / .deterministic_collision / .cross_user_read
evidence branches.

This is the claim-discipline half of slice 4.3: each invariant-free reset FACT is minted ONLY through the
admission choke (``verdict.admit`` -> the FACT-capable branch -> ``oracle_adapter.certify_admitted(
provenance="live_redrive")``), the offline ``framework.v2 verify`` path re-fires the retained
``oracle_context``, and a tampered value is rejected. An LLM-provenanced context is demoted to a LEAD. A
conclusive non-fire (the single-use / distinct-token benign twins) is CLEAN — not minted; a non-conclusive
non-fire is INCONCLUSIVE/LEAD, never a false CLEAN.

The token-reuse FACT rests on the PRIVATE-READ REDUCTION (the replay-set secret reaches a victim-PRIVATE datum
absent from a substantive same-shape unauthorized read), reusing the Wave-3.1 machinery; the collision FACT on
a DETERMINISTIC (byte-identical / exact-arithmetic) collision; the cross-user FACT on the Wave-3.1 IdorCheck
same-shape cross-read UNCHANGED. A benign single-use/expiring token, a distinct-token generator, and a
per-user-scoped token never produce a firing context.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# A scanner→integration test that imports vigil_integration.live.* must not fail the CRUCIBLE-core CI leg,
# which lacks the gateway package (CI-HYGIENE, Wave-3 lesson).
import pytest  # noqa: E402

pytest.importorskip("vigil_gateway")

from framework.v2.scanner.access_control import access_control_finding  # noqa: E402
from framework.v2.scanner.checks import IdorCheck  # noqa: E402
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate  # noqa: E402
from framework.v2.scanner.reset import (  # noqa: E402
    confirm_password_reset_collision,
    confirm_password_reset_reuse,
    password_reset_finding,
)
from framework.v2.verify.models import OracleKind  # noqa: E402
from framework.v2.verify.reverify import reverify_finding  # noqa: E402
from framework.v2.verify.verifier import OracleVerifier  # noqa: E402

from vigil_integration.live.reset_invariant_redrive import _BRANCH_FOR  # noqa: E402
from vigil_integration.live.verdict import Verdict, admit, branch_ids  # noqa: E402
from vigil_integration.live.wiring import _redrive_branch_for  # noqa: E402
from vigil_integration.oracle_adapter import certify_admitted  # noqa: E402

_D = "RESET-PRIVATE-victim-9931-2050"
_CHROME = "<html><nav>Home</nav><main>{extra}</main><footer>Acme Corp support portal</footer></html>"
_P2 = "OBSIDIAN-TEST-second-secret-9001"


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _authed(extra: str) -> dict:
    return {"status": 200, "body": _CHROME.format(extra=extra)}


# ---- reuse: VIGIL-owned test account, consume-then-replay, private-read reduction ----

def _reuse_ctx(*, single_use: bool):
    """Drive confirm_password_reset_reuse with fake gated primitives. VULNERABLE (single_use=False): the replay
    re-sets the password to P2, so authenticating with P2 reaches the victim-private datum. BENIGN TWIN
    (single_use=True): the replay sets nothing, so the P2 read is a logged-out page (D absent)."""
    def consume(token, pw):
        return {"status": 200, "body": "password updated"}

    def replay(token, pw):
        return {"status": 200, "body": ("invalid or expired token" if single_use else "password updated")}

    def read_as_secret(pw):
        # P2 authenticates ONLY when the replay genuinely re-set it (the vulnerable, reusable token).
        return _authed(_D) if (pw == _P2 and not single_use) else _authed("Please log in — you are logged out")

    return confirm_password_reset_reuse(
        reset_token="rt_deadbeefcafebabe0011", private_discriminator=_D,
        first_secret="OBSIDIAN-TEST-first-secret-1000", second_secret=_P2,
        consume=consume, replay=replay, read_as_secret=read_as_secret,
        owner_read=lambda: _authed(_D),
        unauth_read=lambda: _authed("record owner=victim status=(restricted) — no access"),
        nocred_read=lambda: {"status": 403, "body": "login required to view this account page"},
        logged_out_markers=("You are logged out",))


def _reuse_finding():
    ctx = _reuse_ctx(single_use=False)
    assert ctx is not None
    return password_reset_finding(ctx, check_id="reset:password_reset_reuse:0", insertion_point="reset:reuse")


# ---- collision: deterministic (arithmetic) vs distinct twin ----

def _collision_ctx(*, deterministic: bool):
    seq = iter((["00001001", "00001002", "00001003"] if deterministic
                else ["9f3a1c77bd", "2e88d0114a", "c50177ffde"]))
    return confirm_password_reset_collision(request_reset_token=lambda: next(seq, ""), samples=3)


def _collision_finding():
    ctx = _collision_ctx(deterministic=True)
    assert ctx is not None
    return password_reset_finding(ctx, check_id="reset:password_reset_collision:0",
                                  insertion_point="reset:collision")


# ---- cross-user: Wave-3.1 IdorCheck same-shape cross-read, bug_class password_reset_cross_user ----

def _cross_finding():
    victim_ref, control_ref = "2", "1"

    def victim_send(req):
        return {"status": 200, "body": _D}

    def attacker_send(req):
        # the cross-user reset token reaches bob's (id=2) private record; the attacker's own object lacks it.
        rid = _req_id(req)
        if rid == victim_ref:
            return _authed(_D)
        return _authed("alice-own-account-0001")

    def nocred_send(req):
        return {"status": 403, "body": _CHROME.format(extra="login required")}

    def unauth_send(req):
        # substantive same-shape 2xx render of the same object WITHOUT bob's private marker (the round-5 proof).
        return _authed("record #2 owner=bob body=(restricted)")

    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://target.test/obj?id=1"))
    point = next(p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "id")
    check = IdorCheck(id="reset-cross-user", ref_param="id", victim_ref=victim_ref, victim_send=victim_send,
                      bug_class="password_reset_cross_user", victim_discriminator=_D, control_ref=control_ref,
                      nocred_send=nocred_send, unauth_send=unauth_send)
    ctx = check.probe(tmpl, point, attacker_send)
    assert ctx is not None, "the sound cross-user reset cross-read did not produce a firing context"
    return access_control_finding(ctx, check_id="reset:password_reset_cross_user:0", insertion_point="query:id")


def _req_id(req: HttpRequest) -> str:
    from urllib.parse import parse_qs, urlsplit
    return (parse_qs(urlsplit(req.url).query).get("id") or [""])[0]


# ============================================================================


def test_the_branches_are_registered_and_classes_map_to_them() -> None:
    assert set(_BRANCH_FOR) == {"password_reset_reuse", "password_reset_collision", "password_reset_cross_user"}
    for cls, branch in _BRANCH_FOR.items():
        assert branch in branch_ids(), f"{branch} not registered"
        assert _redrive_branch_for(cls) == branch
    # spelling variants fold onto the canonical classes
    assert _redrive_branch_for("reset_token_reuse") == "password_reset.token_reuse"
    assert _redrive_branch_for("reset_token_collision") == "password_reset.deterministic_collision"
    assert _redrive_branch_for("cross_user_reset_token") == "password_reset.cross_user_read"
    # host-poisoning folds onto the EXISTING host_header_injection FACT (never duplicated as a reset branch)
    assert _redrive_branch_for("password_reset_host_poisoning") is None or \
        _redrive_branch_for("password_reset_host_poisoning") not in _BRANCH_FOR.values()


def test_reuse_admitted_live_redrive_mints_a_signed_fact() -> None:
    finding = _reuse_finding()
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit("password_reset.token_reuse", fired=True, conclusive=True,
                     observed={"channel_established": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(finding, admitted, engagement_slug="alpha", signers=_signers(),
                           provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.PASSWORD_RESET_INVARIANT.value
    assert res.signed is not None


def test_collision_admitted_live_redrive_mints_a_signed_fact() -> None:
    finding = _collision_finding()
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit("password_reset.deterministic_collision", fired=True, conclusive=True,
                     observed={"channel_established": True})
    res = certify_admitted(finding, admitted, engagement_slug="alpha", signers=_signers(),
                           provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.PASSWORD_RESET_INVARIANT.value


def test_cross_user_reuses_achieved_state_and_mints() -> None:
    finding = _cross_finding()
    assert finding["bug_class"] == "password_reset_cross_user"
    assert OracleVerifier().confirm(finding["oracle_context"]).confirmed
    admitted = admit("password_reset.cross_user_read", fired=True, conclusive=True,
                     observed={"channel_established": True})
    res = certify_admitted(finding, admitted, engagement_slug="alpha", signers=_signers(),
                           provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.ACHIEVED_STATE.value   # cross-user REUSES ACHIEVED_STATE


def test_llm_provenanced_context_is_demoted_to_a_lead() -> None:
    finding = _reuse_finding()
    admitted = admit("password_reset.token_reuse", fired=True, conclusive=True,
                     observed={"channel_established": True})
    res = certify_admitted(finding, admitted, engagement_slug="alpha", signers=_signers(), provenance="llm")
    assert not res.is_fact
    assert res.signed is None


def test_offline_reverify_re_fires_and_rejects_tamper() -> None:
    finding = _reuse_finding()
    finding["confirmed_by"] = OracleKind.PASSWORD_RESET_INVARIANT.value
    finding["confidence"] = 0.92
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False

    # tamper: strip the private datum from the replay-authenticated read -> the differential no longer holds
    octx = finding["oracle_context"]
    rec = dict(octx["password_reset_invariant"])
    rec["authorized_view"] = {"status": 200, "body": _CHROME.format(extra="you are logged out")}
    tampered = {**finding, "oracle_context": {**octx, "password_reset_invariant": rec}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_the_benign_twins_produce_no_firing_context() -> None:
    # single-use / expiring reset token: the replay-set secret never authenticates -> not confirmed.
    reuse_twin = _reuse_ctx(single_use=True)
    assert reuse_twin is not None
    assert not OracleVerifier().confirm(reuse_twin.to_verifier_context()).confirmed
    # distinct-token generator: no deterministic collision -> not confirmed.
    coll_twin = _collision_ctx(deterministic=False)
    assert coll_twin is not None
    assert not OracleVerifier().confirm(coll_twin.to_verifier_context()).confirmed


def test_a_non_firing_reset_probe_is_not_clean_only_inconclusive_or_lead() -> None:
    # These branches may never assert absence: a conclusive non-fire is INCONCLUSIVE, never CLEAN.
    admitted = admit("password_reset.token_reuse", fired=False, conclusive=True,
                     observed={"channel_established": True})
    assert admitted.verdict is Verdict.INCONCLUSIVE
