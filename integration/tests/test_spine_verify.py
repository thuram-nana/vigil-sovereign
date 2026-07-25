"""S5b — the boundary-safe, public-key-only offense-spine verifier (`live.spine_verify`).

Proves the owner tie is established ONLY by consuming a valid owner-signed OFFENSE_SPINE_ROLE delegation (the
role's first live consumer): a spine signed by an owner-DELEGATED key verifies as owner-rooted; a wrong-owner
/ expired / wrong-key delegation or a tampered spine fails; without a delegation the audit is integrity-only
(NOT owner-rooted); and the verifier NEVER mutates the file it audits (read-only — no torn-tail repair).

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_spine_verify.py -q
"""
from __future__ import annotations

from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.delegation import OFFENSE_SPINE_ROLE, sign_delegation
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.live.spine_verify import (
    ABSENT,
    FAILED,
    UNVERIFIABLE,
    VERIFIED,
    verify_offense_home,
    verify_offense_spine,
)
from vigil_integration.live.spine_vigilcore import VigilCoreSpine

OWNER = generate_keypair()
SPINE_KP = generate_keypair()
SPINE_AUTH = AuthorizerKey(key_id="offense-spine-0", name="offense-spine-0",
                           public_key_b64=SPINE_KP.public_key_b64)
NOW, NOT_AFTER = 1000, 2000
SCOPE = "loopback"


def _write_spine(path, kp=SPINE_KP, n=3):
    spine = VigilCoreSpine(kp, str(path))
    for i in range(n):
        st = AgentState(engagement_slug=SCOPE, phase=Phase.EXPLOITATION, iteration=i, objective="own the box")
        st.record_fact(Finding(ref=f"f-{i}", bug_class="sqli", title="auth bypass", severity="critical"),
                       evidence_ref=f"cert:evi-{i}")
        spine.write_state(st, seq=i, engagement=SCOPE)
    return str(path)


def _delegation(*, owner=OWNER, authorizers=(SPINE_AUTH,), scope=SCOPE, not_after=NOT_AFTER):
    return sign_delegation(owner, role=OFFENSE_SPINE_ROLE, scope=scope,
                           authorizers=list(authorizers), threshold=1, not_after=not_after)


def test_spine_under_an_owner_delegated_key_is_owner_rooted(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=_delegation(), now=NOW, scope=SCOPE)
    assert v.status == VERIFIED and v.owner_rooted is True


def test_wrong_owner_delegation_fails(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp, owner_pubkey=generate_keypair().public_key_b64,
                             delegation=_delegation(), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False and "delegation invalid" in v.detail


def test_expired_delegation_fails(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=_delegation(not_after=NOT_AFTER), now=NOT_AFTER + 1, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_delegation_for_a_different_key_fails(tmp_path):
    # The owner delegated a DIFFERENT offense-spine key; the spine (signed by SPINE_KP) must NOT verify under
    # it — a delegation for key A cannot bless a spine signed by key B.
    sp = _write_spine(tmp_path / "loopback.spine")
    other = generate_keypair()
    other_auth = AuthorizerKey(key_id="other", name="other", public_key_b64=other.public_key_b64)
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=_delegation(authorizers=(other_auth,)), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_tampered_spine_fails_under_a_valid_delegation(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    data = (tmp_path / "loopback.spine").read_text().splitlines()
    data[0] = data[0].replace("auth bypass", "auth bypass TAMPERED")   # mutate a signed record
    (tmp_path / "loopback.spine").write_text("\n".join(data) + "\n")
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=_delegation(), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_no_delegation_pinned_key_is_integrity_only(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp, spine_pubkey=SPINE_KP.public_key_b64)
    assert v.status == VERIFIED and v.owner_rooted is False      # verified, but NO owner tie proven
    assert "INTEGRITY ONLY" in v.detail


def test_no_delegation_no_key_is_unverifiable(tmp_path):
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp)
    assert v.status == UNVERIFIABLE and v.owner_rooted is False


def test_missing_clock_fails_closed_not_open(tmp_path):
    # HIGH fix: without a trusted `now`, the delegation's expiry cannot be checked → fail-CLOSED (never map a
    # missing clock to 0 = valid-forever, which would silently disable the bearer cert's only revocation bound).
    sp = _write_spine(tmp_path / "loopback.spine")
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=_delegation(), now=None, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False and "trusted clock" in v.detail
    # and an EXPIRED delegation is genuinely refused when now IS supplied (the check is live, not vacuous)
    v2 = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                              delegation=_delegation(not_after=5), now=NOW, scope=SCOPE)
    assert v2.status == FAILED


def test_threshold_gt_1_spine_delegation_is_refused(tmp_path):
    # MED fix: the offense spine is SINGLE-SIGNER, so a threshold>1 delegation is unsatisfiable and must NOT
    # be silently downgraded to 1-of-n. Hand-craft a 2-of-2 (delegate_offense_spine now forces threshold=1).
    sp = _write_spine(tmp_path / "loopback.spine")
    k2 = generate_keypair()
    two_of_two = sign_delegation(
        OWNER, role=OFFENSE_SPINE_ROLE, scope=SCOPE, threshold=2, not_after=NOT_AFTER,
        authorizers=[SPINE_AUTH, AuthorizerKey(key_id="k2", name="k2", public_key_b64=k2.public_key_b64)])
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=two_of_two, now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False and "single-signer" in v.detail


def test_one_of_n_rotation_stays_owner_rooted(tmp_path):
    # threshold=1 over MULTIPLE authorizers (key rotation: an old + current spine key both blessed) is the
    # intended shape and stays owner-rooted — the spine verifies under whichever delegated key signed it.
    sp = _write_spine(tmp_path / "loopback.spine")
    old = generate_keypair()   # a rotated-out key, still owner-blessed
    one_of_two = sign_delegation(
        OWNER, role=OFFENSE_SPINE_ROLE, scope=SCOPE, threshold=1, not_after=NOT_AFTER,
        authorizers=[AuthorizerKey(key_id="old", name="old", public_key_b64=old.public_key_b64), SPINE_AUTH])
    v = verify_offense_spine(spine_path=sp, owner_pubkey=OWNER.public_key_b64,
                             delegation=one_of_two, now=NOW, scope=SCOPE)
    assert v.status == VERIFIED and v.owner_rooted is True


def test_absent_spine_is_absent_not_failed(tmp_path):
    v = verify_offense_spine(spine_path=str(tmp_path / "nope.spine"),
                             owner_pubkey=OWNER.public_key_b64, delegation=_delegation(), now=NOW, scope=SCOPE)
    assert v.status == ABSENT and v.owner_rooted is False


def test_verifier_never_mutates_the_file_it_audits(tmp_path):
    # A read-only audit must NOT repair a torn tail (it does not own the file). The bytes must be identical
    # before and after — including the partial trailing line.
    p = tmp_path / "loopback.spine"
    _write_spine(p)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write('{"partial": "torn')          # a torn tail, no newline
    before = p.read_bytes()
    verify_offense_spine(spine_path=str(p), spine_pubkey=SPINE_KP.public_key_b64)
    assert p.read_bytes() == before             # untouched — no torn-tail repair on the audit path


def test_home_view_reports_every_segment(tmp_path):
    _write_spine(tmp_path / "loopback.spine")
    verdicts = {v.segment: v for v in verify_offense_home(
        str(tmp_path), owner_pubkey=OWNER.public_key_b64, delegation=_delegation(), now=NOW, scope=SCOPE)}
    assert verdicts["offense-spine"].status == VERIFIED and verdicts["offense-spine"].owner_rooted
    assert verdicts["offense-usage-ledger"].status == ABSENT           # no ledger written in this test
    # the DB-projection is honestly unverifiable by a byte-reader, never claimed verified
    assert verdicts["crucible-blackboard-chain"].status == UNVERIFIABLE
