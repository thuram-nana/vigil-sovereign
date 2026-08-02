"""S5b — the boundary-safe, public-key-only offense-spine verifier (`live.spine_verify`).

Proves the owner tie is established ONLY by consuming a valid owner-signed OFFENSE_SPINE_ROLE delegation (the
role's first live consumer): a spine signed by an owner-DELEGATED key verifies as owner-rooted; a wrong-owner
/ expired / wrong-key delegation or a tampered spine fails; without a delegation the audit is integrity-only
(NOT owner-rooted); and the verifier NEVER mutates the file it audits (read-only — no torn-tail repair).

Also covers T3 — the PERSISTED CRUCIBLE blackboard chain: a live-engage-style persist writes it as inert
governance-signed bytes and a PUBLIC-KEYS-ONLY offline verify (under an owner-signed OFFENSE_GOVERNANCE_ROLE
delegation) is owner-rooted; a tampered entry/head, wrong owner, expired/wrong-role delegation, missing clock,
or cross-engagement head each fails closed. (The blackboard round-trip builds a real blackboard, so this
suite needs the framework on the path.)

Run: PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_spine_verify.py -q
"""
from __future__ import annotations

from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.delegation import OFFENSE_GOVERNANCE_ROLE, OFFENSE_SPINE_ROLE, sign_delegation
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.live.spine_verify import (
    ABSENT,
    BLACKBOARD_CHAIN_FILE,
    BLACKBOARD_HEAD_FILE,
    FAILED,
    UNVERIFIABLE,
    VERIFIED,
    verify_blackboard_chain,
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

# --- T3: the persisted CRUCIBLE blackboard chain (governance-signed head + entry-digest chain) ------
GOV_KP = generate_keypair()
GOV_KEY_ID = "root0"   # the anchor-1 governance signer key_id (wiring.DEFAULT_KEY_ID) the head signs under
GOV_AUTH = AuthorizerKey(key_id=GOV_KEY_ID, name=GOV_KEY_ID, public_key_b64=GOV_KP.public_key_b64)


def _gov_delegation(*, owner=OWNER, authorizers=(GOV_AUTH,), scope=SCOPE, not_after=NOT_AFTER, threshold=1):
    return sign_delegation(owner, role=OFFENSE_GOVERNANCE_ROLE, scope=scope,
                           authorizers=list(authorizers), threshold=threshold, not_after=not_after)


def _persist_blackboard(base_dir, monkeypatch, *, slug=SCOPE, n=3, signers=None):
    """Seed an ISOLATED blackboard for ``slug`` with ``n`` events and persist its chain through the REAL
    live.wiring._persist_blackboard_chain (monkeypatching open_blackboard onto a tmp DB). Returns
    (head_path, chain_path)."""
    from framework.v2.agents import blackboard as bb_mod
    from vigil_integration.live.wiring import _persist_blackboard_chain
    db = base_dir / "bb.sqlite"
    seed = bb_mod.Blackboard(db_path=db)
    seed.engagement_id(slug)
    for i in range(n):
        seed.post(engagement=slug, kind="observation", agent_name="a",
                  payload={"source": "s", "surface": "p", "summary": f"e{i}"})
    seed.close()
    monkeypatch.setattr(bb_mod, "open_blackboard", lambda **_kw: bb_mod.Blackboard(db_path=db))
    _persist_blackboard_chain(str(base_dir), slug, signers or [(GOV_KEY_ID, GOV_KP.private_key_b64)])
    return str(base_dir / BLACKBOARD_HEAD_FILE), str(base_dir / BLACKBOARD_CHAIN_FILE)


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
    # T3: with NO persisted blackboard artifacts (this test writes only a spine), the segment is honestly
    # UNVERIFIABLE — because there is nothing to read, NOT because it is forever DB-only.
    assert verdicts["crucible-blackboard-chain"].status == UNVERIFIABLE
    assert verdicts["crucible-blackboard-chain"].owner_rooted is False


# --- T3: persisted CRUCIBLE blackboard chain — round trip + fail-closed axes ------------------------


def test_blackboard_chain_round_trips_to_owner_rooted(tmp_path, monkeypatch):
    # A live-engage-style persist (via the REAL wiring._persist_blackboard_chain) writes the chain as inert
    # bytes; a PUBLIC-KEYS-ONLY offline verify under an owner-signed OFFENSE_GOVERNANCE_ROLE delegation
    # succeeds and is owner-rooted (no DB, no framework, only the owner PUBLIC key + the persisted files).
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    import os
    assert os.path.exists(head_p) and os.path.exists(chain_p)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(), now=NOW, scope=SCOPE, slug=SCOPE)
    assert v.status == VERIFIED and v.owner_rooted is True
    assert "owner-rooted via OFFENSE_GOVERNANCE_ROLE" in v.detail


def test_blackboard_chain_absent_is_unverifiable(tmp_path):
    # No persisted artifacts → honest UNVERIFIABLE (never a fake pass), even with a valid delegation + owner.
    v = verify_blackboard_chain(
        head_path=str(tmp_path / BLACKBOARD_HEAD_FILE), chain_path=str(tmp_path / BLACKBOARD_CHAIN_FILE),
        owner_pubkey=OWNER.public_key_b64, delegation=_gov_delegation(), now=NOW, scope=SCOPE)
    assert v.status == UNVERIFIABLE and v.owner_rooted is False


def test_blackboard_chain_present_but_no_delegation_is_unverifiable(tmp_path, monkeypatch):
    # Artifacts present but NO governance delegation → the owner tie cannot be established (the head names its
    # signer only by key_id) → honest UNVERIFIABLE, never a fake integrity pass.
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=None, now=NOW, scope=SCOPE)
    assert v.status == UNVERIFIABLE and v.owner_rooted is False


def test_blackboard_chain_tampered_entry_fails(tmp_path, monkeypatch):
    import json
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    entries = json.loads(open(chain_p, encoding="utf-8").read())
    entries[0]["cert_digest"] = "de" * 32          # mutate a signed entry digest (raw-file edit)
    open(chain_p, "w", encoding="utf-8").write(json.dumps(entries))
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_blackboard_chain_tampered_head_fails(tmp_path, monkeypatch):
    import json
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    head = json.loads(open(head_p, encoding="utf-8").read())
    head["last_seq"] = int(head["last_seq"]) + 5    # rewrite the signed head so it no longer binds the chain
    open(head_p, "w", encoding="utf-8").write(json.dumps(head))
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_blackboard_chain_wrong_owner_fails(tmp_path, monkeypatch):
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p,
                                owner_pubkey=generate_keypair().public_key_b64,
                                delegation=_gov_delegation(), now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False and "delegation invalid" in v.detail


def test_blackboard_chain_expired_delegation_fails(tmp_path, monkeypatch):
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(not_after=NOT_AFTER), now=NOT_AFTER + 1, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_blackboard_chain_wrong_role_delegation_fails(tmp_path, monkeypatch):
    # A delegation for the OFFENSE_SPINE_ROLE must NOT root the governance-signed blackboard head.
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    spine_role_deleg = sign_delegation(OWNER, role=OFFENSE_SPINE_ROLE, scope=SCOPE, threshold=1,
                                       not_after=NOT_AFTER, authorizers=[GOV_AUTH])
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=spine_role_deleg, now=NOW, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False


def test_blackboard_chain_missing_clock_fails_closed(tmp_path, monkeypatch):
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(), now=None, scope=SCOPE)
    assert v.status == FAILED and v.owner_rooted is False and "trusted clock" in v.detail


def test_blackboard_chain_cross_engagement_head_is_refused(tmp_path, monkeypatch):
    # The head is anchored to SCOPE; asking to verify it as a DIFFERENT engagement slug is refused.
    head_p, chain_p = _persist_blackboard(tmp_path, monkeypatch)
    v = verify_blackboard_chain(head_path=head_p, chain_path=chain_p, owner_pubkey=OWNER.public_key_b64,
                                delegation=_gov_delegation(scope="*"), now=NOW, scope="*", slug="other-engagement")
    assert v.status == FAILED and v.owner_rooted is False and "cross-engagement" in v.detail


def test_home_view_blackboard_owner_rooted_when_artifacts_present(tmp_path, monkeypatch):
    # The integrated home view: with a persisted blackboard chain + BOTH delegations, the blackboard segment
    # is now owner-rooted (item 3: the hard-coded UNVERIFIABLE verdict is replaced by a real verify).
    _write_spine(tmp_path / "loopback.spine")
    _persist_blackboard(tmp_path, monkeypatch)
    verdicts = {v.segment: v for v in verify_offense_home(
        str(tmp_path), owner_pubkey=OWNER.public_key_b64, delegation=_delegation(),
        governance_delegation=_gov_delegation(), now=NOW, scope=SCOPE, slug=SCOPE)}
    assert verdicts["offense-spine"].status == VERIFIED and verdicts["offense-spine"].owner_rooted
    bb = verdicts["crucible-blackboard-chain"]
    assert bb.status == VERIFIED and bb.owner_rooted is True
