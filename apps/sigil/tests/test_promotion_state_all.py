"""`PromotionPolicy.state_all()` — the read-only enumeration the UI's "Agent promotions" card lists.

It MUST be the same verified fold `is_promoted` uses, so what the owner sees is exactly what is enforced:
  * a later `revoke` supersedes an earlier `grant` (LWW) — a revoked pair is NOT listed;
  * an unsigned / forged grant (e.g. one a prompt-injected agent wrote via the shared store) is NOT listed
    (fail-closed) — so the card can never over-report the owner's real grants;
  * a wildcard "*" grant is listed as such;
  * every listed pair satisfies `is_promoted` (consistency), and nothing is listed that `is_promoted` denies.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_promotion_state_all.py -q
"""
import itertools
import tempfile

from sigil.governor.promotion import PromotionPolicy
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64


# Strictly-increasing, DETERMINISTIC `issued_at` for each owner-signed GRANT (the anti-replay high-water).
# NEVER time.time(): two grants inside one clock tick would collide and the second would be refused as
# its own replay — a flake that would hide the guard failing.
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _populate(store):
    """The same crafted set as the fold-equivalence test: a live-untouched grant, a grant-then-revoke, a
    revoke-then-regrant, a wildcard grant, and a FORGED unsigned grant that must be ignored."""
    pol = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    pol.grant("SCHOLAR", "draft", issued_at=_iss())      # granted, never touched -> listed
    pol.grant("ARTIFICER", "wire", issued_at=_iss())     # granted then revoked below -> NOT listed
    pol.revoke("TESTER", "code")       # revoked then re-granted below -> listed
    pol.revoke("ARTIFICER", "wire")
    pol.grant("TESTER", "code", issued_at=_iss())
    pol.grant("BASTION", "*", issued_at=_iss())          # wildcard -> listed as "*"
    store.append(kind="event", source="governor", actor="WARDEN",   # forged, unsigned -> must be ignored
                 payload={"signal": "governor.promotion", "state": "granted",
                          "agent": "EVIL", "scope": "draft"})
    return pol


def test_state_all_lists_only_verified_granted():
    store = _store()
    _populate(store)
    pol = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    got = pol.state_all()
    assert got == [
        {"agent": "BASTION", "scope": "*"},
        {"agent": "SCHOLAR", "scope": "draft"},
        {"agent": "TESTER", "scope": "code"},
    ], got
    agents = {r["agent"] for r in got}
    assert "ARTIFICER" not in agents           # revoked (LWW) -> not listed
    assert "EVIL" not in agents                # forged/unsigned -> fail-closed, not listed


def test_state_all_is_consistent_with_is_promoted():
    store = _store()
    _populate(store)
    pol = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    for row in pol.state_all():                # everything listed is actually enforced
        assert pol.is_promoted(row["agent"], row["scope"]) is True
    # and the two that must NOT be listed are also NOT promoted
    assert pol.is_promoted("EVIL", "draft") is False
    assert pol.is_promoted("ARTIFICER", "wire") is False


def test_forged_grant_signed_by_a_foreign_key_is_not_listed():
    # An adversary signs a grant with THEIR OWN key and writes it via the shared store. Under the owner's
    # trusted pubkey it must not verify -> not listed (this is the core anti-forgery property).
    store = _store()
    attacker = generate_keypair()
    PromotionPolicy(store, owner_key=attacker, trusted_pubkey=attacker.public_key_b64).grant("MALICE", "*", issued_at=_iss())
    honest = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    assert honest.state_all() == []
    assert honest.is_promoted("MALICE", "*") is False


def test_snapshot_exposes_promotions_under_the_process_key():
    # dashboard.snapshot() builds PromotionPolicy(store) with the DEFAULT process owner key. Establish that
    # owner identity first (fresh SIGIL_HOME has none -> state_all is correctly []), then grant with the same
    # default key and assert the content flows through; ENVOY (no promotion path) is refused, never listed.
    from sigil.dashboard import snapshot
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()                     # anchor the owner key so owner_keypair()==owner_pubkey()
    store = _store()
    pol = PromotionPolicy(store)               # default = the process owner key snapshot() also uses
    pol.grant("ARCHIVIST", "draft", issued_at=_iss())
    pol.grant("ENVOY", "*", issued_at=_iss())                     # structurally refused -> must not appear
    snap = snapshot(store)
    assert isinstance(snap.get("promotions"), list)
    assert {"agent": "ARCHIVIST", "scope": "draft"} in snap["promotions"]
    assert not any(r["agent"] == "ENVOY" for r in snap["promotions"])


def test_snapshot_promotions_shape_on_a_fresh_home():
    # Shape contract regardless of owner-identity state: `promotions` is always a list, never a raise (the
    # dashboard fail-softs). On a store with no verified grants it is empty — fail-closed, never fabricated.
    from sigil.dashboard import snapshot
    snap = snapshot(_store())
    assert isinstance(snap.get("promotions"), list)


def test_a_signed_denylisted_grant_is_not_listed_and_not_enforced():
    # The REAL negative control for the NO_PROMOTION denylist (red-pen #1): craft a genuinely OWNER-SIGNED
    # grant for a denylisted agent DIRECTLY (bypassing grant()'s mint-time refusal), then assert state_all
    # mirrors is_promoted — the grant verifies, but neither lists nor enforces it. This is the "mint gate must
    # be mirrored at the read surface" invariant: a currently-promotable agent later ADDED to the denylist
    # must not become a phantom card row.
    from sigil.governor.authn import signed_payload
    from sigil.governor.promotion import NO_PROMOTION_AGENTS, SIGNAL
    store = _store()
    for agent in sorted(NO_PROMOTION_AGENTS):
        core = {"signal": SIGNAL, "state": "granted", "agent": agent, "scope": "*", "issued_at": _iss()}
        payload = {**signed_payload(core, OWNER), "by": "owner", "tier": "A0", "decision": "auto"}
        store.append(kind="event", source="governor", actor="WARDEN", payload=payload)   # a REAL signed grant
    pol = PromotionPolicy(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)
    listed = {r["agent"] for r in pol.state_all()}
    for agent in NO_PROMOTION_AGENTS:
        assert agent not in listed, f"{agent} is denylisted — state_all must not list its signed grant"
        assert pol.is_promoted(agent, "*") is False       # and it is not enforced either (consistency)
    assert pol.state_all() == []                          # nothing but denylisted grants -> empty


def test_broker_reports_error_on_a_refused_promote():
    # red-pen #2: a refused promote must NOT read as success. The broker returns ok:False WITH an explicit
    # error (so the UI's r.error path shows the refusal, not a false "Promoted" toast). A legit promote has
    # no error; revoke always records.
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.actions import do_action
    ensure_owner_keypair()
    store = _store()
    refused = do_action("promote", {"agent": "ENVOY", "scope": "*"}, store=store)
    assert refused["ok"] is False and refused.get("recorded_seq") is None
    assert "error" in refused and "ENVOY" in refused["error"]
    ok = do_action("promote", {"agent": "ARCHIVIST", "scope": "draft"}, store=store)
    assert ok["ok"] is True and "error" not in ok
