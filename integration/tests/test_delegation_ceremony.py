"""S7b — the owner-tie ceremony wired end-to-end (offense export → owner mint → offense verify).

Proves the loop the S4/S5/S7a primitives were built for now actually CLOSES: `vigil identity` exports the
offense side's stable spine pubkey (public data only), the OWNER mints an offense-spine delegation over it
(what `sigil delegate-offense` does, via the same vigil_core primitive), and `vigil verify` consumes it so a
real offense spine verifies as OWNER-ROOTED. Without the ceremony (no delegation) the same spine is only
integrity-checkable, not owner-rooted — the honest baseline.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_delegation_ceremony.py -q
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.delegation import OFFENSE_SPINE_ROLE, sign_delegation
from vigil_integration.agent.state import AgentState, Finding, Phase
from vigil_integration.cli import _cmd_identity
from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
from vigil_integration.live.spine_verify import VERIFIED, verify_offense_spine
from vigil_integration.live.spine_vigilcore import VigilCoreSpine

NOW = 1000
NOT_AFTER = 9_999_999_999
SCOPE = "loopback"


def _write_spine(base, spine_kp):
    sp = VigilCoreSpine(spine_kp, str(base / f"{SCOPE}.spine"))
    st = AgentState(engagement_slug=SCOPE, phase=Phase.EXPLOITATION, iteration=0, objective="own the box")
    st.record_fact(Finding(ref="f0", bug_class="sqli", title="auth bypass", severity="critical"),
                   evidence_ref="cert:evi-0")
    sp.write_state(st, seq=0, engagement=SCOPE)


def test_identity_export_is_public_only(tmp_path):
    base = tmp_path / "home"
    _cmd_identity(SimpleNamespace(base_dir=str(base)))
    identity = json.loads((base / "offense-identity.json").read_text())
    assert identity["schema"] == 1
    assert identity["spine"]["key_id"] == "offense-spine"
    # PUBLIC keys only — a private key must NEVER appear in the exported identity
    blob = (base / "offense-identity.json").read_text()
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE))
    assert kp.public_key_b64 in blob
    assert kp.private_key_b64 not in blob


def test_ceremony_round_trips_to_owner_rooted(tmp_path):
    base = tmp_path / "home"
    # 1. offense exports its stable identity (creates the stable keys under base_dir)
    _cmd_identity(SimpleNamespace(base_dir=str(base)))
    identity = json.loads((base / "offense-identity.json").read_text())
    # the exported spine pubkey is the SAME stable key that will sign the spine
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE))
    assert spine_kp.public_key_b64 == identity["spine"]["public_key_b64"]
    _write_spine(base, spine_kp)
    # 2. the OWNER mints an offense-spine delegation over the EXPORTED pubkey (== `sigil delegate-offense`)
    owner = generate_keypair()
    sp = identity["spine"]
    cert = sign_delegation(owner, role=OFFENSE_SPINE_ROLE, scope=SCOPE, threshold=1, not_after=NOT_AFTER,
                           authorizers=[AuthorizerKey(key_id=sp["key_id"], name=sp["key_id"],
                                                      public_key_b64=sp["public_key_b64"])])
    # 3. the offense side consumes it → OWNER-ROOTED
    v = verify_offense_spine(spine_path=str(base / f"{SCOPE}.spine"), owner_pubkey=owner.public_key_b64,
                             delegation=cert, now=NOW, scope=SCOPE)
    assert v.status == VERIFIED and v.owner_rooted is True


def test_without_the_ceremony_the_spine_is_not_owner_rooted(tmp_path):
    # the honest baseline: no owner delegation supplied → integrity-only at best, never owner-rooted
    base = tmp_path / "home"
    _cmd_identity(SimpleNamespace(base_dir=str(base)))
    spine_kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE))
    _write_spine(base, spine_kp)
    v = verify_offense_spine(spine_path=str(base / f"{SCOPE}.spine"), spine_pubkey=spine_kp.public_key_b64)
    assert v.status == VERIFIED and v.owner_rooted is False
