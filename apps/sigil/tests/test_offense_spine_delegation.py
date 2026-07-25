"""S5 — the owner-side issuer for the stable offense-spine identity delegation.

`delegate_offense_spine` lets the owner (holder of the sovereign key) mint a DelegationCert authorizing the
stable offense-spine pubkey under OFFENSE_SPINE_ROLE, so a verifier can chain an offense spine head back to
the owner. Proves the wrapper wires the right role and produces a cert that verifies for the spine role and
refuses under the governance role.

Run: pytest apps/sigil/tests/test_offense_spine_delegation.py -q
"""
import pytest

from sigil.governor.identity import delegate_offense_governance, delegate_offense_spine
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core.delegation import (
    OFFENSE_GOVERNANCE_ROLE,
    OFFENSE_SPINE_ROLE,
    DelegationError,
    verify_delegation,
)

OWNER = generate_keypair()
SPINE = generate_keypair()
SPINE_AUTH = AuthorizerKey(key_id="offense-spine-0", name="offense-spine-0",
                           public_key_b64=SPINE.public_key_b64)
NOW, NOT_AFTER = 1000, 2000


def test_owner_delegates_the_spine_identity_and_it_verifies():
    cert = delegate_offense_spine(OWNER, authorizers=[SPINE_AUTH], scope="loopback", not_after=NOT_AFTER)
    root = verify_delegation(cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                             role=OFFENSE_SPINE_ROLE, scope="loopback")
    assert root.threshold == 1
    assert root.authorizers[0].public_key_b64 == SPINE.public_key_b64


def test_spine_delegation_threshold_is_fixed_at_one():
    # The offense spine is single-signer; delegate_offense_spine FIXES threshold=1 (1-of-n over multiple
    # authorizers = key rotation), so an owner cannot mint an unsatisfiable threshold>1 spine delegation.
    other = generate_keypair()
    cert = delegate_offense_spine(
        OWNER, authorizers=[SPINE_AUTH, AuthorizerKey(key_id="k2", name="k2",
                                                      public_key_b64=other.public_key_b64)],
        scope="loopback", not_after=NOT_AFTER)
    assert cert.threshold == 1


def test_a_spine_delegation_does_not_authorize_governance():
    spine_cert = delegate_offense_spine(OWNER, authorizers=[SPINE_AUTH], scope="loopback", not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="role"):
        verify_delegation(spine_cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                          role=OFFENSE_GOVERNANCE_ROLE, scope="loopback")


def test_a_governance_delegation_does_not_authorize_the_spine():
    gov_cert = delegate_offense_governance(OWNER, authorizers=[SPINE_AUTH], threshold=1,
                                           scope="loopback", not_after=NOT_AFTER)
    with pytest.raises(DelegationError, match="role"):
        verify_delegation(gov_cert, trusted_owner_pubkey=OWNER.public_key_b64, now=NOW,
                          role=OFFENSE_SPINE_ROLE, scope="loopback")


def test_cmd_delegate_offense_mints_valid_owner_signed_certs(tmp_path, monkeypatch):
    """S7b sovereign half: `sigil delegate-offense` reads an offense-identity.json and writes owner-signed
    offense-spine + offense-governance delegations that verify under the owner key. HERMETIC: the owner-key
    accessors are monkeypatched to a throwaway keypair, so this NEVER touches the real ~/.sigil owner key
    regardless of SIGIL_HOME (cmd_delegate_offense imports them at call time, so the patch takes effect)."""
    import json
    from types import SimpleNamespace

    import sigil.governor.identity as gid
    from sigil.cli import cmd_delegate_offense
    test_owner = generate_keypair()
    monkeypatch.setattr(gid, "ensure_owner_keypair", lambda: test_owner)
    monkeypatch.setattr(gid, "owner_pubkey", lambda: test_owner.public_key_b64)

    gov = generate_keypair()
    idf = tmp_path / "offense-identity.json"
    idf.write_text(json.dumps({
        "schema": 1,
        "spine": {"key_id": "offense-spine", "public_key_b64": SPINE.public_key_b64},
        "governance": {"key_id": "root0", "public_key_b64": gov.public_key_b64},
    }), encoding="utf-8")
    cmd_delegate_offense(SimpleNamespace(offense_identity=str(idf), scope="loopback", hours="24", out_dir=""))

    from vigil_core.delegation import DelegationCert
    spine_cert = DelegationCert.model_validate_json((tmp_path / "offense-spine.deleg.json").read_text())
    gov_cert = DelegationCert.model_validate_json((tmp_path / "offense-governance.deleg.json").read_text())
    # both verify under the (test) owner key for their respective roles, over the exported pubkeys
    sroot = verify_delegation(spine_cert, trusted_owner_pubkey=test_owner.public_key_b64, now=NOW,
                              role=OFFENSE_SPINE_ROLE, scope="loopback")
    groot = verify_delegation(gov_cert, trusted_owner_pubkey=test_owner.public_key_b64, now=NOW,
                              role=OFFENSE_GOVERNANCE_ROLE, scope="loopback")
    assert sroot.authorizers[0].public_key_b64 == SPINE.public_key_b64
    assert groot.authorizers[0].public_key_b64 == gov.public_key_b64
    assert sroot.threshold == 1 and groot.threshold == 1


def test_cmd_delegate_offense_refuses_bad_hours_and_schema(tmp_path, monkeypatch, capsys):
    """NIT fixes: --hours must be finite/positive (no int(inf) crash), and an unsupported identity schema is
    refused — both fail closed (no cert written)."""
    import json
    from types import SimpleNamespace

    import sigil.governor.identity as gid
    from sigil.cli import cmd_delegate_offense
    monkeypatch.setattr(gid, "ensure_owner_keypair", lambda: OWNER)
    monkeypatch.setattr(gid, "owner_pubkey", lambda: OWNER.public_key_b64)
    good = {"schema": 1, "spine": {"key_id": "offense-spine", "public_key_b64": SPINE.public_key_b64},
            "governance": {"key_id": "root0", "public_key_b64": generate_keypair().public_key_b64}}
    idf = tmp_path / "id.json"

    for bad_hours in ("1e400", "-5", "abc"):
        idf.write_text(json.dumps(good))
        cmd_delegate_offense(SimpleNamespace(offense_identity=str(idf), scope="loopback",
                                             hours=bad_hours, out_dir=""))
        assert "refusing" in capsys.readouterr().out.lower()
        assert not (tmp_path / "offense-spine.deleg.json").exists()   # fail-closed: no cert written

    idf.write_text(json.dumps({**good, "schema": 2}))
    cmd_delegate_offense(SimpleNamespace(offense_identity=str(idf), scope="loopback", hours="24", out_dir=""))
    assert "unsupported offense-identity schema" in capsys.readouterr().out
    assert not (tmp_path / "offense-spine.deleg.json").exists()
