"""SIGIL Phase 9 W1-E — the PC-side mesh pairing CLI: authorize / revoke / list phone device keys.
Authorizations are owner-signed via the persisted owner identity. Driven through the module-level
helpers `cmd_mesh` delegates to, over a temp spine (no real ~/.sigil writes).
Run: ~/.sigil/venv/bin/python tests/test_cli_mesh.py"""
import tempfile

from sigil.cli import _device_fingerprint, _mesh_authorize, _mesh_list, _mesh_revoke
from sigil.mesh import authorized_devices
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
DEV = generate_keypair()


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


# ---- authorize / revoke round-trip ---------------------------------------------------------------
def test_authorize_adds_the_device_key():
    s = _store()
    _mesh_authorize(s, "phone1", DEV.public_key_b64, OWNER, assume_yes=True)
    assert DEV.public_key_b64 in authorized_devices(s, OP), "an owner-signed authorize adds the device key"


def test_revoke_removes_the_device_key():
    s = _store()
    _mesh_authorize(s, "phone1", DEV.public_key_b64, OWNER, assume_yes=True)
    assert DEV.public_key_b64 in authorized_devices(s, OP)
    _mesh_revoke(s, "phone1", DEV.public_key_b64, OWNER)
    assert DEV.public_key_b64 not in authorized_devices(s, OP), "a later owner-signed revoke removes it"


# ---- the fingerprint confirmation gate -----------------------------------------------------------
def test_authorize_aborts_when_fingerprint_not_confirmed():
    s = _store()
    seq = _mesh_authorize(s, "phone1", DEV.public_key_b64, OWNER, confirm=lambda _p: "no")
    assert seq is None and DEV.public_key_b64 not in authorized_devices(s, OP), \
        "authorize aborts (writes nothing) unless the operator confirms the fingerprint"


def test_authorize_proceeds_when_fingerprint_confirmed():
    s = _store()
    seq = _mesh_authorize(s, "phone1", DEV.public_key_b64, OWNER, confirm=lambda _p: "yes")
    assert seq is not None and DEV.public_key_b64 in authorized_devices(s, OP), \
        "authorize proceeds once the operator confirms the fingerprint with 'yes'"


# ---- the device fingerprint (PC and phone must agree) --------------------------------------------
def test_fingerprint_is_deterministic_and_grouped():
    a = _device_fingerprint(DEV.public_key_b64)
    assert a == _device_fingerprint(DEV.public_key_b64), "the fingerprint is deterministic for a given pubkey"
    assert a != _device_fingerprint(generate_keypair().public_key_b64), "different pubkeys → different fingerprints"
    groups = a.split("-")
    assert len(groups) == 4 and all(len(g) == 4 for g in groups), "fingerprint is 4 groups of 4 hex chars"
    assert all(c in "0123456789abcdef" for c in a.replace("-", "")), "fingerprint is lowercase hex"


# ---- list-devices reflects the authorized set ----------------------------------------------------
def test_list_reflects_authorized_set_after_revoke():
    s = _store()
    other = generate_keypair()
    _mesh_authorize(s, "phone1", DEV.public_key_b64, OWNER, assume_yes=True)
    _mesh_authorize(s, "phone2", other.public_key_b64, OWNER, assume_yes=True)
    _mesh_revoke(s, "phone1", DEV.public_key_b64, OWNER)
    listed = _mesh_list(s, OP)
    assert other.public_key_b64 in listed and DEV.public_key_b64 not in listed, \
        "_mesh_list returns the currently-authorized set (post-revoke)"


# ---- doctrine: only the OWNER key can authorize (fail-closed) ------------------------------------
def test_authorization_not_signed_by_owner_is_ignored():
    s = _store()
    attacker = generate_keypair()
    _mesh_authorize(s, "evil", DEV.public_key_b64, attacker, assume_yes=True)  # signed by attacker, not OWNER
    assert DEV.public_key_b64 not in authorized_devices(s, OP), \
        "an authorization not signed by the owner key is not owner-minted — ignored"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-9 W1-E (mesh pairing CLI) guarantees hold")
