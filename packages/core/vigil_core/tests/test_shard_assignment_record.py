"""Front C S2a — the shard-assignment seam contract (the sovereign mints, the keyless routing edge verifies).

Load-bearing invariants (a false-green would let a forged assignment route a tenant, let an epoch be rolled back
without the owner, or let a shard-assignment signature REPLAY as another capability):
  * an owner-signed assignment round-trips under the owner trust root;
  * a tamper of ANY committed field (tenant / shard / epoch / issued_at) breaks the signature;
  * epoch is INSIDE the signed bytes: two epochs sign DIFFERENT bytes (no silent epoch roll-back);
  * CAPABILITY SEPARATION is cryptographic: a shard-assignment signature does NOT verify as a monitoring or
    connected-repo capability (distinct domain tag) and vice-versa;
  * a wrong-key signature is refused; a quorum-collapsing trust root (duplicate pubkeys) is refused;
  * verify is fail-closed and never raises (malformed signature material -> (False, reason));
  * tenant_id / shard_id must be SAFE single path components (no traversal), and the replicated _TENANT_RE is in
    lockstep with the engine's canonical literal (mirror-drift guard, FATAL-2: read as text, never imported).
"""
from __future__ import annotations

import pathlib
import re

import pytest
import vigil_core.shard_assignment_record as sar
from vigil_core import (
    AuthorizerKey, ConnectedRepoRecord, ShardAssignmentRecord, SignedShardAssignmentRecord, TrustRoot,
    check_tenant_component, connected_repo_signing_bytes, generate_keypair, shard_assignment_signing_bytes,
    sign_connected_repo_record, sign_shard_assignment_record, verify_connected_repo_record,
    verify_shard_assignment_record,
)
from vigil_core.models import Signature
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
ATTACKER = generate_keypair()


def _owner_root():
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=OWNER.public_key_b64)])


def _rec(**over):
    base = dict(tenant_id="acme", shard_id="shard01", epoch=1, issued_at=1.0)
    base.update(over)
    return ShardAssignmentRecord(**base)


def _signed(**over):
    return sign_shard_assignment_record(_rec(**over), {"owner": OWNER.private_key_b64})


def test_owner_signed_assignment_roundtrips():
    ok, reason = verify_shard_assignment_record(_signed(), _owner_root())
    assert ok, reason


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "globex"), ("shard_id", "shard99"), ("epoch", 7), ("issued_at", 999.0)])
def test_a_tamper_of_any_committed_field_breaks_the_signature(field, value):
    signed = _signed()
    tampered = SignedShardAssignmentRecord(
        document=signed.document.model_copy(update={field: value}), signatures=signed.signatures)
    ok, _ = verify_shard_assignment_record(tampered, _owner_root())
    assert not ok, f"tampering {field} must break the signature"


def test_epoch_is_inside_the_signed_bytes():
    assert shard_assignment_signing_bytes(_rec(epoch=1)) != shard_assignment_signing_bytes(_rec(epoch=2))


def test_a_shard_assignment_signature_does_not_verify_as_connected_repo():
    # A signature over the shard-assignment domain must not satisfy a connected-repo verify (distinct domain tag).
    repo = ConnectedRepoRecord(org_id="acme", installation_id=1, repo="github.com/acme/widgets", issued_at=1.0)
    # Hand the connected-repo verifier a signature actually made over the shard-assignment bytes:
    from vigil_core.crypto import sign as _sign
    forged = type(sign_connected_repo_record(repo, {"owner": OWNER.private_key_b64}))(
        document=repo,
        signatures=[Signature(key_id="owner", signature_b64=_sign(OWNER.private_key_b64, shard_assignment_signing_bytes(_rec())))])
    ok, _ = verify_connected_repo_record(forged, _owner_root())
    assert not ok, "a shard-assignment signature must not verify as a connected-repo record"


def test_a_connected_repo_signature_does_not_verify_as_shard_assignment():
    from vigil_core.crypto import sign as _sign
    repo = ConnectedRepoRecord(org_id="acme", installation_id=1, repo="github.com/acme/widgets", issued_at=1.0)
    forged = SignedShardAssignmentRecord(
        document=_rec(),
        signatures=[Signature(key_id="owner", signature_b64=_sign(OWNER.private_key_b64, connected_repo_signing_bytes(repo)))])
    ok, _ = verify_shard_assignment_record(forged, _owner_root())
    assert not ok, "a connected-repo signature must not verify as a shard-assignment record"


def test_a_wrong_key_signature_is_refused():
    forged = sign_shard_assignment_record(_rec(), {"owner": ATTACKER.private_key_b64})
    ok, _ = verify_shard_assignment_record(forged, _owner_root())
    assert not ok


def test_a_quorum_collapsing_trust_root_is_refused():
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="a", name="a", public_key_b64=OWNER.public_key_b64),
        AuthorizerKey(key_id="b", name="b", public_key_b64=OWNER.public_key_b64)])
    ok, reason = verify_shard_assignment_record(_signed(), dup)
    assert not ok and "duplicate" in reason


def test_verify_is_fail_closed_on_malformed_signature_material():
    bad = SignedShardAssignmentRecord(document=_rec(),
                                      signatures=[Signature(key_id="owner", signature_b64="!!not-base64!!")])
    ok, reason = verify_shard_assignment_record(bad, _owner_root())
    assert not ok and reason


@pytest.mark.parametrize("bad", ["", "../escape", "a/b", "has space", ".", "..", "x" * 65, "\x00nul"])
def test_tenant_and_shard_must_be_safe_single_path_components(bad):
    with pytest.raises(ValueError):
        ShardAssignmentRecord(tenant_id=bad, shard_id="ok", epoch=1)
    with pytest.raises(ValueError):
        ShardAssignmentRecord(tenant_id="ok", shard_id=bad, epoch=1)


def test_epoch_must_be_at_least_one():
    with pytest.raises(ValueError):
        ShardAssignmentRecord(tenant_id="acme", shard_id="s1", epoch=0)


def test_state_must_be_assigned():
    with pytest.raises(ValueError):
        ShardAssignmentRecord(tenant_id="acme", shard_id="s1", epoch=1, state="unassigned")


def test_check_tenant_component_accepts_a_valid_component_and_labels_errors():
    assert check_tenant_component("acme.01", label="tenant_id") == "acme.01"
    with pytest.raises(ValueError, match="shard_id"):
        check_tenant_component("a/b", label="shard_id")


def test_shard_assignment_domain_tag_is_distinct():
    tag = DOMAIN_TAGS["shard-assignment"]
    others = [v for k, v in DOMAIN_TAGS.items() if k != "shard-assignment"]
    assert tag not in others, "the shard-assignment domain tag must be unique"


def test_signing_bytes_carry_the_registered_domain_tag():
    # The signed bytes must be domain-separated under THE shard-assignment tag (not some other purpose's), so a
    # signature can never be computed/verified under a different domain by construction.
    body = shard_assignment_signing_bytes(_rec())
    assert body.startswith(DOMAIN_TAGS["shard-assignment"])
    for name, tag in DOMAIN_TAGS.items():
        if name != "shard-assignment":
            assert not body.startswith(tag), f"shard-assignment signing bytes must not carry the {name!r} domain"


def test_tenant_re_in_lockstep_with_engine_paths_literal():
    # FATAL-2: engine paths.py is framework/offense-side and MUST NOT be imported. Read it as TEXT and assert the
    # replicated _TENANT_RE literal is byte-identical (mirror-drift guard, exactly as governor/orgs.py does).
    root = pathlib.Path(sar.__file__).resolve().parents[4]     # .../<repo root>
    paths_py = root / "engine" / "crucible" / "framework" / "v2" / "common" / "paths.py"
    assert paths_py.is_file(), f"engine paths.py not found at {paths_py}"
    m = re.search(r'_TENANT_RE = re\.compile\((r"[^"]+")\)', paths_py.read_text(encoding="utf-8"))
    assert m, "could not locate _TENANT_RE literal in engine paths.py"
    assert m.group(1) == r'r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"'
    assert sar._TENANT_RE.pattern == r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
