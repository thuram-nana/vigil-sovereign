"""A signed core that cannot be canonicalised to UTF-8 is NOT authentic, and never crashes a fold.

JSON on the spine can carry a lone surrogate (``"\\ud800"``) that no signer could have produced: canonical_json
encodes to UTF-8, and encoding a lone surrogate raises ``UnicodeEncodeError`` (a ``ValueError``). Before this
fix ``verify_signed`` caught only ``IntegrityError``/``TypeError``, so ONE such record (a raw spine-file write)
raised out of every governance fold that scanned it, taking every tenant's state down with it, instead of
being skipped as unverified like any other forged record.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from sigil.governor import eval_capability_grant, eval_offense_attestation
from sigil.governor.authn import signed_payload, verify_signed
from sigil.governor.orgs import OrgRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

_CORE = ("signal", "name", "issued_at")


def test_verify_signed_refuses_an_unencodable_core_instead_of_raising():
    k = generate_keypair()
    p = signed_payload({"signal": "t", "name": "Acme", "issued_at": 1.0}, k)
    assert verify_signed(p, _CORE, k.public_key_b64) is True          # control: the untouched record verifies
    p["name"] = "\ud800"                                              # lone surrogate: only a raw write makes this
    assert verify_signed(p, _CORE, k.public_key_b64) is False


def test_one_unencodable_record_on_the_spine_does_not_take_the_orgs_fold_down():
    k = generate_keypair()
    path = os.path.join(tempfile.mkdtemp(), "spine.jsonl")
    reg = OrgRegistry(SpineStore(path), owner_key=k, trusted_pubkey=k.public_key_b64)
    reg.create_org("acme", "Acme Ltd", owner="alice", issued_at=1.0)
    reg.create_org("beta", "Beta", owner="bob", issued_at=2.0)
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    assert '"name": "Acme Ltd"' in raw
    with open(path, "w", encoding="utf-8") as fh:                     # the raw spine-file write
        fh.write(raw.replace('"name": "Acme Ltd"', '"name": "\\ud800"', 1))
    reg2 = OrgRegistry(SpineStore(path), owner_key=k, trusted_pubkey=k.public_key_b64)
    # the tampered record is ignored as unverified; the other tenant's record still folds
    assert [o.org_id for o in reg2.orgs()] == ["beta"]
    assert reg2.org("acme") is None


def test_the_evaluator_pop_verifiers_refuse_an_unencodable_core():
    evaluator = generate_keypair()
    for mod in (eval_capability_grant, eval_offense_attestation):
        core = {k: "\ud800" for k in mod._CORE}
        core["evaluator_pubkey"] = evaluator.public_key_b64
        assert mod._verify_pop(core, "AAAA") is False, mod.__name__


# ---- the approval queue: one hostile approval record must never take pending() (and every gate) down ----------
def _queued(store, subject):
    return store.append(kind="draft", source="agents", actor="TESTER",
                        payload={"subject": subject, "decision": "queued", "status": "awaiting-approval",
                                 "tier": "A2"})


def _approval_rig():
    from sigil.agents.approvals import ApprovalQueue
    k = generate_keypair()
    path = os.path.join(tempfile.mkdtemp(), "spine.jsonl")
    store = SpineStore(path)
    q = ApprovalQueue(store, owner_key=k, trusted_pubkey_b64=k.public_key_b64)
    return k, path, store, q


def test_an_unencodable_approval_on_the_spine_leaves_the_queue_working():
    from sigil.agents.approvals import pending
    k, path, store, q = _approval_rig()
    s1, s2 = _queued(store, "one"), _queued(store, "two")
    q.approve(s1, approver="alice")
    assert [r.seq for r in pending(store, k.public_key_b64)] == [s2]
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    assert '"approver": "alice"' in raw
    with open(path, "w", encoding="utf-8") as fh:                     # the raw spine-file write
        fh.write(raw.replace('"approver": "alice"', '"approver": "\\ud800"', 1))
    store2 = SpineStore(path)
    # the tampered approval no longer verifies, so s1 is pending again; nothing raises
    assert [r.seq for r in pending(store2, k.public_key_b64)] == [s1, s2]


@pytest.mark.parametrize("sig,pub", [("AAAA", "OWNER"), (["x"], "OWNER"), ("AAAA", ["unhashable"]),
                                     ("AAAA", {"k": 1})])
def test_a_junk_approval_appended_without_the_owner_key_cannot_wedge_the_queue(sig, pub):
    from sigil.agents.approvals import SIGNAL, pending
    k, _path, store, q = _approval_rig()
    s1 = _queued(store, "one")
    store.append(kind="event", source="governor", actor="ANYONE",                    # no owner key needed
                 payload={"signal": SIGNAL, "approval": "approved", "target_seq": s1, "approver": "x",
                          "pubkey": k.public_key_b64 if pub == "OWNER" else pub, "sig": sig})
    assert [r.seq for r in pending(store, k.public_key_b64)] == [s1]               # still pending, no raise
    q.approve(s1)                                                                   # and the queue still works
    assert pending(store, k.public_key_b64) == []
