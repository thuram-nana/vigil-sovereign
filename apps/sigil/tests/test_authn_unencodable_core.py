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
