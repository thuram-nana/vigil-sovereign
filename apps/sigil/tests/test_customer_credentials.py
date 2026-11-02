"""Slice E2a — governor.customer_credential substrate (CustomerCredentialRegistry): owner-signed per-customer
passkey / TOTP / Google-OIDC-link credentials, LWW, hard-prune-durable.

Load-bearing invariants (a false-green would let a forged credential verify, a stale one resurrect a revoked
one, a duplicate-id hijack resolve a login to the WRONG customer, or a pruned credential vanish):
  * enroll = owner-signed + FRESH (per-(username, cred_key) high-water); revoke = honored on sight;
  * GLOBAL uniqueness: a credential_id / (iss,sub) active for one customer can't be bound to another, and the
    resolvers fail-closed on 0 or an ambiguous >1 active binding;
  * a forged/unsigned active credential is inert; a captured active can't resurrect a revoked one (LWW);
  * build() == scan for credentials, and an active credential whose only grant is pruned survives via the seed.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.authn import signed_payload
from sigil.governor.customer_credentials import (KIND_PASSKEY, SIGNAL, CustomerCredentialRegistry, _cred_core)
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_iss = itertools.count(1)


def _issue():
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(s):
    return CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)


# ---- CRUD + resolution -------------------------------------------------------------------------------
def test_enroll_passkey_resolves_by_credential_id_and_for_user():
    r = _reg(_store())
    r.enroll_passkey("cust_a", "credAAA", cose_alg=-7, public_key_spki_b64="PUBKEY_A", uv=True, issued_at=_issue())
    c = r.by_credential_id("credAAA")
    assert c is not None and c.username == "cust_a" and c.kind == KIND_PASSKEY
    assert c.cose_alg == -7 and c.public_key_spki_b64 == "PUBKEY_A" and c.uv is True
    assert [x.cred_key for x in r.for_user("cust_a")] == ["credAAA"]
    assert r.by_credential_id("nope") is None


def test_enroll_totp_and_link_federated_resolve():
    r = _reg(_store())
    r.enroll_totp("cust_a", sealed_secret="SEALED", issued_at=_issue())
    assert r.totp_for("cust_a").sealed_secret == "SEALED"
    r.link_federated("cust_a", iss="https://accounts.google.com", sub="SUB123", issued_at=_issue())
    assert r.by_federated("https://accounts.google.com", "SUB123") == "cust_a"
    assert r.by_federated("https://accounts.google.com", "OTHER") is None


# ---- global uniqueness (anti-takeover) ---------------------------------------------------------------
def test_passkey_credential_id_is_globally_unique():
    r = _reg(_store())
    r.enroll_passkey("cust_a", "credX", cose_alg=-7, public_key_spki_b64="PKA", uv=False, issued_at=_issue())
    with pytest.raises(ValueError):
        r.enroll_passkey("cust_b", "credX", cose_alg=-7, public_key_spki_b64="PKB", uv=False, issued_at=_issue())


def test_federated_binding_is_globally_unique():
    r = _reg(_store())
    r.link_federated("cust_a", iss="iss1", sub="sub1", issued_at=_issue())
    with pytest.raises(ValueError):
        r.link_federated("cust_b", iss="iss1", sub="sub1", issued_at=_issue())


# ---- LWW + forgery + revoke --------------------------------------------------------------------------
def test_revoke_then_captured_active_cannot_resurrect():
    s = _store()
    r = _reg(s)
    r.enroll_passkey("cust_a", "credX", cose_alg=-7, public_key_spki_b64="PKA", uv=False, issued_at=5.0)
    captured = None
    for rec in s.iter_records():
        p = rec.payload
        if isinstance(p, dict) and p.get("signal") == SIGNAL and p.get("state") == "active":
            captured = dict(p)
    r.revoke("cust_a", "credX")
    assert r.by_credential_id("credX") is None
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)   # replay issued_at 5.0 <= hw
    assert r.by_credential_id("credX") is None, "a replayed captured active must not resurrect a revoked credential"


def test_forged_active_is_inert():
    s = _store()
    r = _reg(s)
    core = {"signal": SIGNAL, "username": "cust_a", "cred_key": "credF", "kind": KIND_PASSKEY,
            "state": "active", "issued_at": 9.0, "cose_alg": -7, "public_key_spki_b64": "EVIL", "uv": False}
    forged = {**signed_payload(core, ATTACKER), "by": "owner"}        # signed by the WRONG key
    s.append(kind="event", source="governor", actor="WARDEN", payload=forged)
    assert r.by_credential_id("credF") is None, "an active credential not signed by the owner is inert"


def test_malformed_credential_id_refused():
    r = _reg(_store())
    with pytest.raises(ValueError):
        r.enroll_passkey("cust_a", "bad id with spaces", cose_alg=-7, public_key_spki_b64="PK", uv=False,
                         issued_at=_issue())


# ---- build == scan + prune survival ------------------------------------------------------------------
def _scan_active(reg):
    return set(reg._fold().keys())


def _built_active(store):
    snap = build(list(store.iter_records()), trusted_pubkey=OP, base_seq=0, snapshot_seq=-1)
    st = snap.customer_credential_state_map()
    return {(row[0], row[1]) for row in snap.customer_credential_row
            if st.get((row[0], row[1])) == "active"}


def test_build_equals_scan():
    s = _store()
    r = _reg(s)
    r.enroll_passkey("cust_a", "credX", cose_alg=-7, public_key_spki_b64="PKA", uv=False, issued_at=_issue())
    r.enroll_totp("cust_a", sealed_secret="SEAL", issued_at=_issue())
    r.link_federated("cust_b", iss="iss1", sub="sub1", issued_at=_issue())
    r.enroll_passkey("cust_b", "credY", cose_alg=-257, public_key_spki_b64="PKB", uv=True, issued_at=_issue())
    r.revoke("cust_b", "credY")
    want = {("cust_a", "credX"), ("cust_a", "totp"), ("cust_b", "oidc")}
    assert _scan_active(r) == _built_active(s) == want


class _PrunedView:
    def __init__(self, inner, K):
        self._inner, self._K = inner, K

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self._K:
                yield r

    def get(self, seq):
        return self._inner.get(seq)

    def append(self, **kw):
        return self._inner.append(**kw)


def test_active_credential_survives_a_hard_prune(monkeypatch):
    s = _store()
    r = _reg(s)
    r.enroll_passkey("cust_a", "credX", cose_alg=-7, public_key_spki_b64="PKA", uv=False, issued_at=5.0)  # seq 0
    seed = build(list(s.iter_records()), trusted_pubkey=OP, base_seq=1, snapshot_seq=0)   # prefix [0..1) carried
    monkeypatch.setattr(SnapshotState, "load", staticmethod(lambda store: seed))
    r2 = CustomerCredentialRegistry(_PrunedView(s, 1), owner_key=OWNER, trusted_pubkey=OP)   # seq 0 physically hidden
    assert r2.by_credential_id("credX") is not None, "a pruned active credential must survive via the snapshot seed"
