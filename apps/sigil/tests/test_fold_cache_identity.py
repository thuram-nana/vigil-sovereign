"""Front C S0d-1 — the identity folds on the verified incremental fold cache: operator accounts (`resolve` runs
on every operator request; `account` / `mint_session_bearer` on every operator login) and customer credentials
(TOTP / passkey / Google lookups on every customer login).

The cache may change only HOW the folds are read. Every test compares the CACHED public API against the SAME
API with the flag OFF (the unchanged full folds) over the same spine, and fails if a cached read silently fell
back to the full fold. The generic trust-model cases (anchor, rotation, genesis, build race, faults,
concurrency) are proven once on the shared substrate in `test_fold_cache_customers.py`.

  * seeded randomized equivalence over every account op (create with and without a TTL, role change, pubkey
    / TOTP / password enrol, TOTP disable, session-bearer mint, revoke, replay, forged, unsigned, a second
    store instance) across several `now` instants (expiry is a read-time filter);
  * the same for credentials (passkey, TOTP, Google link, revoke, replay, forged, unsigned), plus the
    owner-signed edge cases only a raw append can make: one credential_id held by two customers (ambiguous ⇒
    None), and two oidc credentials of ONE customer binding the same Google identity (ambiguous ⇒ None);
  * O(new records): a warm `resolve` / `by_credential_id` verifies ZERO signatures;
  * a seeded hard prune keeps pruned accounts and credentials; a different seed under the same boundary
    rebuilds;
  * flag OFF: neither cache is consulted.
"""
from __future__ import annotations

import itertools
import random

import pytest

from sigil.governor import accounts as acc
from sigil.governor import customer_credentials as cc
from sigil.governor.authn import signed_payload
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64
ATTACKER = generate_keypair()
USERS = ["alice", "bob", "carol", "dave"]
CUSTOMERS = ["cust_a", "cust_b", "cust_c"]
CIDS = ["cidA", "cidB", "cidC"]
GOOGLE = [("https://accounts.google.com", "g1"), ("https://accounts.google.com", "g2")]
NOWS = [None, 0.0, 150.0, 10_000.0]
_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


@pytest.fixture(autouse=True)
def _cache_on(monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    yield
    fold_cache.clear_all()


def _regs(store, key=OWNER, pub=OWNER_PUB):
    return (acc.AccountsRegistry(store, owner_key=key, trusted_pubkey=pub),
            cc.CustomerCredentialRegistry(store, owner_key=key, trusted_pubkey=pub))


@pytest.fixture
def no_full_fold(monkeypatch):
    calls = {"n": 0}
    for cls in (acc.AccountsRegistry, cc.CustomerCredentialRegistry):
        real = cls._fold

        def spy(self, _real=real):
            calls["n"] += 1
            return _real(self)

        monkeypatch.setattr(cls, "_fold", spy)
    return calls


def _answers(areg, creg, tokens):
    out = {"accounts": areg.accounts()}
    for now in NOWS:
        for t in tokens + ["not-a-token"]:
            out[("resolve", t, now)] = areg.resolve(t, now=now)
        for u in USERS + ["nobody"]:
            out[("account", u, now)] = areg.account(u, now=now)
    for u in CUSTOMERS + ["nobody"]:
        out[("for_user", u)] = creg.for_user(u)
        out[("totp", u)] = creg.totp_for(u)
    for cid in CIDS + ["missing", cc._CRED_KEY_TOTP]:
        out[("cid", cid)] = creg.by_credential_id(cid)
    for iss, sub in GOOGLE + [("https://accounts.google.com", "none")]:
        out[("fed", iss, sub)] = creg.by_federated(iss, sub)
    return out


def _assert_equivalent(areg, creg, tokens, monkeypatch, no_full_fold=None):
    before = no_full_fold["n"] if no_full_fold is not None else 0
    cached = _answers(areg, creg, tokens)
    if no_full_fold is not None:
        assert no_full_fold["n"] == before, "a cached identity read fell back to a full fold"
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "")
    try:
        full = _answers(areg, creg, tokens)
    finally:
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    assert cached == full


def _raw(store, payload):
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


@pytest.mark.parametrize("seed", [31, 32, 33])
def test_randomized_equivalence_with_the_full_identity_folds(tmp_path, seed, monkeypatch, no_full_fold):
    rng = random.Random(seed)
    path = str(tmp_path / "spine.jsonl")
    store, other = SpineStore(path), SpineStore(path)
    (areg, creg), (areg2, creg2) = _regs(store), _regs(other)
    tokens: list = []
    captured: list = []
    for step in range(70):
        u, cu = rng.choice(USERS), rng.choice(CUSTOMERS)
        a, c = (areg2, creg2) if rng.random() < 0.2 else (areg, creg)
        op = rng.choice(["create", "create", "role", "pubkey", "totp", "untotp", "password", "mint", "revoke",
                         "passkey", "ctotp", "google", "crevoke", "replay", "forged", "unsigned", "noise"])
        seq = None
        try:
            if op == "create":
                tok = f"bearer-{step}-" + "x" * 24
                seq = a.create(u, rng.choice(["viewer", "analyst", "operator"]), bearer_token=tok,
                               issued_at=_iss(), ttl_seconds=rng.choice([None, 100.0, 5000.0]))
                tokens.append(tok)
            elif op == "role":
                seq = a.assign_role(u, rng.choice(["viewer", "operator"]), issued_at=_iss())
            elif op == "pubkey":
                seq = a.enroll_pubkey(u, generate_keypair().public_key_b64, issued_at=_iss())
            elif op == "totp":
                seq = a.enroll_totp(u, "c2VhbGVk", issued_at=_iss())
            elif op == "untotp":
                seq = a.disable_totp(u, issued_at=_iss())
            elif op == "password":
                seq = a.set_password(u, "operator-pw-1", issued_at=_iss())
            elif op == "mint":
                tok, seq = a.mint_session_bearer(u, issued_at=_iss())
                tokens.append(tok)
            elif op == "revoke":
                a.revoke(u)
            elif op == "passkey":
                seq = c.enroll_passkey(cu, rng.choice(CIDS), cose_alg=-7, public_key_spki_b64="cGs=", uv=True,
                                       issued_at=_iss())
            elif op == "ctotp":
                seq = c.enroll_totp(cu, sealed_secret="c2VhbGVk", issued_at=_iss())
            elif op == "google":
                iss, sub = rng.choice(GOOGLE)
                seq = c.link_federated(cu, iss=iss, sub=sub, issued_at=_iss())
            elif op == "crevoke":
                c.revoke(cu, rng.choice(CIDS + [cc._CRED_KEY_TOTP, cc._CRED_KEY_OIDC]))
            elif op == "replay" and captured:
                _raw(store, rng.choice(captured))
            elif op == "forged":
                core = {"signal": acc.SIGNAL, "username": u, "role": "operator", "cred_hash": "00", "cred_salt": "00",
                        "state": "active", "issued_at": _iss() + 1e6}
                _raw(store, signed_payload(core, ATTACKER))
            elif op == "unsigned":
                _raw(store, {"signal": cc.SIGNAL, "username": cu, "cred_key": rng.choice(CIDS), "kind": "passkey",
                             "state": "active", "issued_at": _iss() + 1e6})
            else:
                store.append(kind="event", source="t", actor="u", payload={"signal": "noise", "i": step})
        except ValueError:
            pass                                            # an op the registry refuses (unknown / revoked / taken)
        if seq is not None:
            captured.append(store.get(seq).payload)
        _assert_equivalent(areg, creg, tokens, monkeypatch, no_full_fold)
    assert acc._ACCOUNTS_FOLD._entries and cc._CREDENTIALS_FOLD._entries


def test_owner_signed_ambiguities_resolve_to_none_in_both_paths(tmp_path, monkeypatch, no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    areg, creg = _regs(store)
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    assert creg.by_credential_id("cidA").username == "cust_a"               # warm
    # one credential_id held by TWO customers (only an owner-signed raw append can do this)
    core = {"signal": cc.SIGNAL, "username": "cust_b", "cred_key": "cidA", "kind": "passkey", "state": "active",
            "issued_at": _iss(), "cose_alg": -7, "public_key_spki_b64": "cGs=", "uv": True}
    _raw(store, signed_payload({k: core[k] for k in cc._cred_core(core)}, OWNER) | core)
    # two oidc credentials of ONE customer binding the same Google identity
    for ck in ("oidc", "oidc-dup"):
        core = {"signal": cc.SIGNAL, "username": "cust_c", "cred_key": ck, "kind": "oidc", "state": "active",
                "issued_at": _iss(), "federated_iss": GOOGLE[0][0], "federated_sub": GOOGLE[0][1]}
        _raw(store, signed_payload({k: core[k] for k in cc._cred_core(core)}, OWNER) | core)
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.by_credential_id("cidA") is None, "an id bound to two customers resolves to no one"
    assert creg.by_federated(*GOOGLE[0]) is None, "two credentials binding one identity is ambiguous"


def _signed_cred(store, **core):
    core = {"signal": cc.SIGNAL, "state": "active", "issued_at": _iss(), **core}
    return _raw(store, signed_payload({k: core[k] for k in cc._cred_core(core)}, OWNER) | core)


def test_only_oidc_credentials_bind_a_google_identity(tmp_path, monkeypatch, no_full_fold):
    """A passkey that happens to carry federated fields (owner-signed raw) never resolves a Google login."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    areg, creg = _regs(store)
    assert creg.by_federated(*GOOGLE[1]) is None                             # warm
    _signed_cred(store, username="cust_b", cred_key="cidB", kind="passkey", cose_alg=-7,
                 public_key_spki_b64="cGs=", uv=True, federated_iss=GOOGLE[1][0], federated_sub=GOOGLE[1][1])
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.by_federated(*GOOGLE[1]) is None


def test_an_unhashable_google_identity_is_never_matched_in_either_path(tmp_path, monkeypatch, no_full_fold):
    """An owner-signed oidc credential whose iss is a list can never equal a Google (iss, sub) string: the
    full scan's `==` never matches it, and the cache leaves it out of the index — through grant AND revoke."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    areg, creg = _regs(store)
    creg.enroll_totp("cust_a", sealed_secret="c2VhbGVk", issued_at=_iss())
    assert creg.totp_for("cust_a") is not None                               # warm
    _signed_cred(store, username="cust_c", cred_key="oidc", kind="oidc", federated_iss=["not", "hashable"],
                 federated_sub="g9")
    creg.link_federated("cust_b", iss=GOOGLE[0][0], sub=GOOGLE[0][1], issued_at=_iss())
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert [c.cred_key for c in creg.for_user("cust_c")] == ["oidc"]
    assert creg.by_federated(*GOOGLE[0]) == "cust_b"
    creg.revoke("cust_c", "oidc")
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.for_user("cust_c") == [] and creg.by_federated(*GOOGLE[0]) == "cust_b"


def test_a_revoked_or_moved_google_link_stops_resolving_through_the_cache(tmp_path, monkeypatch, no_full_fold):
    """The anti-takeover property E2b trusts: once a customer's Google link is revoked, or re-linked to another
    Google identity, the OLD identity must stop resolving to them — and may then resolve to whoever links it next."""
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    areg, creg = _regs(store)
    creg.link_federated("cust_a", iss=GOOGLE[0][0], sub=GOOGLE[0][1], issued_at=_iss())
    assert creg.by_federated(*GOOGLE[0]) == "cust_a"                         # warm
    creg.revoke("cust_a", cc._CRED_KEY_OIDC)
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.by_federated(*GOOGLE[0]) is None
    creg.link_federated("cust_a", iss=GOOGLE[0][0], sub=GOOGLE[0][1], issued_at=_iss())
    creg.link_federated("cust_a", iss=GOOGLE[1][0], sub=GOOGLE[1][1], issued_at=_iss())   # moved
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.by_federated(*GOOGLE[0]) is None and creg.by_federated(*GOOGLE[1]) == "cust_a"
    creg.link_federated("cust_b", iss=GOOGLE[0][0], sub=GOOGLE[0][1], issued_at=_iss())
    _assert_equivalent(areg, creg, [], monkeypatch, no_full_fold)
    assert creg.by_federated(*GOOGLE[0]) == "cust_b"


def test_a_passkey_id_held_by_another_customer_is_refused_through_the_cache(tmp_path):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    _areg, creg = _regs(store)
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    with pytest.raises(ValueError):
        creg.enroll_passkey("cust_b", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=False, issued_at=_iss())
    assert creg.by_credential_id("cidA").uv is False, "the same customer may re-enrol their own passkey"
    assert cc._CREDENTIALS_FOLD._entries


def test_a_warm_login_lookup_verifies_no_signature(tmp_path, monkeypatch):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    areg, creg = _regs(store)
    tok = "warm-bearer-" + "y" * 24
    areg.create("alice", "operator", bearer_token=tok, issued_at=_iss())
    for i in range(15):
        areg.create(f"user{i}", "viewer", bearer_token=f"t{i}-" + "z" * 24, issued_at=_iss())
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    fold_cache.clear_all()
    count = {"n": 0}
    for mod in (acc, cc):
        real = mod.verify_signed

        def counting(*a, _real=real, **kw):
            count["n"] += 1
            return _real(*a, **kw)

        monkeypatch.setattr(mod, "verify_signed", counting)
    assert areg.resolve(tok) is not None and creg.by_credential_id("cidA") is not None
    assert count["n"] == 17                                   # cold: each grant verified once
    count["n"] = 0
    for _ in range(5):
        assert areg.resolve(tok) is not None and areg.account("alice") is not None
        assert creg.by_credential_id("cidA") is not None and creg.totp_for("cust_a") is None
    assert count["n"] == 0, "a warm login lookup must not re-verify any signature"


class _PrunedView:
    def __init__(self, inner):
        self._inner, self.K, self.path = inner, 0, inner.path

    def iter_records(self, *, since_seq=-1):
        for r in self._inner.iter_records(since_seq=since_seq):
            if r.seq >= self.K:
                yield r

    def get(self, seq):
        return self._inner.get(seq) if seq >= self.K else None

    def append(self, **kw):
        return self._inner.append(**kw)


def test_a_seeded_prune_keeps_accounts_and_credentials_and_a_new_seed_rebuilds(tmp_path, monkeypatch,
                                                                                no_full_fold):
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    view = _PrunedView(store)
    areg, creg = _regs(view)
    tok = "pruned-bearer-" + "q" * 24
    areg.create("alice", "operator", bearer_token=tok, issued_at=_iss())
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    k = store.append(kind="event", source="t", actor="u", payload={"signal": "marker"})
    snap = build([r for r in store.iter_records() if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k,
                 snapshot_seq=k - 1)
    view.K = k
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: snap))
    _assert_equivalent(areg, creg, [tok], monkeypatch, no_full_fold)
    assert areg.resolve(tok) is not None and creg.by_credential_id("cidA") is not None, "the seed carries them"
    emptied = snap.model_copy(update={"account_cred": [], "customer_credential_row": []})
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, s: emptied))
    _assert_equivalent(areg, creg, [tok], monkeypatch, no_full_fold)
    assert areg.resolve(tok) is None and creg.by_credential_id("cidA") is None, "a new seed rebuilds"


@pytest.mark.parametrize("value", ["", "0", "off"])
def test_flag_off_never_consults_an_identity_cache(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", value)

    def boom(*_a, **_kw):
        raise AssertionError("an identity fold cache was consulted with the flag OFF")

    monkeypatch.setattr(acc._ACCOUNTS_FOLD, "read", boom)
    monkeypatch.setattr(cc._CREDENTIALS_FOLD, "read", boom)
    areg, creg = _regs(SpineStore(str(tmp_path / "spine.jsonl")))
    tok = "off-bearer-" + "w" * 24
    areg.create("alice", "operator", bearer_token=tok, issued_at=_iss())
    areg.assign_role("alice", "viewer", issued_at=_iss())
    assert areg.resolve(tok).role == "viewer" and [a.username for a in areg.accounts()] == ["alice"]
    creg.enroll_passkey("cust_a", "cidA", cose_alg=-7, public_key_spki_b64="cGs=", uv=True, issued_at=_iss())
    creg.link_federated("cust_a", iss=GOOGLE[0][0], sub=GOOGLE[0][1], issued_at=_iss())
    assert creg.by_credential_id("cidA").username == "cust_a" and creg.by_federated(*GOOGLE[0]) == "cust_a"
    assert [c.cred_key for c in creg.for_user("cust_a")] == ["cidA", "oidc"]
