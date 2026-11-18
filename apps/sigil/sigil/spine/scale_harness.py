"""Front C S4 (in-repo part) — the deterministic, OFFLINE scale harness for the 100,000 -> 1,000,000 user
acceptance run.

WHAT THIS IS (and is not). Front C's production scaling — containers, autoscaling, per-shard routing, a
real multi-host fleet — is owner-gated server/deploy work and is OUT of this module. What IS in the repo,
and what this harness exercises, are the two pure-code primitives scaling rests on:

  * the verified incremental FOLD CACHE (`spine/fold_cache.py`, `governor/fold_read.py`, default-OFF behind
    `VIGIL_FOLD_CACHE_ENABLED`) — a hot per-request registry read (customer login `by_email`, org admission
    `membership_role`, the credit meter `balance`) costs O(records appended since the last read), NOT
    O(all users), and each owner signature is verified exactly once when its record is first folded; and
  * the registries' in-fold read INDEXES (`_CustomerView.emails`, `_OrgsView.members/active_mems`,
    `_WalletView.granted/debited`) — a per-key read is an O(1) dict lookup, O(returned) for a per-org list,
    never a scan of every tenant.

This module SEEDS a large spine fixture deterministically and offline (no network, no real money, no AI
spend), reusing `authn.signed_payload` so every seeded record is byte-shape-identical to the one the real
registry mutation would have appended — and it MEASURES the verification work a warm read performs, which
is the machine-independent proxy for "it scales" (the measured wall was ~150-200 us PER SIGNATURE, so a
warm read that verifies ZERO signatures regardless of N is the falsifiable O(1)-in-N claim).

`tests/test_front_c_scale.py` is the CI gate built on this harness (a swept representative N by default, the
owner's real 100k / 1M behind `VIGIL_SCALE_N`). `main()` lets the owner run the real-N acceptance directly:

    python -m sigil.spine.scale_harness --fold customer --n 1000000

RESIDUALS (documented, never hidden; see `docs/decisions/FRONT-C-1M-SCALE-DESIGN.md` and HANDOFF §4.2):
one COLD build is still O(N) per process (~2.5 min at 1M) — it runs at boot off the request path
(`governor/fold_warm.py`), and this harness pays it once per N to warm the cache before measuring the warm
path; the folded state is one in-memory copy per registry per process, sized by N (S4 sizes it against the
owner's targets). This harness is tooling: it is never imported by a request path, so it changes no shipped
behaviour and needs no flag of its own.

FATAL-2: sovereign-side (`assert_no_offense` at import); no framework/strix import.
"""
from __future__ import annotations

import argparse
import sys
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import customers as _cust  # noqa: E402
from ..governor import orgs as _orgs  # noqa: E402
from ..governor import wallet as _wallet  # noqa: E402
from ..governor.authn import signed_payload  # noqa: E402

__all__ = [
    "seed_customers", "seed_orgs_memberships", "seed_wallets", "counting_verifications",
    "customer_name", "customer_email", "org_name", "wallet_entry_id",
    "FOLD_SEEDERS", "measure_fold", "main",
]

_DEFAULT_BATCH = 5000


# --- deterministic, stable identities (sortable: zero-padded) -----------------------------------------
def customer_name(i: int) -> str:
    return f"cust_scale_{i:09d}"


def customer_email(i: int) -> str:
    return f"u{i:09d}@scale.test"


def org_name(i: int) -> str:
    return f"org_scale_{i:09d}"


def wallet_entry_id(i: int) -> str:
    return f"seed-{i:09d}"


# --- the governed-append envelope (the fields the registries add around the signed core) ---------------
def _enveloped(core: dict, owner_key: Any, reason: str) -> dict:
    """A seeded grant payload: the owner-signed `core` plus the same governed-latch envelope every registry
    append carries (`by/requested_by/tier/decision/reason`). The fold authenticates ONLY the signed core, so
    these extra fields are provenance, exactly as in the real `_append_active*` helpers."""
    return {**signed_payload(core, owner_key), "by": "owner", "requested_by": "owner",
            "tier": "A0", "decision": "auto", "reason": reason}


def _append_specs(store: Any, specs: "list[dict]", batch: int) -> None:
    """Append `specs` in batches via `store.append_many` (ONE fsync per batch — the whole point of seeding
    a million records offline in reasonable time; `append` fsyncs per record)."""
    for start in range(0, len(specs), batch):
        store.append_many(specs[start:start + batch])


def seed_customers(store: Any, n: int, owner_key: Any, *, start: int = 0,
                   with_password: bool = False, batch: int = _DEFAULT_BATCH) -> None:
    """Append `n` owner-signed ACTIVE customer grants (seqs `start`..`start+n-1`), each a distinct username +
    unique email, folded identically to a `CustomerRegistry.create`. `with_password=False` keeps the fold a
    pure Ed25519 verify (no scrypt) — the login HOT PATH's cost. `issued_at` is strictly increasing so each
    is the LWW winner for its own username."""
    specs: "list[dict]" = []
    for k in range(start, start + n):
        core = {"signal": _cust.SIGNAL, "username": customer_name(k), "email": customer_email(k),
                "state": "active", "issued_at": float(k + 1)}
        specs.append({"kind": "event", "source": "governor", "actor": "WARDEN",
                      "payload": _enveloped(core, owner_key, f"seed customer {k}")})
    _append_specs(store, specs, batch)


def seed_orgs_memberships(store: Any, n: int, owner_key: Any, *, role: str = "viewer",
                          start: int = 0, batch: int = _DEFAULT_BATCH) -> None:
    """Append `n` orgs, each with ONE active membership (`customer_name(k)` as `role` in `org_name(k)`) — the
    shape `OrgRegistry.admit_customer` / `membership_role` reads. Both records per org, folded identically to
    `create_org` + `grant_membership`."""
    specs: "list[dict]" = []
    for k in range(start, start + n):
        oid, user, iat = org_name(k), customer_name(k), float(k + 1)
        org_core = {"signal": _orgs.ORG_SIGNAL, "org_id": oid, "name": f"Org {k}", "owner": user,
                    "state": "active", "issued_at": iat}
        mem_core = {"signal": _orgs.MEMBERSHIP_SIGNAL, "org_id": oid, "username": user, "role": role,
                    "state": "active", "issued_at": iat}
        specs.append({"kind": "event", "source": "governor", "actor": "WARDEN",
                      "payload": _enveloped(org_core, owner_key, f"seed org {oid}")})
        specs.append({"kind": "event", "source": "governor", "actor": "WARDEN",
                      "payload": _enveloped(mem_core, owner_key, f"seed membership {user}@{oid}")})
    _append_specs(store, specs, batch)


def seed_wallets(store: Any, n: int, owner_key: Any, *, credits: int = 1000, kind: str = "topup",
                 start: int = 0, batch: int = _DEFAULT_BATCH) -> None:
    """Append `n` owner-signed credit grants, one per tenant (`org_name(k)`), each with a unique `entry_id` —
    the shape `WalletRegistry.balance` reads. Folded identically to `WalletRegistry.grant`."""
    specs: "list[dict]" = []
    for k in range(start, start + n):
        core = {"signal": _wallet.CREDIT_GRANT_SIGNAL, "org_id": org_name(k), "entry_id": wallet_entry_id(k),
                "credits": int(credits), "kind": kind, "source_ref": "", "issued_at": float(k + 1)}
        specs.append({"kind": "event", "source": "governor", "actor": "WARDEN",
                      "payload": _enveloped(core, owner_key, f"seed grant {org_name(k)}")})
    _append_specs(store, specs, batch)


# --- verification-work counter (the machine-independent scale proxy) -----------------------------------
@contextmanager
def counting_verifications(module: Any, attr: str = "verify_signed") -> "Iterator[list[int]]":
    """Count calls to `module.attr` (the signature verifier the fold invokes) for the duration of the block,
    restoring the original afterwards. A warm read's count is the number of NEW records it folded — 0 when
    nothing was appended since the last read, exactly k after k appends — independent of N."""
    counter = [0]
    real = getattr(module, attr)

    def wrapper(*a: Any, **kw: Any) -> Any:
        counter[0] += 1
        return real(*a, **kw)

    setattr(module, attr, wrapper)
    try:
        yield counter
    finally:
        setattr(module, attr, real)


# --- a self-contained per-fold measurement for `main()` (the owner's acceptance run) ------------------
def _measure_customer(store: Any, n: int, owner_key: Any, pub: str) -> dict:
    reg = _cust.CustomerRegistry(store, owner_key=owner_key, trusted_pubkey=pub)
    seed_customers(store, n, owner_key)
    with counting_verifications(_cust) as c:
        reg.by_email(customer_email(n - 1))                     # cold: folds (verifies) all n
        cold = c[0]
        c[0] = 0
        reg.by_email(customer_email(0))                         # warm: verifies nothing
        reg.customer(customer_name(n // 2))
        warm = c[0]
        seed_customers(store, 3, owner_key, start=n)            # +3 records
        reg.by_email(customer_email(n + 2))
        appended = c[0] - warm
    return {"cold": cold, "warm": warm, "k_appends": 3, "k_cost": appended}


def _measure_orgs(store: Any, n: int, owner_key: Any, pub: str) -> dict:
    reg = _orgs.OrgRegistry(store, owner_key=owner_key, trusted_pubkey=pub)
    seed_orgs_memberships(store, n, owner_key)
    with counting_verifications(_orgs) as c:
        reg.membership_role(customer_name(n - 1), org_name(n - 1))   # cold
        cold = c[0]
        c[0] = 0
        reg.membership_role(customer_name(0), org_name(0))           # warm
        reg.admit_customer(username=customer_name(n // 2), org_id=org_name(n // 2), permission="read")
        warm = c[0]
        seed_orgs_memberships(store, 1, owner_key, start=n)          # +2 records (org + membership)
        reg.membership_role(customer_name(n), org_name(n))
        appended = c[0] - warm
    return {"cold": cold, "warm": warm, "k_appends": 2, "k_cost": appended}


def _measure_wallet(store: Any, n: int, owner_key: Any, pub: str) -> dict:
    reg = _wallet.WalletRegistry(store, owner_key=owner_key, trusted_pubkey=pub)
    seed_wallets(store, n, owner_key)
    with counting_verifications(_wallet) as c:
        reg.balance(org_name(n - 1))                            # cold
        cold = c[0]
        c[0] = 0
        reg.balance(org_name(0))                                # warm
        reg.available(org_name(n // 2))
        warm = c[0]
        seed_wallets(store, 3, owner_key, start=n)              # +3 records
        reg.balance(org_name(n + 2))
        appended = c[0] - warm
    return {"cold": cold, "warm": warm, "k_appends": 3, "k_cost": appended}


FOLD_SEEDERS: "dict[str, Callable[[Any, int, Any, str], dict]]" = {
    "customer": _measure_customer,
    "orgs": _measure_orgs,
    "wallet": _measure_wallet,
}


def measure_fold(fold: str, n: int, *, store_path: str) -> dict:
    """Seed `n` records of `fold` into a fresh spine at `store_path` (with the fold cache ON) and return the
    measured verification counts: cold (= n, one full verifying fold), warm (= 0), and the cost of a few
    appends (= exactly that many). Deterministic, offline. The owner's acceptance run."""
    import os

    from .store import SpineStore
    from ..reuse import generate_keypair

    os.environ["VIGIL_FOLD_CACHE_ENABLED"] = "1"
    owner = generate_keypair()
    store = SpineStore(store_path)
    t0 = time.perf_counter()
    out = FOLD_SEEDERS[fold](store, n, owner, owner.public_key_b64)
    out["seconds"] = round(time.perf_counter() - t0, 3)
    out["n"] = n
    out["fold"] = fold
    return out


def main(argv: "list[str] | None" = None) -> int:
    """Run the in-repo scale measurement for one fold at a given N. For the owner's real 100k / 1M
    acceptance: `python -m sigil.spine.scale_harness --fold customer --n 1000000 --store /tmp/scale.jsonl`.
    Prints, and asserts, the scale invariant: warm == 0 and k_cost == k_appends regardless of N (a non-zero
    warm count would mean a read re-folded the whole spine — an O(N) regression)."""
    import tempfile

    ap = argparse.ArgumentParser(description="Front C in-repo scale harness (offline, deterministic).")
    ap.add_argument("--fold", choices=sorted(FOLD_SEEDERS), default="customer")
    ap.add_argument("--n", type=int, default=100_000, help="seeded records (users/orgs/tenants)")
    ap.add_argument("--store", default="", help="spine path (default: a throwaway temp file)")
    args = ap.parse_args(argv)

    store_path = args.store or tempfile.mkstemp(prefix="vigil-scale-", suffix=".jsonl")[1]
    res = measure_fold(args.fold, args.n, store_path=store_path)
    print(f"[scale] fold={res['fold']} n={res['n']} seconds={res['seconds']}")
    print(f"[scale] cold verifications (one full fold, the per-request cost WITHOUT the cache) = {res['cold']}")
    print(f"[scale] warm verifications (per request WITH the cache, must be 0 regardless of N) = {res['warm']}")
    print(f"[scale] {res['k_appends']} appends then one warm read cost = {res['k_cost']} verifications "
          f"(must equal {res['k_appends']})")
    # The scale invariant: a warm per-request read verifies NOTHING, and k appends cost exactly k — both
    # independent of N (a non-zero warm count, or k_cost != k, means a read re-folded the spine: an O(N)
    # regression). `cold` is informational — the full-fold cost the cache removes (one verify per folded
    # signed record: n for customer/wallet, 2n for orgs, which folds an org AND a membership per tenant).
    ok = res["warm"] == 0 and res["k_cost"] == res["k_appends"]
    print(f"[scale] INCREMENTAL-FOLD INVARIANT (warm==0 and k appends cost k, both O(1) in N): "
          f"{'HELD' if ok else 'VIOLATED'}")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - manual acceptance entry point
    sys.exit(main())
