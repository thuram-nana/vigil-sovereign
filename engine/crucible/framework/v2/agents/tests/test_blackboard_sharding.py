"""
Wave D / D2 — horizontal single-tenant worker sharding + the bounded structural check.

Proves the load-bearing D2 invariants:

  * TENANT SHARDING. With ``CRUCIBLE_TENANT`` set, the otherwise-global ``.blackboard`` / ``.memory``
    SQLite singletons resolve under a per-tenant subdir. Two tenants get PHYSICALLY DISJOINT stores;
    a tenant-A worker cannot see tenant-B's engagements/events (no cross-tenant commingling). Unset =>
    byte-identical to the historical singleton. A set-but-UNSAFE id FAILS CLOSED.
  * NO CONTENTION. N single-tenant workers writing concurrently to their sharded DBs do not contend or
    cross-read (each SQLite file has one writer — its own tenant).
  * BOUNDED STRUCTURAL CHECK. ``PRAGMA quick_check`` no longer runs on EVERY open: ``first`` (default)
    scans once per path per process, ``always`` every open, ``off`` never — while a torn store is still
    caught, and the on-demand ``check_integrity()`` still works.
  * TAMPER-EVIDENCE PRESERVED. The spine hash-chain (agents.spine_chain) STILL verifies — and still
    detects tampering and a second-writer FORK — even with the per-open quick_check turned OFF, because
    quick_check is SQLite-page structure, not the cryptographic chain.
"""

from __future__ import annotations

import multiprocessing
import os
import threading
from pathlib import Path

import pytest

from framework.v2.agents import blackboard as bb_mod
from framework.v2.agents.blackboard import (
    BlackboardError, blackboard_path, open_blackboard,
)
from framework.v2.agents.spine_chain import (
    build_spine_chain, sign_spine_head, verify_spine_chain, verify_spine_head,
)
from framework.v2.common import paths, tenant
from framework.v2.common.errors import CrucibleRootNotFound
from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot


def _obs(b, slug: str, summary: str) -> int:
    return b.post(engagement=slug, kind="observation", agent_name="a",
                  payload={"source": "s", "surface": "p", "summary": summary})


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"g{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    return tr, [(f"g{i}", k.private_key_b64) for i, k in enumerate(keys)]


def _fleet_race_worker(tenant_name: str, root_str: str, go_path: str, q) -> None:
    """A real, separate process that races the fleet guard against a SHARED root. Module-level so a
    fork-context Process can target it. Spins on a 'go' file so all workers hit the atomic claim at once,
    then reports PASS / FAILCLOSED / ERROR through the queue. Sets ``paths.v2_root`` to the shared root
    directly (works whether the child was forked with the parent's monkeypatch or started fresh)."""
    import os as _os
    import time as _time
    from pathlib import Path as _Path
    from framework.v2.common import paths as _paths, tenant as _t

    _paths.v2_root = lambda: _Path(root_str)
    _os.environ["CRUCIBLE_TENANT"] = tenant_name
    while not _os.path.exists(go_path):        # align all workers on the claim
        _time.sleep(0.001)
    try:
        _t.assert_tenant_fleet_isolated()
        q.put((tenant_name, "PASS"))
    except _t.TenantIsolationError:
        q.put((tenant_name, "FAILCLOSED"))
    except BaseException as e:  # noqa: BLE001 — surface any unexpected shape as a test failure
        q.put((tenant_name, "ERROR:" + repr(e)))


# ---------------------------------------------------------------------------
# tenant path resolution
# ---------------------------------------------------------------------------


def test_default_unset_is_byte_identical(monkeypatch) -> None:
    """No CRUCIBLE_TENANT => the historical singleton paths, unchanged (make-gate / benchmark path)."""
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    assert paths.active_tenant() is None
    assert tenant.is_sharded() is False
    assert paths.blackboard_dir() == paths.v2_root() / ".blackboard"
    assert blackboard_path() == paths.v2_root() / ".blackboard" / "store.sqlite"
    assert paths.memory_db() == paths.v2_root() / ".memory" / "store.sqlite"


def test_tenant_set_shards_both_stores(monkeypatch) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    assert paths.active_tenant() == "alpha"
    assert tenant.is_sharded() is True
    v2 = paths.v2_root()
    assert blackboard_path() == v2 / ".blackboard" / "tenants" / "alpha" / "store.sqlite"
    assert paths.memory_db() == v2 / ".memory" / "tenants" / "alpha" / "store.sqlite"


@pytest.mark.parametrize("bad", ["../evil", "a/b", "a\\b", "..", ".", "-lead", "x" * 65, "@x"])
def test_unsafe_tenant_fails_closed(monkeypatch, bad: str) -> None:
    """A hostile / mis-set tenant id RAISES rather than silently falling back to the shared singleton —
    a silent fallback would commingle the worker with the default store (the exact vector to prevent)."""
    monkeypatch.setenv("CRUCIBLE_TENANT", bad)
    with pytest.raises(CrucibleRootNotFound):
        paths.active_tenant()


@pytest.mark.parametrize("bad", ["../evil", "a/b", "..", "", "a\x00b"])
def test_explicit_tenant_path_is_also_validated(bad: str) -> None:
    """The explicit ``store_paths(tenant=...)`` route (used to compute another tenant's paths) is guarded
    by the SAME fail-closed rule, so a traversal component can never be smuggled into a computed shard —
    including an embedded NUL the OS would refuse in an env var but a caller could pass directly."""
    with pytest.raises(CrucibleRootNotFound):
        tenant.store_paths(tenant=bad)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_tenant_is_unset(monkeypatch, blank: str) -> None:
    monkeypatch.setenv("CRUCIBLE_TENANT", blank)
    assert paths.active_tenant() is None                       # blank == unset, not an error


# ---------------------------------------------------------------------------
# real cross-tenant isolation (writes to disjoint sharded stores)
# ---------------------------------------------------------------------------


def test_two_tenants_cannot_cross_read(tmp_path, monkeypatch) -> None:
    """Tenant alpha writes an engagement + event; tenant beta's store — a different physical file —
    has NO such engagement. Cross-read is structurally impossible."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)   # keep writes off the repo tree

    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    a_path = blackboard_path()
    with open_blackboard(db_path=a_path) as a:
        _obs(a, "job", "alpha-only-secret")
        assert a.count(engagement="job") == 1

    monkeypatch.setenv("CRUCIBLE_TENANT", "beta")
    b_path = blackboard_path()
    assert a_path != b_path
    # neither store path is nested inside the other
    with pytest.raises(ValueError):
        a_path.relative_to(b_path.parent)
    with open_blackboard(db_path=b_path) as b:
        # beta's fresh store does not know engagement 'job' at all
        with pytest.raises(BlackboardError):
            b.engagement_id("job", create=False)

    assert a_path.exists() and b_path.exists()                 # two real, separate files


def test_assert_isolated_from_guard(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    tenant.assert_isolated_from("beta")                        # disjoint => no raise
    with pytest.raises(AssertionError):
        tenant.assert_isolated_from("alpha")                  # same tenant => not isolated from itself


# ---------------------------------------------------------------------------
# fail-closed fleet-startup isolation guard (spine+memory shard is NOT enough on a shared root)
# ---------------------------------------------------------------------------


def test_fleet_isolation_requires_sharding(monkeypatch) -> None:
    """An unsharded worker uses the shared/default store — NOT tenant-isolated — so the fleet guard
    refuses it (evidence/targets/authority would commingle)."""
    monkeypatch.delenv("CRUCIBLE_TENANT", raising=False)
    with pytest.raises(tenant.TenantIsolationError):
        tenant.assert_tenant_fleet_isolated()


def test_fleet_isolation_fails_closed_when_two_tenants_share_a_root(tmp_path, monkeypatch) -> None:
    """The core red-pen scenario: two tenants deployed into ONE CRUCIBLE_ROOT. The second worker's
    startup guard FAILS CLOSED (the first claimed the root) — a hard error, not silent commingling of
    targets/evidence/authority."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)   # ONE shared root for both
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    tenant.assert_tenant_fleet_isolated()                      # alpha claims the root — passes
    assert tenant.root_owner() == "alpha"

    monkeypatch.setenv("CRUCIBLE_TENANT", "beta")             # beta starts in the SAME root
    with pytest.raises(tenant.TenantIsolationError) as ei:
        tenant.assert_tenant_fleet_isolated()
    assert "own" in str(ei.value).lower() and "beta" in str(ei.value)
    assert tenant.root_owner() == "alpha"                      # beta never took ownership


def test_fleet_isolation_passes_for_one_root_per_tenant(tmp_path, monkeypatch) -> None:
    """Properly deployed: each tenant gets its OWN CRUCIBLE_ROOT. Both pass and each claims its own root;
    re-asserting for the same tenant/root is idempotent."""
    root_a, root_b = tmp_path / "A", tmp_path / "B"
    root_a.mkdir()
    root_b.mkdir()

    monkeypatch.setattr(paths, "v2_root", lambda: root_a)
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    tenant.assert_tenant_fleet_isolated()                      # passes + claims root_a
    tenant.assert_tenant_fleet_isolated()                      # idempotent re-attach (same tenant) — passes
    assert tenant.root_owner() == "alpha"

    monkeypatch.setattr(paths, "v2_root", lambda: root_b)
    monkeypatch.setenv("CRUCIBLE_TENANT", "beta")
    tenant.assert_tenant_fleet_isolated()                      # passes + claims root_b
    assert tenant.root_owner() == "beta"


def test_fleet_isolation_detects_preexisting_other_tenant_shard(tmp_path, monkeypatch) -> None:
    """Even with NO claim file, an existing OTHER-tenant spine/memory shard under the root proves the root
    is shared — the scan-based leg fails closed independently of the TOFU claim."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    (tmp_path / ".blackboard" / "tenants" / "alpha").mkdir(parents=True)   # alpha ran here before
    monkeypatch.setenv("CRUCIBLE_TENANT", "beta")
    with pytest.raises(tenant.TenantIsolationError) as ei:
        tenant.assert_tenant_fleet_isolated()
    assert "shared" in str(ei.value).lower() and "alpha" in str(ei.value)


def test_fleet_isolation_claim_false_is_readonly(tmp_path, monkeypatch) -> None:
    """A dry-run probe (claim=False) verifies but never takes ownership, so it leaves no on-disk trace."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    tenant.assert_tenant_fleet_isolated(claim=False)
    assert tenant.root_owner() is None                         # nothing claimed
    assert not tenant.tenant_claim_path().exists()


def test_fleet_isolation_unsafe_tenant_id_still_fails(tmp_path, monkeypatch) -> None:
    """A hostile tenant id fails closed here too (via the shared fail-closed validation)."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setenv("CRUCIBLE_TENANT", "../evil")
    with pytest.raises((tenant.TenantIsolationError, CrucibleRootNotFound)):
        tenant.assert_tenant_fleet_isolated()


# --- fail-OPEN regressions the red-pen found (atomic claim + malformed-is-fail-closed) --------------


def test_fleet_isolation_concurrent_exactly_one_winner(tmp_path) -> None:
    """RED-PEN (a): N real processes race the guard in ONE shared root. Because the claim is published
    atomically (temp write + os.link), EXACTLY ONE wins and every other FAILS CLOSED — no loser ever reads
    a 0-byte claim as 'unclaimed'. Proves the concurrent fail-open hole is closed."""
    ctx = multiprocessing.get_context("fork")
    root = tmp_path / "shared"
    root.mkdir()
    go = tmp_path / "GO"
    q = ctx.Queue()
    n = 8
    procs = [ctx.Process(target=_fleet_race_worker, args=(f"t{i}", str(root), str(go), q))
             for i in range(n)]
    for p in procs:
        p.start()
    go.write_text("go")                                    # release all workers at once
    for p in procs:
        p.join(timeout=60)
    results = [q.get(timeout=5) for _ in range(n)]
    outcomes = [r[1] for r in results]
    assert outcomes.count("PASS") == 1, results            # EXACTLY ONE passer
    assert outcomes.count("FAILCLOSED") == n - 1, results  # everyone else fails closed
    winner = next(r[0] for r in results if r[1] == "PASS")
    assert (root / ".tenant-owner").read_text().strip() == winner   # the winner is the recorded owner


def test_fleet_isolation_empty_claim_residue_fails_closed(tmp_path, monkeypatch) -> None:
    """RED-PEN (b): a pre-existing 0-byte .tenant-owner (crash-mid-claim residue / the old bug's transient
    state) must fail closed for EVERY tenant — never degrade the guard to pass-for-all."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    claim = tenant.tenant_claim_path()
    claim.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))   # exactly the 0-byte residue
    assert claim.stat().st_size == 0
    for t in ("alpha", "beta"):
        monkeypatch.setenv("CRUCIBLE_TENANT", t)
        with pytest.raises(tenant.TenantIsolationError) as ei:
            tenant.assert_tenant_fleet_isolated()
        assert "malformed" in str(ei.value).lower()
    assert tenant.root_owner() is None                     # the empty residue was never accepted as an owner


def test_fleet_isolation_whitespace_or_partial_claim_fails_closed(tmp_path, monkeypatch) -> None:
    """Any non-well-formed claim content (whitespace, garbage, an invalid id, empty) is fail-closed, not
    'unclaimed' — so a partial write can never be mistaken for a free root."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    claim = tenant.tenant_claim_path()
    claim.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    for junk in ("   \n", "not a valid id!!\n", "a/b\n", "", "alpha\nbeta\n"):
        claim.write_text(junk, encoding="utf-8")
        with pytest.raises(tenant.TenantIsolationError):
            tenant.assert_tenant_fleet_isolated()


def test_claim_is_atomic_never_zero_byte(tmp_path, monkeypatch) -> None:
    """The published claim, once present, always has valid content — there is no create-then-write window:
    a claim written by _claim_root is non-empty and names the tenant."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    monkeypatch.setenv("CRUCIBLE_TENANT", "alpha")
    tenant.assert_tenant_fleet_isolated()
    claim = tenant.tenant_claim_path()
    assert claim.exists() and claim.stat().st_size > 0
    assert claim.read_text(encoding="utf-8").strip() == "alpha"
    # no orphan temp files left beside it
    leftovers = [p.name for p in claim.parent.iterdir()
                 if p.name.startswith(tenant._TENANT_OWNER_FILE + ".")]
    assert leftovers == [], leftovers


def test_n_workers_concurrent_no_contention_no_cross_read(tmp_path, monkeypatch) -> None:
    """N single-tenant workers write concurrently to their OWN sharded DBs. No SQLite 'database is
    locked' contention (each file has one writer) and each store ends with ONLY its own events."""
    monkeypatch.setattr(paths, "v2_root", lambda: tmp_path)
    n_workers, per_worker = 6, 25
    tenants = [f"t{i}" for i in range(n_workers)]
    db_paths = {t: tenant.store_paths(tenant=t)["blackboard"] for t in tenants}
    errors: list[str] = []
    barrier = threading.Barrier(n_workers)

    def work(t: str) -> None:
        try:
            barrier.wait(timeout=10)                          # maximise overlap
            with open_blackboard(db_path=db_paths[t]) as b:
                for k in range(per_worker):
                    _obs(b, "job", f"{t}-e{k}")
        except Exception as exc:  # noqa: BLE001 — surface any lock/contention/cross-write failure
            errors.append(f"{t}: {exc!r}")

    threads = [threading.Thread(target=work, args=(t,)) for t in tenants]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=30)

    assert not errors, errors
    # every store has EXACTLY its own events, and every summary belongs to that tenant only
    for t in tenants:
        with open_blackboard(db_path=db_paths[t]) as b:
            rows = b.read(engagement="job", limit=10_000)
            assert len(rows) == per_worker
            assert all(r.payload["summary"].startswith(f"{t}-") for r in rows)


# ---------------------------------------------------------------------------
# bounded structural check (quick_check off the hot path)
# ---------------------------------------------------------------------------


def _count_checks(monkeypatch) -> dict:
    calls = {"n": 0}
    orig = bb_mod.Blackboard.check_integrity

    def counting(self):
        calls["n"] += 1
        return orig(self)

    monkeypatch.setattr(bb_mod.Blackboard, "check_integrity", counting)
    return calls


def test_first_mode_scans_once_per_path(tmp_path, monkeypatch) -> None:
    bb_mod._reset_integrity_memo()
    calls = _count_checks(monkeypatch)
    db = tmp_path / "s.sqlite"
    for _ in range(4):                                         # per-request re-opens on the hot path
        open_blackboard(db_path=db).close()
    assert calls["n"] == 1                                     # scanned once, not on every open


def test_always_mode_scans_every_open(tmp_path, monkeypatch) -> None:
    bb_mod._reset_integrity_memo()
    calls = _count_checks(monkeypatch)
    db = tmp_path / "s.sqlite"
    for _ in range(3):
        open_blackboard(db_path=db, integrity="always").close()
    assert calls["n"] == 3


def test_off_mode_never_scans_on_open_but_on_demand_works(tmp_path, monkeypatch) -> None:
    bb_mod._reset_integrity_memo()
    calls = _count_checks(monkeypatch)
    db = tmp_path / "s.sqlite"
    for _ in range(3):
        b = open_blackboard(db_path=db, integrity="off")
        b.close()
    assert calls["n"] == 0                                     # opting out removes the hot-path scan
    # on-demand / at-boundary structural check still available and clean on a valid store
    with open_blackboard(db_path=db, integrity="off") as b:
        b.check_integrity()                                   # no raise on a valid store


def test_corruption_still_detected_on_first_open(tmp_path) -> None:
    """The default bound did NOT disable detection: a garbage / non-DB file is still caught at (first) open."""
    bb_mod._reset_integrity_memo()
    bad = tmp_path / "store.sqlite"
    bad.write_bytes(b"absolutely not a sqlite database, pure garbage bytes " * 8)
    with pytest.raises(BlackboardError) as ei:
        open_blackboard(db_path=bad)                          # default mode == 'first' → scans on first touch
    assert any(w in str(ei.value).lower() for w in ("corrupt", "integrity", "not a database"))


# ---------------------------------------------------------------------------
# tamper-evidence survives the quick_check change
# ---------------------------------------------------------------------------


def test_spine_hash_chain_verifies_without_per_open_quick_check(tmp_path) -> None:
    """With per-open quick_check OFF, the cryptographic spine chain STILL verifies and STILL detects
    tampering — proving quick_check was never the tamper-evidence (the hash-chain is)."""
    db = tmp_path / "bb.sqlite"
    with open_blackboard(db_path=db, integrity="off") as b:
        b.engagement_id("job")
        for i in range(5):
            _obs(b, "job", f"e{i}")
        entries = build_spine_chain(b, "job")
        ok, reason = verify_spine_chain(b, "job", entries)
        assert ok, reason

    # reopen (still no per-open scan) — chain verifies from the reloaded store, and a raw-content edit is caught
    with open_blackboard(db_path=db, integrity="off") as b:
        entries2 = build_spine_chain(b, "job")
        ok2, reason2 = verify_spine_chain(b, "job", entries2)
        assert ok2, reason2
        tampered = list(entries2)
        tampered[0] = tampered[0].model_copy(update={"cert_digest": "de" * 32})
        bad, why = verify_spine_chain(b, "job", tampered)
        assert not bad and "mismatch" in why


def test_second_writer_fork_still_detected_without_per_open_quick_check(tmp_path) -> None:
    """A signed head anchors the single writer's committed spine. A SECOND writer appending to the same
    engagement is a fork relative to that head — and is still DETECTED with per-open quick_check off."""
    db = tmp_path / "bb.sqlite"
    tr, signers = _trust_root()
    with open_blackboard(db_path=db, integrity="off") as b:
        b.engagement_id("job")
        for i in range(4):
            _obs(b, "job", f"e{i}")
        head = sign_spine_head(b, "job", signers=signers[:2])
        ok, _ = verify_spine_head(b, "job", head, tr)
        assert ok                                             # intact + anchored

    with open_blackboard(db_path=db, integrity="off") as b2:  # a second writer on the same spine
        _obs(b2, "job", "forked-append-by-second-writer")
        ok, reason = verify_spine_head(b2, "job", head, tr)
        assert not ok                                         # the un-anchored forked append is detected
