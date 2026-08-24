"""Hard-prune Slice E — KILL-9-DURING-CUTOVER FUZZ (required before merge; issue #530).

The cutover DELETES records, so a crash at ANY instant during it must reconstruct to a sound state: either
the un-pruned spine (prune not committed) or the pruned spine (below-K deleted from the live window but
PRESERVED + owner-anchored in the archive) — never a torn/lost/forked chain. A child process runs
`commit_prune` and is crashed BOTH deterministically (os._exit at each labelled barrier via
SIGIL_SPINE_CRASH_AT) and non-deterministically (SIGKILL at a random instant). The parent then proves
recovery: verify() + the owner-signed head verify, the chain is contiguous+dup-free, NO acked record is lost
(≥K retained live, <K recoverable from the archive), and — after `finish_prune()` — the prune completes
with the pruned prefix gone from the live spine and intact in the archive.

Runs in the required "SIGIL governor gates (P7)" job (pure spine — no qdrant/kuzu). A longer soak is wired
in scheduled-chaos-failover.yml.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/python -m pytest tests/test_spine_prune_crashfuzz.py -q
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# The child: an ISOLATED spine+head+keys+floor+archive under `d`, built to 4 sealed segments (0,5,10,15) +
# a live tail, owner-signed, then `commit_prune(K=10)`. A labelled-barrier crash (os._exit) or a SIGKILL
# ends it mid-cutover. `premeta.json` records the pre-prune tip so the parent knows what must survive.
_CHILD = r"""
import os, sys, json
from pathlib import Path
d = Path(sys.argv[1])
os.environ["SIGIL_SPINE_ARCHIVE_DIR"] = str(d / "arch")

import sigil.config as cfg
import sigil.spine.store as _store
import sigil.spine.checkpoint as _cp
import sigil.spine.floor as _fl
import sigil.spine.snapshot as _snap
head, keys = d / "head.json", d / "keys"
_cp.HEAD_PATH = head; _snap.HEAD_PATH = head; cfg.HEAD_PATH = head
_cp.KEYS_DIR = keys; _cp._PRIV = keys / "owner.priv"; _cp._PUB = keys / "owner.pub"
_fl.FLOOR_PATH = d / "floor.json"

def _hook(name):
    if os.environ.get("SIGIL_SPINE_CRASH_AT") == name:
        os._exit(137)
_store._crash_hook = _hook

from sigil.spine.store import SpineStore
from sigil.spine import prune
s = SpineStore(d / "spine.jsonl")
s.migrate()
seq = 0
for _seg in range(4):
    for _i in range(5):
        s.append(kind="event", source="fuzz", actor="u", payload={"n": seq}); seq += 1
    s.rotate()
for _i in range(3):
    s.append(kind="event", source="fuzz", actor="u", payload={"n": seq}); seq += 1
_cp.checkpoint(s)
(d / "premeta.json").write_text(json.dumps({"K": 10, "pre_tip": s.next_seq - 1}))
prune.commit_prune(s, 10, confirm=True)
(d / "done.json").write_text("ok")
"""


@pytest.fixture(autouse=True)
def _restore_module_globals():
    """`_open_isolated` re-points the process's checkpoint/floor/config globals at each test's temp dir. Those
    are module globals (not monkeypatch), so without restoring them a later test in the same pytest process
    would inherit a stale HEAD_PATH/KEYS_DIR/FLOOR_PATH pointing at a now-deleted dir. Snapshot + restore them
    (and reset the cached owner vault) so this fuzz never pollutes the rest of the suite."""
    import sigil.config as cfg
    import sigil.platform.vault as _vault
    import sigil.spine.checkpoint as _cp
    import sigil.spine.floor as _fl
    import sigil.spine.snapshot as _snap
    saved = {(m, n): getattr(m, n) for m, n in [
        (_cp, "HEAD_PATH"), (_cp, "KEYS_DIR"), (_cp, "_PRIV"), (_cp, "_PUB"),
        (_snap, "HEAD_PATH"), (_fl, "FLOOR_PATH"), (cfg, "HEAD_PATH")]}
    try:
        yield
    finally:
        for (m, n), v in saved.items():
            setattr(m, n, v)
        _vault.reset_owner_vault_for_test()


def _fresh_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="sigil-prunefuzz-"))


def _run_child(d: Path, *, crash_at: str | None = None, kill_after: float | None = None) -> int:
    env = dict(os.environ)
    env["SIGIL_SPINE_ARCHIVE_DIR"] = str(d / "arch")
    if crash_at:
        env["SIGIL_SPINE_CRASH_AT"] = crash_at
    proc = subprocess.Popen([sys.executable, "-c", _CHILD, str(d)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if kill_after is not None:
        import time
        time.sleep(kill_after)
        proc.kill()
    return proc.wait(timeout=60)


def _open_isolated(d: Path):
    """Open the child's spine from the PARENT process with the same isolated head/keys/floor/archive."""
    import sigil.config as cfg
    import sigil.spine.checkpoint as _cp
    import sigil.spine.floor as _fl
    import sigil.spine.snapshot as _snap
    head, keys = d / "head.json", d / "keys"
    _cp.HEAD_PATH = head; _snap.HEAD_PATH = head; cfg.HEAD_PATH = head
    _cp.KEYS_DIR = keys; _cp._PRIV = keys / "owner.priv"; _cp._PUB = keys / "owner.pub"
    _fl.FLOOR_PATH = d / "floor.json"
    from sigil.spine.store import SpineStore
    return SpineStore(d / "spine.jsonl")


def _head_base_seq(d: Path) -> int:
    from sigil.reuse.models import SignedChainHead
    hp = d / "head.json"
    if not hp.exists():
        return 0
    return SignedChainHead.model_validate_json(hp.read_text()).base_seq


def _assert_recovers(d: Path) -> None:
    import sigil.spine.checkpoint as _cp
    from sigil.spine import prune

    meta = json.loads((d / "premeta.json").read_text())
    K, pre_tip = meta["K"], meta["pre_tip"]
    acked = set(range(pre_tip + 1))                    # every record the child appended before the prune

    s = _open_isolated(d)
    ok, why = s.verify()
    assert ok, f"verify() FAILED after crash: {why}"
    hok, hmsg = _cp.verify_checkpoint(s)
    assert hok, f"signed head FAILED after crash: {hmsg}"
    live = [r.seq for r in s.iter_records()]
    assert len(live) == len(set(live)), f"duplicate seq after crash: {live}"
    assert live == list(range(live[0], live[-1] + 1)), f"non-contiguous/forked chain after crash: {live}"

    B = _head_base_seq(d)
    if B == 0:                                          # prune NOT committed → whole pre-prune spine present
        assert live[0] == 0
        assert acked <= set(live), "an acked record was LOST in the un-pruned recovery"
    else:                                               # prune committed (head signed) → below-K in the archive
        assert B == K
        aok, amsg = prune.verify_with_archive(s, adir=d / "arch")
        assert aok, f"committed prune but the archive does not verify: {amsg}"
        present = set(live)
        # ≥K acked records are retained live; <K acked records must be gone-from-live-but-in-archive.
        assert {a for a in acked if a >= K} <= present, "a retained (≥K) acked record was LOST"

    # ROLL FORWARD to the terminal state and re-check: the prune either fully un-happened or fully happened,
    # and deletion is crash-safe (pruned prefix gone from live, intact in the owner-anchored archive).
    s.finish_prune()
    s2 = _open_isolated(d)
    ok2, why2 = s2.verify(); assert ok2, why2
    assert _cp.verify_checkpoint(s2)[0]
    live2 = [r.seq for r in s2.iter_records()]
    assert live2 == list(range(live2[0], live2[-1] + 1))
    if _head_base_seq(d) > 0:
        assert live2[0] == K, "after finish_prune the pruned prefix must be gone from the live spine"
        aok2, amsg2 = prune.verify_with_archive(s2, adir=d / "arch")
        assert aok2, f"pruned prefix not recoverable from the archive: {amsg2}"
        assert {a for a in acked if a >= K} <= set(live2)      # nothing ≥K lost
    else:
        assert acked <= set(live2)                             # nothing lost in the un-pruned outcome

    # the store must stay writable + verifiable after recovery.
    s2.append(kind="event", source="recover", actor="u", payload={"ok": True})
    assert _open_isolated(d).verify()[0]


@pytest.mark.parametrize("barrier", ["prune_after_archive", "prune_after_snapshot",
                                     "prune_after_head", "prune_after_manifest"])
def test_crash_at_each_cutover_barrier(barrier):
    """Deterministic: crash at each labelled cutover barrier. Recovery is clean every time — and the
    pre-commit barriers roll back while the post-commit ones roll forward."""
    d = _fresh_dir()
    rc = _run_child(d, crash_at=barrier)
    assert rc == 137, f"child did not crash at {barrier}; rc={rc}"
    assert not (d / "done.json").exists(), "child claimed completion despite the barrier crash"
    _assert_recovers(d)


@pytest.mark.parametrize("trial", range(8))
def test_random_sigkill_during_cutover(trial):
    """Non-deterministic: SIGKILL at a random instant across (roughly) the cutover window. Whether it lands
    in the build, the checkpoint, or mid-cutover, recovery must be clean; a kill before the baseline is
    signed has nothing to prune (skip). The deterministic barriers above are the robust per-step proof; this
    adds coverage of the instants WITHIN a step (mid-fsync, mid-manifest-write)."""
    d = _fresh_dir()
    delay = 0.20 + 0.06 * trial                         # ~0.2..0.6s — after the build, across the cutover
    rc = _run_child(d, kill_after=delay)
    assert rc in (-9, 137, 0), f"child exited unexpectedly (rc={rc})"
    if not (d / "premeta.json").exists():
        pytest.skip("SIGKILL landed before the pre-prune baseline was signed — nothing to prune yet")
    _assert_recovers(d)


def test_recovery_oracle_is_not_a_rubber_stamp():
    """NEGATIVE CONTROL: prove the recovery oracle actually detects damage. Run a CLEAN prune to completion,
    then delete a RETAINED (≥K) live record — verify() must FAIL. If it passed, the fuzz's `verify()`
    assertion would be a no-op."""
    d = _fresh_dir()
    rc = _run_child(d)                                   # no crash → a clean, fully-committed prune
    assert rc == 0 and (d / "done.json").exists()
    _assert_recovers(d)                                  # sanity: the clean outcome recovers

    # corrupt the retained window: DELETE A MIDDLE line of the active segment (a retained ≥K record). A middle
    # deletion breaks the next record's prev_hash / opens a seq gap, so the UNKEYED verify() itself must fail
    # — proving the fuzz's verify() assertion is load-bearing, not a rubber stamp. (A tail deletion is caught
    # only by the signed head; a middle one is caught by verify() directly, which is the stronger claim here.)
    s = _open_isolated(d)
    active = s._active
    lines = [ln for ln in active.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 3, "need >=3 records in the active segment to delete a middle one"
    del lines[1]
    active.write_text("\n".join(lines) + "\n")
    ok, why = _open_isolated(d).verify()
    assert not ok, f"the oracle must FAIL on a deleted retained record (else the fuzz proves nothing); got {why!r}"
