"""W16-STD-6 (a) log rotation-with-retention and (b) per-engagement (no cross-log) routing.

These are regression tests for two ops defects in ``common.logging``:

  (a) the engagement log used to be rotated to exactly ONE ``.1`` backup, so history past ~2x the cap was
      silently DISCARDED. It now rotates through a numbered backup ring with an explicit retention window.
  (b) the bound engagement slug used to be a bare module GLOBAL, so two engagements running concurrently in
      one process cross-logged into whichever bound last. It is now a ContextVar, isolated per thread/task.

Each test observes the FAIL on a tree without the fix (documented inline) and carries a NEGATIVE CONTROL.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from framework.v2.common import logging as v2log


# --- (a) rotation retains history ------------------------------------------


def _fill(p: Path, n_lines: int, tag: str) -> None:
    for i in range(n_lines):
        v2log._append_capped(p, f"{tag}-{i:04d}-" + "x" * 40)


def test_rotation_retains_history_across_multiple_backups(tmp_path, monkeypatch) -> None:
    """Enough volume to force SEVERAL rotations keeps a RING of numbered backups — not a single ``.1``.

    Fails without the fix: the old code did ``os.replace(p, p.suffix + '.1')`` every rotation, so a second
    rotation OVERWROTE ``.1`` and ``.2`` was never created. Here we assert ``.2`` (and ``.3``) exist."""
    monkeypatch.setattr(v2log, "_LOG_MAX_BYTES", 200)
    monkeypatch.setattr(v2log, "_LOG_BACKUP_COUNT", 3)
    log = tmp_path / "eng.log"

    _fill(log, 60, "A")  # each line ~50B, cap 200B => many rotations

    assert log.exists()
    assert (tmp_path / "eng.log.1").exists()
    assert (tmp_path / "eng.log.2").exists(), "old single-.1 behaviour would never create .2"
    assert (tmp_path / "eng.log.3").exists()
    # NEGATIVE CONTROL: retention is a real, BOUNDED window — .4 is pruned, not silently kept forever,
    # and not a no-op that keeps everything.
    assert not (tmp_path / "eng.log.4").exists(), "retention window must prune past _LOG_BACKUP_COUNT"


def test_rotation_preserves_earlier_lines_that_old_code_discarded(tmp_path, monkeypatch) -> None:
    """Content that a SECOND rotation would have discarded under the old one-backup scheme is still on disk.

    We write two clearly separated batches; each batch is large enough to trigger its own rotation. Under the
    old code the first batch (living in ``.1``) was overwritten by the second rotation and LOST. Now it lives
    in ``.2``. We assert the first batch's marker is still recoverable from the backup ring."""
    # cap ~= 6 lines/file; retention 20 keeps every line we write below (30), so the assertion isolates the
    # "later rotation destroyed earlier history" bug rather than the (separately tested) retention window.
    monkeypatch.setattr(v2log, "_LOG_MAX_BYTES", 300)
    monkeypatch.setattr(v2log, "_LOG_BACKUP_COUNT", 20)
    log = tmp_path / "eng.log"

    _fill(log, 15, "BATCH1")  # ~2 rotations worth — old one-backup code would lose BATCH1's start
    _fill(log, 15, "BATCH2")

    all_text = ""
    for p in [log, *(tmp_path.glob("eng.log.*"))]:
        all_text += p.read_text(encoding="utf-8")
    assert "BATCH1-0000" in all_text, "earliest history must survive a later rotation (no silent discard)"
    assert "BATCH2-0014" in all_text


# --- (b) concurrent engagements do not cross-log ---------------------------


def test_concurrent_engagements_do_not_cross_log(tmp_path, monkeypatch) -> None:
    """Two threads bind DIFFERENT slugs and log concurrently; each line lands in its own engagement file.

    Fails without the fix: with a module-global slug, both threads read whichever slug bound LAST after the
    barrier, so both lines went to ONE file and the other stayed empty."""
    # route slug -> a per-slug file under tmp, so we never touch the real targets/ tree
    monkeypatch.setattr(v2log.paths, "crucible_v2_log", lambda slug: tmp_path / f"{slug}.log")

    barrier = threading.Barrier(2)

    def worker(slug: str) -> None:
        v2log.bind_engagement(slug)
        barrier.wait()  # force BOTH to have bound before EITHER writes — exposes the global race
        p = v2log._engagement_log_path()
        v2log._append_capped(p, f"line-for-{slug}")
        v2log.bind_engagement(None)

    t1 = threading.Thread(target=worker, args=("alpha",))
    t2 = threading.Thread(target=worker, args=("bravo",))
    t1.start(); t2.start(); t1.join(); t2.join()

    alpha = (tmp_path / "alpha.log").read_text(encoding="utf-8")
    bravo = (tmp_path / "bravo.log").read_text(encoding="utf-8")
    assert "line-for-alpha" in alpha and "line-for-bravo" not in alpha
    assert "line-for-bravo" in bravo and "line-for-alpha" not in bravo


def test_unbound_context_routes_to_ambient_not_a_siblings_engagement(tmp_path, monkeypatch) -> None:
    """NEGATIVE CONTROL: a fresh thread that never binds routes to the AMBIENT process log — never into an
    engagement file bound by another thread. Proves the per-context default is fail-safe (ambient), not
    'inherit whatever some other engagement set'."""
    monkeypatch.setattr(v2log.paths, "crucible_v2_log", lambda slug: tmp_path / f"{slug}.log")
    monkeypatch.setattr(v2log.paths, "v2_root", lambda: tmp_path)

    # main thread binds an engagement
    v2log.bind_engagement("mainthread-eng")
    try:
        captured: dict[str, Path] = {}

        def worker() -> None:  # never binds
            captured["path"] = v2log._engagement_log_path()

        t = threading.Thread(target=worker)
        t.start(); t.join()

        assert captured["path"] == tmp_path / ".crucible-v2.log"
        assert captured["path"] != tmp_path / "mainthread-eng.log"
    finally:
        v2log.bind_engagement(None)
