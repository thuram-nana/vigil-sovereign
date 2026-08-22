"""W8-4 (#470) — integration test for ``tools/ha/mirror-sync.sh``, the script that MOVES live
sovereign state (~/.sigil) between hosts for an active-PASSIVE failover.

Until now only the guard's *decision core* (``tools/ha/spine_failover_guard.py`` →
``test_ha_failover_guard.py``) was covered; the shell script that actually copies the state was
UNTESTED. This runs a REAL ``mirror-sync.sh delta`` between two directories (the two "hosts") and
covers the two hazards the HA profile calls out:

  (a) TORN-SYNC — the copy is interrupted mid-transfer. The mirror must be left DETECTABLY
      incomplete (the read-only "Last synced" completion sentinel is only stamped AFTER a full
      copy, and the script exits non-zero), NEVER silently marked complete/promotable.
  (b) STALE-MIRROR — a mirror whose off-box witnessed anchor is older than the freshness bound is
      REFUSED by the promotion guard (``STALE ANCHOR``, exit 2), not silently promoted.

Each hazard is a distinct test WITH a negative control (a clean sync of the same harness succeeds /
a fresh anchor promotes), so the checks are proven not to be no-ops.

The interrupt is injected WITHOUT changing prod behaviour: the script calls ``rsync`` unqualified,
so a fake ``rsync`` earlier on ``$PATH`` deterministically copies a partial subset and then dies —
exactly a mid-transfer network drop / SIGKILL, exercising the REAL ``set -euo pipefail`` script.

Fixtures mirror ``test_ha_failover_guard.py``: witness.py is config-free, so keys + heads are
injected directly and the guard module is loaded by path.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from vigil_integration.transparency import Witness

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W

_REPO = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO / "tools" / "ha" / "mirror-sync.sh"
_GUARD_DIR = _REPO / "tools" / "ha"
if str(_GUARD_DIR) not in sys.path:
    sys.path.insert(0, str(_GUARD_DIR))
import spine_failover_guard as guard  # noqa: E402

OWNER = generate_keypair()
SCOPE = "sigil"
SENTINEL = "MIRROR-READONLY"          # must match tools/ha/mirror-sync.sh
_W7_WARN = 100
_W7_REFUSE = 200


# --------------------------------------------------------------------------- helpers

def _chain(n, salt=""):
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _solo_tr():
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _owner_tr():
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _witnessed_env_at(head, tmp_path, *, now):
    """A witnessed anchor envelope stamped with an emission timestamp (the off-box, scheduled emitter)."""
    wc = W.emit_checkpoint(head, [Witness("owner", OWNER.private_key_b64)],
                           tip_path=tmp_path / "tip", scope=SCOPE, now=now)
    return W.dump_witnessed(wc, scope=SCOPE, emitted_at=int(now))


def _make_active_home(root: Path) -> dict:
    """Populate a directory that stands in for the ACTIVE writer's ~/.sigil: a few spine-shaped files in
    nested dirs. Returns {relpath: bytes} of every file (the completeness oracle for the mirror)."""
    files = {
        "spine/entries.jsonl": b'{"seq":0}\n{"seq":1}\n{"seq":2}\n',
        "spine/head.json": b'{"entry_count":3,"last_seq":2}\n',
        "keys/owner.pub": b"owner-public-key-material\n",
        "sigil.env": b"SIGIL_SCOPE=sigil\n",
    }
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return files


def _run(mode: str, *, active_src: Path, mirror: Path, live_home: Path, extra_path: Path | None = None):
    """Run the REAL mirror-sync.sh. ``live_home`` is the (throwaway) SIGIL_HOME the read-only gate compares
    against — it MUST differ from the mirror. ``extra_path`` (if given) is prepended to $PATH so a fake
    rsync there shadows the real one (torn-sync injection)."""
    env = os.environ.copy()
    env["VIGIL_ACTIVE_SIGIL"] = f"{active_src}/"       # trailing slash: copy CONTENTS into the mirror
    env["VIGIL_MIRROR_HOME"] = str(mirror)
    env["SIGIL_HOME"] = str(live_home)                 # the live writer home to protect (must != mirror)
    if extra_path is not None:
        env["PATH"] = f"{extra_path}{os.pathsep}{env['PATH']}"
    return subprocess.run(["bash", str(_SCRIPT), mode], env=env,
                          capture_output=True, text=True, timeout=120)


def _sentinel_text(mirror: Path) -> str | None:
    p = mirror / SENTINEL
    return p.read_text(encoding="utf-8") if p.exists() else None


def _install_torn_rsync(shim_dir: Path) -> None:
    """A fake ``rsync`` that copies exactly ONE file of the transfer, then FAILS (exit 1) — a mid-copy
    interrupt (network drop / SIGKILL). It ignores --delete, so it can only ever leave a PARTIAL mirror."""
    shim_dir.mkdir(parents=True, exist_ok=True)
    fake = shim_dir / "rsync"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "# torn-sync injection: partial copy then die mid-transfer.\n"
        'args=("$@"); n=${#args[@]}\n'
        'src="${args[n-2]}"; dst="${args[n-1]}"\n'
        'mkdir -p "$dst"\n'
        'first=$(find "$src" -type f | sort | head -1)\n'
        'if [ -n "$first" ]; then\n'
        '  rel="${first#"$src"}"\n'
        '  mkdir -p "$dst/$(dirname "$rel")"\n'
        '  cp "$first" "$dst/$rel"\n'
        'fi\n'
        'echo "fake-rsync: interrupted mid-transfer" >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def _no_writer_running():
    """The script fail-closes (exit 2) if a `sigil serve` writer is live on this host. Skip rather than
    emit a misleading failure if one happens to be running in the dev environment (CI has none)."""
    r = subprocess.run(["pgrep", "-f", "sigil serve"], capture_output=True, text=True)
    if r.returncode == 0:
        pytest.skip("a 'sigil serve' writer is running on this host; mirror-sync refuses (by design)")


# --------------------------------------------------------------------- (1) a REAL sync is complete/correct

def test_delta_mirror_sync_transfers_state_faithfully(tmp_path, _no_writer_running):
    """NEGATIVE CONTROL / the happy path: a real rsync delta between two dirs copies every file BYTE-FOR-BYTE
    into a separate mirror, honours --delete (a stray mirror file is removed) while PRESERVING the read-only
    sentinel, and stamps a fresh completion sentinel. This is the 'a clean sync succeeds' control the torn /
    stale tests are measured against."""
    active = tmp_path / "active"
    mirror = tmp_path / "mirror"
    live = tmp_path / "live-home"          # throwaway SIGIL_HOME (must differ from the mirror)
    want = _make_active_home(active)

    # pre-seed the mirror with a STRAY file (--delete must remove it) and a pre-existing sentinel (--delete
    # must NOT remove it — it is excluded).
    mirror.mkdir()
    (mirror / "stray-old-file").write_bytes(b"delete me")
    (mirror / SENTINEL).write_text("old sentinel\n", encoding="utf-8")

    r = _run("delta", active_src=active, mirror=mirror, live_home=live)
    assert r.returncode == 0, f"clean delta must succeed: {r.stderr}"

    # every source file arrived byte-identical
    for rel, data in want.items():
        got = mirror / rel
        assert got.exists(), f"{rel} not mirrored"
        assert got.read_bytes() == data, f"{rel} mirrored with wrong bytes"
    # --delete faithfulness: the stray is gone, the sentinel survived (excluded)
    assert not (mirror / "stray-old-file").exists(), "--delete must prune files absent from the source"
    # the completion sentinel is present, self-describing read-only, and freshly stamped for THIS run
    txt = _sentinel_text(mirror)
    assert txt is not None and "READ-ONLY" in txt and "Last synced" in txt and "mode: delta" in txt
    assert txt != "old sentinel\n", "the completion sentinel must be re-stamped after a successful sync"
    # the sentinel is a MIRROR artifact only — it must never be pushed back into the active source
    assert not (active / SENTINEL).exists()


# ------------------------------------------------------------------------------- (2) TORN-SYNC

def test_torn_delta_sync_is_detectably_incomplete_not_silently_partial(tmp_path, _no_writer_running):
    """(a) TORN-SYNC: interrupt the copy partway. The mirror must be DETECTABLY incomplete — the script
    exits non-zero AND never stamps the completion sentinel (so a consumer/guard can see it is not a
    finished, promotable mirror) — NEVER silently marked complete over a partial copy.

    Negative control asserted in the SAME run: with the interrupt removed, the identical harness completes,
    stamps the sentinel, and copies every file — proving the torn detection is not a no-op."""
    active = tmp_path / "active"
    want = _make_active_home(active)
    assert len(want) >= 2, "need >=2 files so an interrupted copy is genuinely partial"
    live = tmp_path / "live-home"
    shim = tmp_path / "shim"
    _install_torn_rsync(shim)

    # --- interrupted run on a FRESH mirror -----------------------------------------------------------
    torn_mirror = tmp_path / "mirror-torn"
    r = _run("delta", active_src=active, mirror=torn_mirror, live_home=live, extra_path=shim)
    assert r.returncode != 0, "an interrupted rsync must propagate failure (set -euo pipefail), not exit 0"
    # NOT silently marked complete: the read-only completion sentinel was never written.
    assert _sentinel_text(torn_mirror) is None, \
        "a torn sync must NOT stamp the completion sentinel — that would mark a partial mirror as ready"
    # and it really is partial (the interrupt copied a strict subset)
    copied = {str(p.relative_to(torn_mirror)) for p in torn_mirror.rglob("*") if p.is_file()}
    assert copied and copied != set(want), f"expected a partial mirror, got {copied}"

    # --- NEGATIVE CONTROL: same harness, real rsync -> clean, complete, marked ready -----------------
    clean_mirror = tmp_path / "mirror-clean"
    r2 = _run("delta", active_src=active, mirror=clean_mirror, live_home=live)   # no shim on PATH
    assert r2.returncode == 0, f"clean delta must succeed: {r2.stderr}"
    assert _sentinel_text(clean_mirror) is not None, "a complete sync MUST stamp the completion sentinel"
    for rel, data in want.items():
        assert (clean_mirror / rel).read_bytes() == data


# ------------------------------------------------------------------------------- (3) STALE-MIRROR

def test_stale_mirror_anchor_is_refused_fresh_is_promoted(tmp_path, _no_writer_running):
    """(b) STALE-MIRROR: the off-box witnessed anchor is TRANSPORTED by a real mirror-sync, then the
    promotion guard evaluates the mirror. An anchor older than the refusal bound is REFUSED (STALE ANCHOR,
    exit 2); a fresh one PROMOTES. Two distinct verdicts, negative control asserted in the same run —
    proving the freshness gate is real, and that the guard consumes the anchor the SCRIPT actually moved."""
    active = tmp_path / "active"
    mirror = tmp_path / "mirror"
    live = tmp_path / "live-home"
    _make_active_home(active)

    # emit the off-box witnessed anchor at t=1000 and place it in the active's state to be transported.
    entries, head = _chain(3)
    env_text = _witnessed_env_at(head, tmp_path, now=1_000)
    (active / "witnessed-anchor.json").write_text(env_text, encoding="utf-8")

    r = _run("delta", active_src=active, mirror=mirror, live_home=live)
    assert r.returncode == 0, f"clean delta must succeed: {r.stderr}"

    # the anchor arrived at the mirror byte-for-byte — the guard reads THIS transported copy.
    transported = (mirror / "witnessed-anchor.json").read_text(encoding="utf-8")
    assert transported == env_text
    assert json.loads(transported)["scope"] == SCOPE

    # STALE: evaluated well past the refusal bound -> REFUSE (exit 2)
    stale = guard.evaluate_promotion(head, transported, scope=SCOPE, trust_root=_solo_tr(),
                                     owner_trust_root=_owner_tr(), entries=entries,
                                     now=1_000 + _W7_REFUSE + 1, warn_after_s=_W7_WARN,
                                     refuse_after_s=_W7_REFUSE)
    assert not stale.activate and stale.exit_code == 2 and "STALE ANCHOR" in stale.reason
    assert stale.freshness == "stale-refuse"

    # NEGATIVE CONTROL (same run): a FRESH clock on the SAME transported anchor promotes.
    fresh = guard.evaluate_promotion(head, transported, scope=SCOPE, trust_root=_solo_tr(),
                                     owner_trust_root=_owner_tr(), entries=entries,
                                     now=1_000 + _W7_WARN - 1, warn_after_s=_W7_WARN,
                                     refuse_after_s=_W7_REFUSE)
    assert fresh.activate and fresh.exit_code == 0 and fresh.freshness == "fresh"


# --------------------------------------------- (bonus) the read-only invariant gate the sync depends on

def test_delta_refuses_when_mirror_equals_live_home(tmp_path, _no_writer_running):
    """The load-bearing safety gate: syncing onto the LIVE writer's SIGIL_HOME (mirror == live home) would
    risk a second writer / clobber. mirror-sync REFUSES (exit 2) — the negative control proving the sync is
    not an unconditional copier."""
    active = tmp_path / "active"
    _make_active_home(active)
    same = tmp_path / "same-home"
    same.mkdir()
    r = _run("delta", active_src=active, mirror=same, live_home=same)
    assert r.returncode == 2, "mirror-sync must refuse to sync onto the live SIGIL_HOME"
    assert "REFUSING" in r.stderr and _sentinel_text(same) is None
