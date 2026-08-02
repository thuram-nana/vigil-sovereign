"""VF-1b — the durable, file-backed anti-rollback high-water floor (`vigil_core.highwater`).

Proves the namespace-pure floor: it loads/absents cleanly, is UPWARD-ONLY under a downgrade guard, uses
``entry_count`` as the PRIMARY monotonic quantity (catching the 0-indexed ``last_seq`` degeneracy), writes
atomically at 0600, and fails CLOSED on a corrupt-but-present floor.

Run: pytest packages/core/vigil_core/tests/test_highwater.py -q
"""
import json
import os
import stat
from types import SimpleNamespace

import pytest

from vigil_core import (
    HighWaterDowngrade, HighWaterError, advance_highwater, check_highwater, load_highwater,
)


def _head(entry_count: int, last_seq: int) -> SimpleNamespace:
    # check_highwater / advance_highwater read only .entry_count and .last_seq.
    return SimpleNamespace(entry_count=entry_count, last_seq=last_seq)


def test_absent_floor_loads_none(tmp_path):
    assert load_highwater(tmp_path / "hw.json") is None


def test_advance_then_load_roundtrips(tmp_path):
    p = tmp_path / "hw.json"
    written = advance_highwater(p, _head(entry_count=3, last_seq=2))
    assert written == {"schema_version": 1, "entry_count": 3, "last_seq": 2}
    assert load_highwater(p) == {"entry_count": 3, "last_seq": 2}


def test_advance_is_upward_only_and_monotonic(tmp_path):
    p = tmp_path / "hw.json"
    advance_highwater(p, _head(2, 1))
    advance_highwater(p, _head(5, 4))          # upward: fine
    assert load_highwater(p) == {"entry_count": 5, "last_seq": 4}
    # equal is allowed (idempotent re-advance of the same head)
    advance_highwater(p, _head(5, 4))
    assert load_highwater(p) == {"entry_count": 5, "last_seq": 4}


def test_downgrade_raises_typed_error_and_does_not_write(tmp_path):
    p = tmp_path / "hw.json"
    advance_highwater(p, _head(5, 4))
    with pytest.raises(HighWaterDowngrade):
        advance_highwater(p, _head(3, 2))       # both fields lower → refused
    assert load_highwater(p) == {"entry_count": 5, "last_seq": 4}   # floor unchanged


def test_entry_count_is_the_primary_guard_catching_1_to_0(tmp_path):
    # last_seq is 0 for BOTH a 1-record chain (entry_count=1) and an empty chain (entry_count=0), so a 1->0
    # truncation slips a last_seq-only check but MUST be caught by the entry_count guard.
    p = tmp_path / "hw.json"
    advance_highwater(p, _head(entry_count=1, last_seq=0))
    ok, msg = check_highwater(_head(entry_count=0, last_seq=0), load_highwater(p))
    assert not ok and "entry_count" in msg
    with pytest.raises(HighWaterDowngrade):
        advance_highwater(p, _head(entry_count=0, last_seq=0))


def test_check_highwater_last_seq_guard(tmp_path):
    ok, msg = check_highwater(_head(10, 3), {"entry_count": 10, "last_seq": 7})
    assert not ok and "last_seq" in msg


def test_check_highwater_none_floor_passes():
    ok, msg = check_highwater(_head(0, 0), None)
    assert ok


def test_corrupt_present_floor_fails_closed_not_absent(tmp_path):
    p = tmp_path / "hw.json"
    p.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(HighWaterError):
        load_highwater(p)


def test_shape_invalid_floor_fails_closed(tmp_path):
    p = tmp_path / "hw.json"
    # a bool must not masquerade as a count (bool is an int subclass); a missing field is rejected.
    p.write_text(json.dumps({"entry_count": True, "last_seq": 0}), encoding="utf-8")
    with pytest.raises(HighWaterError):
        load_highwater(p)
    p.write_text(json.dumps({"last_seq": 0}), encoding="utf-8")
    with pytest.raises(HighWaterError):
        load_highwater(p)
    p.write_text(json.dumps({"entry_count": -1, "last_seq": 0}), encoding="utf-8")
    with pytest.raises(HighWaterError):
        load_highwater(p)


def test_floor_is_written_0600(tmp_path):
    p = tmp_path / "hw.json"
    advance_highwater(p, _head(1, 0))
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, oct(mode)


def test_advance_creates_parent_dir(tmp_path):
    p = tmp_path / "nested" / "sub" / "hw.json"
    advance_highwater(p, _head(2, 1))
    assert load_highwater(p) == {"entry_count": 2, "last_seq": 1}
