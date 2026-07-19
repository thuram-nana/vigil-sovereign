"""SIGIL spine — Slice 5: persisted seq->offset `.idx` sidecars for O(1) cold-start get() into a sealed
segment (avoids re-scanning / fully decompressing the segment on the first indexed read). The sidecar is a
pure CACHE derived from the segment bytes — validated against the segment size, regenerated on any mismatch,
never a tamper input. Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_sidecars.py -q
"""
import json
import tempfile
from pathlib import Path

from sigil.spine.manifest import SpineLayout
from sigil.spine.store import SpineStore


def _rotated(records: int = 20, seg_max_records: int = 5) -> tuple[Path, SpineLayout]:
    d = Path(tempfile.mkdtemp(prefix="sigil-sidecar-"))
    p = d / "spine.jsonl"
    s = SpineStore(p, seg_max_bytes=0, seg_max_records=seg_max_records)
    s.migrate()
    for i in range(records):
        s.append(kind="event", source="t", actor="a", payload={"n": i})
    return p, SpineLayout.for_path(p)


def test_sidecar_written_then_loaded_correct():
    p, lay = _rotated(20)
    assert SpineStore(p).get(2).payload["n"] == 2                 # cold get -> index seg-0 -> write sidecar
    assert list(lay.segments_dir.glob("*.idx")), "a sidecar is written for the indexed sealed segment"
    # a fresh store loads the sidecar (no re-scan) and returns the correct record across all sealed segments
    assert SpineStore(p).get(2).payload["n"] == 2
    assert all(SpineStore(p).get(i).payload["n"] == i for i in range(20))
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_sidecar_stale_is_ignored_and_regenerated():
    p, lay = _rotated(20)
    SpineStore(p).get(2)                                          # write seg-0's sidecar
    sc = lay.segments_dir / "seg-00000000.jsonl.idx"
    d = json.loads(sc.read_text())
    d["seg_bytes"] = 999999                                       # pretend the segment changed -> sidecar stale
    sc.write_text(json.dumps(d))
    assert SpineStore(p).get(2).payload["n"] == 2                 # must ignore the stale sidecar, scan, regen
    assert json.loads(sc.read_text())["seg_bytes"] != 999999, "stale sidecar was regenerated"


def test_tampered_sidecar_offset_rejected_and_get_still_correct():
    """A sidecar with a valid seg_bytes but a WRONG offset must be rejected by the load-time spot-check
    (offsets[0] must point to seq==first_seq), so a bad/tampered cache can never make a read return a wrong
    record or under-count — it falls back to scanning."""
    p, lay = _rotated(20)
    SpineStore(p).get(2)
    sc = lay.segments_dir / "seg-00000000.jsonl.idx"
    d = json.loads(sc.read_text())
    d["offsets"][0] = int(d["offsets"][0]) + 5                    # corrupt the first offset; seg_bytes stays valid
    sc.write_text(json.dumps(d))
    assert SpineStore(p).get(2).payload["n"] == 2                 # spot-check rejects -> scan -> correct
    assert all(SpineStore(p).get(i).payload["n"] == i for i in range(20))
    ok, reason = SpineStore(p).verify()
    assert ok, reason


def test_sidecar_gzip_segment_decompressed_offsets():
    p, lay = _rotated(20)
    SpineStore(p).compact()                                       # sealed segments -> gzip
    # a cold get into a GZIP segment builds + persists a sidecar with DECOMPRESSED offsets, and is correct
    assert SpineStore(p).get(3).payload["n"] == 3
    assert list(lay.segments_dir.glob("*.gz.idx")), "a sidecar is written for the gz segment"
    assert all(SpineStore(p).get(i).payload["n"] == i for i in range(20))


def test_stale_plaintext_sidecar_removed_on_compact():
    p, lay = _rotated(20)
    SpineStore(p).get(2)                                          # write seg-0.jsonl.idx (plaintext)
    assert (lay.segments_dir / "seg-00000000.jsonl.idx").exists()
    SpineStore(p).compact()                                       # gzip seg-0 -> unlink seg-0.jsonl + its .idx
    assert not (lay.segments_dir / "seg-00000000.jsonl.idx").exists(), "stale plaintext sidecar removed"
    ok, reason = SpineStore(p).verify()
    assert ok, reason
    assert [r.seq for r in SpineStore(p).iter_records()] == list(range(20))
