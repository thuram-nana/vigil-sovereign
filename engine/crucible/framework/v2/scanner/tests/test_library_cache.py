"""
Speed X1 — the shipped library (~170 JSON files) is parsed ONCE per process, not re-read
at every report render / corpus row / campaign run, while remaining byte-for-byte the same
list. Arbitrary directories (test fixtures, custom packs) are always read fresh, so nobody
can observe a stale directory, and every call still hands back a private, mutable list.
"""

from __future__ import annotations

import json

import framework.v2.scanner.library as library
from framework.v2.scanner.library import LIBRARY_DIR, load_library


def _valid_entry(entry_id: str) -> dict:
    return {
        "id": entry_id, "bug_class": "xss", "title": "t", "severity": "High",
        "oracle": {"kind": "reflection", "payload_template": "{marker}"},
    }


def test_shipped_library_is_parsed_once(monkeypatch) -> None:
    library._load_shipped_library.cache_clear()
    calls = {"n": 0}
    real = library._read_library_dir

    def _counting(directory):
        calls["n"] += 1
        return real(directory)

    monkeypatch.setattr(library, "_read_library_dir", _counting)
    a = load_library()
    b = load_library()
    c = load_library()
    assert calls["n"] == 1                      # three loads, one directory read
    assert [e.id for e in a] == [e.id for e in b] == [e.id for e in c]


def test_each_call_returns_a_private_mutable_list() -> None:
    library._load_shipped_library.cache_clear()
    a = load_library()
    n = len(a)
    a.sort(key=lambda e: e.id, reverse=True)    # mutate the returned list
    a.append(a[0])
    b = load_library()
    assert len(b) == n                          # the cache was not corrupted
    assert b[0].id != a[0].id or n == 1         # b is freshly ordered, not the mutated a


def test_custom_directory_is_read_fresh_not_cached(monkeypatch, tmp_path) -> None:
    library._load_shipped_library.cache_clear()
    calls = {"n": 0}
    real = library._read_library_dir

    def _counting(directory):
        calls["n"] += 1
        return real(directory)

    monkeypatch.setattr(library, "_read_library_dir", _counting)

    (tmp_path / "a.json").write_text(json.dumps(_valid_entry("z-a")), encoding="utf-8")
    first = load_library(tmp_path)
    assert {e.id for e in first} == {"z-a"}

    # mutating the directory and reloading the SAME path must reflect the change — a custom
    # dir is never memoized, so no staleness is possible.
    (tmp_path / "b.json").write_text(json.dumps(_valid_entry("z-b")), encoding="utf-8")
    second = load_library(tmp_path)
    assert {e.id for e in second} == {"z-a", "z-b"}
    assert calls["n"] == 2                      # each custom-dir load re-reads


def test_default_dir_and_shipped_helper_agree() -> None:
    library._load_shipped_library.cache_clear()
    assert [e.id for e in load_library(LIBRARY_DIR)] == [e.id for e in load_library()]
