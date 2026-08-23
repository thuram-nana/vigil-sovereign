"""
S9c re-work — the ONE shared, fail-closed inconclusive-manifest parser.

The schema used to be hand-duplicated in the writer + two readers. It now lives in
``framework.v2.inconclusive_manifest``; the dossier reader, the console proof-list reader and the posture
attestation all go through it, so producer and readers cannot drift.

FAIL-CLOSED is the load-bearing property: the writer only ever emits this file on a GENUINE inconclusive, so
its mere PRESENCE means the run is coverage-incomplete. A present-but-WRONG-SHAPE artifact that is still
valid JSON (``{}``, ``[]``, ``{"foo": "bar"}``, ``{"inconclusive": []}``, a garbage-row list) used to read
coverage_incomplete=False (clean) — the exact silent-CLEAN a sound-negative product must never make. It now
fails CLOSED (coverage_incomplete=True), naming nothing (``unparsed``) so the caller shows the generic
notice. Only ABSENT or EMPTY is clean.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2 import inconclusive_manifest as M
from framework.v2.console import api
from framework.v2.report import dossier as D


def _write(rd: Path, text: str) -> None:
    (rd / M.INCONCLUSIVE_ARTIFACT).write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# fail-closed schema: a present-but-not-a-valid-manifest artifact blocks clean
# ---------------------------------------------------------------------------

WRONG_SHAPE = [
    "{}",                                   # a JSON object with no manifest key
    "[]",                                   # a JSON array, not the object the schema requires
    '{"foo": "bar"}',                       # an object of the wrong shape
    '{"inconclusive": []}',                 # the key, but an empty list the writer never emits
    '{"inconclusive": ["garbage"]}',        # the key, but a non-dict row
    '{"inconclusive": [{"missing_prerequisite": "x"}]}',   # a row with no sensor
    '{"inconclusive": [{"sensor": "cloud_live"}, "garbage"]}',  # a valid row + a garbage row
    "{ corrupt",                            # unparseable bytes
]


@pytest.mark.parametrize("body", WRONG_SHAPE)
def test_wrong_shape_present_artifact_fails_closed(tmp_path: Path, body: str) -> None:
    _write(tmp_path, body)
    m = M.read_manifest(tmp_path)
    assert m["present"] is True
    assert m["coverage_incomplete"] is True, f"a present artifact must block clean: {body!r}"
    assert m["valid"] is False and m["unparsed"] is True
    assert m["surfaces"] == []


def test_absent_and_empty_are_clean(tmp_path: Path) -> None:
    assert M.read_manifest(tmp_path)["coverage_incomplete"] is False       # absent
    _write(tmp_path, "   \n")
    m = M.read_manifest(tmp_path)                                          # empty file
    assert m["present"] is False and m["coverage_incomplete"] is False


def test_valid_manifest_is_named_and_incomplete(tmp_path: Path) -> None:
    _write(tmp_path, json.dumps({"inconclusive": [
        {"sensor": "k8s_live", "missing_prerequisite": "kubeconfig", "count": 1},
        {"sensor": "cloud_live", "missing_prerequisite": "aws creds", "count": 2}]}))
    m = M.read_manifest(tmp_path)
    assert m["valid"] is True and m["coverage_incomplete"] is True and m["unparsed"] is False
    assert [s["sensor"] for s in m["surfaces"]] == ["cloud_live", "k8s_live"]   # sorted


# ---------------------------------------------------------------------------
# dedup: the writer round-trips through the shared reader, and both consumers agree
# ---------------------------------------------------------------------------


def test_writer_reader_roundtrip(tmp_path: Path) -> None:
    assert M.write_manifest(tmp_path, [("cloud_live", "aws creds"), ("cloud_live", "aws creds")]) is True
    m = M.read_manifest(tmp_path)
    assert m["surfaces"] == [{"sensor": "cloud_live", "missing_prerequisite": "aws creds", "count": 2}]


@pytest.mark.parametrize("body", WRONG_SHAPE + ['{"inconclusive": [{"sensor": "cloud_live", '
                                                '"missing_prerequisite": "aws creds", "count": 1}]}'])
def test_all_consumers_share_one_verdict(tmp_path: Path, body: str) -> None:
    """The dossier reader and the console reader must derive the SAME coverage-incomplete verdict as the
    shared parser for every input — the whole point of collapsing the duplicated schema into one reader."""
    _write(tmp_path, body)
    shared = M.read_manifest(tmp_path)["coverage_incomplete"]
    assert D._read_sensor_inconclusive(tmp_path)["coverage_incomplete"] is shared
    assert api._sensor_inconclusive_summary(tmp_path)["coverage_incomplete"] is shared
