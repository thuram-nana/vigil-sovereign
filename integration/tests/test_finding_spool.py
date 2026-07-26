"""P5b — the offense-side spool producer (`vigil_integration.finding_spool`). It only WRITES a pre-built
inert envelope into the seam safely; the sovereign watcher does the real verification. Invariants:
  * 0600 file inside a 0700 incoming/ dir, published via an atomic temp→rename (no partial file is ever
    visible to the watcher), content-derived name (idempotent re-spool);
  * fail-closed on obviously-bad input (non-str, empty, oversized, non-JSON, no 'schema') BEFORE any write;
  * boundary: this producer imports NO framework/strix/sigil (it is vigil_core-safe integration glue).
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from vigil_integration.finding_spool import incoming_dir, spool_envelope
from vigil_integration.inert_finding import MAX_ENVELOPE_BYTES

ENV = json.dumps({"schema": "vigil.inert-finding.v1", "certificate": {"finding_ref": "x"}, "signatures": []})


def test_writes_0600_file_in_0700_incoming(tmp_path):
    p = spool_envelope(str(tmp_path), ENV)
    assert p.parent == incoming_dir(str(tmp_path))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(p.parent).st_mode) == 0o700
    assert json.loads(p.read_text(encoding="utf-8"))["schema"] == "vigil.inert-finding.v1"


def test_name_is_content_derived_and_idempotent(tmp_path):
    p1 = spool_envelope(str(tmp_path), ENV)
    p2 = spool_envelope(str(tmp_path), ENV)          # same bytes → same path (idempotent re-spool)
    assert p1 == p2
    assert len(list(incoming_dir(str(tmp_path)).glob("*.json"))) == 1
    other = spool_envelope(str(tmp_path), json.dumps({"schema": "vigil.inert-finding.v1", "n": 2}))
    assert other != p1                                # different bytes → different path


def test_no_partial_file_visible(tmp_path):
    # only fully-written *.json land; the atomic rename means the watcher never sees a .tmp- as a *.json
    spool_envelope(str(tmp_path), ENV)
    names = [q.name for q in incoming_dir(str(tmp_path)).iterdir()]
    assert all(not n.startswith(".tmp-") for n in names)


@pytest.mark.parametrize("bad", [b"bytes-not-str", 123, None, {"a": 1}])
def test_non_str_envelope_refused(tmp_path, bad):
    with pytest.raises(TypeError):
        spool_envelope(str(tmp_path), bad)


def test_empty_oversized_and_non_json_refused(tmp_path):
    with pytest.raises(ValueError):
        spool_envelope(str(tmp_path), "   ")
    with pytest.raises(ValueError):
        spool_envelope(str(tmp_path), "x" * (MAX_ENVELOPE_BYTES + 1))
    with pytest.raises(ValueError):
        spool_envelope(str(tmp_path), "{not json")
    with pytest.raises(ValueError):
        spool_envelope(str(tmp_path), json.dumps([1, 2, 3]))          # not a JSON object
    with pytest.raises(ValueError):
        spool_envelope(str(tmp_path), json.dumps({"no": "schema"}))    # missing 'schema'
    assert list(incoming_dir(str(tmp_path)).glob("*.json")) == []      # nothing written on any refusal


def test_producer_imports_no_offense_or_sovereign_engine():
    import sys
    import vigil_integration.finding_spool  # noqa: F401
    leaked = [m for m in sys.modules if m.split(".")[0] in ("framework", "strix", "sigil")]
    assert leaked == [], f"the offense spool producer must stay vigil_core-safe: {leaked}"
