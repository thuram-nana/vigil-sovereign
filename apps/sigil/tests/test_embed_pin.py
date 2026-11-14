"""The embedding model pin and the golden fixture's metadata — pure checks, no onnxruntime, no network.

``sigil/vectors/embed.py`` pins the Hugging Face revision and the sha256 of the ONNX graph and the tokenizer.
Resolution is local-first BY CONTENT (a cached snapshot under any commit directory whose files match the pins
is used without network), a fetch is made at the pinned revision, and a file that does not match its pin is
refused. These tests drive that logic with tiny fake files and a fake ``huggingface_hub``, so they run in
every sigil job, including one without the sovereign ML stack. They also pin the golden fixture's metadata
to the code and to the sovereign lock, so an onnxruntime bump without a re-baseline fails here.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
import sys
import types
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "fixtures" / "bge_small_golden.json"
SOVEREIGN_LOCK = Path(__file__).resolve().parents[3] / "infra" / "supply-chain" / "sovereign.lock.txt"

FAKE = "fake/model"
REV = "0" * 40
OTHER_REV = "1" * 40
ONNX_BYTES = b"onnx-bytes"
TOK_BYTES = b'{"tokenizer": true}'


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture()
def emb(monkeypatch, tmp_path):
    m = importlib.import_module("sigil.vectors.embed")
    monkeypatch.setitem(m._ONNX_SOURCES, FAKE, {
        "repo": "fake-org/fake-onnx", "onnx": "model.onnx", "revision": REV,
        "onnx_sha256": _h(ONNX_BYTES), "tokenizer_sha256": _h(TOK_BYTES),
    })
    monkeypatch.setenv("SIGIL_EMBED_CACHE_DIR", str(tmp_path / "cache"))
    return m


def _snapshot(root: Path, rev: str, onnx: bytes = ONNX_BYTES, tok: bytes = TOK_BYTES) -> Path:
    d = root / "models--fake-org--fake-onnx" / "snapshots" / rev
    d.mkdir(parents=True, exist_ok=True)
    (d / "model.onnx").write_bytes(onnx)
    (d / "tokenizer.json").write_bytes(tok)
    return d


def _fake_hub(monkeypatch, download):
    hub = types.ModuleType("huggingface_hub")
    hub.snapshot_download = download  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "huggingface_hub", hub)


def test_the_fetch_is_made_at_the_pinned_revision(emb, monkeypatch, tmp_path):
    calls = []

    def download(**kw):
        calls.append(kw)
        return str(_snapshot(Path(kw["cache_dir"]), kw["revision"]))

    _fake_hub(monkeypatch, download)
    got = emb.resolve_model_dir(FAKE)
    assert len(calls) == 1 and calls[0]["revision"] == REV and calls[0]["repo_id"] == "fake-org/fake-onnx"
    assert calls[0]["cache_dir"] == str(tmp_path / "cache")
    assert got.endswith(REV)


def test_a_wrong_onnx_hash_is_refused(emb, monkeypatch):
    _fake_hub(monkeypatch, lambda **kw: str(_snapshot(Path(kw["cache_dir"]), kw["revision"], onnx=b"other")))
    with pytest.raises(emb.ModelIntegrityError) as ei:
        emb.resolve_model_dir(FAKE)
    assert _h(ONNX_BYTES) in str(ei.value) and _h(b"other") in str(ei.value)   # names expected AND actual


def test_a_wrong_tokenizer_hash_is_refused(emb, monkeypatch):
    _fake_hub(monkeypatch, lambda **kw: str(_snapshot(Path(kw["cache_dir"]), kw["revision"], tok=b"{}")))
    with pytest.raises(emb.ModelIntegrityError) as ei:
        emb.resolve_model_dir(FAKE)
    assert _h(TOK_BYTES) in str(ei.value) and _h(b"{}") in str(ei.value)


def test_a_missing_file_is_refused(emb, monkeypatch):
    def download(**kw):
        d = _snapshot(Path(kw["cache_dir"]), kw["revision"])
        (d / "model.onnx").unlink()
        return str(d)

    _fake_hub(monkeypatch, download)
    with pytest.raises(emb.ModelIntegrityError, match="missing"):
        emb.resolve_model_dir(FAKE)


def test_a_matching_cached_snapshot_under_another_commit_is_used_without_network(emb, monkeypatch, tmp_path):
    cached = _snapshot(tmp_path / "cache", OTHER_REV)

    def no_network(**kw):
        raise AssertionError("the network must not be touched when a matching snapshot is cached")

    _fake_hub(monkeypatch, no_network)
    assert emb.resolve_model_dir(FAKE) == str(cached)


def test_a_non_matching_cached_snapshot_is_never_used(emb, monkeypatch, tmp_path):
    _snapshot(tmp_path / "cache", OTHER_REV, onnx=b"tampered")
    _fake_hub(monkeypatch, lambda **kw: str(_snapshot(Path(kw["cache_dir"]), kw["revision"])))
    assert emb.resolve_model_dir(FAKE).endswith(REV)          # fetched + verified the pin instead


def test_unavailability_is_its_own_error(emb, monkeypatch):
    def offline(**kw):
        raise ConnectionError("offline")

    _fake_hub(monkeypatch, offline)
    with pytest.raises(emb.ModelUnavailableError) as ei:
        emb.resolve_model_dir(FAKE)
    assert not isinstance(ei.value, emb.ModelIntegrityError)


def test_an_unsupported_model_is_refused(emb):
    with pytest.raises(RuntimeError, match="not supported"):
        emb.resolve_model_dir("some/other-model")


def test_cache_dir_default_and_override(monkeypatch):
    m = importlib.import_module("sigil.vectors.embed")
    monkeypatch.delenv("SIGIL_EMBED_CACHE_DIR", raising=False)
    assert m.cache_dir() == m.CACHE_DIR / "models"
    monkeypatch.setenv("SIGIL_EMBED_CACHE_DIR", "/srv/models")
    assert m.cache_dir() == Path("/srv/models")


def test_the_shipped_pin_is_complete():
    m = importlib.import_module("sigil.vectors.embed")
    src = m._ONNX_SOURCES["BAAI/bge-small-en-v1.5"]
    assert re.fullmatch(r"[0-9a-f]{40}", src["revision"])
    assert re.fullmatch(r"[0-9a-f]{64}", src["onnx_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", src["tokenizer_sha256"])


# --- the golden fixture's metadata (pure data) -------------------------------------------------------------


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_atol_is_not_loosened(golden):
    assert golden["atol"] <= 1e-5


def test_the_fixture_records_the_shipped_pins(golden):
    src = importlib.import_module("sigil.vectors.embed")._ONNX_SOURCES[golden["model"]]
    assert golden["hf_repo"] == src["repo"]
    assert golden["hf_revision"] == src["revision"]
    assert golden["onnx_sha256"] == src["onnx_sha256"]
    assert golden["tokenizer_sha256"] == src["tokenizer_sha256"]


def test_the_fixture_was_computed_under_the_sovereign_lock_onnxruntime(golden):
    # An onnxruntime bump in the sovereign lock must re-baseline in the SAME change.
    pin = re.search(r"^onnxruntime==([^\s\;]+)", SOVEREIGN_LOCK.read_text(encoding="utf-8"), re.M)
    assert pin, f"no onnxruntime pin in {SOVEREIGN_LOCK}"
    assert golden["ort_version"] == pin.group(1), (
        f"the sovereign lock pins onnxruntime {pin.group(1)} but the golden vectors were computed under "
        f"{golden['ort_version']} — run `python -m sigil.vectors.baseline --write` under the new pin"
    )


def _cos(a, b):
    return sum(x * y for x, y in zip(a, b)) / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))


def test_previous_baseline_shift_is_below_the_reembed_threshold(golden):
    # The re-baseline moved each stored-space vector by far less than a re-embed would ever be needed for, so
    # vectors written under the previous baseline stay valid.
    baseline = importlib.import_module("sigil.vectors.baseline")
    assert baseline.REEMBED_COSINE_FLOOR == 1.0 - 1e-3
    assert len(golden["previous_vectors"]) == len(golden["vectors"]) == len(golden["texts"])
    for new, old in zip(golden["vectors"], golden["previous_vectors"]):
        assert len(new) == len(old) == golden["dim"]
        assert _cos(new, old) >= baseline.REEMBED_COSINE_FLOOR


def test_the_baseline_tool_refuses_under_another_onnxruntime(monkeypatch):
    baseline = importlib.import_module("sigil.vectors.baseline")
    monkeypatch.setattr(baseline, "_installed_ort", lambda: "0.0.0-not-the-pin")
    with pytest.raises(SystemExit, match="refusing"):
        baseline.check()
    with pytest.raises(SystemExit, match="refusing"):
        baseline.write()
