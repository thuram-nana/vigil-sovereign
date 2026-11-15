"""Golden-vector regression guard for the local ONNX embedding backend.

``sigil/vectors/embed.py`` runs onnxruntime + tokenizers over the PINNED bge-small-en-v1.5 ONNX (revision and
file hashes pinned). The golden vectors are a function of those files AND the onnxruntime release, so the
fixture records the release it was computed under — the one pinned in ``infra/supply-chain/sovereign.lock.txt``
— and is regenerated with ``python -m sigil.vectors.baseline --write`` whenever that pin moves (see
``docs/decisions/EMB-1-embedding-baseline-locked-ort.md``). At ``atol`` 1e-5 this test fails loudly if a change
(a different model, pooling, normalization, ONNX file or onnxruntime release) would silently move the vector
space and invalidate stored embeddings.

It needs the model present (onnxruntime + tokenizers + a fetchable/cached bge ONNX). It SKIPS only when the
model files are not cached and cannot be fetched (offline) — and not even then under
``VIGIL_REQUIRE_SOVEREIGN_CLOSURE=1``, which the CI jobs that install the sovereign lock set, so there a missing
model is a FAILURE. Any other error (a bad ONNX, a hash mismatch, a tokenizer failure) propagates as a failure.
The pure-data checks on the fixture live in ``test_embed_pin.py`` and run without onnxruntime.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("onnxruntime")
pytest.importorskip("tokenizers")
pytest.importorskip("huggingface_hub")
np = pytest.importorskip("numpy")

GOLDEN = Path(__file__).parent / "fixtures" / "bge_small_golden.json"


@pytest.fixture(scope="module")
def backend():
    # vectors/__init__.py binds `embed` the function over the `embed` submodule, so reach the
    # module object via importlib rather than attribute access.
    return importlib.import_module("sigil.vectors.embed")


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN.read_text())


def _model_unavailable(exc):
    """Skip ONLY for the availability condition (model neither cached nor fetchable); FAIL instead where the
    sovereign closure is required (the sovereign-lock CI jobs)."""
    if os.environ.get("VIGIL_REQUIRE_SOVEREIGN_CLOSURE") == "1":
        pytest.fail(f"bge model unavailable but VIGIL_REQUIRE_SOVEREIGN_CLOSURE=1: {exc!r}")
    pytest.skip(f"bge model unavailable in this environment: {exc!r}")


def _embed_or_skip(backend, texts):
    try:
        return backend.embed(list(texts))
    except backend.ModelUnavailableError as exc:  # offline + not cached — nothing else is skipped
        _model_unavailable(exc)


def _ort_mismatch(installed, golden):
    """The re-baseline instruction when the installed onnxruntime is not the one the fixture was computed under
    (None when they agree)."""
    if installed == golden.get("ort_version"):
        return None
    return (
        f"onnxruntime {installed} is installed but the golden vectors were computed under "
        f"{golden.get('ort_version')}: fp32 output moves by ~2e-4 between onnxruntime releases. Install the "
        "sovereign lock, or — when the lock's onnxruntime pin moved — re-baseline in the same change with "
        "`python -m sigil.vectors.baseline --write` (docs/decisions/EMB-1-embedding-baseline-locked-ort.md)."
    )


def test_ort_version_matches_the_baseline(golden):
    import onnxruntime

    problem = _ort_mismatch(onnxruntime.__version__, golden)
    assert problem is None, problem


def test_an_ort_bump_names_the_rebaseline_procedure(golden):
    msg = _ort_mismatch("1.32.0", golden)
    assert msg is not None and "sigil.vectors.baseline --write" in msg and "1.32.0" in msg


def test_golden_vectors_match(backend, golden):
    mine = np.array(_embed_or_skip(backend, golden["texts"]))
    exp = np.array(golden["vectors"])
    assert mine.shape == exp.shape == (len(golden["texts"]), golden["dim"])
    max_abs = float(np.abs(mine - exp).max())
    assert max_abs <= golden["atol"], (
        f"embedding drift: max|Δ|={max_abs:.2e} > atol={golden['atol']:.0e}. The embedding vector "
        "space moved — stored Qdrant vectors would be invalidated. If the onnxruntime pin moved, "
        "re-baseline with `python -m sigil.vectors.baseline --write`; if this is an intentional "
        "embedding migration, regenerate the golden fixture AND re-embed the corpus; otherwise it is "
        "a regression (e.g. a changed model, pooling, or ONNX file)."
    )


def test_vectors_are_l2_normalized(backend, golden):
    norms = np.linalg.norm(np.array(_embed_or_skip(backend, golden["texts"])), axis=1)
    assert np.allclose(norms, 1.0, atol=1e-5)


def test_query_embedding_uses_no_prefix(backend, golden):
    # bge-small-en-v1.5's query embedding == its passage embedding (no instruction prefix) — this
    # matched the fastembed backend exactly and MUST stay so, or queries land in a shifted space.
    text = golden["texts"][1]
    try:
        q = backend.embed_query(text)
        one = backend.embed_one(text)
    except backend.ModelUnavailableError as exc:
        _model_unavailable(exc)
    assert np.allclose(np.array(q), np.array(one), atol=0.0)


def _outcome(fn):
    """'skip' / 'fail' / 'raised:<Type>' / 'ran' — caught here so a wrong outcome fails THIS test instead of
    escaping as a Skipped that would turn the test itself into a skip."""
    try:
        fn()
    except pytest.skip.Exception:
        return "skip"
    except pytest.fail.Exception:
        return "fail"
    except Exception as exc:  # noqa: BLE001 — the outcome under test
        return f"raised:{type(exc).__name__}"
    return "ran"


def test_only_model_unavailability_is_skipped(backend, monkeypatch):
    monkeypatch.delenv("VIGIL_REQUIRE_SOVEREIGN_CLOSURE", raising=False)

    def unavailable(texts):
        raise backend.ModelUnavailableError("offline and not cached")

    def broken(texts):
        raise RuntimeError("onnx load failure")

    def tampered(texts):
        raise backend.ModelIntegrityError("hash mismatch")

    monkeypatch.setattr(backend, "embed", unavailable)
    assert _outcome(lambda: _embed_or_skip(backend, ["x"])) == "skip"
    monkeypatch.setattr(backend, "embed", broken)
    assert _outcome(lambda: _embed_or_skip(backend, ["x"])) == "raised:RuntimeError"
    monkeypatch.setattr(backend, "embed", tampered)
    assert _outcome(lambda: _embed_or_skip(backend, ["x"])) == "raised:ModelIntegrityError"


def test_a_required_sovereign_closure_turns_unavailability_into_a_failure(backend, monkeypatch):
    def unavailable(texts):
        raise backend.ModelUnavailableError("offline and not cached")

    monkeypatch.setattr(backend, "embed", unavailable)
    monkeypatch.setenv("VIGIL_REQUIRE_SOVEREIGN_CLOSURE", "1")
    assert _outcome(lambda: _embed_or_skip(backend, ["x"])) == "fail"
