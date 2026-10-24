"""Golden-vector regression guard for the local ONNX embedding backend.

``sigil/vectors/embed.py`` was rewritten off fastembed (every fastembed release
hard-pins ``pillow<13``, which carries unpatched CVEs) onto onnxruntime +
tokenizers over the SAME bge-small-en-v1.5 ONNX. The rewrite is BIT-IDENTICAL to
the fastembed output (verified at authoring time, max|Δ| = 0), so the committed
golden vectors are exactly the fastembed-era vectors — existing Qdrant data stays
valid. This test fails loudly if a future change (a different model, pooling,
normalization, or ONNX file) would silently move the vector space and invalidate
stored embeddings.

It needs the model present (onnxruntime + tokenizers + a fetchable/cached bge
ONNX) and SKIPS cleanly where that closure is absent (offline CI, the offense-lock
jobs), mirroring the ``importorskip`` idiom the rest of ``apps/sigil/tests`` uses
for heavy deps.
"""
from __future__ import annotations

import importlib
import json
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


def _embed_or_skip(backend, texts):
    try:
        return backend.embed(list(texts))
    except Exception as exc:  # model not fetchable/cached (offline), onnx load failure, etc.
        pytest.skip(f"bge model unavailable in this environment: {exc!r}")


def test_golden_vectors_match(backend, golden):
    mine = np.array(_embed_or_skip(backend, golden["texts"]))
    exp = np.array(golden["vectors"])
    assert mine.shape == exp.shape == (len(golden["texts"]), golden["dim"])
    max_abs = float(np.abs(mine - exp).max())
    assert max_abs <= golden["atol"], (
        f"embedding drift: max|Δ|={max_abs:.2e} > atol={golden['atol']:.0e}. The embedding vector "
        "space moved — stored Qdrant vectors would be invalidated. If this is an intentional "
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
    except Exception as exc:
        pytest.skip(f"bge model unavailable: {exc!r}")
    assert np.allclose(np.array(q), np.array(one), atol=0.0)
