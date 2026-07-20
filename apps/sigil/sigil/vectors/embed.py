"""Local, on-device embeddings via fastembed (BAAI/bge-small-en-v1.5, 384-dim, ONNX/CPU).

No API, no GPU, no cost — fully local-first (SIGIL doctrine §1.3).
"""
from __future__ import annotations

from ..config import EMBED_MODEL

_model = None


def get_model():
    global _model
    if _model is None:
        from fastembed import TextEmbedding
        _model = TextEmbedding(model_name=EMBED_MODEL)
    return _model


def embed(texts: list[str]) -> list[list[float]]:
    """Embed PASSAGES (documents to index) — plain, no instruction prefix."""
    return [list(map(float, v)) for v in get_model().embed(texts)]


def embed_query(text: str) -> list[float]:
    """Embed a QUERY with bge's retrieval instruction prefix (proper query↔passage
    separation). Falls back to plain embed if the model lacks query_embed."""
    m = get_model()
    fn = getattr(m, "query_embed", None)
    if fn is not None:
        return list(map(float, next(iter(fn([text])))))
    return list(map(float, next(iter(m.embed([text])))))


def embed_one(text: str) -> list[float]:
    return list(map(float, next(iter(get_model().embed([text])))))
