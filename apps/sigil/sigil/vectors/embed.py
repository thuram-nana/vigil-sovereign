"""Local, on-device embeddings for BAAI/bge-small-en-v1.5 (384-dim, ONNX/CPU).

No API, no GPU, no cost — fully local-first (SIGIL doctrine §1.3).

Backend: onnxruntime + tokenizers directly, over the SAME quantized ONNX that
fastembed shipped for this model (``qdrant/bge-small-en-v1.5-onnx-q`` /
``model_optimized.onnx``). fastembed was dropped because every fastembed release
hard-requires ``pillow<13`` as a core dependency (for its image-embedding models,
which SIGIL never uses), and pillow<13 carries unpatched CVEs with no installable
fix — this backend removes that dependency entirely while producing BIT-IDENTICAL
vectors (verified max|Δ| = 0.0 against fastembed for both passages and queries),
so existing Qdrant vectors stay valid with no re-embedding.

Pipeline (exactly fastembed's for this model): WordPiece tokenize (max_len 512,
pad_id 0) -> ONNX forward -> take the [CLS] token of last_hidden_state -> L2
normalize. fastembed's ``query_embed`` for bge-small-en-v1.5 applies NO instruction
prefix (queries are embedded identically to passages), so neither does this module.
"""
from __future__ import annotations

import threading

from ..config import CACHE_DIR, EMBED_MODEL

# model_name -> (HF repo that ships the ONNX, the onnx file within it). These are the
# same artifacts fastembed resolved for these models; a model not listed raises rather
# than silently embedding into a different vector space than the stored data.
_ONNX_SOURCES = {
    "BAAI/bge-small-en-v1.5": ("qdrant/bge-small-en-v1.5-onnx-q", "model_optimized.onnx"),
}
_MAX_LEN = 512

_lock = threading.Lock()
_session = None
_tokenizer = None


def _load():
    """Resolve + load the ONNX session and tokenizer once (thread-safe, lazy)."""
    global _session, _tokenizer
    if _session is not None:
        return
    with _lock:
        if _session is not None:
            return
        import os

        import onnxruntime as ort
        from huggingface_hub import snapshot_download
        from tokenizers import Tokenizer

        try:
            repo, onnx_file = _ONNX_SOURCES[EMBED_MODEL]
        except KeyError as e:
            raise RuntimeError(
                f"SIGIL_EMBED_MODEL={EMBED_MODEL!r} is not supported by the local ONNX "
                f"embedding backend (supported: {sorted(_ONNX_SOURCES)}). Set it back to a "
                f"supported model or add its ONNX source to sigil/vectors/embed.py."
            ) from e

        local = snapshot_download(
            repo_id=repo,
            cache_dir=str(CACHE_DIR / "models"),
            allow_patterns=[onnx_file, "tokenizer.json", "config.json",
                            "tokenizer_config.json", "special_tokens_map.json"],
        )
        tok = Tokenizer.from_file(os.path.join(local, "tokenizer.json"))
        tok.enable_truncation(max_length=_MAX_LEN)
        tok.enable_padding(pad_id=0, pad_token="[PAD]")
        sess = ort.InferenceSession(
            os.path.join(local, onnx_file), providers=["CPUExecutionProvider"]
        )
        _tokenizer, _session = tok, sess


def get_model():
    """Trigger load and return the ONNX InferenceSession (compat shim)."""
    _load()
    return _session


def _embed_batch(texts: list[str]):
    """[CLS]-pool + L2-normalize a batch -> numpy float array (bge pipeline)."""
    import numpy as np

    _load()
    assert _session is not None and _tokenizer is not None  # _load() populates both or raises
    encs = _tokenizer.encode_batch(list(texts))
    input_ids = np.array([e.ids for e in encs], dtype=np.int64)
    attention_mask = np.array([e.attention_mask for e in encs], dtype=np.int64)
    token_type_ids = np.array([e.type_ids for e in encs], dtype=np.int64)
    out = _session.run(
        ["last_hidden_state"],
        {"input_ids": input_ids, "attention_mask": attention_mask, "token_type_ids": token_type_ids},
    )[0]
    cls = out[:, 0]  # [CLS] token — bge pooling (padding-invariant under the attention mask)
    norm = np.linalg.norm(cls, axis=1, keepdims=True)
    norm[norm == 0] = 1e-12
    return cls / norm


def embed(texts: list[str]) -> list[list[float]]:
    """Embed PASSAGES (documents to index) — plain, no instruction prefix."""
    return [list(map(float, v)) for v in _embed_batch(list(texts))]


def embed_query(text: str) -> list[float]:
    """Embed a QUERY. bge-small-en-v1.5's query embedding uses no instruction prefix
    (identical to a passage), matching the previous fastembed backend exactly."""
    return list(map(float, _embed_batch([text])[0]))


def embed_one(text: str) -> list[float]:
    return list(map(float, _embed_batch([text])[0]))
