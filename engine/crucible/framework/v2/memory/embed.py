"""
memory.embed — embeddings for similarity search.

Two backends ship in this session:

    LexicalEmbedder           — default. Pure-stdlib feature-hashing TF
                                 vectorizer. 256 dims, deterministic,
                                 no network, no model download.
                                 Quality: lexical similarity only —
                                 finds engagements with overlapping
                                 vocabulary, not semantic neighbours.
    SentenceTransformerEmbedder — optional. Activates if
                                 `sentence-transformers` is importable.
                                 Default model: all-MiniLM-L6-v2 (384
                                 dims, ~80MB on first use).

Selection (WS-G: lexical is the deterministic DEFAULT; semantic is opt-in):
  - unset (default)                         → lexical  (deterministic, even if
                                              sentence-transformers is installed)
  - CRUCIBLE_EMBEDDER=lexical               → force lexical
  - CRUCIBLE_EMBEDDER=sentence-transformers → force ST (raises if missing)
        (aliases: st, semantic)
  - CRUCIBLE_EMBEDDER=auto                  → ST if importable else lexical
        (opt-in "best available"; makes embeddings model-dependent)

Rationale: an optional heavy dep must not silently change the default/replayed
path. Under the old "unset → ST if importable" rule, merely pip-installing
sentence-transformers would swap the default embeddings to a nondeterministic,
downloaded model. Now the default is always the deterministic lexical embedder;
callers that want semantic neighbours ask for it by name. Probe availability
with ``common.capabilities.has_semantic()``.

Vectors round-trip through SQLite as BLOB via array('f').tobytes().
"""

from __future__ import annotations

import abc
import array
import hashlib
import math
import os
import re
from functools import lru_cache

from ..common import logging as v2log
from ..common.numerics import hashed_bincount


_log = v2log.get_logger(__name__)


# ---------------------------------------------------------------------------
# Vector helpers
# ---------------------------------------------------------------------------


def vec_to_blob(vec: list[float]) -> bytes:
    return array.array("f", vec).tobytes()


def blob_to_vec(blob: bytes) -> list[float]:
    a = array.array("f")
    a.frombytes(blob)
    return list(a)


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


# ---------------------------------------------------------------------------
# Embedder interface
# ---------------------------------------------------------------------------


class Embedder(abc.ABC):
    name: str = "abstract"
    dim: int = 0

    @abc.abstractmethod
    def embed(self, text: str) -> list[float]: ...

    def embed_blob(self, text: str) -> bytes:
        return vec_to_blob(self.embed(text))


# ---------------------------------------------------------------------------
# LexicalEmbedder — default
# ---------------------------------------------------------------------------

# Tiny stopword list. Targeted at offensive-security text rather than
# generic English; aggressive stoplists distort the lexical fingerprint.
_STOPWORDS: frozenset[str] = frozenset({
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "for",
    "to", "of", "in", "on", "at", "by", "with", "from", "as", "is",
    "are", "be", "been", "being", "this", "that", "these", "those",
    "it", "its", "i", "you", "we", "they", "he", "she",
})

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,}")


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    for m in _TOKEN_RE.finditer(text.lower()):
        t = m.group(0)
        if t not in _STOPWORDS and len(t) >= 2:
            out.append(t)
    return out


class LexicalEmbedder(Embedder):
    """Feature-hashing TF vectorizer. 256-dim, L2-normalized, signed."""

    name = "lexical-256"
    dim = 256

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _index_and_sign(self, token: str) -> tuple[int, int]:
        """Stable hash via SHA-1 (independent of PYTHONHASHSEED)."""
        h = hashlib.sha1(token.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "big") % self.dim
        sign = 1 if (h[4] & 1) == 0 else -1
        return idx, sign

    def embed(self, text: str) -> list[float]:
        tokens = _tokenize(text)
        if not tokens:
            return [0.0] * self.dim
        # Feature-hash each token to a (bucket, sign) pair, then scatter-add.
        # The scatter-add is pure integer accumulation, so the optional numpy
        # fast path in ``hashed_bincount`` is byte-identical to the loop.
        indices: list[int] = []
        signs: list[int] = []
        for t in tokens:
            i, s = self._index_and_sign(t)
            indices.append(i)
            signs.append(s)
        vec = hashed_bincount(indices, signs, self.dim)
        # L2 normalize so cosine == dot product
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]


# ---------------------------------------------------------------------------
# SentenceTransformerEmbedder — optional
# ---------------------------------------------------------------------------


class SentenceTransformerEmbedder(Embedder):
    """Wraps sentence-transformers. Loads the model lazily."""

    name = "sentence-transformers"
    dim = 384  # all-MiniLM-L6-v2 default; overridden after model load

    def __init__(self, model_name: str | None = None) -> None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "sentence-transformers is not installed. "
                "Install with: pip install sentence-transformers"
            ) from e
        self.model_name = model_name or os.environ.get(
            "CRUCIBLE_ST_MODEL", "all-MiniLM-L6-v2"
        )
        self.name = f"st:{self.model_name}"
        self._model = SentenceTransformer(self.model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, text: str) -> list[float]:
        v = self._model.encode([text], normalize_embeddings=True)[0]
        return [float(x) for x in v]


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_embedder() -> Embedder:
    pref = os.environ.get("CRUCIBLE_EMBEDDER", "").strip().lower()

    if pref in ("sentence-transformers", "st", "semantic"):
        # Explicit opt-in: use the semantic backend, raising if it is absent
        # (the caller asked for it by name — fail loudly, don't silently
        # downgrade).
        return SentenceTransformerEmbedder()

    if pref == "auto":
        # Opt-in "best available": semantic if importable, else lexical. NOT
        # the default — a consumer (e.g. cross-engagement recall that wants
        # richer neighbours) selects it explicitly and accepts that its
        # embeddings become model-dependent.
        try:
            st = SentenceTransformerEmbedder()
            _log.info("memory.embed.selected", embedder=st.name, dim=st.dim, reason="auto-st")
            return st
        except ImportError:
            lex = LexicalEmbedder()
            _log.info(
                "memory.embed.selected",
                embedder=lex.name,
                dim=lex.dim,
                reason="auto-lexical-fallback",
                note="sentence-transformers not installed",
            )
            return lex

    # Default (unset or "lexical"): the deterministic, dependency-free lexical
    # embedder. This is the DEFAULT even when sentence-transformers happens to
    # be installed, so the default/replayed path stays deterministic and
    # byte-identical regardless of the environment. Semantic is opt-in above.
    lex = LexicalEmbedder()
    if pref not in ("", "lexical"):
        _log.info(
            "memory.embed.selected",
            embedder=lex.name,
            dim=lex.dim,
            reason="default-lexical",
            note=f"unrecognized CRUCIBLE_EMBEDDER={pref!r}; using deterministic default",
        )
    return lex


def reset_cache() -> None:
    get_embedder.cache_clear()
