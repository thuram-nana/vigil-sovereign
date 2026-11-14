"""Local, on-device embeddings for BAAI/bge-small-en-v1.5 (384-dim, ONNX/CPU).

No API, no GPU, no cost — fully local-first (SIGIL doctrine §1.3).

Backend: onnxruntime + tokenizers directly, over the SAME quantized ONNX that
fastembed shipped for this model (``qdrant/bge-small-en-v1.5-onnx-q`` /
``model_optimized.onnx``). fastembed was dropped because every fastembed release
hard-requires ``pillow<13`` as a core dependency (for its image-embedding models,
which SIGIL never uses), and pillow<13 carries unpatched CVEs with no installable
fix — this backend removes that dependency entirely. At the switch its output
matched fastembed's (max|Δ| = 0.0 for passages and queries).

Pinned model files. The Hugging Face revision AND the sha256 of the ONNX graph and
of ``tokenizer.json`` are pinned in ``_ONNX_SOURCES``: different files mean a
different vector space, so a cached or downloaded file whose hash does not match
the pin is REFUSED (:class:`ModelIntegrityError`, naming the expected and actual
hash) and never embedded with. Resolution is LOCAL-FIRST BY CONTENT: any cached
snapshot of the repo whose files match the pinned hashes is used as-is with no
network, so an existing cache (fetched before the pin, under any commit directory)
and an offline host keep working.

Reproducibility is a property of (model files, onnxruntime version). With the files
fixed, the fp32 output still moves by ~2e-4 between onnxruntime releases, while one
release is stable across x86 ISAs. The golden fixture
(``apps/sigil/tests/fixtures/bge_small_golden.json``) therefore records the
onnxruntime version it was computed under, ``python -m sigil.vectors.baseline``
checks or regenerates it under the sovereign-lock pin, and an onnxruntime bump
re-runs that tool in the same change
(``docs/decisions/EMB-1-embedding-baseline-locked-ort.md``).

Pipeline (exactly fastembed's for this model): WordPiece tokenize (max_len 512,
pad_id 0) -> ONNX forward -> take the [CLS] token of last_hidden_state -> L2
normalize. fastembed's ``query_embed`` for bge-small-en-v1.5 applies NO instruction
prefix (queries are embedded identically to passages), so neither does this module.

Cache location: ``SIGIL_EMBED_CACHE_DIR`` overrides where the model files are
cached (default ``$SIGIL_HOME/cache/models``), e.g. so CI can keep the cache outside
a throwaway SIGIL_HOME. Production leaves it unset.
"""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Optional

from ..config import CACHE_DIR, EMBED_MODEL

# model_name -> where its ONNX comes from, pinned. These are the artifacts fastembed resolved for these
# models; a model not listed raises rather than silently embedding into a different vector space than the
# stored data. ``revision`` is the Hugging Face commit the files are fetched at (model_optimized.onnx is
# unchanged since the repo's 2024-01 commit); the sha256 pins are what decides — the revision only says
# where to fetch from.
_ONNX_SOURCES: dict[str, dict[str, str]] = {
    "BAAI/bge-small-en-v1.5": {
        "repo": "qdrant/bge-small-en-v1.5-onnx-q",
        "onnx": "model_optimized.onnx",
        "revision": "aa8f8b060edb00e03bfdd08813a2949946c8ba55",
        "onnx_sha256": "51f1bd0addd6e859e42c2c8021a5e5461385bb676a649f4b269aa445449f2431",
        "tokenizer_sha256": "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
    },
}
_TOKENIZER_FILE = "tokenizer.json"
_EXTRA_FILES = ("config.json", "tokenizer_config.json", "special_tokens_map.json")
_CACHE_ENV = "SIGIL_EMBED_CACHE_DIR"
_MAX_LEN = 512

_lock = threading.Lock()
_session = None
_tokenizer = None


class ModelUnavailableError(RuntimeError):
    """The pinned model files are neither cached nor fetchable right now (offline, hub unreachable, no cache).
    An availability condition — distinct from :class:`ModelIntegrityError`."""


class ModelIntegrityError(RuntimeError):
    """A model file does not match its pinned sha256 (or is missing from a snapshot). Fail-closed: a different
    file would embed into a different vector space than the stored data."""


def _source(model: Optional[str] = None) -> dict[str, str]:
    name = EMBED_MODEL if model is None else model
    try:
        return _ONNX_SOURCES[name]
    except KeyError as e:
        raise RuntimeError(
            f"SIGIL_EMBED_MODEL={name!r} is not supported by the local ONNX "
            f"embedding backend (supported: {sorted(_ONNX_SOURCES)}). Set it back to a "
            f"supported model or add its ONNX source to sigil/vectors/embed.py."
        ) from e


def cache_dir() -> Path:
    """Where the model files are cached: ``SIGIL_EMBED_CACHE_DIR``, else ``$SIGIL_HOME/cache/models``."""
    override = os.environ.get(_CACHE_ENV, "").strip()
    return Path(override).expanduser() if override else CACHE_DIR / "models"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pins(src: dict[str, str]) -> tuple[tuple[str, str], ...]:
    # tokenizer first: it is small, so a non-matching snapshot is rejected before the 66 MB graph is hashed
    return ((_TOKENIZER_FILE, src["tokenizer_sha256"]), (src["onnx"], src["onnx_sha256"]))


def _mismatches(snapshot: Path, src: dict[str, str]) -> list[str]:
    out = []
    for name, want in _pins(src):
        f = snapshot / name
        got = _sha256(f) if f.is_file() else "missing"
        if got != want:
            out.append(f"{name}: expected sha256 {want}, got {got}")
            break  # one mismatch decides; skip hashing the rest
    return out


def _verify(snapshot: Path, src: dict[str, str]) -> None:
    bad = _mismatches(snapshot, src)
    if bad:
        raise ModelIntegrityError(
            f"embedding model files in {snapshot} do not match the pinned hashes ({'; '.join(bad)}). "
            "Refusing to embed: a different file means a different vector space than the stored vectors. "
            "Remove the snapshot to re-fetch the pinned revision, or, for an intentional model change, "
            "update the pins in sigil/vectors/embed.py together with the golden fixture "
            "(python -m sigil.vectors.baseline --write)."
        )


def _cached_snapshot(root: Path, src: dict[str, str]) -> Optional[Path]:
    """A cached snapshot of ``src``'s repo (ANY commit directory) whose files match the pins — the pinned
    revision's directory is tried first. None when no cached snapshot matches."""
    snaps = root / ("models--" + src["repo"].replace("/", "--")) / "snapshots"
    if not snaps.is_dir():
        return None
    pinned = snaps / src["revision"]
    candidates = ([pinned] if pinned.is_dir() else []) + sorted(
        d for d in snaps.iterdir() if d.is_dir() and d.name != src["revision"])
    for d in candidates:
        if not _mismatches(d, src):
            return d
    return None


def _unavailable_errors() -> tuple[type[BaseException], ...]:
    errs: list[type[BaseException]] = [ConnectionError, TimeoutError]
    try:
        from huggingface_hub.errors import HfHubHTTPError, LocalEntryNotFoundError, OfflineModeIsEnabled
        errs += [LocalEntryNotFoundError, OfflineModeIsEnabled, HfHubHTTPError]
    except ImportError:  # an older hub without the errors module — fall back to the builtin classes
        pass
    return tuple(errs)


def resolve_model_dir(model: Optional[str] = None) -> str:
    """The directory holding the PINNED, hash-verified model files. Local-first by content (no network when
    a matching snapshot is cached); otherwise fetch the pinned revision and verify it. Raises
    :class:`ModelUnavailableError` when the files can be neither found nor fetched, and
    :class:`ModelIntegrityError` when what was found or fetched does not match the pins."""
    src = _source(model)
    root = cache_dir()
    hit = _cached_snapshot(root, src)
    if hit is not None:
        return str(hit)
    from huggingface_hub import snapshot_download

    try:
        local = snapshot_download(
            repo_id=src["repo"],
            revision=src["revision"],
            cache_dir=str(root),
            allow_patterns=[src["onnx"], _TOKENIZER_FILE, *_EXTRA_FILES],
        )
    except _unavailable_errors() as e:
        raise ModelUnavailableError(
            f"the pinned embedding model {src['repo']}@{src['revision']} is not cached under {root} and "
            f"could not be fetched: {e!r}"
        ) from e
    _verify(Path(local), src)
    return str(local)


def prefetch(model: Optional[str] = None) -> str:
    """Fetch (if needed) and verify the pinned model files into the cache WITHOUT loading them; return the
    snapshot directory. For a deploy or CI step that warms the cache before going offline."""
    return resolve_model_dir(model)


def _load():
    """Resolve + load the ONNX session and tokenizer once (thread-safe, lazy)."""
    global _session, _tokenizer
    if _session is not None:
        return
    with _lock:
        if _session is not None:
            return
        import onnxruntime as ort
        from tokenizers import Tokenizer

        src = _source()
        local = resolve_model_dir()
        tok = Tokenizer.from_file(os.path.join(local, _TOKENIZER_FILE))
        tok.enable_truncation(max_length=_MAX_LEN)
        tok.enable_padding(pad_id=0, pad_token="[PAD]")
        sess = ort.InferenceSession(
            os.path.join(local, src["onnx"]), providers=["CPUExecutionProvider"]
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
