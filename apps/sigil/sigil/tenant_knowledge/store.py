"""Per-tenant customer KNOWLEDGE corpus - the customer uploads their own organization documents so the system knows
their org, scoped STRICTLY to one tenant.

This module REUSES sigil's own sovereign memory CODE - the local ONNX embeddings (``vectors.embed``), the Qdrant
vector-space + scoring (``vectors.index`` constants), the append-only signed spine (``spine.store.SpineStore``) and the
document chunker (``ingest.docs._chunks``) - but it NEVER reuses the owner's global single-tenant DATA stores. Every
store is keyed to ONE org:

  * a PER-ORG spine at ``CUSTOMER_KNOWLEDGE_DIR/<h>/spine/spine.jsonl`` (never ``config.SPINE_PATH``);
  * a PER-ORG, file-backed vector index under ``CUSTOMER_KNOWLEDGE_DIR/<h>/qdrant`` (never ``config.QDRANT_PATH``);
  * a PER-ORG graph dir at ``CUSTOMER_KNOWLEDGE_DIR/<h>/graph`` (never ``config.GRAPH_DIR``),

where ``<h>`` is a DOMAIN-SEPARATED one-way hash of the org_id (``_org_corpus_root``). Because the path is derived
ONLY from a hashed, validated org_id, one org's corpus can never be another org's, and NONE of them is ever the
owner's global store that holds the owner's own private notes / transcripts / commits. The privacy rule - a customer
must NOT reach the owner's global memory - therefore holds by construction, not by a runtime filter.

Fail-CLOSED everywhere: an invalid org_id raises before any path is built (``_check_org_id``); ``query`` re-asserts
every returned hit is THIS org's (a mismatch - which the per-org store makes impossible - raises
:class:`KnowledgeIsolationError` and serves nothing); the per-document / per-org caps are enforced before any write.

FATAL-2: ``assert_no_offense()`` at import. This is sovereign-to-sovereign reuse (sigil's own embed / index / spine);
it imports NO offense-plane module (``framework`` / ``strix`` / ``engine/crucible`` / worldmodel / knowledge / intel).
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Callable, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from .. import config
from ..governor.orgs import _check_org_id
from ..ingest.docs import _chunks                       # reuse the document chunker (code, not data)
from ..spine.store import SpineStore
from ..vectors.index import MIN_SCORE                   # reuse the sovereign index's noise floor (constant)

__all__ = [
    "KnowledgeError", "KnowledgeCapError", "KnowledgeIsolationError", "TenantKnowledge",
    "ingest_document", "list_documents", "query", "corpus_root",
]

#: Domain separation for the per-org corpus directory hash - distinct from every other per-org hashed-name namespace
#: (``_customer_slug``, the authz-requests name, ...), so a corpus dir can never collide with another per-org store.
_CORPUS_CONTEXT = b"vigil-customer-knowledge\x00"
#: The one stable collection name inside each org's OWN qdrant path. The per-org PATH already isolates tenants, so the
#: collection name need not carry the org (and must not - it would leak the org id into the store's on-disk names).
_COLLECTION = "org_documents"
#: A per-org knowledge document is a spine ``document`` record carrying this marker, so the corpus reader never confuses
#: an uploaded org doc with any other ``document`` record a future feature might write to the per-org spine.
_SOURCE = "customer_knowledge"
_MAX_FILENAME_CHARS = 256
_MAX_EMBED_CHARS = 1600                                 # bound per-chunk text before embedding (bge truncates ~512 tok)
_SNIPPET_CHARS = 600                                    # the text a query hit returns (a citation snippet, capped)


class KnowledgeError(RuntimeError):
    """A knowledge-corpus operation failed (bad input, backend unavailable, or a corpus fault). Raised, never
    swallowed by the store, so the caller (the provisioner) fails closed with a clean message."""


class KnowledgeCapError(KnowledgeError):
    """An upload was refused by a cap (document too large, or the org is at its document ceiling). A clean,
    customer-facing refusal, distinct from an internal fault."""


class KnowledgeIsolationError(KnowledgeError):
    """FAIL-CLOSED cross-tenant guard: a store or a query result did not belong to the asking org. The per-org
    path makes this impossible in normal operation, so raising it means a corruption / bug - never serve past it."""


# ---------------------------------------------------------------------------- per-org path derivation (fail-closed) --

def _org_hash(org_id: str) -> str:
    """The domain-separated one-way hash that names ``org_id``'s corpus directory. ``org_id`` is validated first
    (``_check_org_id`` - an alphanumeric-start tenant id, no separators / traversal), so the input to the hash is
    already safe; the hash then makes the on-disk name opaque (the org id never appears in a path)."""
    oid = _check_org_id(org_id)
    return hashlib.sha256(_CORPUS_CONTEXT + oid.encode("utf-8")).hexdigest()


def _org_corpus_root(org_id: str) -> Path:
    """The root directory of ``org_id``'s corpus, strictly inside ``config.CUSTOMER_KNOWLEDGE_DIR``. Fail-closed: the
    org id is validated, the directory name is a 64-char hex digest (no traversal possible), and the resolved root's
    parent MUST be the knowledge base dir - so this can never resolve onto the owner's global stores or another dir."""
    base = config.CUSTOMER_KNOWLEDGE_DIR
    digest = _org_hash(org_id)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):        # defensive: sha256 hexdigest is always 64 lowercase hex
        raise KnowledgeIsolationError("refusing to build a corpus path from a non-hex org hash")
    root = base / digest
    if root.parent != base:
        raise KnowledgeIsolationError("refusing a corpus path that escapes the knowledge base directory")
    return root


def corpus_root(org_id: str) -> Path:
    """Public accessor for ``org_id``'s corpus root (used by tests / tooling to assert isolation)."""
    return _org_corpus_root(org_id)


def _valid_filename(name: object) -> str:
    """Validate + normalise an uploaded document's filename to a safe BASENAME, fail-closed. Control chars are
    stripped, any path component is dropped (``Path(name).name`` - never a directory, never traversal), surrounding
    whitespace trimmed; a non-str / empty / over-long name raises :class:`KnowledgeError`."""
    if not isinstance(name, str):
        raise KnowledgeError("a document filename must be a string")
    cleaned = "".join(ch for ch in name if ord(ch) >= 0x20 and ord(ch) != 0x7f).strip()
    base = Path(cleaned).name.strip()                    # drop any directory component - basename only
    if not base or base in (".", "..") or len(base) > _MAX_FILENAME_CHARS:
        raise KnowledgeError("a document filename must be a non-empty basename within the length limit")
    return base


# ----------------------------------------------------------------- injection seams (prod defaults; tests inject) -----
# The heavy, network-free local deps (onnxruntime+tokenizers for embeddings, qdrant-client for the index) are imported
# LAZILY here, so importing this module - and the provisioner that uses it - never requires them. Tests inject fakes
# (an in-memory index + a deterministic embedder), exactly as the assistant injects its ``model_call``.

def _default_embed_passages(texts: "list[str]") -> "list[list[float]]":
    from ..vectors.embed import embed
    return embed(texts)


def _default_embed_query(text: str) -> "list[float]":
    from ..vectors.embed import embed_one
    return embed_one(text)


def _default_open_index(qdrant_path: Path, collection: str) -> "Any":
    return _OrgVectorIndex(qdrant_path, collection)


class _OrgVectorIndex:
    """A PER-ORG Qdrant index in local (file-backed) mode under the org's OWN ``qdrant_path`` - never the owner's
    global ``config.QDRANT_PATH``. It reuses the exact bge-small vector space (``config.EMBED_DIM``) and cosine
    distance the sovereign index uses, but its store is this org's alone. ``upsert`` takes ``(id, vector, payload)``
    tuples; ``search`` returns payload dicts scored at or above ``MIN_SCORE``."""

    def __init__(self, qdrant_path: Path, collection: str) -> None:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams
        qdrant_path = Path(qdrant_path)
        qdrant_path.mkdir(parents=True, exist_ok=True)
        self.client = QdrantClient(path=str(qdrant_path))
        self.collection = collection
        names = [c.name for c in self.client.get_collections().collections]
        if collection not in names:
            self.client.create_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=config.EMBED_DIM, distance=Distance.COSINE))

    def upsert(self, points: "list[tuple[int, list[float], dict]]") -> int:
        from qdrant_client.models import PointStruct
        structs = [PointStruct(id=pid, vector=vec, payload=payload) for pid, vec, payload in points]
        if structs:
            self.client.upsert(self.collection, points=structs)
        return len(structs)

    def search(self, query_vector: "list[float]", k: int) -> "list[dict]":
        res = self.client.query_points(self.collection, query=query_vector, limit=k, with_payload=True).points
        return [{"score": float(p.score), **(p.payload or {})} for p in res if float(p.score) >= MIN_SCORE]


# ------------------------------------------------------------------------------------------------- the corpus store --

class TenantKnowledge:
    """One org's knowledge corpus. Every store is per-org and NONE is the owner's global store. The embed / index
    backends are injectable (production defaults lazy-import the real local ONNX + Qdrant); ``list_documents`` reads
    ONLY the per-org spine and so needs neither."""

    def __init__(self, org_id: str, *,
                 embed_passages: "Optional[Callable[[list[str]], list[list[float]]]]" = None,
                 embed_query: "Optional[Callable[[str], list[float]]]" = None,
                 open_index: "Optional[Callable[[Path, str], Any]]" = None) -> None:
        self.org_id = _check_org_id(org_id)
        self.root = _org_corpus_root(self.org_id)
        self._embed_passages = embed_passages or _default_embed_passages
        self._embed_query = embed_query or _default_embed_query
        self._open_index = open_index or _default_open_index
        self._index: Any = None

    # per-org store paths - each DISJOINT from the owner's global stores by construction
    @property
    def spine_path(self) -> Path:
        return self.root / "spine" / "spine.jsonl"

    @property
    def qdrant_path(self) -> Path:
        return self.root / "qdrant"

    @property
    def graph_dir(self) -> Path:
        return self.root / "graph"

    def _store(self) -> SpineStore:
        """This org's OWN spine (never ``config.SPINE_PATH``)."""
        return SpineStore(self.spine_path)

    def _idx(self) -> Any:
        if self._index is None:
            self._index = self._open_index(self.qdrant_path, _COLLECTION)
        return self._index

    # --- writes -------------------------------------------------------------------------------------------------
    def ingest_document(self, filename: object, data_bytes: object) -> dict:
        """Chunk + append ``data_bytes`` to THIS org's spine, then embed + index the chunks. Enforces the caps BEFORE
        any write (fail-closed). Returns ``{"org_id", "filename", "chunks", "bytes"}``. The org tag ``org_id`` is
        written into every chunk's payload as defence-in-depth so a reader can re-assert tenancy."""
        name = _valid_filename(filename)
        if not isinstance(data_bytes, (bytes, bytearray)):
            raise KnowledgeError("a document body must be bytes")
        data = bytes(data_bytes)
        max_bytes = config.customer_knowledge_max_doc_bytes()
        if len(data) == 0:
            raise KnowledgeError("a document body must not be empty")
        if len(data) > max_bytes:
            raise KnowledgeCapError(f"document too large: {len(data)} bytes exceeds the {max_bytes}-byte limit")
        # per-org document ceiling: a NEW filename at the cap is refused (an update to an existing file is allowed).
        existing = self._document_index()
        if name not in existing and len(existing) >= config.customer_knowledge_max_docs_per_org():
            raise KnowledgeCapError(
                f"document limit reached: this workspace already holds {len(existing)} documents "
                f"(max {config.customer_knowledge_max_docs_per_org()}) - remove one before adding another")
        text = data.decode("utf-8", errors="replace")
        chunks = _chunks(text)
        if not chunks:
            raise KnowledgeError("the document has no indexable text")
        store = self._store()
        seqs: "list[int]" = []
        for j, chunk in enumerate(chunks):
            seq = store.append(kind="document", source=_SOURCE, actor=name,
                               payload={"text": chunk, "title": name, "filename": name, "chunk": j,
                                        "org_id": self.org_id})
            seqs.append(seq)
        # embed + index the chunks into THIS org's vector store (best-effort acceleration; the spine is the truth).
        vecs = self._embed_passages([c[:_MAX_EMBED_CHARS] for c in chunks])
        points = [(seq, vec, {"seq": seq, "org_id": self.org_id, "filename": name, "chunk": j,
                              "text": chunk[:_SNIPPET_CHARS]})
                  for seq, vec, (j, chunk) in zip(seqs, vecs, enumerate(chunks))]
        self._idx().upsert(points)
        return {"org_id": self.org_id, "filename": name, "chunks": len(chunks), "bytes": len(data)}

    # --- reads --------------------------------------------------------------------------------------------------
    def _document_index(self) -> "dict[str, dict]":
        """Aggregate THIS org's spine ``document`` records by filename (chunk count, first seq, last ts). Reads only
        the per-org spine - never the owner's global spine - and only records this module wrote (``source``)."""
        docs: "dict[str, dict]" = {}
        store = self._store()
        for r in store.iter_records():
            if r.kind != "document" or r.source != _SOURCE:
                continue
            r = store.decrypted(r)
            p = r.payload or {}
            # defence-in-depth: a per-org spine holds only this org, but a stray cross-tenant tag is refused outright.
            tag = p.get("org_id")
            if tag is not None and tag != self.org_id:
                raise KnowledgeIsolationError("a per-org knowledge record is tagged for a different org")
            name = p.get("filename") or p.get("title")
            if not name:
                continue
            d = docs.get(name)
            if d is None:
                docs[name] = {"filename": name, "chunks": 1, "first_seq": r.seq, "last_ts": r.ts}
            else:
                d["chunks"] += 1
                d["last_ts"] = r.ts
        return docs

    def list_documents(self) -> dict:
        """The org's uploaded documents (filename + chunk count + last-updated), newest-last by first appearance.
        A pure read of the per-org spine: no embed, no index, no owner key, nothing minted."""
        docs = list(self._document_index().values())
        return {"org_id": self.org_id, "documents": docs, "count": len(docs)}

    def query(self, q: object, *, k: "Optional[int]" = None) -> "list[dict]":
        """Grounded document hits for ``q``, scoped to THIS org ONLY. Embeds the query, searches the per-org index,
        and FAIL-CLOSED re-asserts every hit belongs to this org (a mismatch raises :class:`KnowledgeIsolationError`
        and serves nothing). Returns inert citation dicts ``{"filename", "snippet", "chunk", "seq", "score"}``."""
        if not isinstance(q, str) or not q.strip():
            raise KnowledgeError("a knowledge query must be a non-empty string")
        limit = config.customer_knowledge_query_limit() if k is None else int(k)
        limit = max(1, min(limit, 50))
        qv = self._embed_query(q.strip())
        hits = self._idx().search(qv, limit)
        out: "list[dict]" = []
        for h in hits:
            if h.get("org_id") != self.org_id:
                # structurally impossible with a per-org index; if it ever happens, refuse the whole query.
                raise KnowledgeIsolationError("a knowledge hit is tagged for a different org - refusing to serve")
            out.append({"filename": h.get("filename"), "snippet": h.get("text"),
                        "chunk": h.get("chunk"), "seq": h.get("seq"), "score": round(float(h.get("score", 0.0)), 4)})
        return out


# ------------------------------------------------------------------- module-level convenience (the provisioner API) --
# The provisioner calls these; tests may inject fakes by passing the keyword backends, or by monkeypatching the
# module-level ``_default_*`` factories above (the provisioner path uses the defaults).

def ingest_document(org_id: str, filename: object, data_bytes: object, **backends: Any) -> dict:
    return TenantKnowledge(org_id, **backends).ingest_document(filename, data_bytes)


def list_documents(org_id: str, **backends: Any) -> dict:
    return TenantKnowledge(org_id, **backends).list_documents()


def query(org_id: str, q: object, *, k: "Optional[int]" = None, **backends: Any) -> "list[dict]":
    return TenantKnowledge(org_id, **backends).query(q, k=k)
