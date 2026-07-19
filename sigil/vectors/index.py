"""Qdrant vector index over spine records (SIGIL §5b).

One point per spine record (id = spine seq), payload carries provenance (`entry_hash`,
`seq`, kind, source, session, project, ts) so every retrieval is citable. Incremental:
only embeds records above the last-indexed seq. (Chunking of long records = 0b refinement.)
"""
from __future__ import annotations

import logging
from typing import Any

from ..config import EMBED_DIM, QDRANT_COLLECTION, QDRANT_PATH, QDRANT_URL
from ..spine.store import SpineStore
from .embed import embed, embed_one

_log = logging.getLogger(__name__)

# Transport/connection failure classes (matched by NAME so we don't hard-depend on httpx or a
# specific qdrant version). qdrant wraps httpx transport errors in ResponseHandlingException.
_UNREACHABLE_NAMES = frozenset({
    "ResponseHandlingException", "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "TimeoutException", "NetworkError", "TransportError", "ConnectionError",
    "NewConnectionError", "MaxRetryError", "RemoteProtocolError",
})


class VectorBackendUnavailable(RuntimeError):
    """The vector backend is UNREACHABLE (a connection/transport failure), so the durable cursor is
    UNKNOWN. Raised instead of silently reporting an empty cursor (-1): treating an outage as 'empty'
    would re-embed the ENTIRE corpus from scratch on every transient outage. Callers must treat this
    as 'unknown — do not reindex', never as seq -1."""


def _is_backend_unavailable(exc: BaseException) -> bool:
    """True if `exc` (or anything in its cause/context chain) is a transport/connection failure to
    the vector backend — as opposed to a query-shape / collection-absent error, which is a legitimate
    'treat as empty' case. Walking the chain catches qdrant's ResponseHandlingException wrapping an
    httpx ConnectError, etc."""
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if type(e).__name__ in _UNREACHABLE_NAMES:
            return True
        e = e.__cause__ or e.__context__
    return False

# bge-small cosine is compressed: genuinely in-corpus ~0.72-0.78, absent topics ~0.55-0.62.
# GROUNDED = a top hit is a real match; below it, memory has nothing strongly relevant.
GROUNDED_SCORE = 0.66
MIN_SCORE = 0.55  # individual results below this are dropped as noise

_MAX_CHARS = 1600  # bound per-record text before embedding (model truncates ~512 tok anyway)

# only recall-valuable kinds are embedded; the full record set still lives in the spine.
# raw tool_call/tool_result records (65% of a coding transcript, huge + low-recall-value)
# are NOT vector-indexed — they're reachable via episodic.range, not semantic search.
EMBEDDABLE_KINDS = frozenset({"message", "decision", "commitment", "document", "session", "brief", "commit"})


class VectorIndex:
    def __init__(self, collection: str = QDRANT_COLLECTION) -> None:
        from qdrant_client import QdrantClient
        self.collection = collection
        # local/embedded mode (file-backed, no server) unless a server URL is configured
        if QDRANT_URL:
            self.client = QdrantClient(url=QDRANT_URL)
        else:
            QDRANT_PATH.mkdir(parents=True, exist_ok=True)
            self.client = QdrantClient(path=str(QDRANT_PATH))
        self._ensure()

    def _ensure(self) -> None:
        from qdrant_client.models import Distance, PayloadSchemaType, VectorParams
        names = [c.name for c in self.client.get_collections().collections]
        if self.collection not in names:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
            )
        # a payload index on `seq` powers the durable cursor (OrderBy). Server mode enforces
        # it; local mode ignores it. Idempotent — created here so a MIGRATED collection (which
        # never ran index_spine) still gets the cursor. Must exist before last_indexed_seq().
        try:
            self.client.create_payload_index(self.collection, "seq", PayloadSchemaType.INTEGER)
        except Exception:
            pass

    def reset(self) -> None:
        """Drop + recreate the collection (used when the embed policy changes)."""
        try:
            self.client.delete_collection(self.collection)
        except Exception:
            pass
        self._ensure()

    def count(self) -> int:
        return self.client.count(self.collection, exact=True).count

    def last_indexed_seq(self) -> int:
        """Highest spine seq already indexed (durable cursor), or -1 if the collection is genuinely
        empty / not-yet-created.

        Raises `VectorBackendUnavailable` when the backend is UNREACHABLE: a connection/transport
        outage must NOT masquerade as an empty cursor (-1), because the caller feeds -1 into
        `index_spine(since_seq=-1)`, which re-embeds the ENTIRE corpus from scratch. On an outage we
        raise so the reindex never runs — the append-only upsert-by-id spine is never wiped, and an
        operator sees a loud failure instead of a silent full re-embed. A non-outage query error
        (e.g. order_by needs a payload index) is genuinely 'treat as empty' → -1 and is
        non-destructive (index_spine upserts by id=seq, idempotent — it never deletes)."""
        from qdrant_client.models import OrderBy
        try:
            pts, _ = self.client.scroll(self.collection, limit=1, with_payload=True,
                                        order_by=OrderBy(key="seq", direction="desc"))
            return int(pts[0].payload["seq"]) if pts else -1
        except Exception as e:  # noqa: BLE001 — classify, then re-raise outages / -1 the rest
            if _is_backend_unavailable(e):
                _log.warning("vector backend unreachable while reading the durable cursor "
                             "(last_indexed_seq); refusing to report an empty cursor so a transient "
                             "outage does NOT trigger a full destructive reindex: %r", e)
                raise VectorBackendUnavailable(
                    "vector backend unreachable; durable cursor unknown — refusing to reindex "
                    "from scratch") from e
            # collection absent / order_by unsupported without a payload index → treat as empty.
            # Non-destructive: index_spine upserts by id=seq (idempotent), it never wipes.
            return -1

    def index_spine(self, store: SpineStore, *, since_seq: int = -1, batch: int = 256) -> int:
        from qdrant_client.models import PointStruct
        buf: list[Any] = []
        total = 0

        def flush(records):
            vecs = embed([r.text()[:_MAX_CHARS] for r in records])
            points = [
                PointStruct(id=r.seq, vector=v, payload={
                    "seq": r.seq, "kind": r.kind, "source": r.source, "actor": r.actor,
                    "session_id": (r.payload or {}).get("session_id"),
                    "project": (r.payload or {}).get("project"),
                    "ts": r.ts, "entry_hash": r.entry_hash,
                    "text": r.text()[:1200],
                })
                for r, v in zip(records, vecs)
            ]
            self.client.upsert(self.collection, points=points)
            return len(points)

        for r in store.iter_records(since_seq=since_seq):
            if r.kind not in EMBEDDABLE_KINDS or not r.text().strip():
                continue
            buf.append(r)
            if len(buf) >= batch:
                total += flush(buf)
                buf = []
        if buf:
            total += flush(buf)
        # a payload index on seq enables the durable cursor
        try:
            from qdrant_client.models import PayloadSchemaType
            self.client.create_payload_index(self.collection, "seq", PayloadSchemaType.INTEGER)
        except Exception:
            pass
        return total

    def search(self, query: str, k: int = 8, project: str | None = None) -> list[dict]:
        from qdrant_client.models import FieldCondition, Filter, MatchValue
        flt = None
        if project:
            flt = Filter(must=[FieldCondition(key="project", match=MatchValue(value=project))])
        qv = embed_one(query)
        res = self.client.query_points(self.collection, query=qv, limit=k,
                                       with_payload=True, query_filter=flt).points
        return [{"score": float(p.score), **(p.payload or {})} for p in res if float(p.score) >= MIN_SCORE]

    def grounded(self, query: str, k: int = 8, project: str | None = None) -> tuple[list[dict], bool]:
        """Search + a grounding verdict: (results, is_grounded). is_grounded is False when
        the best hit is below GROUNDED_SCORE — i.e. memory has nothing strongly relevant
        (prove-don't-guess: the caller must then decline to answer, not fabricate)."""
        hits = self.search(query, k=k, project=project)
        is_grounded = bool(hits) and hits[0]["score"] >= GROUNDED_SCORE
        return hits, is_grounded
