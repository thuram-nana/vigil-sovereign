"""L2 — the deterministic LLM response cache (engine plane, EC-1b): the biggest AI-cost lever.

A DETERMINISTIC URK completion — single-shot (``samples==1``), ``temperature`` exactly 0.0, on an OLDER
(non-current-generation) model — is a pure function of its prompt + selection. So the SECOND identical such
call can be served from a local store instead of re-calling the provider, at zero tokens. This is a pure
ACCELERANT: a HIT is byte-identical to a recompute (the stored raw is re-parsed against the LIVE prompt
schema), it mints nothing, it never short-circuits a SECURITY gate (it sits OUTSIDE the egress chokepoint —
a hit simply reaches no provider), and a cached completion stays ADVISORY (the LLM only advises; an oracle
still confirms every FACT). The kill-switch (``CRUCIBLE_CACHE_DISABLE``) and every non-deterministic /
ephemeral / dry-run call path are byte-identical to no-L2.

CROSS-TENANT ISOLATION is belt-and-braces: (1) PHYSICAL — the store lives under
``paths.cache_l2_db()`` = ``_tenant_shard(v2_root()/'.cache/l2')/store.sqlite``, the same per-process shard
that isolates ``.memory`` / ``.blackboard`` (a tenant-A worker can only ever resolve its own shard); (2)
LOGICAL — ``org_id`` (``tenant_id()``) AND the engagement slug (``current_engagement()``) are in the key, so
even an unsharded single-tenant default never serves org A's answer to org B or across engagements.

DETERMINISM (framework doctrine): :func:`l2_key` is a PURE function — no wallclock, no RNG. ``created_at`` is
stored for TTL hygiene ONLY and is never in the key, so a TTL-expired entry recomputes to the identical value.

FAIL-SAFE: every store/lookup is wrapped so a broken/locked/corrupt cache can only ever degrade to a MISS or a
no-op — it never raises into, or changes the result of, a completion. SECRETS AT REST: the store holds the
``system``/``user`` prompt + the raw response (which the gateway redactor masks on a best-effort basis), so
the DB is owner-only 0600 under the tenant shard, and L2 is DISABLED for a ZDR / ``--ephemeral`` session
(checked at the ``kernel.llm`` wire-in) so a zero-retention run leaves nothing on disk.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Optional

from ..common import paths
from ..common.logging import current_engagement
from ..common.tenant import tenant_id

# Operator controls (read defensively; default ON, byte-identical when off).
_DISABLE_ENV = "CRUCIBLE_CACHE_DISABLE"       # global hard off for ALL cache layers
_L2_DISABLE_ENV = "CRUCIBLE_L2_DISABLED"      # L2-specific off
_TTL_ENV = "CRUCIBLE_L2_TTL_S"                # entry lifetime (hygiene; never affects an output)
_CACHE_VERSION_ENV = "CRUCIBLE_L2_CACHE_VERSION"   # manual-invalidation salt baked into the key
_DEFAULT_TTL_S = 7 * 24 * 3600                # 7 days
_TRUTHY = ("1", "true", "yes", "on")

# Process-local telemetry (surfaced through status; never persisted, never in a key).
_STATS = {"hits": 0, "misses": 0, "stores": 0}


def stats() -> dict[str, int]:
    """A snapshot of this process's L2 hit/miss/store counters (observability only)."""
    return dict(_STATS)


def l2_disabled() -> bool:
    """True iff the global cache kill-switch or the L2-specific opt-out is set (default: enabled)."""
    for env in (_DISABLE_ENV, _L2_DISABLE_ENV):
        if (os.environ.get(env, "") or "").strip().lower() in _TRUTHY:
            return True
    return False


def _ttl_s() -> float:
    try:
        v = float((os.environ.get(_TTL_ENV, "") or _DEFAULT_TTL_S))
    except (TypeError, ValueError):
        return float(_DEFAULT_TTL_S)
    return v if v > 0 else float(_DEFAULT_TTL_S)


def is_deterministic(prompt: Any, model: str) -> bool:
    """A completion is L2-cacheable only when it is DETERMINISTIC: single-shot (``samples==1``),
    ``temperature`` EXACTLY 0.0, and NOT a current-generation model. Current-gen models drop the sampling
    params for ``output_config.effort`` and are NOT determinism-guaranteed even at temperature 0, so caching
    one would canonicalise one of many stochastic samples — excluded. A ``samples>1`` self-consistency call
    (anti-hallucination) is excluded for the same reason. A minimal prompt double lacking these attrs -> False."""
    try:
        from .llm import is_current_model
        return (int(getattr(prompt, "samples", 1)) == 1
                and float(getattr(prompt, "temperature", 0.2)) == 0.0
                and not is_current_model(str(model or "")))
    except Exception:                                      # noqa: BLE001 — a gate query, never a crash
        return False


def _schema_fingerprint(prompt: Any) -> str:
    """Canonical JSON of the structured-output contract (``schema.model_json_schema()``), so a schema change
    invalidates the cache. Defensive: a prompt double without a pydantic schema folds to a stable sentinel."""
    try:
        sch = getattr(prompt, "schema", None)
        mj = sch.model_json_schema() if sch is not None else {}
        return json.dumps(mj, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:                                      # noqa: BLE001
        return "<<no-schema>>"


def l2_key(prompt: Any, *, backend: str, model: str, tier: str,
           org_id: Optional[str], slug: Optional[str]) -> str:
    """The sha256 cache key — a PURE function of everything that can change the completion: the tenant +
    engagement scope (isolation), the backend/model/tier selection, the sampling knobs, the structured-output
    contract, the structured input, and the full system+user text (the doctrine/metacognition preamble is
    baked into ``system``, so a cognitive-doc change self-invalidates). NO wallclock, NO RNG."""
    from .llm import resolve_effort
    core = {
        "v": (os.environ.get(_CACHE_VERSION_ENV, "") or "1").strip() or "1",
        "org": org_id or "__shared__",
        "eng": slug or "__none__",
        "backend": str(backend or ""),
        "model": str(model or ""),
        "tier": str(tier or ""),
        "temperature": float(getattr(prompt, "temperature", 0.0)),
        "effort": resolve_effort(getattr(prompt, "effort", None)) or "",
        "samples": int(getattr(prompt, "samples", 1)),
        "max_tokens": int(getattr(prompt, "max_tokens", 0)),
        "schema_name": str(getattr(prompt, "schema_name", "")),
        "schema": _schema_fingerprint(prompt),
        "structured_input": json.dumps(getattr(prompt, "structured_input", {}) or {},
                                       sort_keys=True, separators=(",", ":"), default=str),
        "system": str(getattr(prompt, "system", "")),
        "user": str(getattr(prompt, "user", "")),
    }
    blob = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _connect() -> Optional[sqlite3.Connection]:
    """Open the per-tenant L2 store owner-only, mirroring the blackboard open pattern (secure_dir parent ->
    connect -> secure_existing 0600 -> WAL for concurrent readers under the shared HttpExecutor). Returns
    None on any failure (a cache that cannot open simply never hits)."""
    try:
        db = paths.cache_l2_db()
        paths.secure_dir(db.parent)
        conn = sqlite3.connect(str(db), timeout=5.0)
        paths.secure_existing(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS l2 ("
            "key TEXT PRIMARY KEY, raw_response TEXT NOT NULL, schema_name TEXT NOT NULL, "
            "backend TEXT, model TEXT, tokens_in INTEGER, tokens_out INTEGER, created_at REAL NOT NULL)"
        )
        return conn
    except Exception:                                      # noqa: BLE001 — a broken cache is never an error
        return None


def lookup(prompt: Any, *, backend: str, model: str, tier: str,
           org_id: Optional[str], slug: Optional[str]) -> Optional[Any]:
    """Return a rebuilt :class:`~framework.v2.kernel.models.LLMResult` for a cache HIT, else None. A HIT
    requires: the key present, within TTL, the stored ``schema_name`` matching the live prompt, and the
    stored raw STILL parsing against the live ``prompt.schema`` — so a value that can no longer be reproduced
    is a MISS, never a wrong answer. Fail-safe: any error -> None (miss)."""
    if l2_disabled():
        return None
    conn = _connect()
    if conn is None:
        return None
    try:
        key = l2_key(prompt, backend=backend, model=model, tier=tier, org_id=org_id, slug=slug)
        row = conn.execute(
            "SELECT raw_response, created_at FROM l2 WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            _STATS["misses"] += 1
            return None
        raw, created_at = row
        if (time.time() - float(created_at)) > _ttl_s():
            _STATS["misses"] += 1
            return None                                   # expired -> recompute refreshes to the same value
        # NB: schema identity is already in the key (schema_name + the full model_json_schema fingerprint),
        # so a schema change is a key change (a MISS) — no separate stored-schema re-check is needed here. The
        # load-bearing correctness guard is re-parsing the stored raw against the LIVE prompt.schema below: a
        # value that can no longer be reproduced is a MISS, never a wrong answer.
        from .llm import LLMResult, make_call_trace, parse_json_response
        try:
            parsed = parse_json_response(str(raw), prompt.schema)
        except Exception:                                 # noqa: BLE001 — a stale/unparseable value -> miss
            _STATS["misses"] += 1
            return None
        trace = make_call_trace(
            str(backend or ""), is_dryrun=False,
            cognitive_doc=str(getattr(prompt, "cognitive_doc", "")),
            cognitive_sections=list(getattr(prompt, "cognitive_sections", []) or []),
            tokens_in=0, tokens_out=0, cached=True,
        )
        _STATS["hits"] += 1
        return LLMResult(parsed=parsed, trace=trace, raw_response=str(raw))
    except Exception:                                     # noqa: BLE001 — never let the cache break a call
        return None
    finally:
        try:
            conn.close()
        except Exception:                                 # noqa: BLE001
            pass


def store(prompt: Any, result: Any, *, backend: str, model: str, tier: str,
          org_id: Optional[str], slug: Optional[str]) -> None:
    """Persist a fresh (MISS-path) completion's raw response under its key. Idempotent per key
    (INSERT OR REPLACE). Fail-safe: any error is swallowed (a cache write never breaks the call)."""
    if l2_disabled():
        return
    raw = str(getattr(result, "raw_response", "") or "")
    if not raw:
        return                                            # nothing reproducible to cache
    conn = _connect()
    if conn is None:
        return
    try:
        key = l2_key(prompt, backend=backend, model=model, tier=tier, org_id=org_id, slug=slug)
        tr = getattr(result, "trace", None)
        ti = int(getattr(tr, "tokens_in", 0) or 0)
        to = int(getattr(tr, "tokens_out", 0) or 0)
        conn.execute(
            "INSERT OR REPLACE INTO l2 "
            "(key, raw_response, schema_name, backend, model, tokens_in, tokens_out, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (key, raw, str(getattr(prompt, "schema_name", "")), str(backend or ""),
             str(model or ""), ti, to, time.time()),
        )
        conn.commit()
        _STATS["stores"] += 1
    except Exception:                                     # noqa: BLE001
        pass
    finally:
        try:
            conn.close()
        except Exception:                                 # noqa: BLE001
            pass


def resolve_scope() -> tuple[Optional[str], Optional[str]]:
    """``(org_id, slug)`` for the key — the tenant id and the bound engagement slug, each fail-safe to None."""
    try:
        org = tenant_id()
    except Exception:                                     # noqa: BLE001
        org = None
    return org, current_engagement()
