# memory/ — MLS, the Memory & Learning Substrate

Persistent priors substrate. Every engagement writes to it; every new
engagement queries it. The framework's findings-per-hour metric
should improve measurably as the store accumulates.

## Storage

| Path | Contents |
|------|----------|
| `framework/v2/.memory/store.sqlite` | SQLite DB, gitignored |
| `framework/v2/memory/schema.sql` | Schema-of-record (version 1) |

Tables: `engagements`, `findings`, `hypotheses`, `payloads`,
`dead_ends`, `archetype_priors`, `playbook_outcomes`, `schema_meta`.
Each row that benefits from semantic search carries an `embedding`
BLOB.

## Embeddings

| Backend | Activates when | Default |
|---|---|---|
| `LexicalEmbedder` | always | yes |
| `SentenceTransformerEmbedder` | `sentence-transformers` is importable | upgrade |

Override with `CRUCIBLE_EMBEDDER=lexical` or
`CRUCIBLE_EMBEDDER=sentence-transformers`. The default is whichever
is available.

The lexical default is a 256-dim feature-hashing TF vectorizer. It
finds engagements with overlapping vocabulary — *not* semantic
neighbours. This is documented in `V2-LIMITATIONS.md` and is the
right default for an offline-first framework.

## Public API

```python
from framework.v2.memory import open_store
from framework.v2.memory import recorder, recall, priors

with open_store() as store:
    # write
    eid = recorder.record_engagement_start(
        store, slug="newsite", archetype="Laravel marketplace",
        target_url="https://newsite.example",
        business_context="...",
    )
    recorder.record_finding(
        store, "newsite",
        finding_slug="001-idor-on-orders",
        title="IDOR on /api/orders/{id}",
        severity="High", bug_class="IDOR",
        surface="/api/orders/{id}",
        summary="...", impact="...",
    )

    # read
    similar = recall.similar_targets(store, fingerprint={...}, limit=5)
    wins    = recall.winning_hypotheses(store, archetype="Laravel marketplace")
    pp      = recall.payload_priors(store, bug_class="IDOR", archetype="Laravel marketplace")
    pri     = priors.top_priors_for(store, "Laravel marketplace")
```

## CLI

```bash
python3 -m framework.v2 memory status                # row counts
python3 -m framework.v2 memory similar --text "..."  # similar past targets
python3 -m framework.v2 memory priors --archetype "..."
python3 -m framework.v2 memory seed --slug sample-php-panel  # built-in sample engagement fixture
```

## Provenance

Per FORGE PROTOCOL § 3.2, every recall result carries the engagement
ID and row ID it came from. The dataclasses in `recall.py` include a
`Provenance` field. Hallucinated priors are a fatal bug.
