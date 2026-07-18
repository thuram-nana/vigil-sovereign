# SIGIL — Phase 0: the memory loop

Local-first total recall over your entire Claude history, exposed to every Claude session via
an MCP memory server. Ask *"what did I decide about X"* → get a **cited** answer from a
tamper-evident record of your own work. Offense-free by construction. (Full spec:
`../Pictures/PENTEST-main/SIGIL.md`.)

```
~/.claude/projects/**.jsonl ─┐
git commits ─────────────────┼─ingest─▶ episodic spine ─embed─▶ vectors ─┐
subagent transcripts ────────┤        (append-only, hash-   (Qdrant       ├─▶ MCP memory server
curated memory/*.md ─────────┘         chained, signed)      server)      │    (8 gated, cited tools)
                                             │                            │
                                             └────rebuild────▶ Kùzu graph ─┘
                                        consolidate (ARCHIVIST, agent-driven, gated) ─▶ facts
```

## What's built

- **`sigil/spine/`** — append-only, hash-chained JSONL, the source of truth. Two-layer integrity:
  a **binding** check (payload still hashes to its digest) + a **chain** check (links intact); the
  signed head distinguishes benign growth from truncation/rewrite (**tampering**). Owner-signed
  (Ed25519). 43k+ records.
- **`sigil/reuse/`** — the integrity substrate (hash chain + Ed25519), **vendored verbatim** from
  the owner's CRUCIBLE work. SIGIL imports **zero** `framework.*` modules; `assert_no_offense()`
  enforces it at import in every SIGIL process.
- **`sigil/ingest/`** — threaded Claude-Code JSONL (text/thinking/tool blocks) + **git commits**
  (live post-commit/post-merge hooks) + **subagent transcripts** (each its own titled session) +
  curated docs. Incremental per-file cursors; idempotent.
- **`sigil/vectors/`** — on-device embeddings (fastembed / bge-small, CPU, no API, no cost) → Qdrant
  **server mode** (concurrent serve + ingest). Honesty gate: an absent topic returns "no grounded
  match", never a fabrication.
- **`sigil/graph/`** — a **deterministic** Kùzu mirror of the spine (Project/Session/Document/Commit
  + containment); rebuilt by replay with an atomic swap; every node cites its spine anchor. Two
  rebuilds → identical node/edge sets.
- **`sigil/consolidate/`** — the **ARCHIVIST** pass: agent-driven (`claude -p` on Max) extraction of
  decisions/commitments/entities behind a **demote-only veracity gate** that *re-executes* every
  citation (a fact is promoted only if its quote is verbatim in a cited spine record). Only
  spine-traceable facts become records; the rest are recorded honestly as refusals, never dropped.
- **`sigil/mcp/`** — **8 gated, read-only, cited MCP tools**: `memory_search`, `episodic_range`,
  `ingest_status`, `graph_entity`, `graph_query`, `threads_open`, `commitments_due`,
  `contradictions_pending`. Registered in Claude Code **and** Claude Desktop.

## Use

```bash
V=~/.sigil/venv/bin/python
$V -m sigil.cli ingest              # history + subagents (+ --git, --docs) → spine
$V -m sigil.cli index               # spine → vectors (incremental)
$V -m sigil.cli graph               # rebuild the deterministic entity graph
$V -m sigil.cli sign                # anchor the spine (signed head)
$V -m sigil.cli consolidate --provider heuristic   # offline extraction (no Max spend)
$V -m sigil.cli consolidate --provider agent       # agent-driven (headless claude -p, Max)
$V -m sigil.cli search "the veracity firewall"     # cited recall
$V -m sigil.cli status              # counts + integrity
```

Tests: `$V tests/test_integrity.py` · `test_graph.py` · `test_consolidate.py` (integrity /
determinism / demote-only gate, all offline).

## Layout

- code: `/home/kali/sigil/` · runtime data: `~/.sigil/` (spine, keys, vectors, graph — private, 0700)
- Qdrant server: Docker `sigil-qdrant` (loopback 6333). Server URL persisted in `~/.sigil/sigil.env`.

## Roadmap

**0a/0b/0c ✅** — ingest (history + git + subagents + docs) → hash-chained signed spine → vectors
(server mode) → deterministic Kùzu graph → agent-driven consolidation → **8 MCP tools** in Claude
Code + Desktop. Then Phases 1–6 (Rust KERNEL + WARDEN, voice, agent mesh, ARTIFICER/SCHOLAR,
perception, hardening) per the spec.
