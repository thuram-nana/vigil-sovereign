# Contributing to `knowledge/`

This folder is VIGIL's **living knowledge base** — pushed to GitHub so the system's knowledge always
survives, and read back by SIGIL to *know the system*. It is written as we build, and it is the map, not
the territory.

## What lives here

- `kb/` — living knowledge docs (architecture, screens/features/agents, the graph→oracle→gate model).
- `system-map/` — the machine-readable screen/nav manifest SIGIL reads (`screens.yaml` is the human source;
  `system-map.json` is **generated** — never hand-edit it, run `knowledge/sync.sh`).
- `skills/{find,detect,prevent}/` — the deep-learn artifacts K3 writes for a vulnerability. Advisory.
- `decisions/` — ADR-style decision logs.
- `sessions/` — **redacted** build-session transcripts.

## The one doctrine that governs everything here

**Nothing in this folder is a fact.** Skills, KB docs, priors, and learned notes are **leads / skills /
advisory** — the graph counterparts stay `intel`/`ungrounded`. Only a fired deterministic oracle mints a
FACT, and no oracle lives here. Committing a file makes nothing true; it records what we *believe* or
*propose*, clearly labelled as such.

## Syncing to GitHub (operator-gated)

Two explicit, operator-invoked steps — **an agent never runs `git commit` or `git push`**:

1. `vigil knowledge sync` — regenerate the manifest (`knowledge/sync.sh`), **scan the folder for secrets**
   (refuses to commit if any is found — you remove or redact it first), then `git add knowledge/` + `git
   commit`. Commit happens ONLY on this command.
2. `vigil knowledge push` — the single outward-facing act: `git push`. Explicit and separate, because
   pushing publishes.

Before committing a transcript or log, **redact secrets** (the sync scan is a safety net, not a
substitute). Keys, tokens, and private material never belong in a committed file.
