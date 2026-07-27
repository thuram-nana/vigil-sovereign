# sessions/ — redacted build-session transcripts

A durable, human-readable history of how the system was built: redacted transcripts and summaries of build
sessions, written by the orchestrator on `vigil knowledge sync`.

**Redaction is mandatory before commit** — secrets are scrubbed (reusing the sigil secret-handling patterns)
so nothing sensitive ever reaches a committed file, and certainly never the remote. Pushing is always explicit
and operator-gated (`vigil knowledge push`); no agent or automation ever pushes.
