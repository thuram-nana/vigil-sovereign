<!-- CLAIM:W16-STD-7-rederived-drift -->
# W16-STD-7 (#533) — docs completeness + the re-derived doc-vs-code drift batch

This record covers the second half of W16-STD-7: the missing documentation chapters, the whole-command-
surface coverage, the buyer-facing licensing surface, and a further batch of doc-vs-code drifts re-derived
by auditing the code at this HEAD (the first half — the §16 drift batch — is in
[`W16-STD-7-doc-drifts.md`](W16-STD-7-doc-drifts.md)).

## What shipped

- **The whole command surface is documented.** `docs/CLI-REFERENCE.md` now lists, in addition to the 32
  CRUCIBLE subcommands (§A) and 38 subsystems (§B), the **41 `vigil` native verbs** (§C, the argparse
  sub-parsers of `integration/vigil_integration/cli.py`) and the **5 passthrough verbs** (§D,
  `dispatch.py` `PASSTHROUGH_VERBS`) — the ~78 invokable commands the acceptance criteria name.
- **Three new chapters.** `docs/HTTP-API.md` (the loopback gated HTTP API and the other web surfaces),
  `docs/INDEX.md` (a map of the whole `docs/` tree), and `docs/GLOSSARY.md` (the canonical term dictionary).
- **The public-sector licensing exclusion is surfaced where a buyer meets it** — a standalone callout near
  the TOP of the README (not only the bottom-of-file License section) and in the buyer-facing pilot runbook,
  both pointing at `LICENSING.md`.

## The re-derived drift batch (registered claim W16-STD-7-rederived-drift)

**Registered claim:** A further batch of doc-vs-code drifts, re-derived by auditing README/AS-BUILT against
the code at this HEAD, is corrected to match the code, and a required test fails the build if any re-opens —
a forbidden false phrase returns, a corrected anchor is silently reverted, or a cited code fact stops being
true in-tree.

| # | Doc | Was | Now (true of the code) |
|---|-----|-----|------------------------|
| D1 | `docs/AS-BUILT.md` | the `sandbox.exec` runner uses `--unshare-net` | it uses `--unshare-all` (`sandbox_exec.py` base flags; `--unshare-net` is the load-bearing *part* of it, not the flag passed) |
| D2 | `docs/AS-BUILT-LIVE.md` | `test_engine.py`, **17 tests** (a stale UNDERclaim) | the exact count is dropped (it had grown to 32); the doc no longer asserts a brittle number |
| D3 | `docs/AS-BUILT-LIVE.md` | `test_engine_live.py`, **5 tests** (a stale UNDERclaim) | count dropped (it had grown to 19) |
| D4 | `docs/AS-BUILT-LIVE.md` | the **22nd** screen | "one of the UI's screens" — the authoritative count lives in the `NAV` allowlist and is pinned by `test_documented_commands_and_screen_count.py` (the UI has 32) |
| D5 | `README.md` | deterministic oracle **(~33 kinds)** (a stale UNDERclaim) | **(~38 kinds)** — `OracleKind` has 38 members |
| D6 | `README.md` | `vigil doctor` example: **0/7 systemd timers** | **0/9** — `infra/systemd` ships 9 `.timer` units |

Every one of D1/D5/D6 is re-anchored to a **code fact** the guard re-checks (the sandbox flag, the
`OracleKind` member count, the `.timer` file count); D2/D3 were UNDERclaims fixed by removing the brittle
number rather than pinning a new one that would re-drift on the next test added; D4 defers the count to the
existing NAV guard.

## Enforcement

`docs/tests/test_w16_std7_docs_completeness.py` is the guard for all of the above. It runs in the required
`the briefing explains every agent and capability` CI job (`pytest docs/tests -q`, reads files only). It is
BIDIRECTIONAL for every code-derived set:

- a new `vigil` verb / passthrough verb / HTTP route / top-level doc that is undocumented → red (FORWARD);
- a documented `vigil` verb / HTTP route the code does not have, or an index link that does not resolve →
  red (REVERSE — the negative-control direction the acceptance criteria name);
- a re-derived drift that re-opens (forbidden phrase back, anchor gone, cited code fact false) → red.

Each direction has an in-run negative control proving the checker is not a no-op. The claims are registered
in `docs/claims/registry.json` (`W16-STD-7-http-api`, `-docs-index`, `-glossary`, `-vigil-cli-coverage`,
`-licensing-surface`, `-rederived-drift`).
