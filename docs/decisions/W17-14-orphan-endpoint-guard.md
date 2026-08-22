# W17-14 — Wire, document, or remove the orphaned endpoints + justify the `/api/v1` plane

Issue: [#548](https://github.com/thuram-nana/vigil-sovereign/issues/548) ·
Milestone: W17 — FINISH THE HALF-BUILT (feature-wiring audit).

## The claim (registered in the claims registry — [W0-3] #398, id `W17-14`)

<!-- CLAIM:W17-14 -->
> **Registered claim (W0-3 #398):** Every registered console read route is consumed by the shipped unified UI or listed as a documented programmatic endpoint, and a new orphan turns the required CRUCIBLE core CI job red.

## What was found, and the decision for each named orphan

The audit named six surfaces. Each was decided on evidence (a whole-repo grep for callers across the
UI bundle, tests and docs), following the A6/B7 precedent that removes a ROUTE when it has no consumer
but keeps a PROVIDER while an internal caller remains.

- **`api.reports_data` — REMOVED.** It had no HTTP route AND no internal caller (nothing in the console,
  the dossier/report assembly, or the `/api/v1` plane read it). Unlike `authority_full`/`session_detail`
  (kept — the dossier/report assembly still calls them), it was pure dead code. Generated reports on disk
  are surfaced through `run_report` / the dossier.

- **`GET /api/chat/attachments` — REMOVED (route + provider).** The unified UI renders attachment chips
  from each chat record's own `attachments` field; it never fetched this route. Its provider
  `chat.attachments_list` had no other caller, so both are gone (the upload/`_manifests`/`_scan_offer`
  machinery that the chat turn actually uses is untouched).

- **The four sovereign cockpit routes `/api/ask`, `/api/classify`, `/api/graph`, `/api/graph/entity` —
  KEPT as documented gated programmatic endpoints.** These are not dead code: `/api/ask` carries the full
  owner-token action gate and dispatches the shared `KernelDispatch` (the same one the voice channel uses),
  `/api/graph`/`/api/graph/entity` expose the provenance graph (the phone bridge exposes the same
  `read:snapshot` graph), and `/api/classify` is backed by `KernelClassifier`. Each keeps its gate tests.
  They are the cockpit's owner-gated programmatic query/dispatch surface, documented in `docs/FEATURES.md`.

- **The `/api/v1` gated-action plane on `:8799` — KEPT and justified.** It is a documented, supported,
  tested programmatic third-party API (`framework/v2/api/`, described in `docs/plain-english/02-the-parts.md`
  and `docs/plain-english/12-tools-and-what-you-need.md`): "a small deliberate interface for an operator's
  own software". "Documented as a supported API" is a valid resolution under the acceptance criteria, so the
  plane and the port it costs are justified and `vigil up` keeps spawning it.

## How the claim is TRUE of the code

`engine/crucible/framework/v2/console/tests/test_orphan_route_guard_w17_14.py` enumerates the console's
registered read routes directly from the dispatch registries (`_EXACT_ROUTES`, `_SCOPED_ROUTES`,
`_PREFIX_ROUTES`) plus the special-cased GET routes, and asserts each is either a literal the shipped
`packages/vigil-ui/app.js` fetches (`OFF("/api/…")`) or an entry in a documented-programmatic allowlist.
A negative control proves the checker is not a no-op (a synthetic route is flagged; documenting or wiring
it clears it). Two removal pins fail on a tree without this change: `api.reports_data` and
`chat.attachments_list` no longer exist, and `GET /api/chat/attachments` now 404s while a kept route serves.
The test runs in the required `CRUCIBLE core on vigil_core` job, so a NEW orphan route turns CI red.
