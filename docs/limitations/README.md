<!-- CLAIM:W15-1 -->
# The VIGIL documented-limitation inventory (W15-1 #393)

**Registered claim (W0-3 #398):** Every real-unfinished-code limitation in the inventory resolves to a real code anchor, every re-verified-closed item names real evidence, and an unregistered honest-limit marker turns the build red.

<!-- CLAIM:W15-1-prose -->
**Registered claim (W15-1-prose):** The honest-limit prose scan refuses any deferred or limitation docstring in non-test product code that is neither a VIGIL-LIMIT marker line nor a registered honest_limit_sites entry, so adding an unregistered honest-limit docstring turns the build red, and removing a registered site's prose turns it red too.

This directory is the landed answer to the W15 intake question: *what does VIGIL not do yet, stated
against the code rather than against a wish?* The W15 plan is explicit — **"do not treat W15 as complete
until [the three audits] land and their items are filed."** `inventory.json` is that landed inventory for
the documented-limitation audit; `../tests/test_limitation_inventory.py` is the guard that keeps it honest,
and it runs in the **required** `the briefing explains every agent and capability` CI job.

This repo carries **no `TODO`/`FIXME` debt comments** — the debt lives in **honest-limit docstrings**. The
inventory is how those are tracked, and the guard makes the tracking answer to the code.

## Why JSON, not YAML

The `briefing-completeness` CI job installs **only pytest** (it reads files, imports no trust domain). So
the inventory is `inventory.json` and the guard parses it with the stdlib `json` module — the same
constraint that decides `docs/claims/registry.json`.

## The entry schema

`inventory.json` is `{"inventory_version", "classes", "severities", "dispositions", "re_verified_closed",
"limitations", "honest_limit_sites"}`. Each `limitations` entry:

| field | meaning |
|-------|---------|
| `id` | Stable id (e.g. `LIMIT-neo4j-deploy-gated`). Also the token in an honest-limit marker `VIGIL-LIMIT:<id>`. |
| `title` / `summary` | Human label + the honest one-paragraph statement of the limit. |
| `classification` | `doc-only` (a property of the world — hardware absent, no external audit team, a field record that can only accrue) or `real-unfinished-code` (a stub, an interface with no runtime, an infra/credential/tooling-gated path). |
| `severity` | `critical` / `high` / `medium` / `low` / `info`, scored for a **third-party (national-agency) deployment**. `info` = a deliberate, correctly-deferred boundary, not debt to burn down. |
| `anchor` | `{file[, symbol]}` — the code the limit lives in. The guard resolves `symbol` by AST (no import). |
| `marker` | `true` iff an honest-limit docstring carries the `VIGIL-LIMIT:<id>` token (see the bijection below). |
| `check` | How the guard verifies the anchor: `stub-raises` (the anchored function must `raise NotImplementedError`), `symbol-exists`, `file-exists`, `doc-exists`. |
| `source_doc` | The maintained doc the limit is drawn from (usually `docs/DEFERRED-INFRA.md`). |
| `disposition` | `file-into-w16` (an open item tracked in the W16 milestone) or `re-verified-closed`. |
| `w16_issue` | The W16 issue number once filed, or `null` while filing is pending owner review. |

## The honest-limit marker convention (the bijection)

To register an honest-limit docstring you place the token `VIGIL-LIMIT:<id>` in the docstring/comment next
to the limit, and add the matching `inventory.json` entry with `marker: true`. The guard enforces a
**bijection over source files** (excluding vendored/venv trees):

- every `VIGIL-LIMIT:<id>` marker found in a `.py` source MUST be a registered `marker: true` item — *an
  honest-limit marker in code with no inventory entry turns CI red*;
- every `marker: true` item's token MUST be present in its anchor file.

Four honest-limit docstrings are seeded with markers today: the TEE attestation stub
(`LIMIT-attest-tee-hardware`), the symbolic crash-repair stub (`LIMIT-symbolic-crash-repair`), the
output-based sanitizer synthesis stub (`LIMIT-sanitizer-output-synthesis`) and the deploy-gated Neo4j
store (`LIMIT-neo4j-deploy-gated`). Because `stub-raises` items are checked to actually raise
`NotImplementedError`, **implementing a stub without updating the inventory turns CI red** — the debt
cannot be silently "completed" out of the honest list.

## The honest-limit PROSE scan (`honest_limit_sites`) — the marker is opt-in; this is not

The marker convention is opt-in: an author who forgets the `VIGIL-LIMIT:` token would escape the
bijection above. So the guard ALSO scans every **non-test product `.py`** for a curated, high-precision
set of honest-limit / deferred **debt phrases** (`not wired`, `does not yet`, `is a stub`, `is a
scaffold`, `*-gated`, ...) and **refuses any hit that is neither a `VIGIL-LIMIT:` marker line nor a
registered `honest_limit_sites` entry**. Adding a new "… is not wired / does not yet …" docstring
without registering it turns CI red even if no marker is ever added — the literal W15-1 acceptance
criterion. A broad word-list (`placeholder`, `inert`, …) is deliberately NOT used: it produces hundreds
of false hits in ordinary prose; the curated set is the phrasing the W15 intake actually names.

Each `honest_limit_sites` entry is `{file, snippet, kind, note[, limit_id]}`:

- `kind: "debt"` — the phrase IS a capability limit; `limit_id` names the `limitations` item it belongs
  to (which must exist). This is how the prose census maps back to a tracked, W16-fileable item.
- `kind: "non-debt"` — the phrase is a deliberate design choice, a runtime-state description, or a phrase
  describing a **check's target** rather than VIGIL itself; `note` explains why it is not debt.

The scan is **bidirectional**: every `snippet` must still match a debt-phrase line in its `file`, so if
the prose is reworded or moved, the stale site turns CI red until the census is corrected.

## Newly-mined limitations (W15-1 completion)

The prose scan surfaced honest-limit docstrings the first inventory pass had missed. They are now
registered `limitations` (all `file-into-w16`): **`LIMIT-spine-seal-at-capture`** (high — spine
credential excerpts stored in plaintext until seal-at-capture is wired), **`LIMIT-posture-no-structured-findings`**
(medium — cloud/k8s/infra posture assessments record no structured findings/proofs),
**`LIMIT-container-kill-unwired`** (low — sandbox container force-kill has no VIGIL caller),
**`LIMIT-favicon-fingerprint-stub`** (low — fixture-only favicon table),
**`LIMIT-a11y-capture-unwired`** (info — accessibility-tree capture seam) and
**`LIMIT-gesture-native-inject-unwired`** (info — macOS/Windows native input injection is honestly inert).

## The twelve re-verified-closed items (do not re-work these)

These were named on an older audit list and re-verified against the current tree as **already done**. Each
is listed with the evidence path the guard asserts exists, so nobody re-works them:

1. **Signed governance-grant replay** — `apps/sigil/tests/test_governance_replay_guard.py`
2. **Offense-side backup / restore** — `integration/vigil_integration/backup.py`
3. **UI-launched scan skipping the `use_library` corpus** — `docs/decisions/W16-4-default-check-corpus.md`
4. **Engagement crash/restart resume** — `integration/tests/test_engine_resume.py`
5. **Kubernetes RBAC live-fire against a real k3s cluster** — `tools/livefire/k8s_rbac_livefire.py`
6. **The console / legacy-owner-token credential gate + per-user auth** — `integration/tests/test_uiproxy_peruser_auth.py`
7. **The signed per-action approval token** — `integration/vigil_integration/live/approval_token.py`
8. **`execute_sandbox` / `vigil sandbox` wiring** — `integration/tests/test_executor_sandbox.py`
9. **Neo4jGraphStore as a real client body (not a scaffold)** — `engine/crucible/framework/v2/graph/store.py`
10. **`k8s_workload_posture_oracle` wired into the verifier** — `engine/crucible/framework/v2/verify/verifier.py`
11. **The WARDEN gate on Strix's shell is fail-closed** — `integration/vigil_integration/warden_gate.py`
12. **Console orphan routes cleaned + guarded** — `engine/crucible/framework/v2/console/tests/test_orphan_route_guard_w17_14.py`

## What the guard checks (and why it is not advisory)

`../tests/test_limitation_inventory.py`, stdlib-only (`json`, `ast`, `pathlib`, `re`):

1. **schema** — every entry has every field with a valid enum value;
2. **anchor resolves** — a `stub-raises` anchor is a real function that raises `NotImplementedError`; a
   `symbol-exists` anchor is a real symbol; a `file-exists`/`doc-exists` anchor is a real file;
3. **re-verified-closed** — the census is EXACTLY the twelve ids above, each with an evidence path that
   exists (deleting the closing test/module turns CI red);
4. **marker bijection** — the `VIGIL-LIMIT:<id>` marker ↔ inventory correspondence above;
5. **prose scan** — no non-test product `.py` carries an unregistered honest-limit/deferred debt phrase
   (every hit is a marker line or a registered `honest_limit_sites` entry), and every registered site's
   snippet still matches a debt-phrase line (bidirectional);
6. **disposition** — every item is filed-into-w16 or re-verified-closed;
7. **registered** — the behaviour is in the claims registry (`W15-1` for the code-anchored inventory,
   `W15-1-prose` for the code scan);
8. **negative controls** — deliberately-broken entries (missing field, bad enum, a stub that no longer
   raises, an absent symbol, a marker with no token, an RVC with no real evidence, a bad `w16_issue`
   type, an unregistered debt line, a stale `honest_limit_sites` snippet, a debt site with an unknown
   `limit_id`) are rejected by the same validators in the same run, proving the gate is not a no-op.

## Filing the open items into W16

Open items carry `disposition: "file-into-w16"`. Filing each as a W16-milestone issue and recording its
number in `w16_issue` is a bulk, owner-reviewed operation (it mutates the tracker); the inventory is the
**source of truth** the issues are filed from, and the guard keeps that source honest whether or not the
issues have been opened yet.

## How to add a limitation

1. Land (or identify) the honest-limit docstring; add the `VIGIL-LIMIT:<id>` token if it is code debt.
2. Add the `inventory.json` entry (fill every field; pick the honest `classification`, `severity`, `check`).
3. If the docstring uses a debt phrase the prose scan catches (`not wired`, `does not yet`, `is a stub`,
   `*-gated`, ...) and you did NOT add a `VIGIL-LIMIT:` marker, add a `honest_limit_sites` entry
   (`kind: "debt"` with the `limit_id`, or `kind: "non-debt"` with a `note`) so the scan stays green.
4. Run `python -m pytest docs/tests/test_limitation_inventory.py -q` — green before you commit.
