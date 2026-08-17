# Claim 6 — Multi-User Pilot Runbook

> **Audience.** The operator running a controlled pilot of VIGIL's multi-user RBAC, and anyone reproducing
> the evidence in the [audit dossier](../audit/claim-6-rbac-dossier.md). This is a **runbook**, not a
> tutorial: each phase has a goal, the commands to run, and the **expected result** that constitutes a pass.
> Where a command has options this runbook does not enumerate, run it with `--help` — the runbook states the
> verbs, not every flag, so it cannot drift from the CLI.
>
> **Authorization first.** Every engagement in Phase 4 runs against an in-scope target under a filled-in
> [`targets/<slug>/charter.md`](../../targets/_template/charter.md). Do not run Phase 4 without one.

---

## 0. Prerequisites

- A working checkout with both plane environments built (`envs/build_envs.sh` or `bootstrap.sh`).
- The **owner key** provisioned (`ensure_owner_keypair()` runs on first sovereign use; `sigil sign` / the
  first `sigil` command establishes the signed spine head).
- The `vigil` and `sigil` CLIs on `PATH` (or invoked via their plane venvs).
- A scratch directory for pilot artifacts and backups that is **not** inside the repo working tree.

> **One-role-at-a-time discipline.** Keep the owner token and each per-user bearer in separate places. The
> pilot's whole point is to prove roles are enforced; mixing credentials defeats the test.

---

## Phase 1 — Provision accounts and roles

**Goal:** create non-owner users bound to roles, as owner-signed spine grants.

```sh
# as the owner (owner key present):
sigil accounts create alice viewer      # → prints a bearer token ONCE (copy it now)
sigil accounts create bob operator      # → prints bob's bearer ONCE
sigil accounts list                     # → alice: viewer, bob: operator (owner-signed)
```

**Expected:** each `create` prints `account CREATED: <user> → <role> (owner-signed, seq N)` and a bearer
token shown **once** ("only its salted hash is stored"). `list` shows both accounts with their roles.

> The bearer is `secrets.token_urlsafe(32)`; only `sha256(salt+bearer)` is stored. If a user loses their
> bearer, re-issue with `sigil accounts create` (or rotate); you cannot recover the original.

**Role change / revocation (used again in Phase 6):**

```sh
sigil accounts assign alice analyst     # promote alice viewer → analyst (owner-signed)
sigil accounts revoke alice             # alice's bearer no longer authenticates
```

---

## Phase 2 — Bring up the shareable command UI, log in per-user

**Goal:** confirm the command UI is a per-user boundary — no embedded owner credential, each user logs in
with their own bearer.

```sh
vigil up            # brings the whole UI up at one origin; prints the OWNER boot token + URL
```

- Open the URL. The served page carries **no** credential — you are met by the **login gate**, not an
  already-authenticated session.
- The **owner** logs in with the token `vigil up` printed.
- **alice** and **bob** log in with the bearers from Phase 1 (in separate browsers / private windows).

**Expected pass:**
- View source / DevTools on the served `index.html` → **no owner token** embedded (`data-token` empty).
- Each session's identity (Users & Roles / whoami) reflects the **logged-in** user's role, not owner.

Bring it down with `vigil down` when the pilot phase ends.

---

## Phase 3 — Exercise the RBAC boundary (the assurance checks)

**Goal:** reproduce the audit dossier's independent-verification rows. Each is a **negative** control — the
pass condition is a refusal.

| Check | Action | Expected |
|---|---|---|
| **3.1 Above-role action refused** | As **alice (viewer)**, attempt an operator action (e.g. start an engagement) via the UI or `POST /api/…` with alice's bearer | **403 / refused** — a viewer has only `read` |
| **3.2 Operator can, owner-only cannot** | As **bob (operator)**, run an engagement → allowed; attempt an owner-only action (e.g. reveal a secret, toggle the protected-domain guard) | engagement **allowed**; owner-only **refused (403)** |
| **3.3 Owner token never reaches the browser** | As **alice**, request `/offense/` through the proxy; inspect the raw response body | the owner token is **absent** (redacted); alice cannot scrape and replay it |
| **3.4 Revoked bearer stops working** | `sigil accounts revoke bob`; within the auth-cache TTL (≤30 s) bob's next request | **401** once the cache expires (note the ≤30 s revocation lag — this is expected, documented behavior) |
| **3.5 Protected-domain guard is owner-only** | As **bob (operator)**, attempt to set `VIGIL_ALLOW_PROTECTED_DOMAINS` on | **refused** — only the owner (`toggle_protected_guard`) may change it |

> **3.5 detail — the guard is a global toggle, fail-safe ON.** With `VIGIL_ALLOW_PROTECTED_DOMAINS` unset
> (or any non-affirmative value), the categorical `.gov/.mil/.edu/.int`(+IGO) pre-filter is **active**. Only
> an explicit owner-signed affirmative turns it off, and doing so lifts the pre-filter for **all** protected
> classes at once — it is not a per-host exception. Even off, the signed charter scope and the egress floor
> remain in force. Do **not** turn it off for a pilot unless you are deliberately testing that path.

---

## Phase 4 — Run a governed engagement and verify a finding

**Goal:** confirm an operator-role user can drive a real, gated engagement end-to-end, and that a finding is
oracle-confirmed and offline-re-verifiable. **Requires a filled-in charter.**

1. Confirm the active target's `targets/<slug>/charter.md` authorizes the engagement (copy from
   [`targets/_template/charter.md`](../../targets/_template/charter.md), fill it in, have the operator
   confirm it). For a self-contained pilot, use the `loopback` target (a local vulnerable app VIGIL owns).
2. As **bob (operator)**, launch the engagement (UI wizard, or `vigil engage <slug> <seed-url>`).
3. When a finding is minted, confirm it is a **FACT** (a deterministic oracle fired over real bytes), not a
   lead, and export the re-verifiable bundle.
4. Re-verify **offline**: `python3 -m framework.v2 verify <report.json>` re-runs each finding's retained
   `oracle_context` and must reproduce it. Tamper a byte → the re-verify must **reject**.

**Expected pass:** the finding re-verifies 2/2 (or N/N) offline; a tampered bundle is rejected. Every action
was gated (an out-of-scope seed refuses *before* traffic and is recorded as a refusal event).

---

## Phase 5 — Off-host backup and recovery drill

**Goal:** confirm the operator can take an encrypted, signed, off-host backup and restore it safely.

```sh
# take an encrypted, governance-signed backup (choose a passphrase; it is NEVER stored):
vigil backup <scratch>/vigil-backup            # writes the offense + sovereign sealed files
# push a ciphertext-only copy off-host (opt-in):
vigil backup <scratch>/vigil-backup --push     # the pushed file is byte-identical to the local sealed file
# automated recovery drill (backup → restore → re-verify, fails on any error):
tools/backup/recovery_drill.sh
```

**Restore safety check (reproduces audit row 6):**

1. Put a non-captured live file inside the crucible root (e.g. a `framework_code.py` next to `.blackboard/`).
2. `vigil restore … --force` into that root.
3. **Expected:** the captured proof units are restored, and the non-captured file **survives** — a `--force`
   restore replaces only the captured units, never live un-captured data. (A run created *after* the backup,
   which lives *inside* the captured `.console/runs` subtree, is dropped — that is the intended DR-snapshot
   semantic, and the CLI `--force` help states it.)

**Expected pass:** the drill completes green; the restored spine re-verifies; the ciphertext-only push
carries no plaintext secret; un-captured data survives `--force`.

---

## Phase 6 — Revocation and kill-switch

**Goal:** confirm the operator can turn a user off and halt the system.

- **Revoke:** `sigil accounts revoke <user>` → the bearer stops authenticating (≤30 s cache lag). `revoke`
  is honored even unsigned (the safe direction) — you can always turn a user off.
- **Kill-switch:** engage the kill-switch (any authenticated user may *engage*; only the owner
  `kill_release` may un-halt). Confirm autonomous actions are blocked while halted.

**Expected pass:** a revoked user is denied; a halted system refuses mutations until the **owner** releases.

---

## Success criteria (pilot sign-off)

The pilot is a **pass** when all of the following hold, with evidence captured:

- [ ] Phase 1: accounts created as owner-signed grants; bearers issued once.
- [ ] Phase 2: the served UI embeds no owner credential; each user logs in as themselves.
- [ ] Phase 3: every negative control refuses (3.1–3.5), including the owner-token-never-in-browser check.
- [ ] Phase 4: a finding is oracle-confirmed and re-verifies offline; a tampered bundle is rejected.
- [ ] Phase 5: backup + off-host push + recovery drill succeed; `--force` restore preserves un-captured data.
- [ ] Phase 6: revocation and kill-switch behave as specified.

Record each result (command, output, timestamp) in the pilot's evidence folder. The
[audit dossier §10](../audit/claim-6-rbac-dossier.md#10-auditors-independent-verification-checklist) maps
each of these back to the claim it verifies.

---

## Honest caveats for the pilot

- **Revocation is not instant** — up to the ≤30 s auth-cache TTL, and an already-open SSE stream is
  authenticated only at connect. Plan the pilot's revocation test around that window.
- **The command-UI proxy is a loopback / private-VIP listener**, not a hardened public gateway. Run the
  pilot behind the operator's own TLS edge; do not expose the proxy raw to the internet.
- **Offense-plane authorization is coarse** (read vs. `run_engagement`). Per-action offense RBAC is not yet
  built; owner-authority offense actions stay owner-gated on the sovereign plane.
- **The trust root is the owner key + the local accounts store.** The pilot proves the *access model*; it
  does not remove those residual trust roots.
- **Bearer tokens, not per-user keypairs.** The stronger cryptographic-identity replacement is named in the
  dossier but not part of this foundation.
