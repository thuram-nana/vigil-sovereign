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

## Phase 1b — Strong per-user identity (keypair PoP · MFA/TOTP · optional password)

**Goal:** move a user beyond bearer-only by binding a cryptographic identity and a second factor. These are
**owner-only** enrollment **actions** (`manage_users`) on the sovereign action plane — `POST /api/action`
with `{action, username, …}` (the Users & Roles screen drives the same actions). There is **no**
`sigil accounts enroll-*` CLI verb; enrollment is owner-signed into the account grant, so it needs the owner
key present. Do **not** confuse these with the create/assign/revoke CLI verbs in Phase 1.

**1b.1 — Per-user keypair + challenge/response PoP login (`enroll_pubkey`):**

- As the **owner**, enroll alice's Ed25519 public key: `POST /api/action` `{action:"enroll_pubkey",
  username:"alice", user_pubkey:"<base64 raw ed25519 public key>"}`. It is owner-signed into her grant; an
  account is bearer-only until enrolled.
- As **alice**, log in by proof-of-possession (no bearer needed): `GET /api/login/challenge` → a single-use
  server nonce; sign `DOMAIN_TAG + challenge` with her private key; `POST /api/login`
  `{username:"alice", challenge, signature}` → a fresh session bearer is minted.

**Expected pass:** the PoP login succeeds and returns a bearer. **Replaying** the same
`{username, challenge, signature}` a second time is **refused (401)** — the challenge is consumed exactly
once (reproduces audit row 10).

**1b.2 — MFA / TOTP second factor (`enroll_totp`):**

- As the **owner**, enroll TOTP for alice: `POST /api/action` `{action:"enroll_totp", username:"alice"}`.
  The response carries an `otpauth://` **provisioning URI shown ONCE** — scan it into an authenticator now;
  the secret is **sealed** at rest (owner vault) and is never recoverable from the spine. (Enrollment needs a
  provisioned owner vault; if it is not, the action returns a clean "provision the vault" error.)
- As **alice**, log in: `POST /api/login` now requires a valid current `totp` code **in addition** to her
  method (bearer or PoP).

**Expected pass:** a login **without** the code, or with a **stale** code, is **refused (401)**; the current
code succeeds (reproduces audit row 11). The second factor is enforced only at `/api/login`, fail-closed.

**1b.3 — Optional password login (`set_password`), if you want the weaker fallback:**

- As the **owner**, `POST /api/action` `{action:"set_password", username:"alice", password:"…"}` — stored as
  salted **scrypt** (`scrypt$…`); the plaintext never reaches the spine. Keypair PoP (1b.1) is the **stronger**
  path; use a password only where a keypair is impractical.

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
| **3.6 Per-action offense RBAC** | As **alice (viewer)** through `vigil up`, POST an **owner-tier** offense action (e.g. `/offense/api/terminal/run`, `/offense/api/authority/provision`) | **403 / refused** — the proxy stamps a signed hop-assertion, the console verifies it and `role_can` denies `offense_authority`. An *operator* is allowed the operator-tier routes (e.g. launch/retry) but still denied the owner-tier ones. |

> **3.6 detail — the honest bound.** The per-action offense gate protects the **proxy-forwarded per-user
> path**: a request that carries the offense **console token directly** (no hop-signed role) is
> owner-equivalent by construction. That is the offense trust root, not a bypass — the pilot exercises the
> path a shared-UI teammate actually takes (through `vigil up`), where the gate applies.

> **3.5 detail — the guard is a global toggle, fail-safe ON.** With `VIGIL_ALLOW_PROTECTED_DOMAINS` unset
> (or any non-affirmative value), the categorical `.gov/.mil/.edu/.int`(+IGO) pre-filter is **active**. Only
> an explicit owner-signed affirmative turns it off, and doing so lifts the pre-filter for **all** protected
> classes at once — it is not a per-host exception. Even off, the signed charter scope and the egress floor
> remain in force. Do **not** turn it off for a pilot unless you are deliberately testing that path.

---

## Phase 3b — OIDC Relying Party (OPTIONAL — ships OFF by default)

**Goal:** if the pilot includes SSO, confirm the OIDC RP is inert until enabled and that it never lets an
external identity mint a role. **Skip this phase entirely for a default pilot** — with OIDC off there is
nothing to test and the build is byte-identical to one without OIDC.

- **Off (default):** `GET /api/oidc/login` returns **404** — the route is not registered, no egress.
- **On (against an operator-run IdP on the private tunnel):** set `SIGIL_OIDC_ENABLED` (+ issuer / client-id
  / JWKS / signing-algs) and restart the cockpit. Then confirm the two soundness properties:
  - A **verified** OIDC identity that has **no owner-signed `governor.account`** → **refused**. The role is
    taken from the owner-signed grant, **never** from an OIDC claim.
  - A tampered `id_token` — `alg:none`, a bad signature, or a bad/replayed `nonce` — is **refused** (JWKS
    asymmetric-only verification; single-use `state`↔`nonce`). (Reproduces audit row 12.)

> **Honest bounds.** OIDC targets an **operator-run IdP reachable on the private tunnel** — pointing it at a
> public cloud IdP breaks the air-gap. And the RP stops at returning the verified bearer as JSON: a browser
> landing page that **auto-adopts** that bearer into a session **still needs `state`-browser-binding + PKCE**
> (`docs/OIDC-RP.md`, "Required follow-on") — that step is **not** built, so treat OIDC here as an API-level
> identity proof, not a wired browser SSO landing.

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
vigil backup --out <scratch>/vigil-backup                 # writes the offense + sovereign sealed files
# push a ciphertext-only copy off-host (opt-in; --push takes the destination):
vigil backup --out <scratch>/vigil-backup --push /mnt/offhost   # the pushed file is byte-identical to the local sealed file
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
- [ ] Phase 1b (if exercised): keypair PoP login works and a replay is refused; a TOTP-enrolled account needs
      its current code and a stale code is refused.
- [ ] Phase 2: the served UI embeds no owner credential; each user logs in as themselves.
- [ ] Phase 3: every negative control refuses (3.1–3.6), including the owner-token-never-in-browser check and
      the viewer→owner-tier offense-action 403.
- [ ] Phase 3b (only if OIDC enabled): off → routes 404; on → a verified identity with no owner-signed account
      is refused and a forged/replayed `id_token` is refused.
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
- **Per-action offense RBAC rides the proxy hop-assertion.** The offense console now maps each POST to a
  permission (owner-tier `offense_authority` / operator-tier `run_engagement` / read-tier kill-switch trip),
  enforced against a proxy-stamped HMAC hop-assertion — but a client holding the offense **console token
  directly** (no hop-signed role) is **owner-equivalent** by construction. The gate protects the
  proxy-forwarded per-user path (what a shared-UI teammate takes), not a direct console-token holder.
- **The trust root is the owner key + the local accounts store.** The pilot proves the *access model*; it
  does not remove those residual trust roots. Keypair PoP (Phase 1b) proves possession of an **owner-bound**
  key and OIDC (Phase 3b) maps to an **owner-signed** grant — both keep the owner at the root.
- **Keypairs, MFA/TOTP, and OIDC (off-by-default) are built, but bearers remain the session carrier.** After
  a PoP or OIDC login a bearer is minted and carries the session; and the OIDC **browser** landing
  (`state`-binding + PKCE) is a **required follow-on that is not built** (`docs/OIDC-RP.md`).
