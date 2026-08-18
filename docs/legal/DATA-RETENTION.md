# VIGIL — Data Retention

**Status: a description of what this software does, plus a schedule the operator can adopt and edit.
Not legal advice. No claim of compliance with any statute is made here.**

Every default stated below was read from the source on this branch and carries a `path:line` citation.
The engineering reference is [`DATA-GROUND-TRUTH.md`](DATA-GROUND-TRUTH.md); the privacy statement
built on it is [`/PRIVACY.md`](../../PRIVACY.md).

---

## 1. The headline, stated plainly

**Nothing in VIGIL expires on a timer, with one exception.** There is no configured retention limit
for any artifact class. Nothing is swept, aged out, or rotated away on a schedule. Every class below is
kept **indefinitely** until the operator deletes it by hand or by a command.

The one stored class that expires by itself is the OIDC single-use `state → nonce` ledger, which is
TTL-swept and capacity-capped (`apps/sigil/sigil/ui/oidc.py:436-500`). Authorization artifacts —
per-action approval tokens, owner-signed delegations — carry their own validity windows, but that is
expiry of *authority*, not deletion of data.

A retention *policy* therefore exists only if the operator writes one and executes it. §5 offers a
starting point.

---

## 2. Artifact classes

### 2.1 Spine records — the sovereign append-only ledger

| | |
|---|---|
| **Where** | `~/.sigil/spine/spine.jsonl` plus rotated segments in the same directory (`apps/sigil/sigil/config.py:90-91, 103-119`) |
| **Contains** | account grants (username, role, credential hash and salt, enrolled public key, sealed TOTP secret, password hash), governance decisions, device grants, ingested assistant-transcript and git-commit events, findings received from the offense plane |
| **Default retention** | **Indefinite.** No limit is configured anywhere. The ledger grows without bound until the operator intervenes. |
| **Deletion mechanism** | **None per record.** The hard-prune machinery on this branch is dry-run only — its own docstring says "NOTHING here deletes a live record or commits a head" (`apps/sigil/sigil/spine/prune.py:1-4`), and the CLI exposes only `sigil spine prune-plan`, annotated "DRY-RUN — nothing archived or dropped" (`apps/sigil/sigil/cli.py:844-861`). The only bulk delete is `sigil ingest --reset`, which deletes the whole data file, the manifest, all segments, the trash, the cursor and the vector index (`apps/sigil/sigil/cli.py:20-33`; `apps/sigil/sigil/spine/store.py:454-478`). |
| **Survives deletion** | The durable anti-rollback floor at `~/.sigil/floor.json` is deliberately **not** cleared by a reset, because a reset must not be able to silently lower it; `sigil verify` will report `ROLLBACK` until the floor is deliberately re-seeded with `sigil floor reset --yes` (`apps/sigil/sigil/cli.py:29-33`; `apps/sigil/sigil/config.py:98-101`). Any witnessed checkpoint the operator retained off-box also survives. |
| **Note** | `sigil spine compact` gzips sealed segments; it reclaims disk and **preserves every record** (`apps/sigil/sigil/cli.py:836-843`). It is not a deletion mechanism. |

**If the designed prune is ever completed, what would survive it** (relevant to any future erasure
claim): the folded snapshot deliberately carries forward per-account state — username, role,
`cred_hash`, `cred_salt`, bound public key and the anti-replay high-water — because dropping it would
re-open a replay hole (`apps/sigil/sigil/governor/accounts.py:29-35`;
`apps/sigil/sigil/spine/snapshot.py:32-35`); a guard refuses a boundary that would strand an active
account's only grant (`apps/sigil/sigil/spine/prune.py:165`); and a cumulative Merkle root over every
pruned record's hash stays committed in the owner-signed head (`apps/sigil/sigil/spine/merkle.py:1-8`).
**A prune erases content; it does not erase a person.**

### 2.2 Usage-attestation ledger

| | |
|---|---|
| **Where** | `<base_dir>/usage-ledger.jsonl`, default `.vigil-live/usage-ledger.jsonl` (`integration/vigil_integration/live/wiring.py:305`) |
| **Contains** | one append-only hash-chained record per attested action, each embedding the operator's OS login, git name, git email, hostname and key fingerprint (`integration/vigil_integration/attestation/models.py:24-45, 60-82`) |
| **Default retention** | **Indefinite.** Always on; no rotation. |
| **Deletion mechanism** | Filesystem deletion only. |
| **Survives deletion** | The monotonic anti-back-dating counter at `~/.vigil/attestation/` (`integration/vigil_integration/attestation/anchor.py:37`). Deleting the ledger while the counter stands is detectable, which is the point — treat this file as evidence, not as a log to tidy. |

### 2.3 Per-engagement offense spine

`.vigil-live/<slug>.spine` (`integration/vigil_integration/live/wiring.py:344`) — signed, hash-chained
records of the engagement, including findings. **Indefinite**; filesystem deletion only. Deleting it
destroys the chain a client-facing certificate or dossier was derived from; export first (§2.8).

### 2.4 Evidence archive

| | |
|---|---|
| **Where** | `targets/<slug>/evidence/<action_id>/` — `request.http`, `response.http`, and the complete raw `response.body` (`engine/crucible/framework/v2/common/paths.py:358-362`; `engine/crucible/framework/v2/agents/http_executor.py:744-752, 865-869`) |
| **Contains** | the highest-risk class in the system: response bodies are stored **verbatim**, with only credential headers masked (`engine/crucible/framework/v2/common/redact.py:17-22, 35-49`). Client users' personal data lands here in the clear. |
| **Default retention** | **Indefinite.** |
| **Deletion mechanism** | `rm -rf` the action, engagement, or whole `targets/<slug>/` tree. No tooling performs a targeted erasure of one data subject across evidence. |
| **Survives deletion** | Any artifact manifest hash, report, dossier or proof bundle that referenced it, plus any copy already delivered to a client. |
| **Alternative** | `--ephemeral` re-roots the evidence tree onto tmpfs and purges it on exit with verification, raising `EphemeralPurgeError` if a residual remains (`engine/crucible/framework/v2/common/ephemeral.py:1-35`). For an engagement where evidence must not persist, this is the mechanism — decided before the run, not after. **Reachability (verify before relying on it):** the flag is declared **only** on the CRUCIBLE engine's own `engage` parser (`engine/crucible/framework/v2/engage.py:1352`), i.e. `python3 -m framework.v2 engage … --ephemeral` run from `engine/crucible/`. It is **not** an option of the `vigil engage` super-CLI (`integration/vigil_integration/cli.py:1937-1982`) and no UI control sets it on this branch (`grep -n ephemeral packages/vigil-ui/app.js` is empty), so a run started from the UI or from `vigil engage` persists to disk. Every `--ephemeral` reference below carries that same limit. |

### 2.5 Engagement logs and reports in the target tree

`targets/<slug>/.crucible-v2.log`, `<slug>.report.json`, `<slug>.phases.jsonl`
(`engine/crucible/framework/v2/common/paths.py:364-365, 383-399`). Structured-log secret *keys* are
masked (`engine/crucible/framework/v2/common/redact.py:52-79`); target data is not.
**Indefinite**; filesystem deletion; re-rooted to tmpfs under `--ephemeral` (engine CLI only — §2.4).

### 2.6 Console run store, chats, sessions, blackboard

| Artifact | Where | Default | Deletion | Survives |
|---|---|---|---|---|
| Run dirs (`progress.jsonl`, `report.json`, `meta.json`) | `<crucible-root>/framework/v2/.console/runs/<run_id>/` (`engine/crucible/framework/v2/console/actions.py:266-269, 288-294`) | indefinite | filesystem; or tmpfs-only under `--ephemeral` (engine CLI only — §2.4) | dossiers/exports derived from the run |
| Chat transcripts and attachments | `.vigil-live/chats/<id>.jsonl`, `.vigil-live/chats/<id>.attachments/` (`engine/crucible/framework/v2/console/chat.py:449-457`) | indefinite | **chat delete** removes the transcript, its attachments directory and the registry entry (`chat.py:562-582`) | the spine — chat delete never touches it |
| Session registry | `.vigil-live/sessions/<id>/session.json` (`engine/crucible/framework/v2/console/sessions.py:55-70`) | indefinite | **soft delete** writes a tombstone and removes nothing; **hard delete** removes the registry entry and the rebuildable graph partition (`sessions.py:279-305`) | the signed spine, the chat transcript and run metas — the source states hard delete "never touches the signed spine or a FACT" |
| Agent blackboard | `<crucible-root>/framework/v2/.blackboard/store.sqlite` (`engine/crucible/framework/v2/agents/blackboard.py:11, 45`) | indefinite | filesystem | — |

### 2.7 Derived stores

| Artifact | Where | Default | Deletion | Survives |
|---|---|---|---|---|
| Vector index | `~/.sigil/qdrant`, or a configured server (`apps/sigil/sigil/config.py:131-133`) | indefinite | `sigil ingest --reset` clears it (`apps/sigil/sigil/cli.py:20-25`); it is otherwise rebuildable from the spine | nothing of its own — but note it holds up to 1200 characters of record text **in the clear**, outside the spine's field-level encryption (`apps/sigil/sigil/vectors/index.py:135-142, 150`), so it must be deleted alongside, not instead of, the source |
| Graph | `~/.sigil/graph` (embedded Kùzu) (`apps/sigil/sigil/config.py:138`) | indefinite | filesystem; rebuildable | — |
| Remote graph, if configured | operator-chosen Neo4j host | operator's | operator's | outside this machine — treat as an egress destination, not local storage |

### 2.8 Exports delivered to clients

`vigil proof-export` writes a bundle to `<run-dir>/proof-bundle` by default; `vigil dossier` writes
`<run-dir>/dossier.zip` by default (`integration/vigil_integration/cli.py:2251-2288`). These are the
artifacts designed to leave the operator's machine.

**Retention of a delivered copy is not the operator's to control.** Once a bundle is handed over, the
client holds it. Decide before delivery what it contains — a dossier packages reports, exports, the
offline proof bundle and a scrubbed log — and record what was delivered, to whom, and when. The
operator's own copy is `indefinite` and deletable by filesystem operation.

### 2.9 Backups — the one class with a real retention mechanism

| | |
|---|---|
| **Where** | timestamped directories `YYYYmmdd-HHMMSS` under the `--out` root, default `~/vigil-backups` (`integration/vigil_integration/cli.py:2458-2487`) |
| **Contains** | two **separate** encrypted files, one per plane, never merged. The sovereign part packages the spine, floor, security manifest, owner public key, the WARDEN directory, **and the owner private key and spine DEK**, sealed under a key derived from an owner passphrase by scrypt `n=2^16` (`apps/sigil/sigil/backup.py:1-33`) |
| **Default retention** | **Indefinite** — pruning happens only when explicitly requested |
| **Deletion mechanism** | `vigil backup --prune --keep-days N --keep-last M`, backed by a deliberately conservative helper: it only considers directories matching the timestamp format, **never** deletes the newest backup, refuses to delete the sole remaining backup, is a **no-op when neither policy is given**, never follows symlinks, and supports `dry_run` (`tools/backup/retention.py:1-16`) |
| **Survives deletion** | any copy already pushed off-host. `--push` replicates **ciphertext only**; the remote's security and retention are the operator's responsibility (`tools/backup/transport.py:8-13`) |
| **Warning** | the backup passphrase is **never stored**; lose it and the backup is unrecoverable by design (`apps/sigil/sigil/backup.py:31-33`). A backup is also a full copy of everything you may have deleted elsewhere — a retention schedule that ignores backups is not a retention schedule. |

### 2.10 Keys, secrets and identity material

Not "retained data" in the usual sense, but they persist until removed and they gate everything else:
owner keypair at `~/.sigil/spine/keys/`, TPM-sealed KEK blobs at `~/.sigil/vault/`, the secret store
(OS keyring, else sealed `~/.sigil/secrets.sealed`, else plaintext `~/.sigil/sigil.env`)
(`apps/sigil/sigil/platform/secrets.py:1-19`), the WARDEN key, the offense identity keys under
`.vigil-live/`, and the bridge TLS material at `~/.sigil/bridge/`. **Without a provisioned vault these
rest in plaintext behind `0600` permissions** (`packages/core/vigil_core/vigil_core/vault.py:73-75`;
`bootstrap.sh:387`).

---

## 3. What survives deletion, in one place

| Kind of residue | Where it comes from |
|---|---|
| Record hashes and chain links | the spine is hash-chained; a Merkle commitment over pruned records would be committed in the owner-signed head (`apps/sigil/sigil/spine/merkle.py:1-8`) |
| Folded account state | a completed prune deliberately carries username, role, credential hash and salt, and public key forward (`apps/sigil/sigil/spine/snapshot.py:32-35`) |
| Anti-rollback floor | `~/.sigil/floor.json`, deliberately outside `spine/` and not cleared by a reset |
| Monotonic attestation counter | `~/.vigil/attestation/` |
| Tombstones | session soft delete records a tombstone and removes nothing (`engine/crucible/framework/v2/console/sessions.py:279-305`) |
| Backups | a copy of everything as of the backup time, until pruned |
| Delivered exports | proof bundles and dossiers already in a client's hands |
| Witnessed checkpoints | anything the operator retained off-box for anti-rollback |

---

## 4. What no mechanism exists for

State this to a client before they ask, not after:

1. **No per-record spine deletion.** Prune is dry-run only on this branch.
2. **No subject-erasure verb.** Nothing in this repository deletes one data subject across the spine,
   the vector store, the graph and the evidence archive in one operation. That work is manual.
3. **No automatic expiry** for any class except the OIDC state ledger.
4. **No redaction of response bodies at rest.** Masking covers credential header names and
   structured-log keys, not body content.
5. **No retention control over delivered exports.**

---

## 5. A recommended schedule the operator can adopt and edit

**This is a starting point, not a rule and not advice.** The right numbers depend on the operator's
contracts, its clients' requirements, and the applicable law — none of which this document decides.
Adopt it, edit it, and put the agreed numbers in the client engagement contract.

| Class | Suggested retention | How to execute it | Notes |
|---|---|---|---|
| Evidence archive (`targets/<slug>/evidence/`) | **Delete at engagement close**, or 30–90 days if the client needs a re-verification window | scheduled `rm -rf` of the engagement's evidence tree, recorded in the engagement log | The highest-risk class. Prefer `--ephemeral` for engagements where evidence must never persist — but see §2.4: it is reachable only by running the CRUCIBLE engine CLI directly, not from `vigil engage` or the UI. |
| Engagement logs, report snapshot, phase ledger | Same as evidence, or keep the report and delete the log | filesystem | The report is usually the deliverable; the raw log rarely is. |
| Console run dirs, blackboard | 30–90 days | filesystem | Rebuildable working state, not the record of the engagement. |
| Chats and attachments | 30–90 days, or at engagement close | chat delete (removes transcript, attachments and registry entry) | Whatever the operator pasted in is in here. |
| Sessions | Hard-delete at engagement close | session hard delete | Registry and graph partition only; the spine is untouched. |
| Per-engagement offense spine | Keep for the assurance period agreed with the client, then delete | filesystem | Export the proof bundle / dossier first — it is the client-verifiable artifact. |
| Delivered exports (client copies) | Agreed in the engagement contract | contractual, not technical | The operator cannot enforce this technically. |
| Sovereign spine | **Decide deliberately** — see §2.1 and `/PRIVACY.md` §6 | no per-record mechanism exists | The real decision is upstream: what is allowed to enter the ledger at all. |
| Usage-attestation ledger | Keep — it is the attestation record | — | Deleting it while the monotonic counter stands is detectable. |
| Backups | `--keep-days 30 --keep-last 8`, tuned to the recovery objective | `vigil backup --prune --keep-days 30 --keep-last 8`, e.g. via the shipped systemd timer | Deleting data elsewhere does nothing until backups age out. Keep the passphrase somewhere it cannot be lost with the host. |
| Vector index and graph | Rebuild rather than retain; clear when the source is cleared | `sigil ingest --reset` clears vectors; graph is rebuildable | The vector store holds cleartext excerpts; never leave it behind after clearing a source. |
| OIDC state ledger | Leave as shipped | TTL-swept, capacity-capped | The only self-expiring class. |

### Two upstream decisions worth more than any schedule

1. **What is allowed into the spine at all.** `sigil ingest` pulls the operator's AI-assistant
   transcripts and configured git repositories into an append-only ledger with no per-record deletion
   (`apps/sigil/sigil/config.py:122-126, 227-235`). If client-identifying discussion must not become
   permanent, constrain the ingest allowlist rather than planning to delete afterwards.
2. **Whether the engagement runs ephemeral.** `--ephemeral` decides "leaves nothing on disk" before the
   run starts. After the run, the tools to achieve the same result do not exist. Choosing it also
   chooses the **entry point**: it exists only on the CRUCIBLE engine's own `engage` parser (§2.4),
   so an engagement that must run ephemeral cannot be launched from the UI or from `vigil engage`.

---

## 6. Verification record

Complete before relying on this document:

- Verified against commit: `[COMMIT]`
- Date: `[DATE]`
- Verified by: `[NAME]`
