# VIGIL — Privacy and Data-Protection Statement

**Status: a description of what this software does, plus a template the operator must complete.
Not legal advice. No claim of compliance with any statute is made anywhere in this document.**

Before publishing this as your privacy statement:

1. Fill every `[PLACEHOLDER]`. They are deliberately unfilled — jurisdiction, controller identity and
   contact route are yours, not the software's.
2. Have qualified counsel in your jurisdiction review it. This document describes *behaviour*; only
   counsel can map behaviour onto a legal regime.
3. Re-check it against the code before each publication. Every factual statement here was read from
   the source on this branch and carries a `path:line` citation. The engineering reference behind it is
   [`docs/legal/DATA-GROUND-TRUTH.md`](docs/legal/DATA-GROUND-TRUTH.md); where that document says
   **NOT VERIFIED**, this one stays silent rather than guessing.

Related: [`docs/legal/DATA-RETENTION.md`](docs/legal/DATA-RETENTION.md) (artifact classes, deletion
mechanisms) and [`docs/legal/INCIDENT-RESPONSE.md`](docs/legal/INCIDENT-RESPONSE.md) (what to do when
something goes wrong in either direction).

---

## 1. Who is who

| Party | Role in practice |
|---|---|
| **The operator** — `[OPERATOR LEGAL NAME]` | Runs VIGIL on hardware they control. Decides what is tested, what is collected, how long it is kept, and whether model egress is permitted. In the vocabulary common to data-protection regimes the operator is the party that determines the purposes and means of processing — that is, the operator, not the project author, stands as controller for client and target data. How that maps onto the applicable regime is for counsel. |
| **The client** — the organisation whose systems are tested | Owns the tested systems. The personal data of *its* users can appear inside evidence VIGIL captures. |
| **The project author** — Junior Thuram Nana | Supplies the software under `LICENSE` / `LICENSING.md`. The software is self-hosted: nothing in this repository transmits operator or client data to the author, and nothing in it gives the author access to an operator's deployment (§2). |
| **Third-party services** | Model providers, OSINT sources, code hosts and similar, reached only under the gates in §5. |

**The operator is responsible for the lawful basis, the authorization, and the contracts.** VIGIL
enforces a *technical* authorization gate — an engagement refuses to run without a signed charter, and
refuses any host outside that charter's in-scope table
(`engine/crucible/framework/v2/common/ethics.py:104-136, 145-153, 283-303`) — but a signed charter is a
control, not a legal instrument. The operator must separately hold: written authorization from the
system owner, whatever processing agreement its jurisdiction and its client's jurisdiction require, and
a lawful basis for handling personal data that appears in evidence.

---

## 2. What the project author receives: nothing, by default

VIGIL is self-hosted. It is installed on the operator's own machine by `bootstrap.sh` and runs there.

Verified on this branch:

- **No analytics or crash-reporting SDK exists in first-party code.** No PostHog, Sentry, Scarf,
  Datadog, Segment or equivalent appears anywhere in `apps/`, `integration/`, `packages/`, `engine/`
  or `gateway/`.
- **The vendored third-party scanner's phone-home was removed.** Strix's upstream
  `strix/telemetry/{posthog,scarf}.py` — which POSTed scan, finding and skill events to
  `us.i.posthog.com` and `strix.gateway.scarf.sh` — are deleted and replaced by a local-only logging
  sink with no network transport (`NOTICE:28-45`; `vendor/strix/strix/telemetry/sink.py:1-9`).
- **Every outbound destination in the code is either a service the operator configures or a public
  passive source queried about the target.** None is an endpoint the project author controls. The full
  list is §5.
- **No update check, licence check-in, or usage beacon.** Enumerating every hard-coded outbound
  host across first-party code yields only the destinations listed in §5.

Two honest caveats, both operator-initiated and neither automatic:

1. `vigil knowledge push` runs `git push` against whatever remote the operator's clone is configured
   with (`integration/vigil_integration/knowledge_sync.py:137-140`). If that remote is the upstream
   project repository, pushed content lands in a repository the project author controls. The command is
   explicitly operator-invoked, never called by an agent, and the preceding `sync` refuses the commit on
   a secret-scan hit — described in its own source as "a net, NOT a guarantee"
   (`integration/vigil_integration/knowledge_sync.py:1-9`).
2. Anything the operator chooses to send — a bug report, a log excerpt, a backup — is a deliberate
   disclosure by the operator.

---

## 3. Categories of personal data processed

### 3.1 Operator and user account data

Accounts are not rows in a mutable table: each is an owner-signed governance grant appended to the
hash-chained spine (`apps/sigil/sigil/governor/accounts.py:207-221, 400-418`), stored at
`~/.sigil/spine/spine.jsonl` and its rotated segments (`apps/sigil/sigil/config.py:90-91`).

| Field | Form on disk | Note |
|---|---|---|
| `username` (1–64 chars, operator-chosen) | **plaintext** | Not in the encrypted field set, so field-level encryption never covers it (`apps/sigil/sigil/spine/envelope.py:61-65`). Protected by `0700`/`0600` permissions only. |
| `role` (`viewer` / `analyst` / `operator`) | plaintext | `owner` is never grantable; an `active` grant requires a valid owner signature and strict freshness (`accounts.py:210, 244-249, 461-468`). |
| bearer / session token | **not stored** | Only `sha256(cred_salt ‖ bearer)` plus a 16-byte salt; comparison is constant-time; a proof-of-possession login mints a *fresh* bearer (`accounts.py:211-213, 289-291, 366-387, 482-493`). |
| enrolled Ed25519 **public** key | plaintext (it is public) | Owner-bound only; malformed, non-canonical (`y ≥ p`) and low-order forgery keys are refused at binding (`accounts.py:215-216, 252-263`). |
| TOTP shared secret | **AEAD-sealed, never plaintext** | ChaCha20-Poly1305 under the TPM-sealed vault KEK, context-bound to `b"sigil/account.totp"`. Sealing has no plaintext fallback, so **TOTP enrolment refuses outright without a provisioned vault** (`accounts.py:110-113, 217-219`; `packages/core/vigil_core/vigil_core/vault.py:119-129`). |
| password hash (optional weaker login) | salted scrypt `n=2^15, r=8, p=1` | Plaintext password never reaches the spine; verification is constant-time; a decoy hash of identical cost makes login timing independent of whether the username exists (`accounts.py:115-129, 132-161`). |

**OIDC**, when enabled (`SIGIL_OIDC_ENABLED`; routes are not even registered when off —
`apps/sigil/sigil/config.py:154-161`; `apps/sigil/sigil/ui/server.py:209-212`): only the configured
username claim is read, in memory, to look up an owner-signed account. No `id_token`, claim set or
subject is persisted; the sole durable artefact is a single-use `state → nonce` marker under
`<spine-path>.oidc-state/`, TTL-swept and capacity-capped (`apps/sigil/sigil/ui/server.py:517-568`;
`apps/sigil/sigil/ui/oidc.py:436-500`). A role is never taken from a claim.

### 3.2 Operator identity — structurally required, not incidental

Every record of the always-on usage-attestation ledger embeds the operator's **OS login, git
`user.name`, git `user.email`, hostname** and key fingerprint
(`integration/vigil_integration/attestation/models.py:24-45, 60-82`;
`integration/vigil_integration/attestation/identity.py:107-132`). The ledger refuses to mint or accept
a record whose identity carries neither a signing fingerprint nor a human handle
(`models.py:40-45`). **The operator cannot run pseudonymously through the supported path.** The ledger
is an append-only hash-chained JSONL at `<base_dir>/usage-ledger.jsonl`, default
`.vigil-live/usage-ledger.jsonl` (`integration/vigil_integration/live/wiring.py:305`), protected by
file permissions only — it is signed, plaintext data by design.

### 3.3 Operator working data ingested into the ledger

`sigil ingest` reads the operator's **Claude Code assistant transcripts** from `~/.claude/projects`
and appends them to the spine as events, including message text, working directory and git branch
(`apps/sigil/sigil/config.py:122-126`; `apps/sigil/sigil/ingest/transcript.py:31-50`). Repositories
listed in `SIGIL_INGEST_REPOS` are backfilled as commit events (`config.py:227-235`). **Anything the
operator discussed with an AI assistant about a client can therefore land in the append-only ledger.**
Content fields are sealed under the spine key when the vault is provisioned, and plaintext otherwise
(`apps/sigil/sigil/spine/envelope.py:61-65, 101-104`).

### 3.4 Target-derived data — the largest category, and the one containing third parties' data

For each executed action VIGIL writes `request.http`, `response.http` and the **complete raw
`response.body`** under `targets/<slug>/evidence/<action_id>/`
(`engine/crucible/framework/v2/common/paths.py:358-362`;
`engine/crucible/framework/v2/agents/http_executor.py:744-752, 865-869`).

**Credential headers are masked; response bodies are not.** `Authorization`, `Cookie`, `Set-Cookie`,
`X-API-Key` and similar are masked by name; the module states explicitly that the raw body is never
touched and is protected instead by owner-only permissions, because over-masking would destroy the
evidence a finding rests on (`engine/crucible/framework/v2/common/redact.py:17-22, 35-49`).
**If a client's application returns its users' personal data, that data is on the operator's disk
verbatim.**

Also target-derived: the engagement audit log `targets/<slug>/.crucible-v2.log`, the report snapshot
`<slug>.report.json` and the phase ledger `<slug>.phases.jsonl`
(`engine/crucible/framework/v2/common/paths.py:364-365, 383-399`); the per-engagement offense spine
`.vigil-live/<slug>.spine` (`integration/vigil_integration/live/wiring.py:344`); the agent blackboard
SQLite (`engine/crucible/framework/v2/agents/blackboard.py:11, 45`); and console run directories
(`engine/crucible/framework/v2/console/actions.py:266-269`).

Chat transcripts, uploaded attachments and the session registry under `.vigil-live/`
(`engine/crucible/framework/v2/console/chat.py:449-457`;
`engine/crucible/framework/v2/console/sessions.py:55-70`) can contain whatever client material the
operator pasted or uploaded.

### 3.5 Derived stores

- **Vectors.** The embedded Qdrant store at `~/.sigil/qdrant` (`apps/sigil/sigil/config.py:131-133`)
  indexes `session_id`, `project`, timestamp, record hash and **the first 1200 characters of the record
  text in the clear**; records are decrypted before embedding
  (`apps/sigil/sigil/vectors/index.py:135-142, 150`). The spine's field-level encryption does **not**
  extend to it.
- **Graph.** Embedded Kùzu store at `~/.sigil/graph` (`apps/sigil/sigil/config.py:138`). A remote
  Neo4j is configurable and would be an egress path; what a remote projection would carry is not
  verified on this branch and is therefore not described here.

---

## 4. Where it is stored

Everything is on the operator's machine, under two roots:

| Root | Default | Holds |
|---|---|---|
| Sovereign root | `~/.sigil` (or `SIGIL_HOME`) | spine + rotated segments, keys, vault, secret store, vectors, graph, bridge TLS material |
| Offense working dir | `.vigil-live` (or `VIGIL_LIVE_DIR` / `VIGIL_BASE_DIR`) | usage ledger, per-engagement spines, chats, sessions, run store, offense identity keys |
| Engagement dirs | `targets/<slug>/` | charter, evidence archive, audit log, report, phase ledger |

Directories are created `0700` and files `0600`, with the mode set before any bytes are written so
there is no world-readable window (`engine/crucible/framework/v2/common/paths.py:89-146`;
`apps/sigil/sigil/config.py:238-244`).

Network services bind loopback: every compose port publishes on `127.0.0.1`
(`docker-compose.yml:9-11`), and the UI proxy refuses `0.0.0.0`, unspecified and globally-routable
binds (`integration/vigil_integration/uiproxy.py:30-33, 250-252`). Remote access is achieved by a
tunnel plus reverse proxy, not by exposing a public bind (`docs/DEPLOY.md`, "Hosting on a server you
own"). The phone bridge binds loopback or a private WireGuard/Tailscale address only
(`apps/sigil/RUNBOOK.md`).

---

## 5. What can leave the machine, and under which gate

| Egress | Destination | Default | Gate |
|---|---|---|---|
| **Model / LLM calls** (engagement reasoning step, chat, dev-edit, codefix) | `api.anthropic.com` | **ON — see §5.1** | `CRUCIBLE_SOVEREIGNTY_TIER` |
| Sovereign-cloud model backends | Bedrock / Vertex / Mistral | only if selected | same ladder |
| Local model backends | loopback | n/a | same ladder |
| Target traffic | charter-listed hosts | ON for an authorized engagement | signed charter scope + categorical protected-domain floor (both apply on every run) + a runtime host allowlist that refuses **only** under a sovereign tier and is unwired by default — see §5.2 |
| Intel / OSINT collectors | `dns.google`, `crt.sh`, `rdap.org`, `stat.ripe.net` | **OFF** | `--live` flag (`engine/crucible/framework/v2/intel/cli.py:458-460`) |
| Vulnerability-advisory feed | `services.nvd.nist.gov`, `api.osv.dev`, `www.cisa.gov` | **OFF** (offline file ingest is the default) | opt-in gated transport; queries a CVE id, never client data (`engine/crucible/framework/v2/intel/vulnfeed.py:1-15, 36-38`) |
| GitHub (auto-patch PR, knowledge sync) | `github.com` / `api.github.com` | **OFF** | `pr_enabled` + m-of-n quorum + `GITHUB_TOKEN` (`integration/vigil_integration/live/codefix_runner.py:74, 255-257`) |
| Voice (TTS/ASR) | `api.elevenlabs.io` | **OFF** (no key) | `ELEVENLABS_API_KEY`; the source states plainly that the audio leaves (`apps/sigil/sigil/voice/backends.py:239-241`) |
| Secret health probes | provider APIs | **OFF** | explicit `sigil settings check <NAME>` |
| Telemetry export | loopback collector only | **OFF** | loopback-pinned, DNS-free, fail-closed (`integration/vigil_integration/live/otel_export.py:81-104`) |
| Embedding model weights | fetched by `fastembed` on first use | on first embedding | nothing in this repository pins or vendors them; what the library fetches is not verified here |

### 5.1 Model egress — the default is permissive

**Unless the operator selects a sovereignty tier, prompt content may be sent to Anthropic's consumer
API.** `_resolve_tier_from_env()` returns `PERMISSIVE` when `CRUCIBLE_SOVEREIGNTY_TIER` is unset
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`); `PERMISSIVE` permits every backend
class including `cloud_only` — the class `anthropic` is assigned (`:65, 80`) — and its auto-selection
order puts `anthropic` **first** (`:137-141`). The module's own text calls `PERMISSIVE` the development
default, "equivalent to 'no policy enforcement' — every backend is reachable" (`:23-25`). `bootstrap.sh` writes `~/.sigil/sigil.env` with every tier line **commented
out**, under a comment saying exactly that (`bootstrap.sh:321-345`).

Prompt content can include target data, prior tool output, findings, and — on the code paths — the
operator's own source. Findings can contain third parties' personal data (§3.4).

**Any statement that "everything stays local by default" would be false.**

### 5.1a Setting a tier: which mechanism reaches which process

There are three cases. They do **not** have the same reach, and the third one fails **open**.

**(a) An environment variable exported in the shell (or unit, or container) that launches the
process. Always effective, highest precedence.** `_resolve_tier_from_env()` reads `os.environ` and
nothing else (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`). SIGIL's own env-file
loader merges with `setdefault`, so a value already present in the real environment always wins
(`apps/sigil/sigil/config.py:64-88`).

```
export CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED       # local backends only (ollama / vLLM / llama-cpp / TGI)
export CRUCIBLE_SOVEREIGNTY_TIER=SOVEREIGN_CLOUD  # + jurisdictional cloud (Bedrock / Vertex / Mistral)
export CRUCIBLE_SOVEREIGNTY_TIER=TRUSTED_CLOUD    # + Anthropic ZDR (also set CRUCIBLE_ANTHROPIC_ZDR=1)
export CRUCIBLE_SOVEREIGNTY_TIER=PERMISSIVE       # anything — the explicit form of the current default
export CRUCIBLE_SOVEREIGNTY_SEALED=1              # latch the tier for the process lifetime
```

**(b) A value persisted in `~/.sigil/sigil.env` (mode `0600`), or set on the UI's Settings screen —
effective for processes launched through the sovereign settings bridge, i.e. `vigil up`.** The
Settings control writes that same file (`apps/sigil/sigil/ui/settings.py:339-348, 630-659`).
`sigil.env` is read only by SIGIL's config import (`apps/sigil/sigil/config.py:64-88`); no
offense-plane module reads it. `vigil up` closes the gap by asking the sovereign venv for the
resolved runtime environment (`sigil settings export-runtime-env`,
`apps/sigil/sigil/ui/settings.py:849-872`) and injecting the allowlisted variables —
`CRUCIBLE_SOVEREIGNTY_TIER` is on that allowlist (`integration/vigil_integration/uiproxy.py:1631`) —
into the offense children it spawns (`:1712-1739`). So a tier written to `sigil.env` governs the
offense engine **when, and only when, the offense process was started by `vigil up`** (or otherwise
inherits an environment the sovereign side built).

**And only at the moment `vigil up` starts.** That runtime environment is resolved **once**, at
bring-up — `_resolve_offense_llm_env` is called a single time as the offense children are spawned
(`integration/vigil_integration/uiproxy.py:2104`, applied via `_spawn`'s `env.update` at `:1582-1584`);
nothing re-reads `sigil.env` afterward, and even the in-UI "restart backends" control replays the
environment captured at bring-up rather than re-resolving it (`:2130`). So a tier changed on the
Settings screen **while the UI is already running reaches only the offense children of a *subsequent*
`vigil up`**. The natural workflow — open the UI (which *is* a `vigil up`), change Settings →
Sovereignty tier, then launch an engagement from the UI — leaves that run on the tier that was in force
when the UI started, with no warning. **Restart `vigil up` (or the `vigil-command` service) after
changing the tier** for it to take effect. The product carries the same caveat on the Settings card:
"Changes are signed on the server and take effect on the next `vigil up` (or service restart)"
(`packages/vigil-ui/app.js:3959`).

**(c) Anything else — the tier is not applied, and this failure is fail-OPEN and silent.** An
offense process started any other way sees only its own environment: `vigil engage` from a shell,
`python3 -m framework.v2 …` run in `engine/crucible/`, a systemd unit or container that does not
export the variable. A tier that exists **only** in `sigil.env` is not read by such a process,
`_resolve_tier_from_env()` falls through to `PERMISSIVE`
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`), nothing warns, and the run proceeds
with cloud model egress permitted.

**Therefore:** if the tier must hold for every run on this host, export it in the environment those
processes inherit — a shell profile, the systemd unit, or the container environment — not only in
`sigil.env` or the Settings screen. Setting it in both places is the safe combination; the exported
value wins where they differ.

**How to check what is actually in force.** The UI's **Governance** screen (`#/governance`,
"Governance & Gate Audit") shows a read-only tier pill and whether the tier is sealed
(`packages/vigil-ui/app.js:1803-1809`). It is read from `sovereignty.current()` **in the offense
process that serves the UI** (`engine/crucible/framework/v2/console/api.py:986-989`), so it is the
authoritative answer for that process — and only for that process. It says nothing about a separate
offense process launched from a shell, which is governed by its own environment. And because that
process took its environment at `vigil up` start, the pill will **disagree with the Settings screen**
after you change the tier there: it keeps reporting the tier the UI started with until you restart
`vigil up` (or the `vigil-command` service). The pill, not the value shown on the Settings screen, is
what is in force.

What is true and worth stating alongside it:

- The gate is applied **before the SDK is imported or a client is constructed**, so under
  `AIR_GAPPED` / `SOVEREIGN_CLOUD` / `TRUSTED_CLOUD` a direct consumer Anthropic call is refused and no
  bytes leave (`sovereignty.py:291-307`; `integration/vigil_integration/live/think_claude.py:36-42`).
- An **unrecognised** tier value fails closed to `AIR_GAPPED`, not open (`sovereignty.py:186-191`).
- `TRUSTED_CLOUD` requires the operator to attest that the key is on a zero-data-retention contract
  (`CRUCIBLE_ANTHROPIC_ZDR`). The source is candid that this is an **attestation, not a proof**
  (`sovereignty.py:152-155`).
- Without `CRUCIBLE_SOVEREIGNTY_SEALED`, the tier is re-read from the environment on each call, so a
  long-running process could have its tier changed mid-run (`sovereignty.py:383-388`).
- `--ephemeral` inverts the defaults for one session: tmpfs write root with a verified purge on exit,
  a forced non-permissive tier, and persistence suppressed
  (`engine/crucible/framework/v2/common/ephemeral.py:1-35`). **Scope of this flag:** it is declared
  on the CRUCIBLE engine's own `engage` CLI only (`engine/crucible/framework/v2/engage.py:1352`),
  reached as `python3 -m framework.v2 engage … --ephemeral` from `engine/crucible/`. It is **not**
  an option of the `vigil engage` super-CLI (`integration/vigil_integration/cli.py:1937-1982`) and
  there is no control for it in the UI on this branch. A run launched from the UI or from
  `vigil engage` is therefore a persisting run.

### 5.2 Target traffic

Two gates bound target traffic **on every run**, and a third engages **only under a sovereign tier**.

The two that always apply. A **signed charter** whose in-scope table bounds every host — five ordered
checks run inside `HttpExecutor` before any request reaches the wire
(`engine/crucible/framework/v2/common/ethics.py:104-136, 283-303`;
`engine/crucible/framework/v2/agents/scope_gate.py`); and a **categorical protected-domain floor**
covering government, military, educational and intergovernmental domains, evaluated before any other
gate with Unicode-homoglyph folding, default ON and owner-only to disable
(`packages/core/vigil_core/vigil_core/hard_guardrail.py:1-31, 239-246`). Inside the in-process egress
guard this same protected-domain floor also runs **unconditionally** — including under the default
`PERMISSIVE` tier (`engine/crucible/framework/v2/agents/egress_guard.py:254-281`).

The third is **not** independent of the sovereignty tier and does **not** fire on the default path: a
**runtime host allowlist** on the offense httpx transport. Under a sovereign tier it refuses any host
outside the charter scope, LLM hosts, provisioned collector hosts (held disjoint from target hosts by
construction, `egress_guard.py:80-93`) or explicit extras. But under the default `PERMISSIVE` tier it
**logs and passes everything through** (`egress_guard.py:265-266`, where `strict = tier != Tier.PERMISSIVE`,
`engine/crucible/framework/v2/kernel/sovereignty.py:260-262`); and for target traffic it is wired only
when `HttpExecutor.egress_allowlist` is set, which **defaults to `None`**
(`engine/crucible/framework/v2/agents/http_executor.py:257`), the transport being installed only in
that case (`:658-663`). So on a default deployment the charter/scope gate and the protected-domain floor
are the operative controls; the host allowlist is defence in depth that engages once a sovereign tier is
selected. `ACCEPTABLE-USE.md` § 4 and `docs/legal/DATA-GROUND-TRUTH.md` § 2.2 state this the same way.

### 5.3 Parties the operator should treat as sub-processors (or their local equivalent)

Whether any of these is legally a "sub-processor" depends on the operator's regime and contracts; the
factual position is what matters here — each can receive data when the corresponding gate is open.

| Party | What it can receive | When |
|---|---|---|
| **Anthropic** | prompt content: target data, tool output, findings, source code | **by default** (PERMISSIVE) |
| AWS Bedrock / Google Vertex / Mistral | the same prompt content | only if that backend is selected |
| Azure OpenAI | the same prompt content | PERMISSIVE or explicit selection |
| ElevenLabs | audio and text of voice interactions | only with `ELEVENLABS_API_KEY` |
| Google (`dns.google`), crt.sh, rdap.org, RIPE NCC | the **target's identity** — a domain, IP or ASN query string | `--live` intel only |
| NVD / OSV / CISA | a CVE identifier | opt-in advisory feed only |
| GitHub | repository content, patch branches, pushed `knowledge/` | opt-in, token-gated, quorum-gated |
| Hugging Face (via `fastembed`) | a model-weights download request | first embedding use |
| Neo4j host, if the operator points at a remote one | graph projection content | operator configuration |
| The operator's own hosting, tunnel and backup providers | whatever passes through or rests there | operator deployment choice |

Vendored third-party code (Strix, Apache-2.0; hexstrike-ai, MIT, vendored non-runnable; adapted
redamon portions, MIT) is documented in `NOTICE`. Vendoring is not a data relationship — none of these
receives data — but the operator should know what is in the tree.

---

## 6. Retention, deletion, and the tension the operator must resolve

Full detail: [`docs/legal/DATA-RETENTION.md`](docs/legal/DATA-RETENTION.md). The essentials:

**There is no default retention limit anywhere.** Nothing expires on a timer. Every artifact class is
kept indefinitely until the operator acts.

**The spine is append-only by design.** It is a hash-chained JSONL where every line carries
`{seq, prev_hash, entry_hash}`, the head is owner-signed, and a durable anti-rollback floor sits
outside the spine directory so a reset cannot lower it (`apps/sigil/sigil/spine/store.py:1-8`;
`apps/sigil/sigil/config.py:98-101`). That is exactly what makes the audit trail trustworthy — and
exactly what makes erasure hard.

**On this branch the hard-prune machinery is dry-run only.** The module's own docstring states
"NOTHING here deletes a live record or commits a head" (`apps/sigil/sigil/spine/prune.py:1-4`), and the
CLI exposes only `prune-plan`, annotated "DRY-RUN — nothing archived or dropped"
(`apps/sigil/sigil/cli.py:844-861`). **So today there is no supported way to erase a single record from
the spine.** The only bulk delete is `sigil ingest --reset`, which destroys the entire ledger
(`apps/sigil/sigil/cli.py:22-33`; `apps/sigil/sigil/spine/store.py:454-478`).

**Even the designed prune would not erase a person.** By design it archives a prefix and commits a
signed snapshot that deliberately carries forward account state — username, role, credential hash and
salt, bound public key, anti-replay high-water — because dropping it would re-open a replay hole
(`apps/sigil/sigil/governor/accounts.py:29-35`; `apps/sigil/sigil/spine/snapshot.py:32-35`), and a
guard refuses a boundary that would strand an active account's only grant
(`apps/sigil/sigil/spine/prune.py:165`). A cumulative Merkle root over every pruned record's hash stays
in the owner-signed head (`apps/sigil/sigil/spine/merkle.py:1-8`).

So, stated precisely:

| | |
|---|---|
| **Can be removed today** | chat transcripts and their attachments; session registry entries and rebuildable graph partitions; evidence directories and target directories (plain filesystem deletion); the vector index (rebuilt from the spine); an entire spine, via `--reset` |
| **Cannot be removed today** | any individual spine record, including an account grant |
| **Would survive even a fully-implemented prune** | record hashes and the cumulative Merkle commitment; folded account state (username, role, `cred_hash`, `cred_salt`, public key) |
| **What the operator must decide** | how to reconcile a data subject's erasure request with a tamper-evident ledger that is designed not to be secretly editable — including whether to hold personal data in the spine at all, whether to run engagements under the engine CLI's `--ephemeral` flag (see §5.1a — it is not available on `vigil engage` or in the UI), and what the deletion story is *before* a request arrives |

This document does not tell the operator which way to resolve that. It states the mechanism honestly so
counsel can.

---

## 7. Security controls — and their honest limits

Verified controls (fuller list with citations in `docs/legal/DATA-GROUND-TRUTH.md` §5):

- **Two-environment boundary.** Sovereign and offense run in separate virtual environments; the build
  fails if offense modules are importable from the sovereign environment (`envs/build_envs.sh:92-101`).
  The offense plane never holds the owner private key.
- **Single owner-key trust root with an RBAC admission gate.** Role→permission is checked *before* the
  owner key signs, so a viewer's request never produces an owner signature; roles are cumulative and
  default-deny (`packages/core/vigil_core/vigil_core/rbac.py:26-51`).
- **Signed, hash-chained, append-only ledger** with a durable external anti-rollback floor; chain
  verification is keyless, so an auditor needs no decryption key
  (`apps/sigil/sigil/spine/envelope.py:22-25`).
- **TPM-sealed key-encryption key, fail-closed.** Sealed to this machine's TPM and useless on another;
  no silent plaintext fallback (`packages/core/vigil_core/vigil_core/kek.py:1-17`).
- **Field-level encryption at rest** for content fields, AEAD-bound to `(scope, seq, field)` so a
  sealed value cannot be transplanted (`apps/sigil/sigil/spine/envelope.py:26-31`).
- **Credential masking before disk**, deliberately scoped to header and log-key names
  (`engine/crucible/framework/v2/common/redact.py:35-49`).
- **Owner-only file permissions** with no world-readable window
  (`engine/crucible/framework/v2/common/paths.py:89-146`).
- **Loopback-only binds** with Host and exact-Origin anti-CSRF / anti-DNS-rebinding checks
  (`apps/sigil/sigil/ui/server.py:152-165`).
- **m-of-n quorum for destructive actions**, with a mandatory owner fixed at deployment, action
  binding, a validity window, and single-use enforced by an `O_EXCL` nonce ledger that survives restart
  (`integration/vigil_integration/destruction_gate.py:1-52`).
- **Timing-safe authentication** and **weak-key rejection** at enrolment
  (`apps/sigil/sigil/governor/accounts.py:120-129, 252-263`).

Limits that must be stated with them:

1. **Without a TPM-provisioned vault, key material and spine payloads are plaintext at rest.**
   `bootstrap.sh` warns "no usable TPM — keys are PLAINTEXT at rest" (`bootstrap.sh:387`); the vault's
   own status string is "UNSEALED — trust-root keys/secrets are PLAINTEXT at rest"
   (`packages/core/vigil_core/vigil_core/vault.py:73-75`); spine payloads pass through unencrypted
   (`apps/sigil/sigil/spine/envelope.py:101-104`). Protection then rests entirely on `0600`/`0700`
   permissions. The only thing that hard-refuses without a vault is TOTP enrolment.
2. **Response bodies are stored verbatim** (§3.4).
3. **Finding certificates are a documented plaintext boundary** — sealing them would break offline
   re-verification, so finding evidence stays plaintext even with a provisioned vault
   (`apps/sigil/sigil/spine/envelope.py:57-59`).
4. **The vector store holds up to 1200 characters of record text in the clear** (§3.5).
5. **Session bearer tokens have no expiry.** Revocation is prompt because the fold is recomputed per
   request, but an unrevoked leaked token is otherwise valid indefinitely
   (`apps/sigil/sigil/governor/accounts.py:366-387`; `apps/sigil/sigil/ui/server.py:129-142`).
6. **One deliberate fail-open path**: the legacy embedded shared owner token always resolves to the
   owner principal, so the owner physically at the host is never locked out. Possession of that token
   is full owner authority (`apps/sigil/sigil/ui/server.py:129-138`).
7. **The optional seccomp egress supervisor is off by default** and its own docstring says it is "NOT a
   containment boundary for hostile code", naming three limits
   (`integration/vigil_integration/live/egress_guard.py:25, 33-56`).
8. **Backup restore authenticity reduces to passphrase possession** unless an expected governance
   public key is pinned out of band (`integration/vigil_integration/backup.py:22-34`).

---

## 8. If you are a data subject

**Contact the operator, not the project.** The project author supplies software only: nothing in it
transmits a deployment's data to them and nothing in it gives them access to a deployment (§2), so they
cannot look anything up on your behalf.

Route: `[OPERATOR CONTACT NAME]`, `[OPERATOR CONTACT EMAIL / POSTAL ADDRESS]`,
`[DATA-PROTECTION CONTACT, IF THE OPERATOR HAS APPOINTED ONE]`.

When you make contact, it helps to say which relationship applies:

- **You hold an account on this VIGIL deployment.** The operator can tell you what account data exists
  (§3.1) and can revoke the account. Note the limit in §6: revocation records a `revoked` state; it
  does not remove the historical grant from the ledger.
- **Your data appeared in a system the operator was authorized to test.** Then the *client* — the
  organisation that owns the tested system — is normally the party with the primary relationship to
  you, and the operator processes that data on the client's instruction. The operator should tell you
  who the client is where it is permitted to, and should route the request accordingly.

The operator's honest answer to an erasure request must reflect §6: some classes can be deleted
outright, and the append-only ledger currently cannot have individual records removed. That is a
design property, not an evasion, and the operator should say so and explain what it will do instead
(for example: revoking the account, deleting every deletable class, and documenting the residual).

---

## 9. Applicable law and jurisdiction

**Not settled here, deliberately.** The operator's primary jurisdiction appears to be
`[OPERATOR JURISDICTION — e.g. Cameroon]`; clients and data subjects may be elsewhere, and several
regimes (including EU/UK and US state law) can reach an operator extraterritorially depending on whose
data is processed and where services are offered.

Complete before publishing:

- Governing law: `[APPLICABLE LAW]`
- Forum / competent authority: `[FORUM]`
- Supervisory authority the operator answers to, if any: `[AUTHORITY]`
- Cross-border transfer mechanism relied on, if any: `[MECHANISM]`

References to any specific regulation elsewhere in this document explain *why* a section exists. They
are not assertions of conformance with it.

---

## 10. Changes to this statement

This describes the software as it exists on this branch. Behaviour changes with the code. Re-verify
against `docs/legal/DATA-GROUND-TRUTH.md` — which carries a `path:line` citation for every claim, and
marks anything it could not verify — before republishing, and record the date and the commit the
statement was verified against:

- Verified against commit: `[COMMIT]`
- Date: `[DATE]`
- Verified by: `[NAME]`
