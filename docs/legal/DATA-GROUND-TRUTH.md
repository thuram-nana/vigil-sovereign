# VIGIL — Data Ground Truth

**Status: internal engineering reference. Not a privacy notice, not a contract, not legal advice.**

This document records what the code on this branch actually does with data. It exists so that any
privacy, security, or client-facing document written afterwards can be checked line-by-line against
the source. Every factual statement below carries a `path:line` citation and was read on this branch.

Where a behaviour could not be verified from the source in this repository it is marked
**NOT VERIFIED** rather than asserted.

Conventions used here:

- `~/.sigil` is the sovereign data root, resolved from `SIGIL_HOME` or defaulted
  (`apps/sigil/sigil/config.py:23-27`).
- `.vigil-live` is the offense plane's working dir, resolved from `VIGIL_LIVE_DIR` /
  `VIGIL_BASE_DIR` or defaulted (`integration/vigil_integration/warden_gate.py:329-330`,
  `packages/core/vigil_core/vigil_core/token_budget.py:89`).
- "CRUCIBLE root" is the directory containing `CLAUDE.md`, discovered by
  `engine/crucible/framework/v2/common/paths.py:28,40-66`.

---

## 1. Personal data stored at rest

### 1.1 Per-user accounts (RBAC, Claim 6)

Account records are **owner-signed governance grants appended to the hash-chained spine** — they are
not rows in a mutable table (`apps/sigil/sigil/governor/accounts.py:1-13, 400-418`). The spine file
is `~/.sigil/spine/spine.jsonl` (`apps/sigil/sigil/config.py:90-91`), plus rotated segments under the
same directory (`apps/sigil/sigil/config.py:103-119`).

Per account the following fields are written into the signed grant
(`apps/sigil/sigil/governor/accounts.py:207-221`, appended at `:400-418`):

| Field | What it is | Form on disk |
|---|---|---|
| `username` | operator-chosen handle, 1–64 chars | **plaintext** |
| `role` | `viewer` / `analyst` / `operator` (never `owner`) | plaintext |
| `cred_hash` | `sha256(cred_salt ‖ bearer_token)` — the plaintext bearer is never stored | hash |
| `cred_salt` | per-account 16-byte random | plaintext |
| `user_pubkey` | owner-bound Ed25519 **public** key for challenge/response login | plaintext (public) |
| `totp_secret` | the TOTP shared secret, **AEAD-sealed** under the vault KEK, base64 | ciphertext |
| `password_hash` | salted scrypt, `n=2^15, r=8, p=1`, 16-byte salt, 32-byte dk | one-way hash |
| `issued_at` | anti-replay high-water | plaintext |
| `state` | `active` / `revoked` | plaintext |

Key details:

- **Password KDF is scrypt** with `n=2^15 (32 MiB), r=8, p=1`, fresh 16-byte salt per password, stored
  as a self-describing `scrypt$n$r$p$salt_b64$dk_b64` string
  (`apps/sigil/sigil/governor/accounts.py:117, 132-144`). Verification is constant-time
  (`:147-161`). A password shorter than 8 characters is refused (`:137-138`).
- **TOTP secrets are sealed, never plaintext.** The plaintext secret is generated in the actions
  layer, displayed once as an `otpauth://` provisioning URI, and sealed via the owner vault before it
  reaches the spine (`apps/sigil/sigil/ui/actions.py:112-133`). Sealing is
  ChaCha20-Poly1305 AEAD bound to the context `b"sigil/account.totp"`
  (`apps/sigil/sigil/governor/accounts.py:113`;
  `packages/core/vigil_core/vigil_core/sealing.py:1-24`).
  `Vault.seal_secret` has **no plaintext fallback** — it raises `VaultLocked` if the vault is not
  provisioned (`packages/core/vigil_core/vigil_core/vault.py:119-129`), and the enroll path surfaces
  that as a clean refusal (`apps/sigil/sigil/ui/actions.py:125-128`). So **TOTP enrolment is
  impossible without a TPM-provisioned vault** — this is the one credential that cannot land in the
  clear.
- **Bearer tokens are never stored in plaintext** — only the salted hash
  (`apps/sigil/sigil/governor/accounts.py:211, 289-291`). A successful proof-of-possession login
  mints a *fresh* bearer rather than echoing a stored one (`:366-387`).
- **Revocation is honoured even unsigned** (fail-safe direction), with a fixed `issued_at` of 0.0 so a
  replayed revoke merely re-revokes (`apps/sigil/sigil/governor/accounts.py:389-398, 459-460`).
  The `active` direction requires a valid owner signature **and** freshness (`:461-468`).

### 1.2 OIDC subject / claims

The OIDC Relying Party is **off unless `SIGIL_OIDC_ENABLED` is affirmative**; when off, the routes are
not registered at all (`apps/sigil/sigil/config.py:154-161`; `apps/sigil/sigil/ui/server.py:209-212`;
`docs/OIDC-RP.md:7-15`).

When enabled:

- The `id_token` is verified against the IdP's JWKS, asymmetric algorithms only; `alg:none` and all
  symmetric algorithms are refused (`apps/sigil/sigil/ui/oidc.py:252-325`).
- **Only one claim is read** — the configured `username_claim`, default `preferred_username`
  (`apps/sigil/sigil/config.py:180-182`; `apps/sigil/sigil/ui/oidc.py:328-334`).
- **The role is never taken from a claim.** It is looked up from an owner-signed `governor.account`
  grant; an OIDC identity with no active owner-signed account is refused
  (`apps/sigil/sigil/ui/server.py:544-557`).
- **No id_token, no claim set, and no OIDC subject is persisted** by the callback path
  (`apps/sigil/sigil/ui/server.py:517-568`). The only durable artefact is the single-use
  `state → nonce` ledger at `<spine-path>.oidc-state/` (`apps/sigil/sigil/ui/server.py:467-472`;
  `apps/sigil/sigil/ui/oidc.py:436-500`), which stores a `sha256(state)`-named marker with the nonce
  and issue time, TTL-swept and capacity-capped.

### 1.3 Operator identity — this is real personal data

`OperatorIdentity` binds **OS login, git `user.name`, git `user.email`, hostname**, plus the operator
key fingerprint (`integration/vigil_integration/attestation/models.py:24-45`), resolved live from the
machine (`integration/vigil_integration/attestation/identity.py:107-132`).

That identity is embedded in **every** record of the always-on usage-attestation ledger
(`integration/vigil_integration/attestation/models.py:60-82`), which is an append-only hash-chained
JSONL file at `<base_dir>/usage-ledger.jsonl`, default `.vigil-live/usage-ledger.jsonl`
(`integration/vigil_integration/live/wiring.py:305`). The ledger will not mint or accept a record
whose identity has no signing fingerprint *and* no human handle
(`integration/vigil_integration/attestation/models.py:40-45`) — i.e. the personal handle is
structurally required, not incidental.

A monotonic anti-back-dating counter lives at `~/.vigil/attestation/`
(`integration/vigil_integration/attestation/anchor.py:37`).

### 1.4 Cryptographic key material

| Key | Path | Sealed at rest? |
|---|---|---|
| Owner Ed25519 private key | `~/.sigil/spine/keys/owner.priv` | via vault, if provisioned (`apps/sigil/sigil/governor/identity.py:16-17, 28-39`) |
| Owner Ed25519 public key | `~/.sigil/spine/keys/owner.pub` | public, plaintext |
| Spine payload DEK | `~/.sigil/spine/keys/spine.dek` | sealed under TPM KEK (`apps/sigil/sigil/config.py:94-96`) |
| TPM-sealed KEK blobs | `~/.sigil/vault/kek.tpm.{pub,priv}` | TPM-bound (`apps/sigil/sigil/platform/vault.py:25-33`; `packages/core/vigil_core/vigil_core/kek.py:32-34`) |
| Secret key/value store | `~/.sigil/secrets.sealed` | AEAD-sealed when vault on; else OS keyring; else plaintext `~/.sigil/sigil.env` (`apps/sigil/sigil/platform/secrets.py:1-7, 17-19`) |
| WARDEN kernel key | `$SIGIL_WARDEN_HOME` or `~/.sigil/warden/warden.key` | plaintext 0600 (`apps/sigil/sigil/backup.py:82-91`) |
| Offense operator key | `.vigil-live/operator.key` | via offense vault, if provisioned (`integration/vigil_integration/live/wiring.py:293, 302`) |
| Offense spine key | `.vigil-live/offense-spine.key` | same (`integration/vigil_integration/live/wiring.py:50`) |
| Offense governance key | `.vigil-live/offense-governance.key` | same (`integration/vigil_integration/live/governance_identity.py:28-35`) |
| Bridge TLS cert/key | `~/.sigil/bridge/` (dir 0700, files 0600) | plaintext (`apps/sigil/sigil/bridge/server.py:476-491`) |

Mesh/companion **device public keys** are owner-signed onto the spine as
`device_id` + `device_pubkey` grants (`apps/sigil/sigil/mesh/registry.py:49, 110-128`).

### 1.5 Target-derived data (the client's systems, and third parties' data in them)

This is the largest category and the one most likely to contain **third parties' personal data** —
the client's own users, appearing inside HTTP responses.

- **Full HTTP evidence archive.** For each action: `request.http`, `response.http`, and the complete
  raw `response.body` are written under
  `targets/<slug>/evidence/<action_id>/`
  (`engine/crucible/framework/v2/common/paths.py:358-362`;
  `engine/crucible/framework/v2/agents/http_executor.py:744-752, 865-869`).
- **Credential headers are masked; response bodies are not.** `redact_header` masks `Authorization`,
  `Cookie`, `Set-Cookie`, `X-API-Key`, and similar
  (`engine/crucible/framework/v2/common/redact.py:35-49, 83-87`). The module states explicitly that
  the raw body is never touched and is protected only by owner-only file permissions
  (`engine/crucible/framework/v2/common/redact.py:17-22`). **So personal data inside a response body
  is stored verbatim.**
- **Engagement audit log** `targets/<slug>/.crucible-v2.log`
  (`engine/crucible/framework/v2/common/paths.py:364-365`), **scan report snapshot**
  `targets/<slug>/<slug>.report.json` (`:392-399`), **phase ledger** `<slug>.phases.jsonl` (`:383-390`).
- **Per-engagement offense spine** `.vigil-live/<slug>.spine`
  (`integration/vigil_integration/live/wiring.py:344`).
- **Agent blackboard** — SQLite at `<crucible-root>/framework/v2/.blackboard/store.sqlite`
  (`engine/crucible/framework/v2/agents/blackboard.py:11, 45`).
- **Console run store and chat transcripts** under `.vigil-live/` — `chats/<id>.jsonl`,
  `chats/<id>.attachments/`, `sessions/<id>/session.json`
  (`engine/crucible/framework/v2/console/chat.py:449-457, 562-582`;
  `engine/crucible/framework/v2/console/sessions.py:7-9, 55-70`).

### 1.6 Operator working data ingested into the spine

`sigil ingest` reads the operator's **Claude Code transcripts** from `~/.claude/projects` and appends
them to the spine as events, including message text, `cwd`, and `gitBranch`
(`apps/sigil/sigil/config.py:122-126`; `apps/sigil/sigil/ingest/transcript.py:1-6, 31-50`). Git
repositories listed in `SIGIL_INGEST_REPOS` are backfilled as commit events
(`apps/sigil/sigil/config.py:227-235`). Anything the operator discussed with an AI assistant about a
client can therefore land in the spine.

### 1.7 Derived stores

- **Vectors (Qdrant).** Embedded file-backed store at `~/.sigil/qdrant`, or a server if
  `SIGIL_QDRANT_URL` is set (`apps/sigil/sigil/config.py:131-133`). The indexed payload includes
  `session_id`, `project`, `ts`, `entry_hash` and **the first 1200 characters of the record text in
  the clear** (`apps/sigil/sigil/vectors/index.py:135-142`). Records are decrypted before embedding
  (`:150`). **The vector store is not covered by the spine's field-level encryption.**
- **Graph (Kùzu, embedded).** `~/.sigil/graph` (`apps/sigil/sigil/config.py:138`).
- **Neo4j is optional and may be remote.** Connection URI and username are non-secret config; the
  password lives in the sealed secret store (`apps/sigil/sigil/platform/secret_probes.py:251-263`;
  `apps/sigil/sigil/ui/settings.py:88, 141`). A local dev container is loopback-bound
  (`docker-compose.yml:43-56`), but an operator may point it at a hosted instance — that would be an
  egress path. **NOT VERIFIED:** what subset of spine content a remote Neo4j projection would carry
  (the shipped graph module is the embedded projection only —
  `apps/sigil/sigil/graph/{query,rebuild,schema}.py`).

### 1.8 Field-level encryption of spine payloads

When the vault is provisioned, the **values** of a fixed set of content fields are sealed per-field
under a per-spine DEK, bound as AEAD associated data to `(scope, seq, field)`
(`apps/sigil/sigil/spine/envelope.py:1-31, 72-75`). The sealed field set is
`text, content, message, body, quote, captured_text, output, answer, title, description, tool_input,
vision_reading_advisory, grounded_objects, advisory_leads, statement`
(`apps/sigil/sigil/spine/envelope.py:61-65`).

Documented plaintext boundaries, stated in the source itself
(`apps/sigil/sigil/spine/envelope.py:57-60`):

- governance metadata (`decision`, `tier`, `usage`, `signal`, `promotion_key`, `folded_state`) — so
  keyless folds keep working;
- the short labels `subject` and `summary`;
- **a CRUCIBLE finding's opaque `certificate`** — sealing it would break offline re-verification, so
  finding evidence is stored plaintext;
- **account fields** (`username`, `role`, `cred_hash`, `cred_salt`, `user_pubkey`, `issued_at`) are
  not in `CONTENT_FIELDS`, so they stay plaintext in the record; only the TOTP secret is sealed, and
  it is sealed by the caller before it reaches the spine.

**Without a provisioned vault, `dek is None` and every payload passes through in plaintext**
(`apps/sigil/sigil/spine/envelope.py:101-104`).

---

## 2. What leaves the machine, to whom, and what gates it

| Egress | Destination | Default | Gate |
|---|---|---|---|
| **Model/LLM calls (offense think step, chat, dev-edit, codefix)** | `api.anthropic.com` | **ON (PERMISSIVE)** | `CRUCIBLE_SOVEREIGNTY_TIER` |
| Local model backends | `localhost` / `127.0.0.1` | n/a | same ladder |
| Sovereign-cloud backends (Bedrock/Vertex/Mistral) | `*.amazonaws.com`, `*.googleapis.com`, `api.mistral.ai` | only if selected | same ladder |
| Target traffic | charter-listed hosts | ON for an authorized engagement | signed charter scope + protected-domain floor |
| Intel/OSINT collectors | `dns.google`, `crt.sh`, `rdap.org`, `stat.ripe.net` | **OFF** | `--live` flag |
| GitHub PR (auto-patch) | `github.com` / `api.github.com` | **OFF** | `pr_enabled` + m-of-n quorum + `GITHUB_TOKEN` |
| OTLP telemetry | loopback collector only | **OFF** (compose profile) | loopback pin, fail-closed |
| Voice (ElevenLabs) | `api.elevenlabs.io` | **OFF** (no key) | requires `ELEVENLABS_API_KEY` |
| Secret health probes | provider APIs | **OFF** | explicit `sigil settings check <NAME>` |
| Embedding model weights | HuggingFace (via `fastembed`) | on first use | none in-repo — see §6 |
| Strix telemetry | none — removed | **OFF, no transport exists** | n/a |

### 2.1 Model egress — the default is PERMISSIVE. This is the sharpest fact.

`_resolve_tier_from_env()` returns `Tier.PERMISSIVE` when `CRUCIBLE_SOVEREIGNTY_TIER` is unset and the
legacy `CRUCIBLE_SOVEREIGN_MODE` flag is absent
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`). `PERMISSIVE` permits every backend
class, including `cloud_only` — the direct consumer Anthropic API
(`:65-83, 106-111`), and its auto-selection preference puts `anthropic` **first**
(`:137-141`). The module's own docstring says PERMISSIVE is "Default for development… Equivalent to
'no policy enforcement'" (`:23-25`).

`bootstrap.sh` writes `~/.sigil/sigil.env` with every tier line **commented out**, under a comment
that states plainly: "Left UNSET it is PERMISSIVE (the development default: any backend, including the
direct Anthropic API)" (`bootstrap.sh:321-345`, specifically `:328-335`). The file is created 0600
(`bootstrap.sh:341`) and is never clobbered if it already exists (`:321, 343-344`).

Therefore: **on a default install, unless the operator sets the tier by a mechanism that actually
reaches the process doing the reasoning, prompt content is eligible to be sent to Anthropic's API.**
Prompt content includes target
data and prior tool output handed in as `prompt_ctx`
(`integration/vigil_integration/live/think_claude.py:7-11, 522-546`), the operator's source code on
the dev-edit path (`integration/vigil_integration/live/dev_edit.py:132-141`), and repository source on
the codefix path (`integration/vigil_integration/live/codefix_runner.py:322`).

**Any document that says "everything stays local by default" would be false.**

What *is* true, and worth stating:

- The gate is real and it is applied **before the SDK is imported or a client is constructed** — under
  `AIR_GAPPED` / `SOVEREIGN_CLOUD` / `TRUSTED_CLOUD` a direct consumer Anthropic call is refused and
  no bytes leave (`engine/crucible/framework/v2/kernel/sovereignty.py:291-307`;
  `integration/vigil_integration/live/think_claude.py:36-42`).
- An **unrecognised** tier value fails closed to `AIR_GAPPED`, not open
  (`engine/crucible/framework/v2/kernel/sovereignty.py:186-191`).
- If the policy module cannot be imported at all, the fallback **can over-refuse but never
  under-refuse** (`integration/vigil_integration/live/think_claude.py:174-199`).
- `CRUCIBLE_SOVEREIGNTY_SEALED=1` latches the tier for the process lifetime so a later environment
  change cannot relax it mid-run (`engine/crucible/framework/v2/kernel/sovereignty.py:383-416`).
- `TRUSTED_CLOUD` requires an explicit operator **attestation** (`CRUCIBLE_ANTHROPIC_ZDR`) that the key
  is on a zero-data-retention contract. The source is candid that this is an attestation, not a proof
  (`engine/crucible/framework/v2/kernel/sovereignty.py:152-155, 164-180`).
- A per-session **local** model pick is enforced by refusal, not by silent fallback: a local pick that
  cannot be resolved to a loopback endpoint refuses rather than egressing to the cloud default
  (`engine/crucible/framework/v2/console/actions.py:884-917, 922-963`).
- **`--ephemeral` inverts the default**: it forces the tier to `TRUSTED_CLOUD` (or an operator
  override), redirects evidence and audit writes to tmpfs, purges on exit with verification, and
  disables spine/learning persistence (`engine/crucible/framework/v2/common/ephemeral.py:1-35, 52`).
  **Reachability, verified:** the flag is declared only on the CRUCIBLE engine's own `engage` parser
  (`engine/crucible/framework/v2/engage.py:1352`), i.e. `python3 -m framework.v2 engage … --ephemeral`
  run from `engine/crucible/`. `vigil engage` does not define it
  (`integration/vigil_integration/cli.py:1937-1982`) and no UI control sets it on this branch
  (`grep -n ephemeral packages/vigil-ui/app.js` is empty). `console/actions.py` carries an `ephemeral`
  keyword (`:288-300, 306-318`), but no HTTP route passes it, so the UI cannot turn it on.

### 2.1a Which mechanism actually delivers the tier to which process

The tier is read from `os.environ` and from nowhere else — `_resolve_tier_from_env()` calls
`os.environ.get(_TIER_ENV, …)` (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`).
`~/.sigil/sigil.env` is loaded only by SIGIL's config import
(`apps/sigil/sigil/config.py:64-88`); **no offense-plane module reads that file** (verified by grep
over `integration/vigil_integration/` and `engine/crucible/framework/v2/kernel/`). That gives three
distinct cases:

| Mechanism | Reaches | Evidence |
|---|---|---|
| Exported in the shell / systemd unit / container that launches the process | **Every** process launched from it. Highest precedence — `_load_env_file` merges with `setdefault`, so the real environment wins | `sovereignty.py:183-195`; `apps/sigil/sigil/config.py:64-88` |
| Written to `~/.sigil/sigil.env`, or set on the UI Settings screen (which writes that file) | Offense processes launched **through the sovereign settings bridge** — in practice `vigil up`, which calls `sigil settings export-runtime-env` in the sovereign venv and injects the allowlisted vars into its offense children | `apps/sigil/sigil/ui/settings.py:339-348, 630-659, 849-872`; `integration/vigil_integration/uiproxy.py:1631, 1712-1739` |
| Neither — e.g. `vigil engage` from a shell, `python3 -m framework.v2 …`, a unit that does not export it | **Nothing.** The process falls through to `PERMISSIVE` | `sovereignty.py:183-195` |

**The third row is fail-OPEN and silent.** Nothing warns that a tier stored in `sigil.env` was not
applied; the run simply proceeds with cloud model egress permitted. A tier that must hold for every
run on the host has to be exported in the environment those processes inherit, not only stored in
`sigil.env`.

**The authoritative read-only check** is the tier pill on the UI's Governance screen
(`#/governance`, `packages/vigil-ui/app.js:1803-1809`), fed by `sovereignty.current()` evaluated
**inside the offense process that serves the UI**
(`engine/crucible/framework/v2/console/api.py:986-989`). It is authoritative for that process only.

### 2.2 Target traffic

Gated by three independent things:

1. **A signed charter.** `require_charter_signed` refuses an unsigned charter
   (`engine/crucible/framework/v2/common/ethics.py:104-136`); `require_in_scope` refuses any host not
   matching the charter's `## 2. In-scope systems` table
   (`engine/crucible/framework/v2/common/ethics.py:145-153, 283-303`).
2. **A categorical protected-domain floor** — government / military / educational / intergovernmental
   domains, evaluated before the charter and before any gate, with Unicode-homoglyph folding
   (`packages/core/vigil_core/vigil_core/hard_guardrail.py:1-31, 42-60`). It is **default ON**;
   the only OFF state is an explicit affirmative in `VIGIL_ALLOW_PROTECTED_DOMAINS`
   (`:239-246`), and turning it off is an owner-only action
   (`apps/sigil/sigil/governor/accounts.py:83; apps/sigil/sigil/ui/actions.py:60-69`).
3. **A runtime egress allowlist** for httpx clients under any sovereign tier
   (`engine/crucible/framework/v2/agents/egress_guard.py:1-44, 71-90`), with collector hosts held
   disjoint from target hosts by construction (`:80-89`).

Additionally, an opt-in **seccomp egress supervisor** can confine spawned scanner binaries to
loopback (`integration/vigil_integration/live/egress_guard.py:1-31`). It is **default OFF**
(`:25`, `:137-146`); `VIGIL_EGRESS_GUARD=require` makes an unavailable guard fail closed
(`:158-180`). Its own docstring lists three honest limits: a 32-bit binary matches no arch branch and
is unfiltered; `sendmmsg` and `io_uring` are not filtered; and exit code 97 is ambiguous
(`:42-56`).

### 2.3 Intel / OSINT collectors — default OFF

Live collection targets four public passive sources:
`https://dns.google/resolve`, `https://crt.sh/?q=`, `https://rdap.org/domain/`,
`https://stat.ripe.net/data/network-info/` (`engine/crucible/framework/v2/intel/live.py:36-45`).

They are **queried about the target and are never the target**
(`engine/crucible/framework/v2/intel/live.py:10-17`). Egress is off unless `--live` is passed
(`engine/crucible/framework/v2/intel/cli.py:458-460`); without it, the command reports that egress is
disabled and makes no network call (`:213-214, 236`). A recurring feed daemon is doubly gated
(`:269, 289`).

**What leaves:** a domain / IP / ASN query string for the target. That is the client's identity, and
should be described as such.

### 2.4 GitHub — default OFF, and hard to turn on

The auto-patch PR leg is off by default (`pr_enabled: bool = False`,
`integration/vigil_integration/live/codefix_runner.py:74`), refuses without a `GITHUB_TOKEN`
(`:255-257`), and — as the module docstring states — the destructive PR leg additionally requires an
m-of-n destruction quorum (`:16-20`). Clone hosts are allowlisted
(`engine/crucible/framework/v2/console/actions.py:995`). The token is held `repr=False` so a stray log
cannot expose it (`integration/vigil_integration/live/codefix_runner.py:67-68`) and is forwarded only
into the child process environment (`:282`).

A separate, explicit operator CLI verb pushes `knowledge/` to GitHub, with a defence-in-depth secret
scan that refuses the commit on a hit — described in its own docstring as "a net, NOT a guarantee"
(`integration/vigil_integration/knowledge_sync.py:1-9`).

### 2.5 Telemetry

- **No third-party analytics anywhere in first-party code.** No PostHog, Sentry, Datadog, or similar.
- The vendored Strix's upstream phone-home modules (`posthog.py`, `scarf.py`) were **deleted** and
  replaced with a local-only logging sink with no network transport (`NOTICE:33-37`;
  `vendor/strix/strix/telemetry/sink.py:1-9`).
- OTLP export exists but is **pinned to loopback, fail-closed and DNS-free** — a hostname, a public
  IP, or a `127.0.0.1.evil.com` look-alike all resolve to "not loopback" and are refused
  (`integration/vigil_integration/live/otel_export.py:18, 81-104`). The shipped collector config
  exports to stdout only, with no external exporter
  (`infra/sidecars/otel-config.yaml:1-2, 9-11`), and the container publishes on `127.0.0.1:4318`
  (`docker-compose.yml:57-67`). The collector is an opt-in compose profile.
- The console's `/api/telemetry` reads a **local file** `<live>/live-ui/telemetry.json`
  (`engine/crucible/framework/v2/console/api.py:507-520`).

### 2.6 Voice (ElevenLabs) — off unless a key is set

Text-to-speech and speech-to-text call `api.elevenlabs.io`; both raise without
`ELEVENLABS_API_KEY` (`apps/sigil/sigil/voice/backends.py:218-225, 244-253, 271`). The source states
plainly that "the AUDIO leaves" for the ASR path (`:239-241`). The offense plane is explicitly
forbidden from receiving this key — "never ELEVENLABS (voice = sovereign)"
(`integration/vigil_integration/uiproxy.py:1648`).

### 2.7 Secret-health probes

`sigil settings check <NAME>` live-probes a provider endpoint to validate a stored credential —
Anthropic, GitHub, Mistral, OpenAI, Perplexity, ElevenLabs, Azure, AWS, GCP, Kubernetes, Neo4j
(`apps/sigil/sigil/platform/secret_probes.py:74-302`). Explicitly operator-invoked; it prints only a
redacted verdict (`bootstrap.sh:297-313`).

### 2.8 Container images and packages

Every third-party image is **digest-pinned**, and the previous floating `:latest` indirections were
deliberately removed (`docker-compose.yml:25-31`). Python dependencies install from a hash-locked
requirements file that "refuses ANY unpinned/unhashed package"
(`envs/build_envs.sh:70-74`). Strix's live-scan dependencies are the stated exception — installed
**not** hash-locked (`envs/build_envs.sh:74`).

---

## 3. Retention and deletion

### 3.1 The spine is append-only, and on this branch nothing prunes it

The spine is a hash-chained JSONL where each line carries `{seq, prev_hash, entry_hash}`
(`apps/sigil/sigil/spine/store.py:1-8`). The head is owner-Ed25519-signed and anchored by a durable
external anti-rollback floor at `~/.sigil/floor.json`, deliberately placed **outside** `spine/` so a
reset cannot lower it (`apps/sigil/sigil/config.py:98-101`; `apps/sigil/sigil/spine/floor.py:3`).

**The hard-prune machinery on this branch is dry-run only.** `spine/prune.py`'s own docstring says:
"NOTHING here deletes a live record or commits a head — Slice E wires these into the crash-safe
cutover" (`apps/sigil/sigil/spine/prune.py:1-4`). The module exports guards, a snapshot payload
builder, an archive **copy**, and a verifier — there is no commit/cutover function
(`apps/sigil/sigil/spine/prune.py:38-479`). The CLI exposes only `prune-plan`, annotated
"DRY-RUN — nothing archived or dropped" (`apps/sigil/sigil/cli.py:844-861`), and `verify-archive`
(`:862-868`). `SnapshotState.load()` correspondingly returns the empty identity universally
(`apps/sigil/sigil/spine/snapshot.py:8-13, 176-185`).

**Consequence: there is no shipped, supported way to erase a single record from the spine. There is
no default retention limit. The spine grows without bound until the operator intervenes.**

### 3.2 What the designed prune *would* do (relevant to any future erasure claim)

The design, as documented in the code that exists:

- Prune deletes records `[0..K)` from the live spine and keeps a signed `kind="snapshot"` record
  committing a **folded summary** of everything the pruned prefix carried that a consumer still needs
  — replay high-waters, latches, authorization sets (`apps/sigil/sigil/spine/snapshot.py:1-10`).
- **Account credentials survive a prune deliberately.** The snapshot seed carries
  `account_cred = {username → role / cred_hash / cred_salt / pubkey}` and the per-username anti-replay
  high-water, and `check_prune_safe` refuses a boundary that would strand an active account's only
  grant (`apps/sigil/sigil/governor/accounts.py:29-35`;
  `apps/sigil/sigil/spine/snapshot.py:32-35`; `apps/sigil/sigil/spine/prune.py:165`). Not carrying
  them would re-open the LWW replay-resurrection hole.
- A **cumulative Merkle root** over every pruned record's `entry_hash` is committed in the
  owner-signed head, so any single pruned record retains an inclusion proof
  (`apps/sigil/sigil/spine/merkle.py:1-8`).
- The archive is a **copy**, at `~/.sigil/spine/archive/` (relocatable via
  `SIGIL_SPINE_ARCHIVE_DIR`) (`apps/sigil/sigil/spine/prune.py:6-10, 42-46`). Losing the archive
  makes the pruned prefix unrecoverable, leaving only the owner-signed Merkle commitment — an
  explicitly-named max-reclaim tradeoff (`:16-18`).
- A referential floor blocks pruning anything an open workflow still cites
  (`apps/sigil/sigil/spine/prune.py:70-117`).

So: **even a fully-implemented prune erases content but leaves hashes and folded credential state
behind.** A username, its role, its `cred_hash`/`cred_salt` and its bound public key are exactly the
state the design says must survive. Erasing a *person* from this system is therefore not the same as
running a prune, and any document must not imply otherwise.

### 3.3 What *can* be deleted today

| Action | Deletes | Leaves |
|---|---|---|
| `sigil ingest --reset` | the whole spine data file, manifest, all segments, trash; plus cursor and vectors | the anti-rollback floor (`apps/sigil/sigil/cli.py:22-33`; `apps/sigil/sigil/spine/store.py:454-478`) |
| Account revoke | nothing | the full grant history; the account is folded out as `revoked` (`apps/sigil/sigil/governor/accounts.py:389-398, 459-460`) |
| Chat delete | transcript `chats/<id>.jsonl`, its attachments dir, registry entry | the spine (`engine/crucible/framework/v2/console/chat.py:562-582`) |
| Session delete, soft | nothing — tombstone only | everything (`engine/crucible/framework/v2/console/sessions.py:279-305`) |
| Session delete, hard | registry entry + rebuildable graph partition | the signed spine, the chat transcript, run metas — explicitly "Neither ever touches the signed spine or a FACT" (`:280-282`) |
| `--ephemeral` run | the whole tmpfs write root, purge verified on exit, `EphemeralPurgeError` if a residual remains | nothing on disk for that run (`engine/crucible/framework/v2/common/ephemeral.py:12-18`) |
| Segment compact | rewrites/gzips sealed segments | every record — compaction preserves content (`apps/sigil/sigil/cli.py:836-843`) |

Deleting evidence directories or target directories is a plain filesystem operation; no tooling in
this repository performs a targeted erasure of a data subject across the spine, the vector store, the
graph, and the evidence archive at once. **NOT VERIFIED / does not exist: any subject-erasure verb.**

### 3.4 Backup and restore

Two **separate** encrypted files, one per plane — never merged, because one process holding both
plane secrets would violate the two-environment boundary
(`integration/vigil_integration/backup.py:36-40`).

- Sovereign backup packages the spine, floor, security manifest, owner public key, WARDEN dir, **plus
  the owner private key and the spine DEK**, all sealed under a key derived from an owner passphrase
  by scrypt `n=2^16` (`apps/sigil/sigil/backup.py:1-33, 56-58`).
- The passphrase is **never stored** — lose it and the backup is unrecoverable by design
  (`apps/sigil/sigil/backup.py:31-33`).
- A plain backup writes to the **same host's disk** and is honestly named as such — it is not off-host
  replication (`apps/sigil/sigil/backup.py:4-8`). Off-host push is a separate opt-in step that moves
  **ciphertext only**; the remote's security is the operator's responsibility
  (`tools/backup/transport.py:8-13`). Only a local-directory backend ships (`:15-18`).
- Restore-time authenticity reduces to **passphrase possession** unless an expected governance pubkey
  is pinned out of band (`integration/vigil_integration/backup.py:22-34`).

---

## 4. Third parties / sub-processor-shaped relationships

| Party | Role | When engaged | Notes |
|---|---|---|---|
| **Anthropic** | model provider (`api.anthropic.com`) | reachable **by default** (PERMISSIVE) | receives prompt content; `TRUSTED_CLOUD` + `CRUCIBLE_ANTHROPIC_ZDR` records a ZDR **attestation**, not a proof (`sovereignty.py:152-155`) |
| **AWS Bedrock / Google Vertex / Mistral** | jurisdictional cloud model backends | only if selected | `sovereignty.py:73-76, 364-371` |
| **Azure OpenAI** | BYO cloud backend | PERMISSIVE or explicit force only | classified `cloud_only` (`sovereignty.py:82`) |
| **ElevenLabs** | TTS / ASR | only with an API key | audio leaves the host (`voice/backends.py:239-241`) |
| **Google (`dns.google`)** | DNS-over-HTTPS | `--live` only | `intel/live.py:37` |
| **Sectigo/crt.sh** | Certificate Transparency | `--live` only | `intel/live.py:38` |
| **rdap.org** | RDAP/WHOIS | `--live` only | `intel/live.py:39` |
| **RIPE NCC (`stat.ripe.net`)** | ASN/BGP | `--live` only | `intel/live.py:40` |
| **GitHub** | PR creation, knowledge sync | opt-in + quorum | `codefix_runner.py:74, 255-257` |
| **Hugging Face** | embedding model weights via `fastembed` | first embedding use | see §6 — no offline pin in-repo |
| **Neo4j (self-hosted or Aura)** | optional graph | operator-configured | `docker-compose.yml:43-56`; `secret_probes.py:251-263` |
| **Docker Hub / image registries** | digest-pinned images | `docker compose` | `docker-compose.yml:25-31` |

### Vendored third-party code

- **Strix** — `vendor/strix/`, **Apache-2.0**, LICENSE and NOTICE retained verbatim
  (`vendor/strix/LICENSE`; `NOTICE:19-45`). VIGIL's modifications are stated per Apache-2.0 §4(b):
  telemetry phone-home removed, OpenRouter attribution headers removed, default model changed
  (`NOTICE:31-42`). Default model is `anthropic/claude-opus-4-8`
  (`vendor/strix/strix/config/settings.py:23`); it routes through LiteLLM
  (`vendor/strix/strix/config/models.py:52-60`), so the reachable providers depend on the operator's
  `STRIX_LLM` value.
- **hexstrike-ai** — `vendor/hexstrike-ai/`, **MIT**, © 2026 Muhammad Osama (0x4m4)
  (`vendor/hexstrike-ai/LICENSE:1-3`). Pinned at commit `d689933f`
  (`vendor/hexstrike-ai/UPSTREAM.md:3-5`). **Vendored NON-RUNNABLE**: the upstream server and MCP
  client are stored with a `.reference` suffix so Python cannot import them; `vendor/` is never on
  `PYTHONPATH`; a CI guard asserts no `import hexstrike` in VIGIL source; the heavy upstream deps are
  not installed (`vendor/hexstrike-ai/UPSTREAM.md:7-31`). What VIGIL reuses is a clean-room
  reimplementation of the decision model, propose-only (`:33-45`).
- **redamon** — adapted portions, **MIT** (`NOTICE:47-70`).
- **AI-Gauntlet tools** (garak, PyRIT, Giskard, promptfoo) — invoked as subprocesses, own licenses,
  outside VIGIL's process (`NOTICE:12-14`).

VIGIL's own first-party code is **PolyForm Noncommercial 1.0.0 OR commercial**, © 2026 Junior Thuram
Nana (`LICENSE:1-22`; `NOTICE:1-11`).

---

## 5. Security controls a statement could honestly cite

1. **Two-environment boundary.** Sovereign and offense run in separate venvs; the build **fails** if
   `framework` or `strix` is importable from the sovereign environment
   (`envs/build_envs.sh:92-101`), and `bootstrap.sh` re-checks it dependency-free at install time
   (`bootstrap.sh:396-400`). The offense plane never holds the owner private key
   (`integration/vigil_integration/backup.py:32-34`).
2. **Single-owner-key trust root with an RBAC admission gate.** Every UI mutation funnels through one
   choke point; RBAC checks role→permission **before** the owner key signs, so a viewer's request
   never produces an owner signature (`apps/sigil/sigil/governor/accounts.py:1-13`). Roles are
   `viewer < analyst < operator < owner`, cumulative, **default-deny** for an unmapped action or
   unknown role (`packages/core/vigil_core/vigil_core/rbac.py:26-51`;
   `apps/sigil/sigil/governor/accounts.py:85-108`). "owner" is not grantable (`:74-78, 244-249`).
   One vocabulary is shared by both planes (`vigil_core/rbac.py:1-19`).
3. **Signed, hash-chained, append-only spine** with an owner-signed head and a durable external
   anti-rollback floor (`apps/sigil/sigil/spine/store.py:1-8`; `apps/sigil/sigil/config.py:98-101`).
   Chain verification is **keyless** — a verifier needs no decryption key
   (`apps/sigil/sigil/spine/envelope.py:22-25`).
4. **TPM-sealed KEK, fail-closed.** The KEK is generated once and sealed to the machine's TPM owner
   hierarchy; the sealed blob is useless on another machine; there is **no silent plaintext fallback**
   — if the TPM cannot unseal, operations raise (`packages/core/vigil_core/vigil_core/kek.py:1-17`).
   Sealing is ChaCha20-Poly1305 with domain + purpose context binding
   (`vigil_core/sealing.py:9-24`).
5. **Field-level payload encryption at rest** for content fields, AEAD-bound to `(scope, seq, field)`
   so a sealed value cannot be transplanted (`apps/sigil/sigil/spine/envelope.py:26-31`).
6. **Anti-replay on every dangerous governance direction.** Per-key `issued_at` high-waters for
   accounts, promotions, capabilities, kill-switch release, and device authorization, applied
   identically at every read surface (`apps/sigil/sigil/governor/accounts.py:20-24, 461-468`;
   `apps/sigil/sigil/governor/promotion.py:14-19`; `apps/sigil/sigil/spine/snapshot.py:16-30`).
7. **Asymmetric authentication doctrine**: the dangerous direction requires an owner signature *and*
   freshness; the safe direction (revoke, halt) is honoured even unsigned, so a fail-safe can never
   fail open (`apps/sigil/sigil/governor/accounts.py:14-19`).
8. **WARDEN A0–A3 tier gate on every tool call**, fail-closed to A3 on an empty/unknown name or a
   denylist hit (`integration/vigil_integration/warden_gate.py:113-122`). The Strix arbitrary-shell
   tool is gated **on by default**; any wiring failure raises rather than returning ungated hooks
   (`:24-40`). A non-auto decision routes to a single-use, owner-signed, per-action approval token
   that the keyless console cannot mint (`:36-42`).
9. **m-of-n threshold quorum for destructive actions**, with five fail-closed properties: distinct
   trusted signers, a **mandatory owner** fixed at deployment time (not a per-call string), action
   binding, a dead-man's-switch validity window, and single-use enforced by an `O_EXCL` nonce ledger
   that survives restart (`integration/vigil_integration/destruction_gate.py:1-52`).
10. **Owner-only permissions at rest.** Restrictive umask latch that only ever adds restrictions,
    0700 dirs, and 0600 files created via `os.open` with the mode set **before** any bytes are written
    — no world-readable window (`engine/crucible/framework/v2/common/paths.py:89-146`). SIGIL's own
    dirs are chmod 0700 (`apps/sigil/sigil/config.py:238-244`); `sigil.env` and `.env` are 0600
    (`bootstrap.sh:341, 348`).
11. **Credential masking before disk.** Deterministic masking of credential headers and structured log
    keys, deliberately conservative so it cannot destroy the evidence a finding rests on
    (`engine/crucible/framework/v2/common/redact.py:1-22, 35-49`).
12. **Categorical protected-domain floor**, default ON, owner-only to disable, with Unicode-homoglyph
    folding (`packages/core/vigil_core/vigil_core/hard_guardrail.py:1-31, 239-246`).
13. **Signed charter as the authorization gate** — unsigned charter or out-of-scope host is refused
    (`engine/crucible/framework/v2/common/ethics.py:104-136, 283-303`).
14. **Ephemeral / ZDR session mode** — tmpfs write root, verified purge on exit, forced non-permissive
    tier, persistence suppressed (`engine/crucible/framework/v2/common/ephemeral.py:1-35`).
15. **Loopback-only service binding** — every compose port publishes on `127.0.0.1`
    (`docker-compose.yml:9-11`); the UI proxy refuses `0.0.0.0`, unspecified, and globally-routable
    binds (`integration/vigil_integration/uiproxy.py:30-33, 250-252`), with Host + exact-Origin
    anti-CSRF / anti-DNS-rebinding checks (`apps/sigil/sigil/ui/server.py:152-165`).
16. **Timing-safe authentication.** A decoy scrypt hash makes login timing independent of whether a
    username exists, closing a ~59× enumeration oracle
    (`apps/sigil/sigil/governor/accounts.py:120-129`); bearer comparison is `hmac.compare_digest`
    (`:491`).
17. **Weak-key rejection.** Ed25519 public keys are validated at binding time; non-canonical (`y ≥ p`)
    and low-order keyless-forgery keys are refused (`apps/sigil/sigil/governor/accounts.py:252-263`).
18. **Envfile injection guard** — one shared validator every `sigil.env` writer must pass, covering
    NEL / U+2028 / U+2029 which an `ord < 0x20` check would miss
    (`apps/sigil/sigil/config.py:30-61`).
19. **Digest-pinned images and hash-locked Python dependencies**
    (`docker-compose.yml:25-31`; `envs/build_envs.sh:70-74`).
20. **Supply-chain honesty about the vendored offensive framework** — hexstrike-ai's runnable server is
    stored non-importable with a CI guard (`vendor/hexstrike-ai/UPSTREAM.md:20-31`).

---

## 6. Honest gaps — a careful reader will find these

These must not be papered over.

1. **Model egress is permissive by default.** Unset tier ⇒ `PERMISSIVE` ⇒ the direct consumer
   Anthropic API is first in the auto-selection order
   (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195, 137-141`), and `bootstrap.sh` writes
   the tier lines commented out (`bootstrap.sh:326-338`). Prompt content can include target data and
   findings, which can include third parties' personal data. Constraining this is an operator action,
   not a shipped default.
2. **Without a TPM, everything is plaintext at rest.** `bootstrap.sh` warns "no usable TPM — keys are
   PLAINTEXT at rest" (`bootstrap.sh:387`); the vault's own status string is
   "UNSEALED — trust-root keys/secrets are PLAINTEXT at rest"
   (`packages/core/vigil_core/vigil_core/vault.py:73-75`). Unprovisioned, `write_text_secret` writes
   plaintext (`:109-117`), spine payloads pass through unencrypted
   (`apps/sigil/sigil/spine/envelope.py:101-104`), and the offense identity keys are plaintext
   (`integration/vigil_integration/live/wiring.py:289-291`). The **only** thing that hard-refuses is
   `seal_secret`, so TOTP enrolment (`vault.py:119-129`). Protection then rests entirely on 0600/0700
   file permissions.
3. **There is no shipped erasure path.** Hard-prune is dry-run only on this branch
   (`apps/sigil/sigil/spine/prune.py:1-4`; `apps/sigil/sigil/cli.py:844-861`). No retention limit is
   configured anywhere. The spine is retained indefinitely by default. The only bulk delete is
   `sigil ingest --reset`, which destroys the entire ledger
   (`apps/sigil/sigil/spine/store.py:454-478`).
4. **Even the designed prune does not erase a person.** Account credentials, roles, public keys and
   anti-replay high-waters are deliberately carried forward in the snapshot seed
   (`apps/sigil/sigil/governor/accounts.py:29-35`; `apps/sigil/sigil/spine/snapshot.py:32-35`), a
   cumulative Merkle root over every pruned record is committed in the signed head
   (`apps/sigil/sigil/spine/merkle.py:1-8`), and `check_prune_safe` refuses a boundary that would
   strand an active account's only grant (`apps/sigil/sigil/spine/prune.py:165`). **Tamper-evidence
   and erasure are in genuine tension here, and the operator must decide how to resolve it.**
5. **Response bodies are stored verbatim.** Only credential *headers* are masked; the raw body is
   explicitly not touched and is protected by file permissions alone
   (`engine/crucible/framework/v2/common/redact.py:17-22`;
   `engine/crucible/framework/v2/agents/http_executor.py:752, 869`). If a client's application returns
   its users' personal data, that data is on the operator's disk in the clear.
6. **Finding certificates are a documented plaintext boundary.** Sealing them would break offline
   re-verification, so finding evidence stays plaintext even with a provisioned vault
   (`apps/sigil/sigil/spine/envelope.py:57-59`).
7. **The vector store holds up to 1200 characters of record text in the clear** alongside
   `session_id` and `project` (`apps/sigil/sigil/vectors/index.py:135-142`), decrypted before
   embedding (`:150`). Field-level spine encryption does not extend to it.
8. **Session bearers have no expiry.** `mint_session_bearer` issues a token with no TTL
   (`apps/sigil/sigil/governor/accounts.py:366-387`), and `_principal_for_token` applies no age check
   (`apps/sigil/sigil/ui/server.py:129-142`). A bearer is valid until an owner revoke or a re-mint.
   Revocation itself is prompt — the fold is recomputed per request
   (`apps/sigil/sigil/governor/accounts.py:482-493`) — but a leaked token is otherwise indefinite.
9. **One deliberate fail-open path**: the legacy embedded shared owner token always resolves to
   `OWNER_PRINCIPAL`, so the owner physically at the host is never locked out
   (`apps/sigil/sigil/ui/server.py:129-138`; `apps/sigil/sigil/governor/accounts.py:230-232`).
   Possession of that token is full owner authority.
10. **Sovereignty is not sealed by default.** `current()` re-reads the environment on each call unless
    `CRUCIBLE_SOVEREIGNTY_SEALED` is set, so on a long-running process a later environment mutation
    could relax the tier mid-run (`engine/crucible/framework/v2/kernel/sovereignty.py:383-388`).
11. **ZDR is an operator attestation, not a proof.** The source says so
    (`engine/crucible/framework/v2/kernel/sovereignty.py:152-155`).
12. **The seccomp egress guard is off by default and has three named limits** — 32-bit binaries are
    unfiltered, `sendmmsg`/`io_uring` are unfiltered, and exit code 97 is ambiguous
    (`integration/vigil_integration/live/egress_guard.py:25, 42-56`). It is described by its own
    docstring as "NOT a containment boundary for hostile code" (`:33-38`).
13. **The knowledge-sync secret scan is a net, not a guarantee** — its own words
    (`integration/vigil_integration/knowledge_sync.py:5-7`).
14. **Backup restore authenticity reduces to passphrase possession** unless an expected governance
    pubkey is pinned out of band (`integration/vigil_integration/backup.py:22-34`).
15. **Strix's live-scan dependencies are not hash-locked**, unlike everything else
    (`envs/build_envs.sh:74`).
16. **`fastembed` downloads model weights on first use.** `TextEmbedding(model_name=EMBED_MODEL)` is
    constructed with no cache pin, offline flag, or vendored weights anywhere in this repository
    (`apps/sigil/sigil/vectors/embed.py:12-17`; dependency at
    `apps/sigil/pyproject.toml:38`). **NOT VERIFIED** what the library fetches or from where — but
    nothing in this repository prevents that fetch, so an "air-gapped by default" claim about first
    run would be unsafe.
17. **Operator personal data is structurally required.** The usage ledger will not mint a record
    without a human handle — OS login, git name, or git email
    (`integration/vigil_integration/attestation/models.py:40-45`). The operator cannot run
    pseudonymously through the supported path.
18. **The operator's AI-assistant transcripts are ingested into the spine** by default project
    allowlist (`apps/sigil/sigil/config.py:122-126`;
    `apps/sigil/sigil/ingest/transcript.py:31-50`), and the default ingest repo list is
    operator-specific paths (`apps/sigil/sigil/config.py:227-235`). Client discussion recorded in an
    assistant transcript lands in the append-only ledger.
19. **A remote Neo4j is configurable and would be an egress path.** The shipped graph code is the
    embedded projection; **NOT VERIFIED** what a remote projection would transmit
    (`apps/sigil/sigil/ui/settings.py:141`; `apps/sigil/sigil/platform/secret_probes.py:258-263`).
20. **Local backup is not off-host backup** — the source names this honestly
    (`apps/sigil/sigil/backup.py:4-8`), and only a local-directory transport backend ships
    (`tools/backup/transport.py:15-18`).
21. **OIDC deployment assumes a private IdP.** A public cloud IdP is explicitly stated to break the
    air-gap posture and is not the default; `VIGIL_EGRESS_GUARD=require` is incompatible with a
    non-private IdP; and a TOTP-enrolled account cannot complete via the OIDC redirect at all
    (`docs/OIDC-RP.md:50-64`).
