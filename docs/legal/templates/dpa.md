# Data Processing Agreement — security engagement

> ## DRAFT TEMPLATE — NOT LEGAL ADVICE — REVIEW BY QUALIFIED COUNSEL IN YOUR JURISDICTION IS REQUIRED BEFORE USE
>
> This is an engineering-authored draft. It has not been reviewed by a lawyer, it is not legal
> advice, and it is not final legal text. **Counsel must review and adapt it before it is put in
> front of a client or signed.**
>
> - Every `<PLACEHOLDER>` must be replaced. An unreplaced placeholder means this document is not ready to sign.
> - This document is **structured around** the elements that controller-to-processor agreements are
>   commonly required to contain (for example EU/UK GDPR Article 28(3)). That structure is a drafting
>   convenience. **It is not a statement that either party complies with that regulation or any
>   other.** Whether any data-protection law applies to this engagement, and which one, is a legal
>   question for counsel.
> - Applicable law, forum, and transfer mechanism are **not settled** here (§ 13, § 14). The
>   Operator's primary jurisdiction is understood to be Cameroon; a Client may be elsewhere, and
>   EU/UK/US law can reach an operator extraterritorially.
> - Every technical statement is traceable to source, cited as `path:line`, and collected in
>   `docs/legal/DATA-GROUND-TRUTH.md`. Where a behaviour could not be verified from source it is
>   marked **NOT VERIFIED** rather than asserted.

---

> ### Read this before signing: the model provider is a sub-processor, and the default permits one
>
> The Operator's tooling can send engagement content to a large-language-model backend. Content can
> include data retrieved from the Client's systems, which can include personal data.
>
> **Under the software's default configuration, no sovereignty tier is selected, and the permissive
> tier applies: every backend class is permitted and the direct Anthropic API is first in
> auto-selection** (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195, 137-141`). The
> installer writes the tier lines commented out, stating "Left UNSET it is PERMISSIVE"
> (`bootstrap.sh:321-345`).
>
> The Client must choose a tier in § 8 and in § 10.2 of the authorization letter **before the
> engagement starts**. Choosing nothing is choosing the permissive default. See § 8 and Annex C.

---

**Effective date:** `<YYYY-MM-DD>`
**Engagement reference:** `<ENGAGEMENT-REF>`
**Related documents:** authorization letter (`docs/legal/templates/authorization-letter.md`);
mutual NDA (`docs/legal/templates/nda.md`)

## 1. Parties and roles

| Role | Legal name | Address | Contact for data-protection matters |
|---|---|---|---|
| **Controller** (the Client) | `<CLIENT LEGAL NAME>` | `<ADDRESS>` | `<NAME, EMAIL>` |
| **Processor** (the Operator) | `<OPERATOR LEGAL NAME>` | `<ADDRESS>` | `<NAME, EMAIL>` |

This agreement applies where the Operator processes personal data on the Client's behalf and on the
Client's documented instructions.

**Counsel must confirm the role allocation.** At least three categories arise in an engagement of
this kind and they may not all be processor-role:

1. Personal data appearing in data retrieved from the Client's systems — the Client's own users'
   data. Processed on the Client's instruction; processor-role is the working assumption here.
2. Contact details of the Client's engagement personnel — the Operator uses these to run the
   engagement and may hold them for its own record-keeping. Counsel to allocate.
3. **The Operator's own identity data.** The tooling embeds the operator's OS login, git name, git
   email, hostname, and signing-key fingerprint in every record of an always-on usage-attestation
   ledger (`integration/vigil_integration/attestation/models.py:24-45`;
   `integration/vigil_integration/live/wiring.py:305`), and refuses to mint a record whose identity
   carries no human handle (`attestation/models.py:38-45`). The Operator cannot run pseudonymously through the
   supported path. This is the Operator's own personal data and is expected to be
   controller-role for the Operator; counsel to confirm.

## 2. Subject matter, duration, nature and purpose

- **Subject matter:** processing incidental to a security assessment of the systems listed in § 3 of
  the authorization letter.
- **Duration:** from the effective date until the retention period in § 11 expires. The testing
  window itself is § 5 of the authorization letter.
- **Nature of the processing:** collection through automated and manual interaction with the Client's
  systems; storage of captured requests and responses as evidence; analysis to identify weaknesses;
  transmission to a model backend where a cloud tier is configured (§ 8); production of reports;
  retention and then deletion under § 11.
- **Purpose:** identifying and evidencing security weaknesses in the Client's systems, and reporting
  them to the Client. The Operator processes for no other purpose.

## 3. Categories of personal data and of data subjects

The Operator cannot predict what a Client's application will return in a response, and **the
Operator's tooling does not redact response bodies** (§ 6). The Client, as controller, must complete
this table.

| Category of data subject | Categories of personal data expected to appear | Where it arises |
|---|---|---|
| The Client's end users / customers | `<e.g. names, email addresses, order data>` | Application responses captured as evidence |
| The Client's employees / administrators | `<e.g. account names, roles, contact details>` | Admin interfaces, source code, configuration |
| The Client's engagement contacts | Names, business contact details | Correspondence, reports |
| `<other>` | `<...>` | `<...>` |

**Special categories and children's data.** The Client must state whether the systems in scope
process special-category data (health, biometric, racial or ethnic origin, political opinions,
religious beliefs, trade-union membership, sex life or sexual orientation), criminal-offence data, or
data relating to children:

- [ ] No, so far as the Client is aware.
- [ ] Yes — categories: `<...>`. Additional measures agreed: `<e.g. exclude the affected endpoints
      from scope; agree a shortened retention period; deliver evidence to the Client and retain no
      copy; select a non-cloud sovereignty tier>`.

## 4. Processor obligations

The Operator will:

1. process personal data only on the Client's documented instructions — this agreement and the
   authorization letter being the initial instructions — and record any further instruction in
   writing;
2. inform the Client if, in the Operator's view, an instruction appears to infringe applicable data
   protection law, and pause the affected processing until the Client confirms;
3. not process personal data for its own purposes, and not use engagement data to train or fine-tune
   any model;
4. keep the processing within the scope of § 3 of the authorization letter, and stop on the stop
   procedure in § 9 of that letter;
5. maintain a record of the processing carried out on the Client's behalf, comprising the engagement
   audit log, the evidence archive index, and the signed records described in Annex B;
6. assist the Client as set out in § 9 and § 10, at the Client's cost where the assistance is
   substantial.

## 5. Confidentiality of personnel

Everyone the Operator authorizes to process personal data under this agreement is bound by an
obligation of confidentiality, whether contractual or statutory, and is instructed to process only
as this agreement permits.

**Honest note on scale.** This deployment is designed around a single owner-controlled trust root.
Roles are `viewer < analyst < operator < owner`, cumulative and default-deny for an unmapped action
or unknown role (`packages/core/vigil_core/vigil_core/rbac.py:26-51`;
`apps/sigil/sigil/governor/accounts.py:85-108`), and `owner` is not grantable
(`accounts.py:74-78, 244-249`). In a single-operator engagement, "personnel" may be one person.

Persons authorized for this engagement: `<name(s), role(s)>`. The Operator will notify the Client
before adding anyone.

## 6. Security measures

Annex B lists the implemented technical measures with source citations, **and their limits**. The
limits are stated because a measure described without its boundary is a misrepresentation. In
particular, and before signing, the Client should note:

- **Response bodies are stored verbatim.** Credential headers and structured log keys are masked;
  the raw body is deliberately untouched so that evidence is not destroyed, and is protected by
  owner-only file permissions alone (`engine/crucible/framework/v2/common/redact.py:14-22`;
  `engine/crucible/framework/v2/agents/http_executor.py:744-752`). Personal data returned by the
  Client's application is therefore stored in the clear on the Operator's disk.
- **Encryption at rest depends on a provisioned hardware vault.** Where the vault is provisioned,
  content fields of ledger records are sealed per field
  (`apps/sigil/sigil/spine/envelope.py:26-31, 61-65`). Where it is not, that material passes through
  in plaintext (`:101-104`) and the vault's own status string reads "UNSEALED — trust-root
  keys/secrets are PLAINTEXT at rest" (`packages/core/vigil_core/vigil_core/vault.py:73-75`).
  Evidence files are protected by 0600/0700 permissions in either case
  (`engine/crucible/framework/v2/common/paths.py:89-146`).
- **The Operator states the machine's configuration for this engagement:** vault provisioned
  `<yes / no>`; `--ephemeral` mode `<in use / not in use>` — available only by running the CRUCIBLE
  engine CLI directly (`python3 -m framework.v2 engage … --ephemeral` from `engine/crucible/`,
  `engine/crucible/framework/v2/engage.py:1352`), **not** via `vigil engage` or the UI on this
  version (`integration/vigil_integration/cli.py:1937-1982`); full-disk encryption on the machine
  `<yes / no — outside this repository's scope to verify>`.

The Client confirms it has considered these measures against the risk presented by the categories in
§ 3, or has required additional measures in writing.

## 7. Assistance with security, notification, and impact assessment

The Operator will provide the Client with the information in Annex B, and reasonable assistance with
any data-protection impact assessment or prior-consultation exercise relating to this engagement, to
the extent the information is within the Operator's knowledge.

## 8. Sub-processors

The Client authorizes the sub-processors listed in **Annex C**. The Operator will notify the Client
of any intended addition or replacement at least `<14>` days in advance, and the Client may object on
reasonable data-protection grounds; if the parties cannot resolve the objection, the Client may
terminate the affected processing.

**The model provider.** Where a cloud sovereignty tier is configured, model/LLM calls transmit prompt
content to a model provider. Prompt content can include target-derived data and findings, which can
include personal data belonging to the Client's users. This is a sub-processing relationship and is
listed as such in Annex C.

**Tier selected for this engagement** (must match § 10.2 of the authorization letter, and must be set
in the Operator's environment before work begins):

- [ ] `AIR_GAPPED` — local model backends only. No model-provider sub-processor.
- [ ] `SOVEREIGN_CLOUD` — adds AWS Bedrock, Google Vertex, Mistral. Those providers are
      sub-processors.
- [ ] `TRUSTED_CLOUD` — adds Anthropic under a zero-data-retention arrangement. **Zero-data-retention
      is recorded as an operator attestation, not proven by the software**
      (`engine/crucible/framework/v2/kernel/sovereignty.py:152-155`); the Client should require sight
      of the Operator's contract with the provider.
- [ ] `PERMISSIVE` — any backend, including the direct Anthropic API. **This applies by default if
      nothing is selected.**

How the tier is applied, verified in source: the offense engine reads `CRUCIBLE_SOVEREIGNTY_TIER`
from the **process environment and from nowhere else**
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`). A value stored in the Operator's
`~/.sigil/sigil.env` or on the UI Settings screen reaches an offense process only when that process
was launched through the sovereign bridge (`vigil up`) — and only as of that start, because the bridge
resolves the runtime environment **once**, at bring-up (`integration/vigil_integration/uiproxy.py:2104`),
so a tier changed in the Settings screen while the UI is already running reaches only the offense
children of a *subsequent* `vigil up`, and a run launched from the UI in the meantime keeps the earlier
tier (restart `vigil up`, or the `vigil-command` service, for the change to take effect). An offense
process started any other way
falls back to `PERMISSIVE` **silently — this failure mode is fail-open**. The tier ticked above is
therefore a commitment to export it in the environment of every process that runs this engagement,
not merely to store it (`/PRIVACY.md` § 5.1a). An unrecognised value fails closed to `AIR_GAPPED`
rather than opening (`sovereignty.py:186-191`); a disallowed backend is refused before the provider
SDK is imported or a client is constructed (`:291-307`;
`integration/vigil_integration/live/think_claude.py:36-42`); and `CRUCIBLE_SOVEREIGNTY_SEALED=1`
latches the tier for the life of the process so a later environment change cannot relax it mid-run
(`sovereignty.py:383-416`). By default the tier is **not** sealed and is re-read on each call
(`:383-388`).

## 9. Assistance with data-subject requests

The Operator will notify the Client without undue delay, and in any event within `<3 business days>`,
if it receives a request from a data subject relating to data processed under this agreement, and
will not respond to it except on the Client's instruction.

The Operator will assist the Client, so far as technically possible, taking account of the nature of
the processing. **The following limits are real and the Client must accept them before the engagement
begins:**

| Request type | What the Operator can do | Limit |
|---|---|---|
| Access / copy | Search the evidence archive and reports for the subject's data and provide extracts | Practical only where the Client identifies the affected endpoints or identifiers |
| Rectification | Not applicable — the Operator stores what the Client's systems returned, as evidence of what they returned | Altering evidence would destroy its integrity |
| **Erasure** | Delete evidence directories, reports, chat transcripts, session entries, and derived indexes | **Individual records in the append-only ledger cannot be erased on this branch.** The prune machinery is dry-run only and deletes nothing (`apps/sigil/sigil/spine/prune.py:1-4`; `apps/sigil/sigil/cli.py:844-861`). The only bulk deletion is `sigil ingest --reset`, which destroys the entire ledger (`apps/sigil/sigil/spine/store.py:454-478`) |
| Restriction | Stop further processing; isolate the evidence archive | The ledger remains |
| Portability | Provide the evidence and reports in their stored formats | — |
| Objection | Stop the affected processing | — |

**Tamper-evidence and erasure are in genuine tension in this system, and the Client must decide how
to resolve it before work begins.** The ledger is hash-chained and signed so that the audit trail
cannot be silently altered; that same property is why a single record cannot be removed. Even the
designed prune, when it ships, is documented to keep a cryptographic commitment (a Merkle root) over
every removed record in the signed head (`apps/sigil/sigil/spine/merkle.py:1-8`) and to carry account
state forward in a snapshot (`apps/sigil/sigil/spine/snapshot.py:32-35`) — so a prune removes content
but leaves hashes and folded state, and is not equivalent to erasure.

Options available to the Client, each of which must be chosen up front:

- [ ] Run the engagement with `--ephemeral`, so evidence and audit output are written to
      memory-backed storage, ledger persistence is suppressed, and the purge is verified on exit
      (`engine/crucible/framework/v2/common/ephemeral.py:1-35`). **Reachability:** this flag exists
      only on the CRUCIBLE engine's own `engage` parser
      (`engine/crucible/framework/v2/engage.py:1352`), i.e. `python3 -m framework.v2 engage …
      --ephemeral` run from `engine/crucible/`. `vigil engage` does not define it and no UI control
      sets it on this version, so ticking this box commits the Operator to running the engagement
      from the engine CLI.
- [ ] Accept that ledger records — hashes, timestamps, record kinds — persist for the retention
      period in § 11 and are destroyed only when the whole ledger is destroyed.
- [ ] Other measure agreed in writing: `<...>`.

## 10. Personal data breach

The Operator will notify the Client without undue delay, and in any event within `<24 hours>` of
becoming aware, of any breach of security leading to accidental or unlawful destruction, loss,
alteration, or unauthorized disclosure of or access to personal data processed under this agreement.
The notification will describe, so far as known: the nature of the breach, the categories and
approximate number of data subjects and records concerned, likely consequences, and the measures
taken or proposed.

The Operator will assist the Client with the Client's own notification obligations. The Operator does
not notify a supervisory authority or a data subject on the Client's behalf unless the Client
instructs it in writing.

Material available to support an investigation: the engagement audit log and phase ledger, the
evidence archive, and the hash-chained signed ledger described in Annex B. The chain can be verified
without any decryption key (`apps/sigil/sigil/spine/envelope.py:22-25`). No claim is made here that
these detect a breach; they are records that support reconstructing what the tooling did.

## 11. Deletion or return at the end of the engagement

On the earlier of the Client's written request or `<30 days>` after delivery of the final report, the
Operator will, at the Client's election:

- [ ] **Return** the engagement evidence and reports to the Client via `<agreed channel>` and then
      delete its copies; or
- [ ] **Delete** them without return.

Deletion covers evidence directories, target working directories, reports, chat transcripts and
attachments, session registry entries, and derived indexes. The Operator will confirm completion in
writing.

Subject to § 9, ledger records persist. Retention period agreed for this engagement:
`<state it, and keep it identical to authorization-letter.md § 10.3 and nda.md § 8>`. **No default
retention limit is configured in the software; retention is whatever the parties agree and the
Operator then performs.**

Each party may retain copies required by law, subject to the confidentiality and security terms of
this agreement for as long as they are retained.

## 12. Audit

The Operator will make available to the Client the information necessary to demonstrate compliance
with this agreement, and will contribute to audits, including inspections, conducted by the Client or
an auditor it mandates — on `<30>` days' notice, no more than `<once>` per twelve months except after
a breach, during business hours, subject to confidentiality, and at the Client's cost.

What the Operator can make available without an on-site visit:

- the source-traceable description of data handling in `docs/legal/DATA-GROUND-TRUTH.md`;
- the engagement audit log and phase ledger for this engagement;
- verification of the ledger's hash chain, which requires no decryption key
  (`apps/sigil/sigil/spine/envelope.py:22-25`);
- offline re-verification of signed finding certificates.

The Operator may object to an auditor that is a competitor, and may require an equivalent
confidentiality undertaking.

## 13. International transfers — PLACEHOLDER

`<TO BE SETTLED BY COUNSEL. Processing takes place on the Operator's machine in <COUNTRY>. Where a
cloud model tier is configured (§ 8), content is additionally transmitted to the provider's
infrastructure in <REGION>. If the Client is established in a jurisdiction that restricts
international transfers, counsel must select and complete a transfer mechanism — for example standard
contractual clauses or an adequacy finding — and a transfer risk assessment may be required. No
mechanism is asserted here.>`

The most direct technical control over transfer is the tier selection in § 8: `AIR_GAPPED` removes
the model-provider transfer entirely.

## 14. Applicable law and forum — PLACEHOLDER

`<TO BE SETTLED BY COUNSEL, consistently with the authorization letter § 14 and the NDA § 11.>`

## 15. Order of precedence and signatures

Where this agreement conflicts with the NDA or the authorization letter on the processing of personal
data, this agreement governs. `<Counsel to confirm precedence against any master services
agreement.>`

**Controller (Client)**

Name: `<________________________>`  Title: `<________________________>`
Signature: `<________________________>`  Date: `<____________>`

**Processor (Operator)**

Name: `<________________________>`  Title: `<________________________>`
Signature: `<________________________>`  Date: `<____________>`

---

## Annex A — Details of the processing

| Item | Value |
|---|---|
| Subject matter | § 2 |
| Duration | § 2 and § 11 |
| Nature and purpose | § 2 |
| Types of personal data | § 3 |
| Categories of data subject | § 3 |
| Frequency | One-off engagement `<or: recurring, cadence ...>` |
| Retention | § 11 |
| Location of processing | `<Operator's machine, COUNTRY>` plus any provider in Annex C |

## Annex B — Technical and organizational measures, with their limits

Each row is implemented behaviour on this branch, with its citation and its boundary. None of these
is a warranty, and none is a claim of compliance with any standard.

| Measure | Implemented behaviour | Limit |
|---|---|---|
| Owner-only storage | Directories 0700, files 0600, mode set before any bytes are written (`common/paths.py:89-146`); SIGIL directories 0700 (`apps/sigil/sigil/config.py:238-244`) | Depends on the host operating system and on the machine's own disk encryption, which this repository does not manage |
| Credential masking | Credential header names and structured log keys masked before writing (`common/redact.py:14-22, 35-49`) | **Response bodies are not masked**, by design |
| Encryption at rest | Content fields of ledger records sealed per field under a machine-sealed key, bound to `(scope, seq, field)` (`spine/envelope.py:26-31, 61-65`) | Only where the hardware vault is provisioned; otherwise plaintext (`:101-104`; `vigil_core/vault.py:73-75`) |
| Key sealing | Key-encryption key sealed to the machine's TPM; no silent plaintext fallback (`vigil_core/kek.py:1-17`) | Without a TPM, key material is plaintext behind file permissions |
| Ephemeral mode | Memory-backed write root, forced non-permissive tier, suppressed persistence, verified purge on exit (`common/ephemeral.py:1-35`) | Opt-in per run |
| Append-only signed ledger | Hash-chained records with an owner-signed head and an external anti-rollback floor (`spine/store.py:1-8`; `apps/sigil/sigil/config.py:98-101`); chain verification needs no key (`spine/envelope.py:22-25`) | Makes individual-record erasure unavailable (§ 9) |
| Access control | Roles `viewer < analyst < operator < owner`, default-deny for unmapped actions and unknown roles (`vigil_core/rbac.py:26-51`); `owner` not grantable (`governor/accounts.py:74-78`) | Local to the deployment |
| Credential storage | Bearer tokens stored only as a salted hash (`governor/accounts.py:211, 289-291`); passwords hashed with scrypt n=2^15 (`:132-144`); TOTP secrets sealed with no plaintext fallback (`vigil_core/vault.py:119-129`) | Session bearers have no expiry; a leaked bearer is valid until revoked (`governor/accounts.py:366-387`) |
| Network exposure | Services bind loopback only (`docker-compose.yml:9-11`); the UI proxy refuses non-loopback binds (`uiproxy.py:30-33, 250-252`) | An operator can deliberately deploy differently |
| Scope enforcement | Unsigned charter refused (`common/ethics.py:104-140`); out-of-scope host refused (`:283-303`); categorical protected-domain block (`vigil_core/hard_guardrail.py:1-31`) | Enforces the charter, not this agreement |
| Destructive-action control | m-of-n threshold authorization with the owner as a mandatory signer, action-bound and single-use (`integration/vigil_integration/destruction_gate.py:1-52`) | Applies to actions routed through that gate |
| Plane separation | Sovereign and offense components run in separate environments; the build fails if the offense engine is importable from the sovereign environment (`envs/build_envs.sh:92-101`) | Build-time and install-time check |

## Annex C — Sub-processors

Listed with the default state on an unmodified install and the control that governs each. "Default
ON" means the relationship exists unless the Operator changes configuration.

| Sub-processor | Function | Personal data it may receive | Default | Control |
|---|---|---|---|---|
| **Anthropic** (`api.anthropic.com`) | Model/LLM backend | Prompt content: target-derived data, findings — which can include the Client's users' personal data | **ON under the default permissive tier** (`sovereignty.py:183-195, 137-141`; `bootstrap.sh:321-345`) | § 8 tier selection |
| AWS Bedrock / Google Vertex / Mistral | Jurisdictional model backends | As above | Only if selected (`sovereignty.py:73-76`) | § 8 tier selection |
| Azure OpenAI | Model backend | As above | Permissive tier or explicit selection (`sovereignty.py:82`) | § 8 tier selection |
| ElevenLabs | Speech synthesis / recognition | Audio, where the voice feature is used — the source states plainly that the audio leaves (`apps/sigil/sigil/voice/backends.py:239-241`) | OFF — requires an API key | Do not set `ELEVENLABS_API_KEY` |
| Google (`dns.google`), crt.sh, rdap.org, RIPE NCC (`stat.ripe.net`) | Passive intelligence lookups | The Client's domain, IP, or ASN as a query string — the Client's identity, not its users' data (`engine/crucible/framework/v2/intel/live.py:36-45`) | OFF — requires `--live` (`intel/cli.py:458-460`) | Do not pass `--live` |
| GitHub | Pull-request creation, knowledge sync | Repository content where the auto-patch leg is used | OFF — requires a token and an m-of-n quorum (`live/codefix_runner.py:74, 255-257`) | Leave disabled |
| Hugging Face (via `fastembed`) | Embedding model weights | **NOT VERIFIED** what is fetched or from where; nothing in this repository pins or vendors the weights or prevents the fetch (`apps/sigil/sigil/vectors/embed.py:12-17`) | Fetched on first embedding use | Counsel and Operator to assess before relying on an offline claim |
| Neo4j (if the Operator configures a remote instance) | Graph store | **NOT VERIFIED** what a remote projection would transmit; the shipped graph module is an embedded local projection | OFF by default (local embedded) | Do not configure a remote instance |
| Container image registries | Software distribution | None | Used at install (`docker-compose.yml:25-31`, digest-pinned) | — |

No third-party analytics or telemetry service is present in first-party code, and the vendored
third-party framework's telemetry modules were removed and replaced with a local-only sink with no
network transport (`NOTICE:32-35`; `vendor/strix/strix/telemetry/sink.py:1-9`). Metrics export, where
enabled, is pinned to loopback and refuses a non-loopback destination
(`integration/vigil_integration/live/otel_export.py:18, 80-104`).
