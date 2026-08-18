# Authorization to Test — engagement authorization letter

> ## DRAFT TEMPLATE — NOT LEGAL ADVICE — REVIEW BY QUALIFIED COUNSEL IN YOUR JURISDICTION IS REQUIRED BEFORE USE
>
> This is an engineering-authored draft. It has not been reviewed by a lawyer, it is not legal
> advice, and it is not final legal text. **Counsel must review and adapt it before it is put in
> front of a client or signed.**
>
> - Every `<PLACEHOLDER>` must be replaced. An unreplaced placeholder means this document is not ready to sign.
> - Applicable law and forum are **not settled** here. The Operator's primary jurisdiction is
>   understood to be Cameroon; a Client may be elsewhere, and EU/UK/US law can reach an operator
>   extraterritorially. § 14 is a placeholder, not a recommendation.
> - Statements in § 10 about what the VIGIL software does are traceable to source, cited as
>   `path:line`, and collected in `docs/legal/DATA-GROUND-TRUTH.md`. Statements about legal effect
>   are counsel's to write and are not traceable to anything here.
> - Nothing in this document asserts compliance with any statute, standard, or certification.

**Document:** Authorization to Test
**Engagement reference:** `<ENGAGEMENT-REF>`
**Target slug (technical charter):** `targets/<SLUG>/charter.md`
**Version:** `<1.0>`  **Date:** `<YYYY-MM-DD>`

---

## How this document relates to the technical charter

Two documents govern one engagement, and they must say the same thing:

- **This letter** is what the parties sign. It is the contractual authorization.
- **The charter** (`targets/<SLUG>/charter.md`) is what the software reads. Parts of it are
  machine-enforced before traffic leaves the host.

Neither replaces the other. Every section below names the charter heading it mirrors, and § 13 is a
field-by-field map. If a value is changed in one document it must be changed in the other, in the
same amendment, on the same date (§ 12).

---

## 1. Parties

| Role | Legal name | Address | Signatory (name, title) |
|---|---|---|---|
| **Client** (the party authorizing the testing) | `<CLIENT LEGAL NAME>` | `<ADDRESS>` | `<NAME, TITLE>` |
| **Operator** (the party performing the testing) | `<OPERATOR LEGAL NAME>` | `<ADDRESS>` | `<NAME, TITLE>` |

The Operator performs the work using the VIGIL software described in § 10.

*Charter cross-reference: `## Operator attestation` — the charter records the person who attests;
this section records the legal entities.*

---

## 2. Client representation of ownership and authority

The Client represents and warrants that, for every asset listed in § 3:

1. The Client either owns the asset or holds a current, documented authorization from its owner
   sufficient to permit the testing described in this letter.
2. Where an asset is hosted, operated, or supplied by a third party (hosting provider, cloud
   provider, SaaS platform, managed service, CDN, WAF, identity provider), the Client has obtained
   any permission that provider's terms require, or has confirmed that none is required. The Client
   will provide evidence of that permission on request.
3. The Client has authority to bind itself to this letter, and the signatory in § 1 has authority to
   sign it.
4. The Client will notify the Operator immediately if any of the above ceases to be true during the
   window in § 5.

The Operator relies on these representations. The Operator does not independently verify ownership
of the listed assets, and has no practical means of doing so.

*Charter cross-reference: `## Operator attestation` (the ownership/authority attestation and the
authorization basis line).*

---

## 3. Assets in scope

Only the assets listed here are authorized. Be specific: a bare company name is not an asset, and a
bare domain is not a scope unless the row says so.

| # | Asset (host / IP / CIDR / repository / application) | Type | Ports / paths | Environment | Authorization basis |
|---|---|---|---|---|---|
| 1 | `<asset>` | `<web app / API / host / repo / mobile app>` | `<ports or paths>` | `<production / staging>` | `<owned / written permission from X>` |
| 2 | `<asset>` | | | | |

**Nothing else is in scope.** `<State the single hard boundary in one sentence — for example: "Only
the exact hosts listed above; every subdomain, sibling service, and upstream is out of scope.">`

Wildcard entries: an entry written `*.example.com` authorizes any subdomain of `example.com` and the
apex `example.com` itself. Write wildcards only where that is intended.

Assets discovered during the engagement that are not listed here are **not authorized**. The
Operator will surface them and wait for a written amendment (§ 12) before testing them.

*Charter cross-reference: `## Target hosts (in scope)` and its "Nothing else is in scope" line.*

> **Operational note (verified in code, not a legal statement).** The engine's scope gate reads the
> charter section headed exactly `## 2. In-scope systems`
> (`engine/crucible/framework/v2/common/ethics.py:147-151`), parses the host column of the table
> under it (`:153-185`), and refuses any host that does not match — including refusing everything
> when no hosts parse (`:283-303`). Wildcard and IPv6 matching are implemented at `:245-275`. The
> intake drafter emits that exact heading (`engine/crucible/framework/v2/intake/drafters.py:81`).
> The copy of `targets/_template/charter.md` on this branch titles that section
> `## Target hosts (in scope)`, which that pattern does not match; a charter that keeps the template
> title yields an empty scope and the gate refuses every host. Make the charter's asset section carry
> the numbered heading, and make its rows identical to the table above.

---

## 4. Out of scope

The following are **not** authorized, regardless of what the Operator can reach from an in-scope
asset:

- Third-party and upstream providers: payment processors, identity providers, email and SMS
  providers, CDNs, WAFs, hosting and cloud control planes, and any other supplier's own systems.
  The Operator may test the **Client's integration** with them (webhook handlers, callback URLs, key
  handling); the provider's systems themselves are excluded.
- Systems the Client owns but has not listed in § 3: `<list them, or write "none">`.
- Shared infrastructure that other parties rely on: `<list, or "none">`.
- Employee, customer, or contractor personal accounts and devices.
- `<any other exclusion>`

If a flaw in an in-scope asset can reach an out-of-scope system (server-side request forgery
reaching a cloud metadata service, webhook forgery reaching a payment processor, token leakage
reaching an identity provider), the Operator will document it, will not exploit it further, and will
notify the Client's contact in § 9 immediately.

*Charter cross-reference: the third-party exclusion note under `## Target hosts (in scope)`.*

> **Operational note (verified in code).** A categorical block on government, military, educational,
> and intergovernmental domains runs before the charter is even parsed, with Unicode-homoglyph
> folding (`packages/core/vigil_core/vigil_core/hard_guardrail.py:1-31`;
> `engine/crucible/framework/v2/common/ethics.py:283-289`). It is on unless an owner explicitly sets
> `VIGIL_ALLOW_PROTECTED_DOMAINS` to an affirmative value
> (`vigil_core/hard_guardrail.py:239-246`). Turning it off does not widen the charter scope.

---

## 5. Testing window

- **Start:** `<YYYY-MM-DD HH:MM TZ>`
- **End:** `<YYYY-MM-DD HH:MM TZ>`
- Authorization exists only inside this window. Outside it, no testing traffic is authorized.
- Extension requires a written amendment under § 12.

*Charter cross-reference: the authorization window on the `## Operator attestation` line.*

---

## 6. Permitted techniques

Within § 3 and § 5, and subject to § 7, the Client authorizes:

- Passive reconnaissance and enumeration of the listed assets.
- Automated and manual scanning of the listed assets, at the rate limits in § 8.
- Authenticated testing using the test accounts the Client provides (`<list roles>`), including
  testing for authorization flaws across those accounts.
- Injection, client-side, business-logic, and configuration testing, using non-destructive payloads.
- Proof-of-concept exploitation limited to the minimum action needed to establish that a flaw is
  real, followed by immediate reporting.
- Creation of clearly-tagged test artifacts (accounts, orders, tickets, records) using the prefix
  `<PREFIX->`, tracked and listed to the Client at close.
- `<source code review, if the Client is supplying source — state which repositories>`

**Posture:** `<owner-test (identifiable, throttled, tagged) | adversarial emulation — only if the
Client explicitly authorizes it here and in the charter>`.

*Charter cross-reference: `## Rules of engagement — posture`.*

---

## 7. Expressly excluded techniques

The following are excluded unless separately authorized in writing by an amendment that names them:

- **Denial of service and resource exhaustion** of any kind, including load, stress, and volumetric
  testing, connection flooding, and algorithmic-complexity attacks.
- **Social engineering** of any person: phishing, vishing, smishing, pretexting, credential
  harvesting from staff, and any test whose subject is a human rather than a system.
- **Physical intrusion**, badge cloning, device implantation, and any on-premises activity.
- **Attacks on third-party or upstream providers** (see § 4), including their control planes and
  APIs beyond the Client's own integration surface.
- **Destructive actions**: bulk deletion, schema changes, mass mailing, real-money movement,
  irreversible configuration changes, or persistence left in place after the session.
- **Contact with the Client's real users**: password resets to real addresses, notifications, SMS,
  or any message delivered to a person who is not a named engagement contact.
- **Bulk collection of personal data.** Where a flaw exposes personal data, the Operator collects
  the minimum needed to demonstrate impact (`<N>` records maximum), and reports it rather than
  extracting it.
- **Anonymization of the Operator's own traffic**: no proxy chains, Tor, or rotating residential
  addresses. The Client is intended to be able to identify the Operator's traffic in its logs.
- `<any Client-specific exclusion>`

*Charter cross-reference: `## Hard limits (inviolable)`.*

> **Operational note (verified in code).** Destructive and high-blast-radius actions additionally
> require an m-of-n threshold authorization in which the owner is a mandatory signer, bound to the
> specific action and single-use (`integration/vigil_integration/destruction_gate.py:1-52`). Tool
> calls are classified into tiers and fail closed to the highest tier on an unknown or empty tool
> name (`integration/vigil_integration/warden_gate.py:110-122`). These are engineering controls, not
> a substitute for the exclusions above.

---

## 8. Rate, timing, and identification

- **Heavy scanning window:** `<HH:MM–HH:MM TZ>`, or `<any time>` where the Client has confirmed it.
- **Concurrency:** default 5–10 parallel requests; higher only with the Client's confirmation.
- **Rate limits:** the Operator respects HTTP 429 and backs off. Rate limits are not bypassed except
  as a single documented test of the rate limit itself.
- **Source address:** `<IP or range>`. The Client can filter its logs on this address.
- **User-Agent:** `<OBSIDIAN/1.0 (authorized owner-test <YYYY-MM-DD>)>` on automated tooling.
- **Staging first:** where a staging environment exists, it is used in preference to production for
  anything with side effects.

*Charter cross-reference: `## Soft limits`.*

---

## 9. Contacts, escalation, and the stop procedure

| Purpose | Client | Operator |
|---|---|---|
| Day-to-day engagement contact | `<name, email, phone>` | `<name, email, phone>` |
| Critical-finding escalation (24/7) | `<name, email, phone>` | `<name, email, phone>` |
| Emergency stop (24/7) | `<name, phone>` | `<name, phone>` |
| Backup contact if the primary is unreachable | `<name, phone>` | `<name, phone>` |

**Stop procedure.**

1. Either party may stop the engagement at any time, for any reason, by contacting the other party's
   emergency-stop contact above by `<phone call, and confirming by email>`.
2. The Operator acknowledges within `<15 minutes>` and halts all testing traffic within
   `<30 minutes>` of acknowledgement.
3. Testing does not resume until the Client confirms resumption in writing.
4. The Operator halts without waiting to be asked, and notifies the Client immediately, if: a test
   appears to be degrading a production system (server-error bursts, sustained latency); evidence of
   a **prior compromise** by someone else is found; the Operator can read real user personal data,
   payment data, or credentials; or authorization becomes unclear for any reason.
5. A stop does not by itself terminate this letter or the confidentiality obligations in § 10.

*Charter cross-reference: `## Stop conditions`.*

---

## 10. Data handling and confidentiality

Confidentiality is governed by the mutual non-disclosure agreement at `docs/legal/templates/nda.md`
(as executed between the parties). Where the Operator processes personal data on the Client's behalf,
the data-processing terms at `docs/legal/templates/dpa.md` (as executed) apply. This section states
the technical facts the Client should understand **before signing**, so that the confidentiality and
data-processing terms are read against what the software actually does.

### 10.1 What the Operator's tooling records

- **Full HTTP evidence.** For each action the tooling writes the request, the response, and the
  complete raw response body under `targets/<SLUG>/evidence/<action-id>/`
  (`engine/crucible/framework/v2/agents/http_executor.py:744-752`;
  `engine/crucible/framework/v2/common/paths.py:358-362`).
- **Credential headers are masked; response bodies are not.** Masking covers credential header names
  and structured log keys only; the raw body is deliberately left untouched so that the evidence a
  finding rests on is not destroyed, and is protected by owner-only file permissions
  (`engine/crucible/framework/v2/common/redact.py:14-22`). **If an in-scope application returns its
  users' personal data in a response, that data is stored verbatim on the Operator's disk.**
- **Findings and evidence certificates** are recorded in a signed, hash-chained ledger
  (`apps/sigil/sigil/spine/store.py:1-8`). The engagement audit log, the scan report, and the
  phase ledger are written per engagement as owner-only files, with secret keys masked in
  structured log output (`engine/crucible/framework/v2/common/redact.py:52-79`).
- Files are created 0600 and directories 0700, with the mode set before any bytes are written
  (`engine/crucible/framework/v2/common/paths.py:89-146`).

### 10.2 Model (LLM) egress — read this before signing

The Operator's tooling can call a large-language-model backend during an engagement. Which backends
are permitted is governed by a sovereignty tier. **Unless a tier is selected, the default is
permissive**: `_resolve_tier_from_env()` returns `PERMISSIVE` when `CRUCIBLE_SOVEREIGNTY_TIER` is
unset (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`), `PERMISSIVE` permits every
backend class and places the direct Anthropic API first in auto-selection (`:137-141`), and the
installer writes every tier line commented out with the note that "Left UNSET it is PERMISSIVE"
(`bootstrap.sh:321-345`).

Prompt content can include target-derived data and findings, which can include personal data
belonging to the Client's users.

**Tier selected for this engagement** (tick one; ticking it here is a commitment, not a control —
the tier must also be **exported in the environment of every process that runs the engagement**):

- [ ] `AIR_GAPPED` — local model backends only; no model-provider egress.
- [ ] `SOVEREIGN_CLOUD` — adds jurisdictional cloud backends (AWS Bedrock, Google Vertex, Mistral).
- [ ] `TRUSTED_CLOUD` — adds Anthropic under a zero-data-retention arrangement. Note that
      zero-data-retention is recorded as an operator attestation, not proven by the software
      (`engine/crucible/framework/v2/kernel/sovereignty.py:152-155`).
- [ ] `PERMISSIVE` — any backend, including the direct Anthropic API. **This is the default if
      nothing is selected.**

Where a cloud tier is selected, the model provider receives Client-related content and is a
sub-processor for the purposes of the data-processing terms. See `dpa.md` § 8.

**How the tier reaches a process, and where it does not.** The engine reads
`CRUCIBLE_SOVEREIGNTY_TIER` from the process environment and from nowhere else
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`). A value stored in the Operator's
`~/.sigil/sigil.env` or on the UI Settings screen governs an offense process only when that process
was launched through the sovereign bridge, i.e. `vigil up`, which injects the allowlisted variables
into the offense children it spawns (`integration/vigil_integration/uiproxy.py:1631, 1712-1739`). An
offense process started any other way — `vigil engage` from a shell, the engine CLI, a systemd unit
or container that does not export the variable — does not see it and falls back to `PERMISSIVE`
**silently. This failure mode is fail-open.** The read-only tier pill on the UI's Governance & Gate
Audit screen (`#/governance`, `packages/vigil-ui/app.js:1803-1809`) reports the tier in force in the
offense process that serves the UI, and only for that process.

An unrecognised tier value fails closed to `AIR_GAPPED` rather than opening
(`sovereignty.py:186-191`), and `CRUCIBLE_SOVEREIGNTY_SEALED=1` latches the tier for the life of the
process (`:383-416`). A run started with `--ephemeral` forces a non-permissive tier, writes to
memory-backed storage, and verifies the purge on exit
(`engine/crucible/framework/v2/common/ephemeral.py:1-35`) — but that flag is declared **only** on the
CRUCIBLE engine's own `engage` parser (`engine/crucible/framework/v2/engage.py:1352`), i.e.
`python3 -m framework.v2 engage … --ephemeral` run from `engine/crucible/`. It is not an option of
`vigil engage` (`integration/vigil_integration/cli.py:1937-1982`) and no UI control sets it on this
version, so it must not be relied on unless the engagement is run from the engine CLI.

### 10.3 Retention, and the limits of deletion

Engagement records are appended to a hash-chained, signed, append-only ledger. That design is what
makes the audit trail tamper-evident, and it constrains deletion:

- On this branch there is **no shipped way to erase an individual record** from the ledger. The
  hard-prune machinery is dry-run only; its own documentation states that nothing there deletes a
  live record (`apps/sigil/sigil/spine/prune.py:1-4`), and the CLI exposes only a plan that
  "archives nothing, drops nothing" (`apps/sigil/sigil/cli.py:844-861`).
- What **can** be deleted today: evidence directories and target directories (ordinary file
  deletion); saved chat transcripts and their attachments
  (`engine/crucible/framework/v2/console/chat.py:562-582`); session registry entries and the
  rebuildable graph projection (`engine/crucible/framework/v2/console/sessions.py:279-305`); and the
  entire ledger at once via `sigil ingest --reset` (`apps/sigil/sigil/spine/store.py:454-478`).
- **No default retention limit is configured.** Retention for this engagement is:
  `<state a period, and who deletes what at the end — see nda.md § 8 and dpa.md § 11>`.

---

## 11. Reporting and deliverables

The Operator will deliver: `<executive summary | technical report | remediation roadmap | evidence
bundle>`, by `<date>`, via `<channel>`.

Critical findings are reported to the Client's escalation contact (§ 9) as soon as they are
confirmed, not held for the final report.

*Charter cross-reference: `## Objectives`.*

---

## 12. Amendments

Any change to the asset list, the window, the permitted or excluded techniques, or the posture
requires:

1. A written amendment signed by both signatories in § 1, appended to § 15 of this letter.
2. A matching edit to `targets/<SLUG>/charter.md`, recorded under its `## Amendments` heading with
   the same date.

Scope is never widened by conversation, by inference, or because a related system was mentioned. If
the two documents disagree, the Operator stops and asks.

*Charter cross-reference: `## Amendments`.*

---

## 13. Field map — this letter against the charter

| This letter | Charter heading (`targets/<SLUG>/charter.md`) | Machine-enforced? |
|---|---|---|
| § 2 Client representation | `## Operator attestation` | Partly — the scope gate refuses a missing, empty, or placeholder `Signed:` line (`ethics.py:104-140`; `agents/scope_gate.py:143-157`) |
| § 3 Assets in scope | `## Target hosts (in scope)` — must be titled `## 2. In-scope systems` for the parser | Yes — host must match the parsed table (`ethics.py:147-185, 245-275, 283-303`) |
| § 4 Out of scope | third-party note under the same charter heading | Partly — categorical protected-domain block only (`vigil_core/hard_guardrail.py:1-31, 239-246`) |
| § 5 Testing window | window on the `## Operator attestation` line | No — procedural |
| § 6 Permitted techniques | `## Rules of engagement — posture` | Partly — tool-tier gate (`warden_gate.py:110-122`) |
| § 7 Excluded techniques | `## Hard limits (inviolable)` | Partly — destructive actions need m-of-n owner-signed quorum (`destruction_gate.py:1-52`) |
| § 8 Rate and identification | `## Soft limits` | No — procedural |
| § 9 Contacts and stop | `## Stop conditions` | No — procedural |
| § 10 Data handling | not represented in the charter | See § 10 citations |
| § 11 Deliverables | `## Objectives` | No |
| § 12 Amendments | `## Amendments` | No |

A row marked "No" or "Partly" is a control that depends on people following it. Neither document is
a technical guarantee.

---

## 14. Applicable law and forum — PLACEHOLDER

`<Governing law: TO BE SETTLED BY COUNSEL. The Operator's primary jurisdiction is understood to be
Cameroon; the Client is established in <COUNTRY>. Do not copy a governing-law clause from another
document without advice: the choice interacts with the data-protection terms in dpa.md, with any
computer-misuse statute that applies to the assets in § 3, and with where those assets are physically
hosted.>`

`<Forum / dispute resolution: TO BE SETTLED BY COUNSEL.>`

Nothing in this letter is a waiver of any third party's rights, and nothing in it authorizes conduct
that is unlawful in any jurisdiction that applies to the assets in § 3. Where this letter and the law
conflict, the law governs and the Operator stops.

---

## 15. Signatures

**Client**

I confirm that the representations in § 2 are true, and I authorize the Operator to perform the
testing described in this letter, against the assets in § 3, during the window in § 5, subject to the
exclusions in § 7.

Name: `<________________________>`
Title: `<________________________>`
Entity: `<________________________>`
Signature: `<________________________>`
Date: `<____________>`

**Operator**

I confirm that testing will be confined to the assets in § 3 and the window in § 5, that the
exclusions in § 7 will be observed, and that the stop procedure in § 9 will be honoured.

Name: `<________________________>`
Title: `<________________________>`
Entity: `<________________________>`
Signature: `<________________________>`
Date: `<____________>`

**Amendments to this letter**

| # | Date | Change | Client signature | Operator signature |
|---|---|---|---|---|
| 1 | `<YYYY-MM-DD>` | `<what changed>` | | |
