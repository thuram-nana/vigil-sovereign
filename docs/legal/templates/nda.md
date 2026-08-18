# Mutual Non-Disclosure Agreement — security engagement

> ## DRAFT TEMPLATE — NOT LEGAL ADVICE — REVIEW BY QUALIFIED COUNSEL IN YOUR JURISDICTION IS REQUIRED BEFORE USE
>
> This is an engineering-authored draft. It has not been reviewed by a lawyer, it is not legal
> advice, and it is not final legal text. **Counsel must review and adapt it before it is put in
> front of a client or signed.**
>
> - Every `<PLACEHOLDER>` must be replaced. An unreplaced placeholder means this document is not ready to sign.
> - Applicable law and forum are **not settled** here (§ 11). The Operator's primary jurisdiction is
>   understood to be Cameroon; a Client may be elsewhere.
> - The technical statements in § 7 and § 8 are traceable to source, cited as `path:line`, and
>   collected in `docs/legal/DATA-GROUND-TRUTH.md`. They are included because a destruction clause
>   that the software cannot honour would be a misrepresentation.
> - Nothing in this document asserts compliance with any statute, standard, or certification.

**Effective date:** `<YYYY-MM-DD>`
**Engagement reference:** `<ENGAGEMENT-REF>` (see the authorization letter at
`docs/legal/templates/authorization-letter.md`)

---

## 1. Parties

| Role | Legal name | Address | Signatory |
|---|---|---|---|
| **Client** | `<CLIENT LEGAL NAME>` | `<ADDRESS>` | `<NAME, TITLE>` |
| **Operator** | `<OPERATOR LEGAL NAME>` | `<ADDRESS>` | `<NAME, TITLE>` |

Each party may act as Discloser and as Recipient. The obligations below are mutual.

## 2. Purpose

The parties will exchange information in connection with a security assessment of the Client's
systems (the **Purpose**). Confidential Information may be used only for the Purpose.

## 3. Confidential Information

**Confidential Information** means information disclosed by a party, in any form, that is marked
confidential or that a reasonable person would understand to be confidential from its nature or the
circumstances of disclosure. It includes, without limitation:

**Disclosed by the Client:**

- system architecture, source code, configuration, credentials, and test-account details;
- business, customer, financial, and personnel information;
- the existence and content of any vulnerability in the Client's systems.

**Generated during the engagement (treated as the Client's Confidential Information unless the
parties agree otherwise in writing):**

- **Engagement data** — reconnaissance output, scan results, and any data retrieved from the
  Client's systems;
- **Findings** — each identified weakness, its exploitability, and its impact;
- **Evidence artifacts** — captured requests and responses, including complete raw response bodies,
  proof-of-concept material, screenshots, and signed evidence certificates;
- **Reports** — executive, technical, and remediation documents, and any retest report.

**Disclosed by the Operator:**

- the Operator's methodology, tooling, non-public engine internals, and unreleased capabilities;
- pricing and commercial terms.

## 4. Exclusions

Information is not Confidential Information to the extent the Recipient can show that it:

1. was public at disclosure, or became public later through no breach of this agreement;
2. was in the Recipient's possession without a duty of confidence before disclosure;
3. was received from a third party free to disclose it; or
4. was independently developed without use of or reference to the Confidential Information.

The Operator's general skills, knowledge, and experience — including techniques learned in the
course of the engagement — are not Confidential Information, provided no Client-identifying or
Client-specific information is used or disclosed.

## 5. Obligations

The Recipient will:

1. use Confidential Information only for the Purpose;
2. not disclose it except as § 6 permits;
3. protect it with at least the care described in § 7 and in any event no less than reasonable care;
4. limit internal access to those who need it for the Purpose; and
5. notify the Discloser without undue delay, and in any event within `<72 hours>`, on becoming aware
   of any unauthorized access to or disclosure of the Discloser's Confidential Information.

**Findings are not published.** The Operator will not publish, present, or otherwise disclose any
finding, evidence artifact, or Client-identifying detail — including in marketing, conference
material, blog posts, or training data — without the Client's prior written consent.
`<Optional: after <N> months, the Operator may publish a fully anonymized description with the
Client's prior written approval of the text.>`

## 6. Permitted disclosures

The Recipient may disclose Confidential Information:

1. **To personnel and contractors** who need it for the Purpose and are bound by confidentiality
   obligations at least as protective as these. The Recipient remains responsible for their acts.
2. **To professional advisers** (legal, accounting, insurance) under a duty of confidence.
3. **Where compelled by law**, court, or regulator — giving the Discloser prompt written notice
   where lawful and practicable, disclosing only what is required, and seeking confidential
   treatment.
4. **To the technical service providers listed in the executed data-processing agreement**
   (`docs/legal/templates/dpa.md`, Annex C), to the extent the engagement is configured to use them.
   This is a real disclosure, not a formality: where a cloud model tier is in use, engagement content
   — which can include findings and data retrieved from the Client's systems — is transmitted to the
   model provider. **Under the software's default configuration no tier is selected and the direct
   Anthropic API is permitted** (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195, 137-141`;
   `bootstrap.sh:321-345`). The tier for this engagement must be recorded in § 10.2 of the
   authorization letter before work begins, **and exported in the environment of every process that
   runs the engagement** — a tier recorded only on paper, or stored only in the Operator's settings
   file, does not constrain a process launched outside the `vigil up` bridge, which falls back to the
   permissive default without warning; and even inside the bridge a tier changed *after* `vigil up`
   started takes effect only on the next `vigil up`, not on a run already launched from the UI
   (`/PRIVACY.md` § 5.1a).
5. **To the Client's own auditors or insurers**, where the Client is the Recipient.

## 7. How the Operator holds engagement material

Stated so that the parties can judge the destruction clause in § 8 against what the software does.
These are descriptions of implemented behaviour, not warranties, and not a claim that the controls
are sufficient for any particular purpose.

- Engagement files are written owner-only: directories 0700, files 0600, with the mode set before any
  bytes are written (`engine/crucible/framework/v2/common/paths.py:89-146`).
- Captured credential headers and structured log keys are masked before writing; **raw response
  bodies are deliberately not masked** and are protected by file permissions alone
  (`engine/crucible/framework/v2/common/redact.py:14-22`).
- Where a hardware vault has been provisioned on the Operator's machine, content fields of ledger
  records are encrypted per field under a machine-sealed key
  (`apps/sigil/sigil/spine/envelope.py:26-31, 61-65`). **Where it has not been provisioned, that
  material is plaintext at rest behind file permissions** — the vault's own status string says
  "UNSEALED — trust-root keys/secrets are PLAINTEXT at rest"
  (`packages/core/vigil_core/vigil_core/vault.py:73-75`;
  `apps/sigil/sigil/spine/envelope.py:101-104`).
- Service interfaces bind to loopback only (`docker-compose.yml:9-11`;
  `integration/vigil_integration/uiproxy.py:30-33, 250-252`).
- Where the parties want engagement material to leave nothing on the Operator's disk, the commitment
  the Operator can actually keep is one of **retention and deletion, not a run mode**: evidence,
  reports and working notes are ordinary files under `targets/<slug>/` — the per-action evidence
  archive (`engine/crucible/framework/v2/common/paths.py:358-363`), the engagement log (`:366-367`)
  and the report snapshot (`:384-389`) — which the Operator delivers and then deletes at the agreed
  time. Records already appended to the hash-chained ledger are subject to the
  limits in § 8, which no setting on the documented route changes.
- Where the Operator discusses the engagement with an AI coding assistant, those transcripts may be
  ingested into the Operator's append-only ledger by an enabled ingestion path
  (`apps/sigil/sigil/config.py:122-126`; `apps/sigil/sigil/ingest/transcript.py:31-50`). The Operator
  will `<disable that ingestion for the duration of the engagement | note that it is enabled>`.

The Operator will state, in writing before the engagement starts, whether the vault is provisioned on
the machine used for it.

## 8. Return or destruction

On the earlier of the Discloser's written request or termination of the engagement, the Recipient
will return or destroy the Discloser's Confidential Information and confirm in writing what was
destroyed, within `<30 days>`.

**Honest limits on destruction, on the Operator's side.**

The Operator's audit trail is a hash-chained, signed, append-only ledger. That is what makes it
tamper-evident, and it means deletion is not uniform across the system:

| Material | Can be destroyed on request | Notes |
|---|---|---|
| Evidence directories, captured requests, responses, raw bodies | Yes | Ordinary file deletion of `targets/<slug>/evidence/` |
| Reports and working notes | Yes | Ordinary file deletion |
| Saved chat transcripts and attachments | Yes | `engine/crucible/framework/v2/console/chat.py:562-582` |
| Session registry entries and the rebuildable graph projection | Yes | `engine/crucible/framework/v2/console/sessions.py:279-305` |
| Derived vector index entries (which retain up to 1200 characters of record text in the clear) | Only by deleting the index | `apps/sigil/sigil/vectors/index.py:135-142` |
| Individual records in the append-only ledger | **No** | The prune machinery on this branch is dry-run only and deletes nothing (`apps/sigil/sigil/spine/prune.py:1-4`; `apps/sigil/sigil/cli.py:844-861`) |
| The ledger as a whole | Yes, all at once | `sigil ingest --reset` destroys every ledger artifact (`apps/sigil/sigil/spine/store.py:454-478`) |

Accordingly:

1. Ledger records created during the engagement — including cryptographic hashes of engagement
   content, and metadata such as timestamps and record kinds — **will survive a destruction request**
   unless the Operator destroys the entire ledger. The parties acknowledge this.
2. Where a future prune mechanism is used, it is designed to leave a cryptographic commitment
   (a Merkle root) over every removed record in the signed head
   (`apps/sigil/sigil/spine/merkle.py:1-8`), and to carry account state forward in a snapshot
   (`apps/sigil/sigil/spine/snapshot.py:32-35`). A prune is therefore not the same as erasure.
3. If the parties require that specific engagement material be genuinely unrecoverable, that must be
   agreed **before** the engagement — by agreeing that evidence is delivered to the Client and not
   retained, and by keeping the material out of the append-only ledger in the first place. After the
   run there is no tool in this repository that erases an individual record. Retention agreed for
   this engagement:
   `<state it, and keep it identical to authorization-letter.md § 10.3 and dpa.md § 11>`.
4. Each party may retain copies required by law or by an automatic backup system, subject to the
   confidentiality obligations in this agreement for as long as they are retained.

## 9. Term and survival

- This agreement starts on the effective date and continues until `<the completion of the engagement
  or YYYY-MM-DD, whichever is later>`.
- Confidentiality obligations survive for `<N — commonly 3 to 5>` years from disclosure.
- Obligations in respect of information that constitutes a trade secret, and in respect of personal
  data, survive for as long as the applicable law requires. `<Counsel to settle.>`
- Termination does not affect the destruction obligations in § 8.

## 10. No licence, no warranty, no obligation to disclose

Confidential Information is provided as-is. Nothing here grants any licence to intellectual property,
obliges either party to disclose anything, or creates a partnership, agency, or exclusivity.

## 11. Applicable law, forum, and remedies — PLACEHOLDER

`<Governing law: TO BE SETTLED BY COUNSEL. The Operator's primary jurisdiction is understood to be
Cameroon; the Client is established in <COUNTRY>. Do not copy a clause from another agreement: the
choice interacts with the data-protection terms in dpa.md and with the location of the systems
tested.>`

`<Forum / dispute resolution: TO BE SETTLED BY COUNSEL.>`

`<Remedies, including whether injunctive relief is available without proof of damage and whether
security or an undertaking is required: TO BE SETTLED BY COUNSEL — availability differs materially
between jurisdictions.>`

## 12. Signatures

**Client**

Name: `<________________________>`  Title: `<________________________>`
Signature: `<________________________>`  Date: `<____________>`

**Operator**

Name: `<________________________>`  Title: `<________________________>`
Signature: `<________________________>`  Date: `<____________>`
