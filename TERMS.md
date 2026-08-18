# TERMS OF USE

**These terms are not legal advice and are not a final legal instrument.** They are the
maintainer's stated terms for the use of VIGIL, written to be read by the people who
actually run it. Jurisdiction and governing law are **unsettled placeholders** (§ 8).
Have qualified counsel in your jurisdiction review and adapt them before relying on them.

---

## 1. What these terms are, and what they are not

VIGIL is distributed under a dual licence: **PolyForm Noncommercial License 1.0.0**
([`LICENSE`](LICENSE), as modified by the Government-Use Supplemental Term) **or** a
**Commercial Licence** from the Licensor ([`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)).
[`LICENSING.md`](LICENSING.md) explains which applies to you.

A licence answers *may you copy, modify, and run this code*. These terms answer a different
question: *on what basis do you use it, and who carries which risk when you do*. They are
therefore separate from, and additional to, the licence.

**Order of precedence.** If these documents conflict:

1. **A signed agreement between you and the Licensor** — a commercial licence, an engagement
   contract, a statement of work, a data-processing agreement — controls over everything
   below, for the subject it covers.
2. **The applicable licence text** ([`LICENSE`](LICENSE) or your commercial agreement)
   controls over these terms on licence subject matter: grant, scope of permitted use,
   termination, warranty, and liability.
3. **These terms**, together with [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md),
   [`SECURITY.md`](SECURITY.md), [`EXPORT.md`](EXPORT.md), and
   [`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md).

Nothing here is intended to give the Licensor *fewer* protections than the licence already
provides, or to reduce rights you hold under mandatory law.

**Acceptance.** By downloading, cloning, installing, running, or otherwise using VIGIL you
accept these terms. If you do not accept them, do not use VIGIL.

## 2. This is security tooling. It can break things.

Read this section before the liability sections, because it is the reason they read the way
they do.

VIGIL is autonomous offensive-security software. In normal, correct operation it sends
traffic designed to trigger faults in the system under test. Even when it behaves exactly
as designed, it can:

- **degrade or take down** the system being tested — an injection probe that hits an
  unindexed query, a request rate a fragile service cannot absorb, a fuzz case that wedges a
  worker;
- **write data** into the target — accounts, orders, tickets, uploads, database rows — that
  someone has to clean up afterwards;
- **trigger side effects with real-world consequences** — emails, SMS, webhooks,
  notifications, payment-provider calls — where a test surface touches production;
- **set off alarms** at the target's provider, CDN, or hosting platform, with the
  contractual and reputational consequences that follow;
- **produce a wrong answer.** VIGIL is built to refuse to assert what it has not proven
  (see [`docs/CLAIM-DISCIPLINE.md`](docs/CLAIM-DISCIPLINE.md)), but no scanner finds
  everything, and a clean result is not a certificate of safety beyond the coverage the
  output itself states.

Test against staging where one exists. Take a backup that you have actually restored from.
Have a rollback and an abort path before you start, not after.

## 3. Your responsibilities

**Authorization.** You test only what you own, or what you hold current written
authorization to test. [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md) is part of these terms and
is a condition of your licence.

**Scope.** You configure the charter, the scope, and the limits correctly, and you keep
VIGIL inside them. The gates described in `ACCEPTABLE-USE.md` § 4 are defence in depth
around your decision; they do not make it.

**Backups and change control.** You take and verify backups before testing anything you
cannot afford to lose, you keep an owner or on-call contact reachable during the window,
and you agree the abort conditions in advance.

**Deployment security.** VIGIL holds signing keys and client data on the host it runs on
(see [`SECURITY.md`](SECURITY.md) § 1). You are responsible for provisioning the vault if
you want keys sealed at rest, for the file permissions and disk encryption around the
engagement directories, and for who can reach the console.

**Two configuration decisions with consequences for people who are not you.** Both are
documented behaviour, not defects:

- **Model egress defaults to permissive.** With no sovereignty tier set, the resolved tier
  is `PERMISSIVE` (`engine/crucible/framework/v2/kernel/sovereignty.py:195`) and the
  installer writes every tier line commented out (`bootstrap.sh:326-336`). In that state
  prompt content — which can include target data and findings, which can include third
  parties' personal data — may be sent to a commercial cloud model provider. If your
  engagement terms, your client contract, or the law that reaches you does not permit that,
  set a tier before the first run — by **exporting** `CRUCIBLE_SOVEREIGNTY_TIER` in the
  environment the process inherits. A tier stored only in `~/.sigil/sigil.env` or on the UI
  Settings screen reaches an offense process only when `vigil up` launched it; started any
  other way, the process falls back to `PERMISSIVE` **silently — fail-open**
  (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`; scope of each mechanism in
  `/PRIVACY.md` § 5.1a). Note the tier's stated limits, including that it does not govern the
  sovereign plane's own model calls (`engine/crucible/SECURITY.md` § 3.5).
- **Evidence is retained unredacted.** `targets/<slug>/evidence/<action_id>/response.body`
  holds full raw response bodies from the tested systems; only credential headers are masked
  (`engine/crucible/framework/v2/agents/http_executor.py:744-752`,
  `engine/crucible/framework/v2/common/redact.py:17-49`). Retention, transfer, and
  destruction of that material are yours to govern.

**Data and personal data.** [`PRIVACY.md`](PRIVACY.md) describes what this software stores, where, and
in what form. Where VIGIL processes personal data — the target's users' data
captured in evidence, or the identity data VIGIL stores about your own operators — you are
responsible for having a lawful basis, for informing whoever must be informed, and for the
retention and deletion decisions in § 4. The maintainer is not a party to your engagements
and does not receive your engagement data.

**Legal compliance.** Including export control and sanctions ([`EXPORT.md`](EXPORT.md)) and
any domestic restrictions on possessing or using intrusion tooling.

## 4. Audit records, retention, and the limits of erasure

VIGIL's audit spine is **append-only, hash-chained, and Ed25519-signed** on purpose: an
audit trail that can be quietly edited proves nothing. That property is in direct tension
with deleting data on request, and you should understand the tension before you store
anything you may later need to erase.

**What the spine holds.** Alongside engagement records it holds owner-signed governance
grants for each per-user account: username and role in **plaintext**, the enrolled Ed25519
public key in plaintext, a salted bearer-token hash, a scrypt password hash, and an
AEAD-sealed TOTP secret (`apps/sigil/sigil/governor/accounts.py:207-221`). Ingested content
fields are sealed under the spine data-encryption key **when the vault is provisioned**, and
are plaintext otherwise (`apps/sigil/sigil/spine/envelope.py:61-65, 102-112`).

**What can be erased today, honestly.** On this branch the hard-prune machinery is
**non-destructive**. `apps/sigil/sigil/spine/prune.py` states in its own header that nothing
in it deletes a live record or commits a head; the crash-safe cutover that would actually
delete is not wired. The shipped commands are `sigil spine prune-plan` — an explicit dry run
that "archives nothing, drops nothing" (`apps/sigil/sigil/cli.py:844-861`) — and
`sigil spine verify-archive`. **There is currently no supported command that erases a record
from the live spine.**

**What would survive a prune when the cutover does land.** By design, not by oversight:

- whole sealed segments below the prune boundary are **copied byte-identically** into
  `~/.sigil/spine/archive/` before anything is dropped (`prune.py:1-17`), so the data still
  exists until you destroy the archive separately — and destroying it makes the pruned
  prefix unrecoverable, which the source calls an explicit trade-off;
- an owner-signed **snapshot record** commits a Merkle root plus a folded summary of the
  pruned prefix, and that fold deliberately carries, per account, the **username, role,
  credential hash and salt, enrolled public key, sealed TOTP secret, and password hash** —
  explicitly so that pruning cannot silently downgrade an account's authentication
  (`apps/sigil/sigil/spine/snapshot.py:100-114`). The fold also keeps
  `{username: active|revoked}` state and a per-username anti-replay high-water, and the
  source notes credential rows are carried even for usernames later revoked. **Revoking an
  account therefore does not remove its username from the folded state, and a prune would
  not either.**

**Derived copies.** Erasing a spine record would not, by itself, erase copies derived from
it. The vector index stores up to 1200 characters of decrypted record text in its payload
(`apps/sigil/sigil/vectors/index.py:134-142`), and backups, rotated segments, and exported
reports are separate artefacts with their own lifecycles.

**What this means for you.** Decide *before* you ingest: what goes into the spine, whose
data it is, how long it is kept, where backups live, and how you would answer an erasure
request. If your obligations require erasure of identity data, the current design is that
identity data in the spine is durable — plan around it (a separate mutable store, minimised
identifiers, per-engagement instances, or destruction of the whole instance and its archive)
rather than assuming a delete command exists. The maintainer does not decide this for you
and cannot perform it for you.

## 5. No warranty

**VIGIL IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OR CONDITION OF ANY KIND,
EXPRESS OR IMPLIED**, including without limitation any implied warranty of merchantability,
fitness for a particular purpose, accuracy, completeness, title, or non-infringement.

Without limiting that: the Licensor does not warrant that VIGIL will find any particular
vulnerability, that its findings are complete or correct, that it will not disrupt a system
it is pointed at, that it will operate uninterrupted or error-free, or that any output is
suitable for any regulatory, contractual, or certification purpose. A result of "no finding"
is not a representation that a system is secure. **The entire risk of using VIGIL is yours.**

This restates and does not narrow the "No Liability" and disclaimer provisions of the
PolyForm Noncommercial License 1.0.0 ([`LICENSE`](LICENSE)) and
[`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md). A commercial licence
provides a warranty **only** to the extent your signed agreement expressly says so.

## 6. Limitation of liability

**TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, AND UNDER NO LEGAL THEORY** — contract,
tort, negligence, strict liability, statute, or otherwise — **SHALL THE LICENSOR OR ANY
CONTRIBUTOR BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR
CONSEQUENTIAL DAMAGES, OR FOR ANY LOSS OF PROFITS, REVENUE, DATA, GOODWILL, OR BUSINESS,
SERVICE INTERRUPTION, SYSTEM OUTAGE OR DAMAGE, CORRUPTION OR DELETION OF DATA, REGULATORY
ACTION, FINES, OR LEGAL COSTS, ARISING OUT OF OR CONNECTED WITH VIGIL OR ITS USE OR MISUSE
BY ANY PERSON**, even if advised of the possibility.

**The Licensor's total aggregate liability** arising out of or connected with VIGIL is
limited to the greater of (a) the amount you paid the Licensor for VIGIL in the twelve
months before the event giving rise to the claim, or (b) **zero**, where you use VIGIL under
the noncommercial licence. Your sole and exclusive remedy for dissatisfaction is to stop
using VIGIL.

**Indemnity.** You will defend, indemnify, and hold harmless the Licensor and contributors
against claims, liabilities, losses, damages, fines, and costs (including reasonable legal
fees) arising from your use or misuse of VIGIL, your breach of these terms or of
[`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md), your violation of any law, or your infringement of
a third party's rights.

**Mandatory law.** Nothing in §§ 5-6 excludes or limits liability that cannot lawfully be
excluded or limited — including, in many jurisdictions, liability for death or personal
injury caused by negligence, or for fraud or fraudulent misrepresentation. Some
jurisdictions do not allow the exclusion of implied warranties or of certain damages, so
parts of these sections may not apply to you.

## 7. Engagement contracts control

VIGIL is a tool used inside engagements between **you and your client**. The Licensor is not
a party to those engagements.

Where you use VIGIL under an engagement contract, statement of work, authorization letter,
non-disclosure agreement, or data-processing agreement, **those instruments govern the
engagement** — scope, authorization, confidentiality, data handling, retention, liability
between you and your client, and disclosure. These terms do not modify them, do not create
rights for your client against the Licensor, and are not a substitute for them.

If a client-facing obligation you have accepted conflicts with how VIGIL behaves by default
— model egress, evidence retention, audit-record durability (§§ 3-4) — resolve it by
configuring VIGIL and by contract, before the engagement, not afterwards.

## 8. Governing law and jurisdiction — PLACEHOLDER

> **Unresolved. Do not treat this section as settled.**
>
> Governing law: `<GOVERNING LAW — TO BE DETERMINED WITH COUNSEL>`
> Forum / venue for disputes: `<FORUM — TO BE DETERMINED WITH COUNSEL>`
>
> The Licensor's primary jurisdiction is understood to be Cameroon — confirm this before
> publication. Users, contributors, and clients are elsewhere, and EU, UK, and US law can
> reach a party extraterritorially regardless of what a governing-law clause says. Mandatory consumer and data-protection rules in a user's own
> country generally cannot be displaced by this clause. This must be settled by qualified
> counsel before these terms are relied on as final; until then, treat this section as an
> open question rather than as an agreed choice of law.

Nothing in this section limits either party's right to seek interim relief where available,
or affects mandatory statutory rights.

## 9. Changes, termination, severability

**Changes.** These terms may be updated. The version in the repository at the time you
obtain or use a given copy is the version that applies to that use. Material changes are
recorded in the repository history.

**Termination.** Your right to use VIGIL ends when your licence ends. Under the PolyForm
Noncommercial License 1.0.0 "Violations" clause, a first written notice of violation gives
you **32 days** to come into full compliance and take practical steps to correct past
violations; otherwise all your licences end immediately ([`LICENSE`](LICENSE)). A commercial
licence terminates as its own signed terms provide. On termination, stop using VIGIL.
Sections 5, 6, 7, and 9 survive.

**Severability.** If a provision is held unenforceable, it is enforced to the greatest
extent permitted and the remainder stays in force. No failure to enforce a provision is a
waiver of it.

**Entire terms.** Together with the licence, [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md),
[`EXPORT.md`](EXPORT.md), [`SECURITY.md`](SECURITY.md), and
[`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md), these are the maintainer's
complete terms for use of VIGIL, subject to the precedence order in § 1.

---

*Contact:* `thuram@thuramnana.com` · <https://thuramnana.com>

*Maintainer note: §§ 5, 6, and 8 in particular are drafted to a plain-English standard, not
to a jurisdiction. Have counsel confirm the liability cap, the indemnity, and the
governing-law choice against Cameroonian law and against the law of the markets you sell
into before treating this document as final.*
