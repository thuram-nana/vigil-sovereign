# Per-engagement legal templates

Three instruments a client signs before a security engagement, plus this note.

| File | What it is | Signed by |
|---|---|---|
| [`authorization-letter.md`](authorization-letter.md) | Authorization to test — the scope, window, permitted and excluded techniques, contacts, and stop procedure | Client and Operator |
| [`nda.md`](nda.md) | Mutual confidentiality agreement covering engagement data, findings, evidence and reports | Client and Operator |
| [`dpa.md`](dpa.md) | Data-processing agreement for where the Operator processes personal data on the Client's behalf | Client (controller) and Operator (processor) |

## These are drafts. They require counsel.

Every one of them carries a header marking it **DRAFT — NOT LEGAL ADVICE — COUNSEL REVIEW REQUIRED**,
and that header is not decoration. These were written by an engineer to be *factually accurate about
what the software does*, not to be legally sufficient anywhere. Nobody has reviewed them for legal
effect.

Do not delete the header. Do not send one to a client without a lawyer having read it. In particular:

- **Applicable law and forum are unsettled.** The Operator's primary jurisdiction is understood to be
  Cameroon; a client may be anywhere, and EU/UK/US law can reach an operator extraterritorially. Each
  document has an explicit placeholder rather than a guessed clause.
- **No document asserts compliance with any statute, standard, or certification.** The DPA is
  *structured around* the elements a controller-to-processor agreement is commonly required to
  contain, because that is a useful shape; that is not a claim that anyone meets the requirement.
- **Liability, insurance, indemnities, fees, and IP ownership are not covered here at all.** Those
  belong in a services agreement, which this directory does not contain.

## Order of operations

1. **NDA signed.** Before the Client shares architecture, source, credentials, or anything else.
2. **Authorization letter signed** — by both parties, with every placeholder filled and the asset
   list agreed. **No traffic reaches any Client system before this signature exists.**
3. **DPA signed** where personal data is in play, which in a web-application engagement is nearly
   always. Two decisions in it must be made *before* work starts, not after:
   - the **model sovereignty tier** (`dpa.md` § 8 and `authorization-letter.md` § 10.2), and
   - what happens on an **erasure request** (`dpa.md` § 9).

   Ticking the tier on the paper does not put it in force. The engine reads
   `CRUCIBLE_SOVEREIGNTY_TIER` from the process environment and from nowhere else
   (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`); a value stored only in
   `~/.sigil/sigil.env` or on the UI Settings screen reaches an offense process only when `vigil up`
   launched it, and any other process falls back to `PERMISSIVE` **silently — fail-open**. Export it
   in the environment of every process that runs the engagement, then confirm it on the read-only
   tier pill on the UI's Governance & Gate Audit screen (`#/governance`). See `/PRIVACY.md` § 5.1a.
4. **Charter written** at `targets/<slug>/charter.md`, matching the authorization letter field for
   field (see the map below and `authorization-letter.md` § 13).
5. **Engagement runs.** The engine applies its own gates independently of the paper: it refuses an
   unsigned charter (`engine/crucible/framework/v2/common/ethics.py:104-140`) and refuses a host that
   does not match the charter's scope table (`:283-303`).
6. **Amendment** if anything changes — signed by both parties *and* mirrored into the charter, same
   date, before the new scope is touched.
7. **Close-out** — deliverables, then the retention and deletion steps in `nda.md` § 8 and
   `dpa.md` § 11, which must state the same period in both.

## How these map to the technical charter

The signed letter and the machine-read charter (`targets/_template/charter.md`) describe the same
engagement. `authorization-letter.md` § 13 is the field-by-field map; each section of the letter also
names the charter heading it mirrors, so a reviewer can check them side by side.

Two practical points about that mapping, both verified in source:

- **The scope gate reads one specific heading.** `parse_scope` looks for a section headed
  `## 2. In-scope systems` (`engine/crucible/framework/v2/common/ethics.py:147-151`) and reads the
  host column of the table beneath it. A charter that keeps the template's
  `## Target hosts (in scope)` title parses to an empty scope, and the gate then refuses every host
  (`:293-297`) — fail-closed, but it will look like a broken tool rather than a scope problem. The
  intake drafter emits the numbered heading (`engine/crucible/framework/v2/intake/drafters.py:81`).
- **Most of the letter is not machine-enforced.** The window, the rate limits, the excluded
  techniques, and the stop procedure are procedural commitments. The gates that do exist —
  signed-charter check, scope match, the categorical protected-domain block
  (`packages/core/vigil_core/vigil_core/hard_guardrail.py:1-31`), the tool-tier gate
  (`integration/vigil_integration/warden_gate.py:110-122`), and the m-of-n quorum on destructive
  actions (`integration/vigil_integration/destruction_gate.py:1-52`) — are narrower than the paper.
  Do not describe them to a client as more than they are.

## Where the facts come from

Every technical statement in these templates is traceable to a `path:line` citation in the source on
this branch, and is collected with fuller context in
[`../DATA-GROUND-TRUTH.md`](../DATA-GROUND-TRUTH.md). If a behaviour changes, both files change.

Two facts appear in all three instruments because a client cannot evaluate the others without them:

1. **Model egress is permissive by default.** With no tier selected, the direct Anthropic API is
   permitted and is first in auto-selection
   (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195, 137-141`;
   `bootstrap.sh:321-345`). Prompt content can include target data and findings. Any document
   implying that everything stays local by default would be false.
2. **The audit ledger is append-only, and individual records cannot be erased on this branch.** The
   prune machinery is dry-run only (`apps/sigil/sigil/spine/prune.py:1-4`;
   `apps/sigil/sigil/cli.py:844-861`); the only bulk deletion destroys the whole ledger
   (`apps/sigil/sigil/spine/store.py:454-478`). Tamper-evidence and erasure are in genuine tension,
   and the client decides how to resolve it before the engagement, not after a request arrives.

## House rule

If a sentence in one of these documents cannot be traced to source or is not a placeholder for
counsel, it should not be there. A document that overclaims what the software protects is worse than
no document: it is a misrepresentation the client relies on.
