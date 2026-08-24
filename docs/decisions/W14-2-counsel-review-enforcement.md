# W14-2 — no client legal instrument ships until counsel has reviewed it AND every placeholder is resolved

Issue: [#504](https://github.com/thuram-nana/vigil-sovereign/issues/504) ·
Milestone: W14 — LEGAL & COMPLIANCE INSTRUMENTS.

## The claim (registered in the claims registry — [W0-3] #398, id `W14-2`)

<!-- CLAIM:W14-2 -->
> No client legal instrument — the authorization letter, the NDA, or the DPA — ships until BOTH a recorded counsel-review flag is true AND a machine placeholder scan of its text is empty; the two checks are conjunctive and fail closed, so an unreviewed instrument, or one still carrying an unresolved placeholder token (`[GOVERNING LAW]`, `<PLACEHOLDER>`, `TBD`, angle/bracket template fill-ins, `YYYY-MM-DD` or signature blanks), is refused with a typed `InstrumentNotShippable` (an `EthicsViolation`) at the `ship_instruments` assemble chokepoint. The review-status manifest records each instrument's counsel-review decision, defaults every entry to false/PENDING, and fails closed on a missing/malformed manifest, a non-`true` review flag, or a missing instrument file. The counsel review and the resolution of the governing-law placeholders are HUMAN actions the framework does not perform; counsel review is recorded PENDING for all three instruments and the gate refuses to ship every one of them (the operator has resolved the governing law to the Republic of Cameroon for the NDA and DPA — a move to Delaware, USA is planned — but counsel review is still pending and per-engagement fill-ins remain).

## Why this exists

An engagement puts three client-facing LEGAL instruments in front of a customer:
the **authorization letter** (the contract leg, already shipped by [W13-3] #496),
a mutual **NDA**, and a **DPA** for any personal data an in-scope system exposes.
Two facts about these instruments must be true before they may be assembled into
a deliverable, and BOTH are human actions the framework cannot perform:

1. **counsel has reviewed the instrument** — a qualified lawyer signing off that
   the terms are sound for the jurisdiction; and
2. **every placeholder is resolved** — most visibly the governing-law clause, but
   also the party names, dates, venue, and every other fill-in.

Before this slice nothing stopped an unreviewed or placeholder-bearing instrument
from being shipped. This slice adds the *enforcement* that makes that impossible,
while being honest that the review and the placeholder resolution themselves
remain to be done by a human.

## This is not a legal judgement — it is a fail-closed refusal

`authority.counsel_review` makes no legal decision and grants no approval, in the
same spirit as `authority.crosscheck` ([W13-3]). It only refuses to ship until a
human record says the human work is done:

- **Placeholder scanner** (`find_placeholders`) — flags the unresolved fill-in
  families a shipped instrument must never contain (`[GOVERNING LAW]`,
  `<PLACEHOLDER>`, `TBD`/`TODO`/`FIXME`, bracket/angle template fill-ins,
  `YYYY-MM-DD`, and signature blanks). It is deliberately conservative: markdown
  links, bracketed acronyms (`[GDPR]`), autolinked URLs, emails, and HTML
  comments are NOT flagged, so a genuinely resolved instrument can pass.
  **Lexical bound (honest limitation).** A single-word ALL-CAPS bracket token is
  shape-ambiguous — `[VENUE]` is a placeholder, `[GDPR]`/`[SOC2]` are acronyms —
  so for single-word bracket tokens the scanner matches a CURATED allowlist of
  known legal fill-in words (`_BRACKET_FILL_WORDS`: `[VENUE]`, `[PARTY]`,
  `[ISSUER]`, `[JURISDICTION]`, …) rather than every single-word bracket. This
  catches the fill-in styles the shipped templates use (both carry `[VENUE]`)
  while leaving true acronyms alone; the trade-off is that a single-word bracket
  placeholder OUTSIDE the allowlist is not caught by that family. A single-word
  fill-in must be added to the allowlist (or written multi-word / angle-form) to
  be scanned. The conjunctive review flag is the independent second gate.
- **Review-status manifest** (`counsel-review-status.json`, read by
  `load_review_manifest`) — records per instrument whether counsel has reviewed
  it. Every entry DEFAULTS to `false` / PENDING; a non-`true` value (missing,
  null, the string `"true"`) coerces to un-reviewed (fail closed), and a missing
  or malformed manifest raises `ManifestError` rather than shipping.
- **Ship gate** (`assert_shippable` / `ship_instruments`) — the assemble
  chokepoint. An instrument ships **iff** its recorded review flag is true AND its
  placeholder scan is empty. The two conditions are conjunctive on purpose: a
  mistakenly-flipped review flag still cannot ship placeholder text, and clean
  text still cannot ship without a recorded review. First-failure-wins,
  fail-closed; a missing instrument file is itself a refusal.

## The four-part bar

- **Behaviour** — the module, the manifest, and the two DRAFT instrument
  templates (`nda.md`, `dpa.md`, each clearly marked PENDING and carrying a
  `[GOVERNING LAW]` placeholder) are added; the authorization letter is referenced
  in place.
- **Fail-without-fix** — `test_counsel_review.py` imports `..counsel_review` at
  module scope; on a tree without this slice the module is absent and the file
  ERRORs at collection (observed by moving the module aside).
- **Negative controls (same run)** — reintroducing a `[GOVERNING LAW]` placeholder
  into an otherwise clean, reviewed instrument turns the gate red
  (`test_reintroducing_a_placeholder_turns_the_gate_red`); an unreviewed clean
  instrument is refused (`test_unreviewed_instrument_is_refused`); a
  missing/malformed manifest, a non-`true` flag, and a missing instrument file all
  fail closed. The positive control
  (`test_a_reviewed_placeholder_free_instrument_ships`) proves the gate is not a
  constant refusal.
- **Required CI + registered claim** — all tests live under
  `engine/crucible/framework/v2/authority/tests/`, run wholesale by the REQUIRED
  check `CRUCIBLE core on vigil_core` (`pytest framework/v2` from `engine/crucible`).
  The claim is registered here with its enforcing symbol and proving tests.

## Where it is TRUE of the code

- **Gate + scanner + manifest loader** —
  `engine/crucible/framework/v2/authority/counsel_review.py`
  (`find_placeholders`, `load_review_manifest`, `check_instrument`,
  `assert_shippable`, `ship_instruments`, `review_report`).
- **Typed refusal** — `InstrumentNotShippable` in
  `engine/crucible/framework/v2/common/errors.py`.
- **Instruments + manifest** —
  `engine/crucible/framework/templates/authorization-letter.md`,
  `engine/crucible/framework/templates/legal/nda.md`,
  `engine/crucible/framework/templates/legal/dpa.md`,
  `engine/crucible/framework/templates/legal/counsel-review-status.json`.
- **Proof** — `engine/crucible/framework/v2/authority/tests/test_counsel_review.py`.

## HONEST residual — the human actions this does NOT do

This slice enforces; it does **not** perform the legal work. Explicitly:

1. **Counsel review** of all three instruments is OUTSTANDING. The manifest records
   every instrument as `reviewed_by_counsel: false` / PENDING. A human (qualified
   legal counsel) must review each instrument and, only then, set its flag true.
   **Do not flip a flag without a real review** — the placeholder scan is an
   independent second check, but the review flag is a record of a human act.
2. **Resolving the governing-law (and every other) placeholder** is OUTSTANDING.
   The `[GOVERNING LAW]`, `[VENUE]`, `[DATA PROTECTION REGIME]`, party, and date
   fill-ins in the NDA and DPA (and the authorization-letter template's
   per-engagement placeholders) must be resolved by a human before an instrument
   can pass the scan.
3. **Wiring the chokepoint into every deliverable assembler** is follow-on (the
   `default: off` posture, exactly as [W13-3]'s executor enforcement is opt-in at
   its stage). `ship_instruments` is THE gate any assembler that emits a legal
   instrument must route through; threading it through each production deliverable
   path is named follow-on, not claimed done.
