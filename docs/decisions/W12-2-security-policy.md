# W12-2 — A root `SECURITY.md` with a security contact and a safe-harbour statement

Issue: [#491](https://github.com/thuram-nana/vigil-sovereign/issues/491) ·
Milestone: W12 — PROCESS HYGIENE. Lands with the legal branch ([W14-1] #503).

## The defect this closes

A security product with no coordinated-disclosure path is a credibility hole: a researcher who
finds a flaw in VIGIL itself has nowhere private to send it, and no stated promise that a
good-faith report will not be met with a lawsuit. There was a component-level policy under
`engine/crucible/SECURITY.md`, but **no root `SECURITY.md`** — the file GitHub surfaces on the
repository's Security tab and the one a sovereign reviewer looks for first.

## The decision

Land a root [`SECURITY.md`](../../SECURITY.md) that publishes, in one front-door document:

- a **security contact** — the maintainer's monitored mailbox (`thuram@thuramnana.com`, the
  same one used for licensing) plus GitHub's private vulnerability-reporting channel;
- a **supported-versions policy** grounded in the one-product-version fact ([W4-1](W4-1-one-product-version.md));
- a **coordinated-disclosure process** with a 90-day default window; and
- an explicit **safe-harbour statement** for good-faith research on VIGIL itself.

The contact is the repository's existing convention, not an invented address: `thuram@thuramnana.com`
already appears in [`LICENSE-COMMERCIAL.md`](../../LICENSE-COMMERCIAL.md), `LICENSING.md`, and the
README. No PGP key is published yet — the doc says so plainly rather than promising an encrypted
channel that does not exist.

The disclosure path is referenced from the README's *Security & trust model* section so a reader
lands on it from the front page.

## The claim (registered in the claims registry — [W0-3] #398, id `W12-2`)

<!-- CLAIM:W12-2 -->
> **Registered claim (W0-3 #398):** A root SECURITY.md publishes a working security contact, a supported-versions policy, a coordinated-disclosure process, and an explicit safe-harbour statement for good-faith research, and a required-CI guard fails the build if the file is missing or any of those four elements is absent.

## Why this is TRUE of the code

- The file [`SECURITY.md`](../../SECURITY.md) exists at the repository root and contains all four
  elements above — a contact (`thuram@thuramnana.com` + the GitHub private-advisory channel), a
  *Supported versions* section, a *Reporting a vulnerability — coordinated disclosure* section, and
  a *Safe harbour* section.
- [`docs/tests/test_security_policy_present.py`](../tests/test_security_policy_present.py) is the
  guard. Its enforcing helper `security_policy_defects(text)` returns the list of missing required
  elements; the positive tests assert the real root `SECURITY.md` has **none** missing and carries a
  contact, and that the README references the disclosure path. It reads files only (imports nothing,
  sends no packet), so it runs in the required **the briefing explains every agent and capability**
  CI job, which runs `pytest docs/tests -q`.
- **Fails without the change.** On a tree without the fix the root `SECURITY.md` does not exist, so
  the guard fails at `test_security_md_exists_at_root` — the failure is observed, not assumed.
- **Negative control.** In the same run, `security_policy_defects` is fed a document with a section
  removed (no contact, no safe-harbour) and must report it as defective — proving the gate is not a
  no-op.

## Residuals

- Whether `thuram@thuramnana.com` should be fronted by a dedicated `security@` alias, and whether a
  PGP key should be published and GitHub private vulnerability reporting enabled on the repository,
  are maintainer decisions the doc leaves open honestly rather than overclaiming.
