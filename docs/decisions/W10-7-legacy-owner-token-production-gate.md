# W10-7 — The legacy shared owner token is REFUSED under the production posture

Issue: [#480](https://github.com/thuram-nana/vigil-sovereign/issues/480) ·
Milestone: W10 — SECURITY CONTROLS THAT DO NOT FIRE (fail-open).

## The claim (register in the claims registry, [W0-3] #398)

> The sigil cockpit's legacy embedded shared owner token — the printed session token that resolves to
> `OWNER_PRINCIPAL` so the operator physically at the host is never locked out — is a **documented
> fail-open dev convenience**. Under `VIGIL_POSTURE=production` (or `prod`, case-insensitive) it is
> **refused**: it no longer resolves to owner, so per-user proof-of-possession auth is required. The
> refusal is enforced **twice** — the refuse-to-start production gate (`vigil up` / `vigil engage`)
> will not start while the token is left enabled, and the running sigil server **also** refuses the
> token at request time under this posture (defence in depth). Outside production the token keeps
> working (nothing already deployed breaks) and can be opted out of explicitly with
> `SIGIL_LEGACY_OWNER_TOKEN=0`. This is a **named residual**, not a fixed lockout.

This claim is TRUE of the code as of W10-7:

- **The one parse, shared by both trust planes** — `vigil_core.posture`
  (`packages/core/vigil_core/vigil_core/posture.py`) is the single source of truth for (a) whether the
  production posture is armed (`production_posture` / `is_production_posture`) and (b) whether the
  legacy token may resolve to owner right now (`legacy_owner_token_grants_owner` — true ONLY when the
  posture is not production AND the toggle is not explicitly disabled). It is pure stdlib and imports
  nothing from `framework` / `strix` / `sigil` / `vigil_integration`, so BOTH planes import it without
  crossing the two-env boundary (FATAL-2).
- **Runtime auth (sovereign plane)** — `sigil.ui.server`'s `_principal_for_token` and `_token_ok`
  (`apps/sigil/sigil/ui/server.py`) gate the shared-token → `OWNER_PRINCIPAL` fail-open path on
  `legacy_owner_token_grants_owner()`. Under production the shared token falls through to the
  owner-signed account fold like any other token and is refused; a per-user bearer still authenticates.
- **Refuse-to-start gate (offense/integration plane)** — the W9-4b PRODUCTION gate in
  `vigil_integration.doctor` adds a sixth precondition, `legacy-owner-token` = `DISABLED`, read from
  `SIGIL_LEGACY_OWNER_TOKEN` via `vigil_core.posture` (no import of sigil). Fail-closed: the fail-open
  default (env unset ⇒ `ENABLED`) refuses the start with a line naming the control and how to satisfy
  it (`SIGIL_LEGACY_OWNER_TOKEN=0`).

Pinned by three suites, each in a required CI job that runs its whole directory (so a new file is
auto-included and can only fail loudly, never silently skip):

- `packages/core/vigil_core/tests/test_posture.py` — the shared parse truth table
  (`vigil_core — shared integrity substrate` job).
- `apps/sigil/tests/test_production_posture_legacy_token.py` — the runtime auth refusal end-to-end over
  HTTP (`SIGIL governor gates (P7 …)` job).
- `integration/tests/test_doctor_production_gate.py` — the sixth precondition in the refuse-to-start
  gate (`integration two-env boundary (P5)` job).

Each suite includes a test that **FAILS on a tree without the fix** — under production the pre-W10-7
server resolves the shared token to owner, and the pre-W10-7 gate has only five controls so an
all-else-satisfied production world passes — and a **negative control** proving the gate is not a
no-op: outside production the token still authenticates and the gate is inert, a per-user bearer still
authenticates under production, and a wrong/unknown token is refused in every posture.

## Why keep the token at all (the residual, not a removal)

Removing the fail-open entirely would risk locking the operator out of a fresh host before any per-user
account exists. So it is **kept as a development convenience and gated by posture**: safe-by-default
outside production, refused inside it. Per-user accounts are provisioned offline, owner-key signed, with
no HTTP token needed (`sigil accounts create <user> <role>`), and log in by proof-of-possession
(W17-2 #536). This W10-7 gate builds on the merged production gate (W9-4 #437) and that PoP login.

## The offense↔sovereign mirror (acceptance criterion)

The rule "the legacy shared owner token is refused under the production posture" is enforced on BOTH
sides of the two-env boundary from the **same** `vigil_core.posture` parse: the offense/integration
refuse-to-start gate will not start a deployment that leaves the token enabled, and the sovereign sigil
server refuses the token at request time even if a server is started outside `vigil up`. Because both
key on one shared predicate, the two can never drift on what "production" means or on when the token is
honoured — the belt-and-suspenders halves cannot disagree.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the residual and its two enforcement points.
