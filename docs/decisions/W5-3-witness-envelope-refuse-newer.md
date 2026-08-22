# W5-3 — The witnessed-checkpoint envelope reader REFUSES a newer schema (fail-closed)

Issue: milestone W5 — UPGRADE & DATA MIGRATION, item W5-3 ·
Registered in the claims registry ([W0-3] #398, id `W5-3`).

## The claim (registered in the claims registry — [W0-3] #398, id `W5-3`)

<!-- CLAIM:W5-3 -->
> **Registered claim (W0-3 #398):** The witnessed-checkpoint envelope reader refuses an envelope whose schema is newer than this build, and an uncoercible schema value fails closed — a newer-build envelope is never silently parsed as the current version.

## Why this is TRUE of the code

`load_witnessed_envelope` (`integration/vigil_integration/witnessed_anchor.py`) applies the SAME schema
ceiling as `apps/sigil/sigil/spine/witness.py`'s `dump_witnessed`. Before it interprets any checkpoint
delta it coerces the envelope's `schema` field to an int and, on failure, treats it as *newer than this
build* (`_ENVELOPE_SCHEMA + 1`) rather than defaulting it down. It then `_require`s
`schema <= _ENVELOPE_SCHEMA`, raising an explicit *upgrade* error otherwise.

This closes a real fail-open: without the ceiling, a `schema>1` envelope written by a newer build would be
parsed as v1, and any checkpoint delta it carried would be silently mislabelled a signature-mismatch — a
security-relevant misread on the verify/reprove path. The refusal is the honest alternative: stop and say
"upgrade", never guess.

The absent-`schema` case is the additive-migration path: a pre-W5-3 envelope with no `schema` field
defaults to the current version and clears the gate (failing only on its body, as any current envelope
would), so the change does not break existing envelopes.

## How it is verified

Pinned by `integration/tests/test_witness_envelope_refuse_newer.py`, which runs in the required
**integration two-env boundary (P5)** CI job (the sovereign leg — the module imports nothing from the
offense tree). The suite includes:

- `test_a_newer_envelope_schema_is_refused_with_an_upgrade_message` — the claim-pinned positive;
- `test_an_uncoercible_schema_fails_closed` — the fail-closed negative control (a non-numeric schema is
  treated as newer and refused, not coerced down);
- `test_current_schema_passes_the_gate_and_fails_only_on_the_body` and
  `test_absent_schema_defaults_to_current_and_clears_the_gate` — the additive-migration controls.
