# W5-2 — The spine record-payload EVOLUTION CONTRACT (additive-only, enforced)

Issue: [#446](https://github.com/thuram-nana/vigil-sovereign/issues/446) ·
Milestone: W5 — UPGRADE & DATA MIGRATION. Builds on
[W5-1 #445](https://github.com/thuram-nana/vigil-sovereign/issues/445) (enforced `kind` + per-record
`schema_version`) and is a sibling of [W5-3 #447](https://github.com/thuram-nana/vigil-sovereign/issues/447)
(refuse-newer for the versioned *artifacts*).

## Why a payload can only ever GROW (the structural fact)

A record's `payload` is folded into `cert_digest` (`digest_payload(content)` over the stored content, and
`content` includes `payload`), `cert_digest` is chained into `entry_hash`, and `entry_hash` is what the
owner's signed head anchors. So **an already-appended record cannot be rewritten without breaking the hash
chain and invalidating the owner signature** — records are structurally *un-migratable*. There is no
`ALTER TABLE` for a signed append-only log. The only shapes of evolution that leave every already-signed
record still readable and still valid are:

1. **Add a NEW, OPTIONAL field** — a reader of an old record supplies the field's default (the read-time
   upcaster), so the old record reads correctly under the new model.
2. **Mint a new `kind`** — an old record keeps its old kind and old shape forever.

Everything else is *breaking*.

## The claim (register in the claims registry, [W0-3] #398)

> The shape of a spine record's `payload` may evolve across `schema_version`s only **additively**: a field
> that has ever been committed to the payload contract stays, with the same type and meaning; new fields
> are **optional with a default** so records written before the field existed still read (a read-time
> **upcaster** supplies the default); an incompatible shape requires a **new `kind`**, never a repurposed
> field. This is **enforced**: a committed baseline (`payload_shapes.json`) is diffed against the live
> per-kind models on every build, and any **breaking** drift fails a **required** CI job.

This claim is TRUE of the code as of W5-2:

- **The contract + models + upcaster + diff engine** live in
  `apps/sigil/sigil/spine/payload_contract.py`. Per-kind `pydantic` models (`extra="allow"`, every field
  optional-with-default) describe the structurally-consumed kinds: `commit`, `document`, `web_page`,
  `finding`, `detection`, `snapshot`. Free-form kinds (`message`/`event`/`refusal`/…) carry no structural
  contract and are intentionally unregistered.
- **The read-time upcaster** is `payload_contract.upcast_payload(kind, payload)`, exposed on the real read
  path as `SpineRecord.typed_payload()` (`apps/sigil/sigil/spine/models.py`). An old payload missing a
  later-added field validates and the field takes its default; an extra field a newer writer added
  round-trips (forward-compat); a malformed legacy value never crashes the read (the chain / `verify()`
  stays the sole fail-closed integrity gate).
- **The committed baseline** is `apps/sigil/sigil/spine/payload_shapes.json`, regenerated with
  `python -m sigil.spine.payload_contract`.
- **Enforcement** is `payload_contract.diff_shapes(committed, current)`, driven by
  `apps/sigil/tests/test_payload_evolution_contract.py`, which runs in the required
  `SIGIL governor gates (P7 …)` CI job (that job executes the whole `apps/sigil/tests/` directory).

## The normative rules

- **C1 — additive-only.** A newer `schema_version` may only ADD fields. A field ever committed to
  `payload_shapes.json` MUST remain, with the same canonical type.
- **C2 — no meaning change.** A committed field's type and meaning are frozen. To change either, pick a NEW
  field name (or a new `kind`) — never repurpose an existing field (a repurpose is invisible to a reader
  and silently corrupts every old record).
- **C3 — new fields are OPTIONAL with a default.** A record from an older `schema_version` lacks any
  later-added field; the reader upcasts it by supplying the default. A new *required* field would make
  every old record read as invalid — forbidden, and flagged by the diff.
- **C4 — deprecation, never deletion.** A field no longer written is marked deprecated (kept in the model +
  committed shapes so old records still read); it is not removed. A genuinely incompatible shape is a NEW
  `kind`.
- **C5 — extra fields pass through.** The models set `extra="allow"`: a reader on an OLD build tolerates a
  field a NEWER writer added (it round-trips as an extra) instead of dropping or rejecting it.

## Enforcement — how the schema diff decides breaking vs additive

`diff_shapes(committed, current)` returns the list of BREAKING changes (empty == compatible). It flags: a
committed field removed (C1/C4), a committed field's canonical type changed (C2), a committed optional field
made required (C3), a NEW required field (C3), or an entire committed kind removed. It does NOT flag a new
optional field or a brand-new kind (both additive). The test suite proves this is not a no-op: it runs the
real `diff_shapes` over the REAL committed baseline with a deliberately breaking mutation (a removed field,
a retyped field, a new-required field, a removed kind) and asserts each is flagged, and a deliberately
additive mutation (a new optional field) is NOT flagged — in the same run.

## Honest scope + residuals

- The contract is enforced as a **build-time (CI) gate** — the mechanism the issue specifies ("enforce
  additive-only in CI via a schema-diff test against the committed shapes"). It is deliberately NOT a
  runtime refusal on `SpineStore.append`: the append seam is the most safety-critical path in the spine and
  adding payload validation there risks a fail-closed regression on a legitimate payload for no gain over
  the CI gate. The runtime presence of the contract is the tolerant read-time upcaster.
- The committed baseline (`payload_shapes.json`) is the frozen source of truth the diff compares against.
  Its protection assumes the baseline is edited **append/deprecate-only** — deleting a committed field from
  the baseline *and* the model would make the diff empty. That deletion is itself the reviewable act (and
  is forbidden by C4); it is a review invariant, not something the diff can self-detect without git history.
- The contract governs the kinds whose payloads a reader consumes **by name**. Free-form kinds are
  unregistered by design; if one later grows a structural contract, register a model + regenerate the
  baseline and it is frozen from that point.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the payload-evolution contract, and
> `test_payload_evolution_contract.py::test_contract_decision_record_exists_and_states_the_rules` pins that
> this document stays true of the code.
