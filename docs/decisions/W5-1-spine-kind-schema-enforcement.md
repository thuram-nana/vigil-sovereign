# W5-1 — Spine records carry a `schema_version` and `kind` is ENFORCED on append

Issue: [#445](https://github.com/thuram-nana/vigil-sovereign/issues/445) ·
Milestone: W5 — UPGRADE & DATA MIGRATION.

## The claim (register in the claims registry, [W0-3] #398)

> Every record appended to the sovereign SIGIL spine carries a `schema_version` and a `kind` drawn
> from an **enforced** vocabulary. An append with an out-of-vocabulary `kind` or an unknown
> `schema_version` **fails closed** (nothing is written). Records that predate the field read back
> with a default version and the chain still verifies end to end — the change is additive.

This claim is TRUE of the code as of W5-1:

- **Write path** — `SpineStore.append` (`apps/sigil/sigil/spine/store.py`) rejects `kind not in KINDS`
  and `schema_version not in KNOWN_SCHEMA_VERSIONS` with a `SpineError`, BEFORE any lock is taken or
  byte written. Enforced at the single append seam, an unfiltered caller (e.g. an LLM-emitted
  `cand.kind`) cannot smuggle an arbitrary kind onto the immutable chain.
- **Read / integrity path** — `SpineStore.verify()` and the per-atom `verify_record`
  (`apps/sigil/sigil/spine/verify.py`) re-reject an out-of-vocabulary `kind`.
- **The field** — `SCHEMA_VERSION`, `KNOWN_SCHEMA_VERSIONS`, `LEGACY_SCHEMA_VERSION` and the enforced
  `KINDS` set live in `apps/sigil/sigil/spine/models.py`; `SpineRecord.schema_version` is stamped on
  every new record and defaults to `LEGACY_SCHEMA_VERSION` for a pre-W5-1 line.

Pinned by `apps/sigil/tests/test_spine_kind_schema_enforcement.py` (runs in the required
`SIGIL governor gates (P7 …)` CI job, which executes the whole `apps/sigil/tests/` directory). The
suite includes a test that FAILS on a tree without the fix (the bogus append would succeed) and a
negative control that a valid kind still appends and the chain still verifies.

## Migration safety — why there is no chain break

`schema_version` is **informational**: it is carried on the record line but is NOT part of the content
digested into `cert_digest` (exactly like `seq`/`ts` and the chain fields). So stamping it on new
records and defaulting it on old ones leaves every existing record's `cert_digest` — and the whole
hash chain — byte-for-byte intact. The security-critical field, `kind`, is already inside the digested
content, so it stays tamper-bound; the read-path vocabulary check is defence-in-depth on top of that.

## The offense↔sovereign mirror (acceptance criterion) — and the one asymmetry

The offense blackboard (`engine/crucible/framework/v2/agents/blackboard.py`) enforces its kind set
**twice**: a Python guard (`if kind not in ALL_EVENT_KINDS: raise`) on the write path, and a storage
constraint `CHECK(kind IN (...))` in the SQLite `events` table that is re-checked on every row it
returns.

The sovereign spine is an append-only **JSONL** file, not a SQL table, so it has **no SQL `CHECK`
layer of its own** — that is the one structural asymmetry. It is mirrored, not dropped: the offense
Python guard maps to `SpineStore.append`'s `kind not in KINDS` refusal, and the offense SQL `CHECK`
(a check applied on read) maps to the `kind` vocabulary check inside `SpineStore.verify()` /
`verify_record` on the sovereign read/integrity path. Both planes therefore reject an out-of-vocabulary
kind on BOTH the write and the read side.

While enforcing this, the `KINDS` set was found to be **out of sync** with the code: `"detection"`
(written by the inbound finding receiver, `apps/sigil/sigil/inbound/finding_receiver.py`) was a real
append kind that had never been added to `KINDS` — precisely because the set was never enforced. It is
now in the set; a regression test pins it.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the claim and the documented asymmetry.
