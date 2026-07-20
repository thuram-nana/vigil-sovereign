# vigil-integration — the offense→sovereign seam (P5 / FATAL-2)

The offense-free guarantee dies if the offense engine and the personal core share one
interpreter. VIGIL keeps them in **two isolated environments** joined only by an **inert,
signed, data-only** channel. This package is that seam.

## What's here
- **`inert_finding.py`** — the sovereign-side receiver. Depends on `vigil_core` alone (never
  `framework.*`/`strix.*`), so it is importable in the offense-free env. A confirmed finding
  arrives as a JSON envelope; `validate_inert_finding` parses it with `json.loads` **only** (no
  pickle/eval — the inertness guarantee), size-bounds it, strictly shapes it, and returns a
  `ValidatedFinding` whose `verify_signature(trust_root)` checks the CRUCIBLE m-of-n governance
  signature with `vigil_core.verify_threshold` over the exact `evidence_signing_bytes` CRUCIBLE
  signed — **anchor 1** of the two-anchor trust model. (The owner-signed spine head is anchor 2,
  added when the sovereign side appends the record — P10.)
- **`offense_worker.py`** — the **keyless** offense trust domain. Construction refuses an owner
  key; the worker holds an engagement-scoped store handle and a ceiling but cannot mint an
  authentic governance event (SIGIL's `governor.authn.verify_signed` is fail-closed on any event
  a keyless actor produces). It serialises a confirmed `SignedEvidence` into the inert envelope —
  the only thing that crosses the boundary.

## The boundary is structural, not disciplinary
`tests/test_two_env_boundary.py` runs a sovereign-only interpreter (vigil_core + apps/sigil +
integration on the path, **not** engine/crucible, **not** vendor/strix) and proves `framework`
and `strix` are unimportable and `assert_no_offense()` passes — with a negative control that the
guard actually fires when an offense module *is* loaded. The two environments are built by
`envs/build_envs.sh` from `envs/sovereign.txt` / `envs/offense.txt` (see `envs/README.md`).

Runtime deps: `vigil_core` only. Tests: `cd integration && PYTHONPATH=. python -m pytest tests -q`.
