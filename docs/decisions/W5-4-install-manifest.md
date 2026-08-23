# W5-4 — Write an install manifest and verify it at startup

Issue: [#448](https://github.com/thuram-nana/vigil-sovereign/issues/448) ·
Milestone: W5 — UPGRADE & DATA MIGRATION (the biggest product risk).

## The defect

A VIGIL data directory (`~/.sigil`, `.vigil-live`, the spine dir) carried **no version marker** — there was
nothing to check on startup. An upgraded binary run against an older, or a **newer**, data directory had no
way to know: a store written by a build this one does not understand loaded silently as the old shape. The
per-artifact refuse-newer gates (W5-1/W5-3: head, floor, segment manifest, snapshot) protect each artifact
*as it is loaded*, but nothing gave the **whole data directory** a single top-level version marker checked
before any work begins.

## The claim (register in the claims registry, [W0-3] #398)

<!-- CLAIM:W5-4 -->
> Every VIGIL data directory (`~/.sigil` and `.vigil-live`) carries an install manifest recording the product version, the schema versions this build writes, and a persisted install id; a fresh install writes it with no operator action, and startup verifies it and REFUSES to run (fail closed) against a data directory this build does not understand — a manifest whose format or any tracked schema is newer than, or unknown to, this build, or whose self-integrity content hash does not match its bytes.

This claim is TRUE of the code as of W5-4:

- **The shared primitive** — `vigil_core/install_manifest.py`:
  - `InstallManifest` records `{manifest_schema, product_version, install_id, schema_versions}` plus a
    `content_hash` (unkeyed sha-256 over the canonical bytes of that content, via `vigil_core.canonical_json`
    — the same serialization the signed spine uses).
  - `ensure_operable(data_dir, …)` is the ONE startup call: **absent → WRITE** the manifest (fresh/legacy
    install, no operator action); **present → READ** it (fail-closed on a corrupt/tampered file whose
    `content_hash` does not match) then **VERIFY** it (`verify_manifest`, fail-closed refuse-newer). It
    raises `InstallManifestRefused` on a directory this build cannot understand.
  - `verify_manifest` refuses a manifest whose own **format** is newer than this build understands, and any
    tracked schema that is **newer than** — or a schema key **unknown to** — this build. An older-or-equal,
    all-known manifest returns quietly (an older schema is a W5-5 *migrate* concern, not a refusal here).
  - It lives in `vigil_core` because BOTH planes need it and the FATAL-2 boundary forbids the offense plane
    importing the sovereign `sigil.spine.schema_guard.refuse_newer`; it MIRRORS that gate's fail-closed
    int-coercion semantics inline (the same pattern the offense blackboard's own `_MAX_BB_SCHEMA` gate
    uses).
- **The sovereign wiring** — `apps/sigil/sigil/config.py::ensure_install_manifest` +
  `install_manifest_schema_versions` (which assembles the tracked schemas from the real per-artifact
  `_MAX_*_SCHEMA` constants, so a bump is reflected automatically), wired at
  `apps/sigil/sigil/cli.py::_assert_install_manifest_or_exit` inside the existing W5-5 startup chokepoint
  (`_assert_store_operable_or_exit`). A normal command against a not-understood `~/.sigil` exits 3; a
  recovery/diagnostic command (`upgrade`/`spine`/`doctor`/`restore`/`backup`/`vault`/`kernel`) WARNS and
  continues so the operator can upgrade the binary or inspect.
- **The offense wiring** — `integration/vigil_integration/install_gate.py::ensure_operable_or_exit`, wired
  at `integration/vigil_integration/cli.py::main` for every native (argparse) verb (a PASSTHROUGH verb runs
  the target subsystem's OWN gate). A normal command against a not-understood `.vigil-live` returns exit 2;
  the offense recovery/diagnostic verbs WARN and continue. `install_gate` imports only `vigil_core` +
  stdlib, so it never crosses FATAL-2.

## Why absent means *adopt*, not *refuse*

A data directory with **no** manifest is a fresh install or a legacy (pre-W5-4) one — not a tampered one —
so `ensure_operable` **writes** the manifest rather than refusing. Refusal is reserved for a directory that
carries a manifest this build cannot understand. This mirrors W5-5's "a fresh/empty store is operable" and
the spine's `LEGACY_SCHEMA_VERSION` adoption pattern. The fresh-install write needs no operator action:
the first command that runs establishes the marker.

## Determinism (no wall-clock, no rng in the verified content)

The verified content is exactly `{manifest_schema, product_version, install_id, schema_versions}`; the only
non-derived value is `install_id`, which is generated **once** at fresh install (or supplied via argument /
env `VIGIL_INSTALL_ID`) and then **persisted**, never regenerated. Given the same inputs the written bytes
are byte-identical (`test_generation_is_reproducible_byte_identical`), and the manifest carries no
timestamp/nonce (`test_verified_content_has_no_wallclock_or_rng`) — generation is reproducible.

## Honest scope (do NOT overclaim)

The `content_hash` is an **unkeyed** sha-256 over the manifest's own bytes. It detects corruption,
truncation, a partial write, and a naive hand-edit that forgets to recompute the hash — all fail closed. It
does **not** by itself prove authenticity against an adversary who edits the manifest AND recomputes the
hash; installation-wide authenticity is the SIGNED spine head's concern, not this marker's. This is a
version-skew + corruption gate, not a code-signing mechanism (same honest scope `integrity_verifier` states
for the spine's unkeyed checks).

## Tests / negative controls

`packages/core/vigil_core/tests/test_install_manifest.py` (the registered proving test, in the required
`vigil_core — shared integrity substrate` CI job) proves the fresh-write, the intact-verify, and the
negative controls — a newer tracked schema refused, an unknown schema key refused, a newer manifest format
refused, a corrupt/tampered (hash-mismatch) manifest refused, a non-integer version failing closed — each
asserted in the same run. Plane wiring is proved by `apps/sigil/tests/test_install_manifest_startup.py`
(sovereign gate exits 3 / warns-and-continues) and `integration/tests/test_install_manifest_offense.py`
(offense gate returns 2 / warns-and-continues). Without the change the proving file fails at import
(`vigil_core.install_manifest` does not exist), so the failure is observed on a tree without the fix.

## Dependencies

Builds on [W4-1] #441 (the single product `VERSION`) and [W5-1] #445 (the per-record `schema_version`).
Feeds [W5-5] #449 (the upgrade orchestrator's startup migration gate is the sibling check at the same
chokepoint).
