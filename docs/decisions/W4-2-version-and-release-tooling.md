# W4-2 — Version reporting and release tooling

Issue: [#442](https://github.com/thuram-nana/vigil-sovereign/issues/442) ·
Milestone: W4 — RELEASE ENGINEERING · Documented by [W4-4] #444.

## The defect this closes

VIGIL had **zero git tags and no `--version` on any CLI**. An operator could not ask a running install
what it was — which version, which commit, and whether it was built from a clean tree. W4-1 (#441) had
already established one product version at the repo-root `VERSION` file; what was missing was a way to
*report* it, a `CHANGELOG.md`, and — for the already-existing signing workflow — a publish step that
carries the changelog out as the release notes.

## The decision

1. **One shared version resolver.** `vigil_core.build_info` is the single, sovereign-safe (vigil_core
   only — no `framework`/`sigil`) resolver every CLI uses. `vigil`, `vigil-gateway`, `sigil` and
   `python3 -m framework.v2` each intercept `--version`/`-V` at the very top of `main`, before any gate,
   and print the same line: product version, build id, git sha.

2. **The build id is HONEST.** It is a PEP 440 local-version string derived deterministically from git
   (no wallclock, no RNG): `<version>+g<short>` for a clean checkout, `<version>+g<short>.dirty` for a
   tree with uncommitted changes, and `<version>+unknown` off a git checkout entirely. If cleanliness
   cannot be determined it is reported `.dirty`, never clean — the fail-closed choice, so `--version`
   never claims a clean sha it cannot prove.

3. **A changelog that cannot rot.** `CHANGELOG.md` follows Keep a Changelog; `tools/release/changelog.py`
   renders a section from conventional-commit history and extracts a version's notes for the release
   workflow. `docs/tests/test_changelog_staleness.py` (required CI) fails the build when the `VERSION`
   version — or any release tag `vX.Y.Z` — has no matching section.

4. **The tag-triggered release now publishes.** The W3-4/W3-5 workflow already signed + attested the
   wheel/sdist and generated the signed CycloneDX SBOMs on a tag push. W4-2 adds the operator-facing
   publish leg to that same `build-sign-attest` job: it derives the release notes from the committed
   `CHANGELOG.md` via `tools/release/changelog.py notes` and publishes a GitHub Release for the tag
   carrying the signed wheel/sdist, their cosign bundles and PEP 740 attestations, with that changelog
   section as the notes — closing the "no publish step" gap #442 names. The signing/attestation legs are
   unchanged; its shape is pinned offline by `integration/tests/test_release_github_release.py`.

## The claim (registered in the claims registry — [W0-3] #398, id `W4-2`)

<!-- CLAIM:W4-2 -->
> **Registered claim (W0-3 #398):** `--version` on every VIGIL CLI reports the product version, an honest build id and the git sha, and a build from a dirty tree reports a dirty build id rather than a clean sha.

Why it is TRUE of the code: the build id is composed by `vigil_core.build_info.compose_build_id`, a pure
function proved by `packages/core/vigil_core/tests/test_build_info.py` in the required "vigil_core —
shared integrity substrate" job. Its negative controls feed a dirty and an unknown state directly and
assert the id is `.dirty` / `+unknown` and never a manufactured clean `+g<sha>`, and an end-to-end test
makes a real temporary git repository dirty and asserts `resolve` reports it. The four CLIs' `--version`
lines are each pinned by a `test_cli_version.py` in that CLI's own required job.

## What this does not claim

Package versions are asserted CONSISTENT with the product version (W4-1's guard), not derived from it at
build time. `--version` reports a clean sha only for an editable/source install (the deployed model, per
`envs/build_envs.sh`); a non-editable wheel with no reachable git reports `+unknown` honestly.
