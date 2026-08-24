# Changelog

All notable changes to VIGIL are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

There is **one product version**, and it lives in the repo-root `VERSION` file (W4-1, #441). Every
released section below names that same number, and `docs/tests/test_changelog_staleness.py` (a required
CI job) fails the build if the `VERSION` version — or any git release tag `vX.Y.Z` — has no matching
`## [X.Y.Z]` section here, so the changelog cannot silently rot relative to the tag range.

Sections are grouped by conventional-commit type (feat → Added, fix → Fixed, …).
`tools/release/changelog.py render` produces a section from the git history of a range; the release
workflow feeds a released section back out as the GitHub release notes via
`tools/release/changelog.py notes`. See `docs/runbooks/RELEASE-UPGRADE-ROLLBACK.md`.

## [Unreleased]

### Added
- A **deploy-verify pipeline with rollback proof** (`sigil.spine.deploy_verify`, W11-8 #489): a deploy is
  modelled as an upgrade of a live owner-signed data plane (reusing the #451 upgrade/rollback machinery), a
  post-deploy smoke is run with its **exit code honoured**, and a failing smoke triggers an **automatic
  rollback** to the prior version that is re-verified intact (owner signature + full record set). A
  deliberately-broken deployment is caught and rolled back — proven by `apps/sigil/tests/test_deploy_verify.py`
  in the required `SIGIL governor gates (P7 …)` job — and the pipeline is documented in the release runbook.
- `make smoke` is now **CI-invoked with its exit code honoured** (it had no workflow caller before): the
  scheduled `.github/workflows/deploy-verify.yml` builds the venvs and runs the real `make smoke`, then
  drives the pipeline (W11-8 #489). The heavy full-venv variant is honestly labelled scheduled-only, not a
  required PR check.

## [0.1.0] - 2026-08-23

The first tracked release of the VIGIL sovereign engine. `0.1.0` establishes the release-engineering
baseline; the full development history that predates it lives in git. From this version forward, every
change worth an operator's attention is recorded in the section above before it is tagged.

### Added
- `--version` on `vigil`, `vigil-gateway`, `sigil` and `python3 -m framework.v2`. Each prints the same
  three facts through the shared `vigil_core.build_info` resolver: the product version, an honest build
  id, and the git sha. A dirty working tree reports a `.dirty` build id and a non-git install reports
  `+unknown` — `--version` never claims a clean sha it cannot prove (W4-2, #442).
- `CHANGELOG.md` plus `tools/release/changelog.py`, a Keep-a-Changelog generator that renders a section
  from conventional-commit history and extracts a version's notes for the release workflow (W4-2, #442).
- The release, upgrade and rollback runbook at `docs/runbooks/RELEASE-UPGRADE-ROLLBACK.md`, with exact
  commands, each guarded against drift by `docs/tests/test_release_runbook.py` (W4-4, #444).

### Changed
- The tag-triggered release workflow now also publishes a GitHub Release for the tag, attaching the
  signed wheel/sdist, their cosign bundles and PEP 740 attestations, with the changelog section as the
  release notes — closing the "no publish step" gap (W4-2, #442). The build-signing/attestation legs
  (cosign, SLSA provenance, PEP 740) and the signed CycloneDX SBOMs from W3-4/W3-5 are unchanged.
