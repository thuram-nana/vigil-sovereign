# W16-7 — The deliverable chain produces the deliverable, end to end

Issue: [#513](https://github.com/thuram-nana/vigil-sovereign/issues/513) ·
Milestone: W16 — DECLARED-LIMITATION BURNDOWN.

## The claim (register in the claims registry, [W0-3] #398)

> An engagement's final deliverable — the tamper-evident dossier ZIP — is produced from a real run with
> every link wired:
> 1. the raw per-action HTTP evidence the executor captured (`request.http` / `response.http` /
>    `response.body`) is reachable from an **API route** and a **UI screen**, and is shipped in the dossier;
> 2. the three human reports (executive / technical / remediation-roadmap) and the SARIF export render from a
>    `findings.json` that a **production run actually writes**;
> 3. `export_bundle` and the console agree on **one** path for `reverifiable.json` — the top-level
>    `<run>/reverifiable.json` a scan writes is the one the exporter reads;
> 4. the dossier is signed under a **stable, per-install** governance trust root, so the signature
>    establishes **origin** (pinnable out of band), not merely integrity; and
> 5. the signed certificate **stored at mint time** is byte-identical to what the download returns (no
>    re-mint that drops the minted signature).

This claim is TRUE of the code as of W16-7:

- **Raw HTTP evidence → API + UI + dossier (AC1).** `framework.v2.console.api.http_evidence` reads the
  per-action capture (path-safe: symlinks are never followed; the preview is capped) and is wired at
  `/api/http-evidence/<run>` in `console/server.py`. The evidence screen in `packages/vigil-ui/app.js`
  (`p3HttpEvidence`) calls it. `report.dossier._gather_http_evidence` ships the same bytes under
  `http-evidence/<action_id>/` and `_render_index` names them in `index.html`. Before this, the capture was
  written to disk and read by no route, screen, or dossier.
- **findings.json in production (AC2).** `console.actions._write_findings_json` runs on the scan-completion
  path (`launch_scan` and `_spawn_background`), deriving the renderer-shape finding set deterministically
  from the scan's `report.json` (via `report.adapt.adapt_scan_export`) joined to the retained
  `oracle_context`. `report.dossier._gather_reports` renders the three reports + SARIF from that source
  (`_load_findings_source`). Raw `report.json` alone cannot be rendered — the renderers reject its shape,
  which is precisely why `report.adapt` exists (pinned by `report/tests/test_adapt.py`).
- **One reverifiable.json convention (AC3).** `proof.run.read_reverifiable` reads BOTH
  `proofs/reverifiable.json` (studio) and the top-level `<run>/reverifiable.json` (what every console/UI scan
  writes via `--reverifiable-out`), de-duplicated. `export_bundle` reads through it, so the console's
  convention and the exporter's now meet.
- **Stable, origin-establishing trust root (AC4).** `console.actions.build_dossier` shells
  `vigil dossier --base-dir <_live_base()>`; `live.wiring.provision_authority(base_dir=…)` loads-or-creates
  ONE sealed governance key under that home, so every run of an install shares a trust root and a bundle from
  a different install does not verify against the pinned fingerprint. Without the flag,
  `export_bundle` fell back to `base_dir or str(run_dir)` — a fresh key per run (integrity, not origin).
- **Stored certificate returned byte-identically (AC5).** `proof.run._persist_reverifiable` stores the
  `SignedEvidence` minted for the finding; `proof.bundle.export_bundle._reuse_stored_cert` returns it
  unchanged when it is well-formed, keyed to the finding's ref, AND authentic against the bundle's own trust
  root — otherwise it re-mints (so a cert signed under another key is never smuggled in). The redundant blob
  is stripped from the shipped `reverifiable.json` (it lives in `evidence-bundle.json`).

## Tests and the required CI jobs

- `integration/tests/test_deliverable_chain.py` — the end-to-end chain and AC2/AC3/AC4/AC5, including the
  negative controls (a wrong-install bundle is refused against the pinned root; a cert under a different key
  is re-minted, not reused; `_write_findings_json` writes nothing on a missing/malformed/empty source). It is
  framework-dependent, so it runs in the **offense leg** of `.github/workflows/ci.yml` (`--ignore`d in the
  sovereign leg and listed in the offense leg — enforced by
  `test_ci_framework_tests_run_in_offense_leg.py`).
- `engine/crucible/framework/v2/console/tests/test_http_evidence_route.py` — the API route (AC1), its
  fail-closed / path-safe behaviour, the UI screen's call to the route, and `build_dossier`'s stable
  `--base-dir` pin (AC4, console side). Runs in the required **CRUCIBLE core** job (`pytest framework/v2`).

Both suites contain assertions that FAIL on a tree without this change (no `_write_findings_json`, no
`http_evidence` route, no `--base-dir` in the dossier argv, no stored `signed_certificate`) — the failure is
structural, not assumed.

## Registration

The claims registry ([W0-3] #398) is not yet landed in this tranche. Per the repo's prior practice
(see `docs/decisions/W5-1-…`), this decision record is the source of truth for the claim until #398 lands;
fold the five sub-claims above into the registry when it does.
