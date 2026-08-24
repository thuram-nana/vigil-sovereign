# W11-2 — the unreferenced live-fire scripts, wired as scheduled jobs that fail closed

**Milestone:** W11 — TESTING DEPTH · **Issue:** #483 · **Registers in:** W0-3 #398.

## The gap

Three live-fire scripts shipped but were referenced by NO workflow:

* `tools/livefire/range.sh` — brings the deliberately-vulnerable range up/down on loopback and runs a
  differential `verify` (the planted weakness must fire, the negative control must stay silent);
* `tools/livefire/k8s_rbac_livefire.sh` — the E4 Kubernetes-RBAC live-fire against a throwaway k3s
  cluster it stands up and destroys;
* `tools/livefire/secret_github_livefire.sh` — the E5 exposed-secret validity live-fire against the
  real `api.github.com` using the operator's own credential.

Because no workflow invoked them, everything they guard could regress green, and the README's
"E4 is live-fire proven against a REAL cluster" rested on a MANUAL run by a person, once.

Worse, the one live-fire workflow that did exist (`livefire-full`, nightly) **tolerated a missing
tool**: it set `VIGIL_LIVEFIRE_ALLOW_MISSING` and the exposed-secret script SKIPPED cleanly when `gh`
was absent. A run that cannot run must not report success — a tolerated-missing-tool green is the exact
overclaim the live-fire programme exists to prevent.

## The claim under test

<!-- CLAIM:W11-2 --> The live-fire tool preflight fails closed on a missing required tool: `require_tools` names every required binary that is not resolvable on PATH and exits non-zero rather than tolerating it or reporting a skip as a pass, and only a tool explicitly acknowledged as optional may be absent without failing the run.

## Where it is enforced

`tools/livefire/require_tools.py` — `require_tools` (pure core `missing_tools`). It resolves every
required tool with `shutil.which`, and on any absent required tool it prints a GitHub `::error::`
annotation per tool and raises `SystemExit` with a non-zero code. It returns `True` only when every
required tool is present, or is named in `allow_missing` (the single, reported way a run may proceed
without a tool). It is stdlib-only and side-effect-free, so it is deterministically falsifiable.

The preflight is wired in three places so the fail-closed property is real regardless of caller:

* each of the three scripts calls it before doing any work (via the `require_bins` shell helper);
* each scheduled job in `.github/workflows/livefire.yml` runs it as an explicit preflight step; and
* the scripts' own result-adjudicators (`k8s_rbac_livefire.py`, `secret_github_livefire.py`, and
  `range.sh verify`) already exit non-zero on any wrong RESULT, so the jobs assert on results — the
  success sentinel is grepped from captured output — not merely on a zero exit.

## How it is proved (required CI)

`integration/tests/test_livefire_require_tools.py`, collected by the required
**integration two-env boundary (P5)** job (sovereign leg, framework-free). It asserts a present tool is
accepted, a missing required tool RAISES with a non-zero code and a `::error::` annotation, and — the
negative control, in the same run — the pure core reports EXACTLY the absent tool and nothing when all
are present. A no-op gate makes four of these tests red; a tolerant gate cannot pass them.

## What runs on cron, and the honest residuals

The three scripts run in **scheduled (nightly) + workflow_dispatch** jobs in `livefire.yml`, honestly
labelled and NON-blocking — they never report on a pull request, so they are recorded in
`KNOWN_NONPR_ADVISORY` (docs/tests/test_required_checks_canonical.py), not in the required set.

* `livefire range (nightly)` — the source range (`up src`) is deterministic and needs no docker or
  network; its fingerprint match is a real result assertion. The container targets and `verify` need
  docker and large image pulls on the runner.
* `livefire k8s RBAC (nightly)` — needs privileged docker to stand up k3s on the runner. The harness
  fails on any deviation. **Residual:** the real-cluster run on a hosted runner is not verifiable from
  the charter-restricted build host; the fail-closed preflight that guards it IS proven in required CI.
* `livefire exposed-secret validity (nightly)` — needs `gh` (fail-closed if absent) AND an operator
  GitHub credential. **Residual:** there is no such credential in CI by default; without one the run is
  an honest reported skip on the credential (not on a missing tool). The default `GITHUB_TOKEN` is an
  app-installation token and cannot authenticate `GET /user`, so a real PAT secret is required to make
  this job actually exercise the provider.

The README E4 line is corrected accordingly: the live-fire harness now runs in a scheduled CI job (it
was a manual run), and only the fail-closed preflight is a required-CI guarantee.
