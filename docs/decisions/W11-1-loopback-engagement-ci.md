# W11-1 — A required CI job runs the end-to-end loopback engagement and re-verifies it offline

Issue: [#482](https://github.com/thuram-nana/vigil-sovereign/issues/482) ·
Milestone: W11 — TESTING DEPTH.

## The claim (register in the claims registry, [W0-3] #398)

> On every pull request, a **required** CI job scans the repository's own loopback target with the
> real engine (`python3 -m framework.v2 scan`), the oracle confirms the planted weaknesses as facts
> each carrying a re-verifiable certificate, and those certificates are **re-verified OFFLINE on a
> clean, independent checkout** (`python3 -m framework.v2 verify`) — asserting both the fact count and
> the re-verify verdict. A **patched twin** (`vulnapp --safe`) is scanned in the same run and asserted
> to be a **sound CLEAN** — zero confirmed findings over the FULL check corpus, not merely silence —
> and a **forged certificate is rejected**, proving the re-verify gate is not a no-op.

This claim is TRUE of the code as of W11-1:

- **The job** — `loopback engagement (end-to-end + offline re-verify)` in
  `.github/workflows/ci.yml`, triggered on `pull_request`. It is a **required** check: its name is in
  `.github/required-status-checks.txt` (now **14** checks), and every doc stating that count/enumeration
  agrees (pinned by `docs/tests/test_required_checks_canonical.py`).
- **The chain** — `tools/loopback-engagement/run_loopback_engagement.sh` drives four ASSERTED legs
  (a failing leg exits non-zero; nothing is merely printed green):
  1. **POSITIVE** — scans the vulnerable app; asserts ≥3 oracle-confirmed facts INCLUDING the three
     planted classes `error_based_sqli`, `boolean_sqli`, `xss`, each carrying an `oracle_context`
     certificate, over the full corpus (`--library`). Measured locally: **5** confirmed
     (`auth_bypass`, `nosqli`, `error_based_sqli`, `boolean_sqli`, `xss` — the last four ride the
     same string-concatenated `/search?q=` query).
  2. **RE-VERIFY** — re-runs `framework.v2 verify` over the retained certificates from a **clean,
     independent checkout** (`_clean-reverify`, `VIGIL_LE_REVERIFY_DIR`); asserts it reproduces every
     one (exit 0). Measured locally: `re-verified 5/5 certificate(s) reproduced and matched their claims`.
  3. **TAMPER** — forges a copy with one finding relabelled to a class its own evidence never proved
     and asserts `verify` returns **non-zero** (the class-binding refusal fires). This is the
     negative control that proves the gate is not a rubber stamp. Measured locally: `verify rc=2`,
     `[BAD] … CLAIM-MISMATCH`.
  4. **NEGATIVE** — scans the patched twin (`vulnapp --safe`); asserts **0** confirmed findings AND a
     conclusive **full-corpus** coverage statement (a sound negative). Measured locally: `0` confirmed,
     `full corpus`.
- **The assertions** — `tools/loopback-engagement/check.py` (stdlib) turns each leg into a pure,
  perturbable predicate; the sound-negative keys on the scanner's own `coverage.full_coverage` flag, so
  "clean" is distinguished from "the scanner reached nothing".
- **The patched twin** — `infra/loopback/vulnapp.py --safe` serves the SAME routes/surface with the two
  confirmable weaknesses on `/search` fixed (parameterized query, escaped reflection) and `/file`
  refusing traversal. Default is OFF: the app stays deliberately vulnerable for the positive leg.
- **The reviewer demonstration** — the job writes `loopback-engagement-out/DEMO.md` and uploads the
  whole directory as the retained `loopback-engagement-demo` artifact (the ANTIC reviewer demo).

Pinned by `docs/tests/test_loopback_engagement_ci.py` (OFFLINE, stdlib only; it rides the required
`the briefing explains every agent and capability` job) and `tools/loopback-engagement/tests/test_check.py`
(the asserter logic + negative controls, run inside the new job). The offline pin includes a test that
FAILS on a tree without the fix — the job, the canonical entry and the driver are all absent on `main`
before this change (observed via `git show HEAD:` — the guard's `workflow_has_job_named` returns False).

## This replaces the hand-run recorded in a memory file (acceptance criterion)

The claim "a real `engage`/`scan` vs 127.0.0.1 produced an oracle-confirmed FACT that re-verified
offline" previously existed only as a hand-run recorded in a memory note — proven by a person once, on
one commit, and unable to promise anything about the next. **This required CI job is now the source of
that claim:** it re-establishes the fact, its offline re-verification, and both controls on every pull
request. The memory note is superseded by this decision record and the job it describes.

## The honest scope decision — `scan` + `verify`, not `engage --spine`

The issue text names a "signed spine". Two engine paths reach a loopback target:

- **`scan`** is loopback-only by construction, needs no charter, no `CRUCIBLE_ROOT` and no spine store,
  and every confirmed finding retains an `oracle_context` certificate that `verify` re-runs offline —
  with **no target and no trust in the producing tool or tree**. This certificate re-verification is
  the portable proof the AC asks for ("re-verify the resulting evidence offline on a clean checkout"),
  and is arguably stronger than trusting the spine bytes.
- **`engage --spine`** additionally writes the governed, signed SIGIL spine, but it fail-closes without
  a **signed charter** discovered under a `CLAUDE.md`-rooted `CRUCIBLE_ROOT` (confirmed: with
  `CRUCIBLE_ROOT` unset-to-repo-root it resolves the charter under `engine/crucible/targets/` and
  refuses `charter_missing`). A **required per-PR gate must be robust** — the entire point of the W0-2
  accounting is that a flaky required check blocks every PR — so the signed-spine `engage` variant is
  deliberately NOT the required gate.

**Honest limit / residual:** the required job proves the oracle-confirmed FACT + offline
re-verification chain over `scan`'s re-verifiable certificates; it does NOT exercise the signed-spine
`engage` path, nor a signed on-chain record. Promoting an `engage --spine` loopback run to CI (a
committed signed loopback charter + a fixed `CRUCIBLE_ROOT`) is a follow-up; until then the signed-spine
loopback run remains a hand-run and this job carries the mechanized claim above.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this
> decision record is the source of truth for the claim, its measured numbers, and the documented
> `scan`-vs-`engage` scope decision.
