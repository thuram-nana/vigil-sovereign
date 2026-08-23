# W3-3 — Every GitHub Action in every workflow is SHA-pinned, and a drift check keeps it that way

Issue: [#426](https://github.com/thuram-nana/vigil-sovereign/issues/426) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-3 -->
> Every `uses:` in every workflow under `.github/workflows/` is pinned to a full 40-char commit SHA, and a drift check fails on any tag or branch ref.

This claim is TRUE of the code as of W3-3.

## The defect

A GitHub Action reference is a supply-chain dependency like any other: `actions/checkout@v4` is a
**mutable tag** on someone else's repository, and the step runs that repo's code with this
workflow's token. If the tag is repointed (compromise, or an ordinary breaking release), the next
run executes different code under the same reference.

Before this slice the repo pinned actions in most workflows but **not all of them**. The SHA-pin
test asserted the invariant for `supply-chain.yml` alone; three further per-workflow tests covered
`release.yml`, `security-scan.yml` and `scheduled-supply-chain-scan.yml`. That left three
workflows entirely outside any check:

- `ci.yml` — 26 tag refs (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/setup-java@v4`,
  `actions/upload-artifact@v4`, `actions/cache@v4`);
- `livefire.yml` — 5 tag refs (checkout, setup-python, `actions/setup-go@v5`);
- `branch-protection-verify.yml` — 1 tag ref (checkout).

32 tag-pinned refs, on the most privileged and most frequently-run workflows in the repo. The test
existed, passed, and covered almost nothing.

## The fix

### 1. Pin the current resolved SHA of every tag in use

Each remaining tag was resolved once to the commit its moving tag pointed at and pinned to that
40-char SHA, with the human-readable version kept in a trailing `# vX.Y.Z` comment. Behaviour is
unchanged — the pin is the exact commit the tag already resolved to at pin time:

```bash
gh api repos/actions/checkout/commits/v4 --jq .sha   # → the SHA; record `# v4.4.0` beside it
```

| action | tag | pinned SHA | version |
|--------|-----|------------|---------|
| `actions/checkout`        | `v4` | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/setup-python`    | `v5` | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `actions/setup-go`        | `v5` | `40f1582b2485089dde7abd97c1529aa768e1baff` | v5.6.0 |
| `actions/upload-artifact` | `v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| `actions/setup-java`      | `v4` | `cf277c60eb25467037889841efdb72551f06f6c3` | v4.9.1 |
| `actions/cache`           | `v4` | `0057852bfaa89a56745cba8c7296529d2fc39830` | v4.3.0 |

The checkout / setup-python / upload-artifact / cache SHAs are byte-identical to the pins already
used elsewhere in the repo, so the whole tree now runs one version of each. `setup-go` and
`setup-java` are new pins (they appeared only in the previously-unpinned workflows).

After the change, `grep -rn 'uses:' .github/workflows | grep -vE '@[0-9a-f]{40}'` returns nothing
(60 `uses:` refs across 10 workflow files, all SHA-pinned).

### 2. Widen the gate into an all-workflows drift check

The per-workflow `supply-chain.yml`-only test was replaced with a check that enumerates **every**
`uses:` in **every** workflow file (`*.yml` and `*.yaml`) and fails on any ref whose `@`-part is
not exactly 40 lowercase hex — i.e. a tag (`@v4`) or a branch (`@main`). Local first-party actions
(`uses: ./…`) are exempt: there is no upstream SHA to pin. Whole-line comments are stripped first,
so a commented-out `uses:` can neither trip nor satisfy the gate.

The check is the enforcement: `_unpinned_action_uses` in `integration/tests/test_supply_chain.py`
computes the violation set, and two tests pin it:

- `test_every_workflow_action_is_sha_pinned` — the drift check. **FAILS on a tree without the
  fix**: pointed at the pre-fix workflows it reports all 32 tag refs. It also guards against a
  vacuous pass (asserts the parser found ≥30 action refs, so a broken glob can't go green).
- `test_sha_pin_gate_rejects_a_tag_pinned_workflow` — the **negative control**. It points the same
  detector at a throwaway fixture workflow pinning `actions/checkout@v4` and asserts it is flagged,
  then at a SHA-pinned twin and a local `./` action and asserts neither is — proving the gate is
  neither a no-op nor a false-alarm, both asserted in the same run.

It runs in the required **integration two-env boundary (P5)** job (which collects the whole
`integration/tests` tree) and, redundantly, in the required **A14 supply-chain gate** job (which
invokes `test_supply_chain.py` directly). An unpinned action therefore cannot merge to `main`.

## Honest scope

- The drift check verifies each ref is a 40-hex SHA; it does not (and offline cannot) re-resolve a
  SHA against its upstream tag on every run. The trailing `# vX.Y.Z` comment records the version
  each SHA corresponded to at pin time and is advisory — the SHA is the thing that binds. Bumping
  an action's version is a deliberate change: re-resolve the tag, update the SHA and the comment
  together.
- `github/codeql-action/*` carries its version as `# codeql-action v3 (codeql-bundle-…)` rather
  than a bare `# vX.Y.Z`. The check keys on the SHA, not the comment shape, so that is fine.
- The three pre-existing per-workflow SHA-pin tests (release/security-scan/scheduled-scan) are left
  in place. They are now subsumed by the widened check but cost nothing and give a targeted
  message per workflow; removing them would only narrow coverage on a future refactor.
