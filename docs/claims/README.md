<!-- CLAIM:REGISTRY-SELF -->
# The VIGIL claims registry (W0-3 #398)

**Registered claim (W0-3 #398):** Every registered claim resolves to a real enforcing symbol and a real
proving test, and the guard fails the build when a registered claim has no backing or when a doc claim
marker has no registry entry.

This directory is the machine-checkable answer to a single question the W0 credibility programme asks of
every product claim: *is this claim true of the code, and is there a test that proves it?* Without a
registry, every fix in the programme can silently rot back into a false claim. `registry.json` is that
registry; `../tests/test_claims_registry.py` is the guard that keeps it honest, and it runs in the
**required** `the briefing explains every agent and capability` CI job.

## Why JSON, not YAML

The `briefing-completeness` CI job installs **only pytest** (it reads files, imports no trust domain, and
carries no other dependency). PyYAML is therefore unavailable in the job that must parse this registry, so
the registry is `registry.json` and the guard parses it with the stdlib `json` module. The issue text
allows either format (`registry.yaml or .json`); the CI constraint decides it.

## The entry schema

`registry.json` is `{"registry_version", "failure_classes", "claims": [...]}`. Each claim entry:

| field | meaning |
|-------|---------|
| `id` | Stable claim id (e.g. `W5-1`). Also the token in the doc marker `<!-- CLAIM:<id> -->`. |
| `title` | Short human label. |
| `claim` | The claim text, as a **verbatim** (whitespace-collapsed) substring that must appear in `source`. |
| `source` | `path:line` where the claim marker lives — the **file:line of the claim text** the AC asks for. |
| `enforced_by` | `{file, symbol}` — the code symbol that ENFORCES the claim. `symbol` may be dotted (`Class.method`). The guard resolves it by AST, without importing anything. |
| `proved_by` | `{file, tests: [...]}` — the test file and the test function(s) that PIN the claim. |
| `ci_job` | The **required** CI job (a `name:` from `.github/required-status-checks.txt`) that runs `proved_by.file`. |
| `failure_class` | Which of the three named drift classes this claim guards against, or `n-a` (see `failure_classes`). |
| `default` | `on` / `off` / `n-a` — whether the enforcement is on by default. An **opt-in** control is labelled `off`, so it can never be silently documented as a default. |

## The marker convention (the bijection)

To register a claim you place a marker `<!-- CLAIM:<id> -->` in the doc where the claim text lives, next to
the claim, and add the matching `registry.json` entry. The guard enforces a **bijection**:

- every `<!-- CLAIM:<id> -->` marker found in the docs tree (`**/*.md`, excluding `vendor/` and this
  `docs/claims/` meta-directory) MUST have a registry entry — *a claim string in the docs with no registry
  entry turns CI red*;
- every registry entry's marker MUST be present in its `source` file at the recorded line.

The one non-`.md` source in the seed set (`test_fix_ladder_matches_the_gate.py`, whose "claim" is the
served UI ladder) carries its marker in the module docstring; `.py` sources are verified in the
registry-to-source (forward) direction only, since the docs bijection is about *documents*.

## What the guard checks (and why it is not advisory)

`../tests/test_claims_registry.py`, stdlib-only (`json`, `ast`, `pathlib`, `re`):

1. **schema** — every entry has every required field with a valid enum value;
2. **symbol resolves** — `enforced_by.symbol` is really defined in `enforced_by.file` (AST, no import);
3. **proof exists** — `proved_by.file` exists and defines every named test function — so **deleting the
   proving test for any registered claim turns CI red** (the registry is not advisory);
4. **claim text present** — the `claim` substring is present in `source`, and the marker sits at the
   recorded line (so silent doc drift of a registered claim is caught);
5. **bijection** — the marker↔registry correspondence above;
6. **required CI** — `ci_job` is in `.github/required-status-checks.txt` and actually collects
   `proved_by.file`;
7. **the three classes** — each of the three named drift classes is exercised by at least one claim;
8. **negative controls** — deliberately broken entries (missing symbol, missing test, absent claim text,
   an unregistered marker) are rejected by the validators in the same run, proving the gate is not a no-op.

## How to add a claim

1. Land the capability and its proving test (or identify the already-landed pair).
2. Put `<!-- CLAIM:<your-id> -->` next to the claim text in the authoritative doc.
3. Add the `registry.json` entry (fill every field; pick the honest `default` and `failure_class`).
4. Run `python -m pytest docs/tests/test_claims_registry.py -q` — it must be green before you commit.
