# W6 — the corpus-wide zero-false-positive gate (FACT-coverage Wave 6)

Wave 6 wires the `engage --profile {surface,deep,full}` roster end-to-end and adds the program-level
assertion that makes "the wider deep/full roster ships on by default" SAFE.

## Context

Waves 0–5 built the FACT-capable packs (browser DOM/stored-XSS, SSO/JWT/OIDC/SAML acceptance, GraphQL
amplification, static-rule facts, differential request-smuggling desync, …) and the `--profile` flag
expansion (Wave 0.2). `surface` is the default `make gate` roster; `deep`/`full` union in the opt-in
passes with their near-zero-FP controls intact. A wider roster is only safe to ship on by default if it
raises **no** alarm on a clean surface — and that must be PROVEN, not asserted.

## Decision

Add a corpus-wide zero-FP gate: run the whole in-process benchmark corpus (every planted bug AND every
benign twin / negative control) under the deep AND full profiles and hold two invariants — zero false
positives anywhere in the corpus, and full planted-bug coverage. It is deliberately asymmetric: a new
false positive fails CI; more true positives never do. It is CRUCIBLE-only and needs no Docker, so it runs
anywhere; the browser-driven surfaces run where Chromium is present and emit INCONCLUSIVE (never CLEAN,
never a finding) where it is absent, so the gate holds on both.

The profile is PURE roster expansion: it adds no oracle, relaxes no WARDEN gate, no never-liftable egress
floor, and no GET-only default, and `surface`/`quick` stays byte-identical (`make gate` unchanged at
11tp/0fp/0fn).

<!-- CLAIM:COV-W6-ZEROFP -->
Under the deep and full engagement profiles the whole benchmark corpus stays zero false positives while every planted bug still confirms, and the corpus-wide zero-FP gate fails CI on any new false positive.

## Enforcement

- `zero_fp_gate` (`engine/crucible/framework/v2/eval/gate.py`) is the asymmetric verdict: any
  `false_positives != 0` for a gated tool is a hard regression, a drop in planted-bug coverage is a hard
  regression, and a run that evaluated nothing is fail-closed.
- `BenchmarkCrucibleAdapter(profile=...)` (`eval/benchmark_run.py`) runs the corpus under the deep/full
  roster; `make gate-zero-fp` / `python3 -m framework.v2 benchmark --zero-fp --no-incumbents` runs the
  gate under both profiles.
- Proved by `engine/crucible/framework/v2/eval/tests/test_corpus_zero_fp.py`, collected by the required
  `CRUCIBLE eval + benchmark corpus` CI job.
