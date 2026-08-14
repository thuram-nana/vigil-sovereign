---
name: crucible-testing-and-gotchas
description: "How to test CRUCIBLE framework/v2 and non-obvious environment gotchas (bs4 absent, test counts)"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

Testing CRUCIBLE (`framework/v2/`):
- Full suite: `python3 -m pytest framework/v2 -p no:cacheprovider` — ~1031 passed,
  13 skipped, ~100s (as of PR #21). The 13 skips are all external-dep/opt-in
  (semgrep, joern, live LLM, live HTTP) — never a real failure.
- `graphify update .` after code changes (CLAUDE.md requires it; AST-only, free).

Non-obvious gotchas:
- **beautifulsoup4 (bs4) is NOT installed** and not a dependency, despite what a
  depth audit may claim. The project parses HTML with stdlib `html.parser`
  (the crawler does; the Wave-6 structural diff + reflection oracle do too).
  Use stdlib `HTMLParser`, never `from bs4 import ...`.
- The gated executor `agents/http_executor.py:HttpExecutor` is the REAL one;
  `executor_proto.py:HttpExecutor` is an unused sketch.
- `KillSwitch` writes to `paths.killswitch_path(slug)` (NOT under `target_dir`),
  so tests that trip a kill-switch MUST monkeypatch `_paths.killswitch_path` too
  (in addition to `target_dir`/`charter_path`) or the `.halt` file leaks across
  tests and breaks every later test using that slug.
- Numpy/scipy/sklearn/z3/sympy are NOT available — all statistics ship as pure
  Python (Mann-Whitney, SPRT, isotonic PAV, Beta belief, EIG all hand-rolled).

See [[crucible-beyond-sota-program]].
