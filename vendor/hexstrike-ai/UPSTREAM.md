# hexstrike-ai — vendored upstream (reference only, NON-RUNNABLE)

- **Upstream:** https://github.com/0x4m4/hexstrike-ai
- **Pinned commit:** `d689933ff579d839c676c82b231f8e98326c5f04` (2026-08-03, "readme update")
- **License:** MIT — Copyright (c) 2026 Muhammad Osama (0x4m4) &lt;contact@0x4m4.com&gt; (see `LICENSE`, kept verbatim).

## What is vendored, and why it is NON-RUNNABLE

VIGIL reuses hexstrike-ai's **decision model** — the deterministic, heuristic tool-selection and
parameter-optimization brain (`IntelligentDecisionEngine`, `TargetProfile`, the attack-pattern
playbooks) — as the reasoning core of a pluggable VIGIL agent body. That reuse is a **clean-room
reimplementation** in `integration/vigil_integration/brains/hexstrike_brain.py`, attributed to this
upstream, **not** an import of the upstream server.

The upstream `hexstrike_server.py` (a Flask API with ~156 tool-execution routes, `shell=True`
subprocess calls, a base64 `exec()` payload builder, a MITM proxy, and live NVD/GitHub calls) and
`hexstrike_mcp.py` (the LLM tool client) are a complete, self-contained **offensive execution
framework**. Running them would bypass VIGIL's conjunctive gate, egress gate, and charter scope
entirely — the exact ungated-offense path VIGIL forbids.

So they are stored here **only as reference blobs** with a `.reference` suffix:

- `hexstrike_server.py.reference`, `hexstrike_mcp.py.reference`, `requirements.txt.reference`

The `.reference` suffix means Python cannot `import hexstrike_server` / `import hexstrike_mcp`, and the
files are never on any import or execution path. `vendor/` is never added to `PYTHONPATH`, no VIGIL
launcher references any hexstrike entrypoint, and a CI guard asserts `grep -r 'import hexstrike'` over
the VIGIL source stays zero. The heavy upstream deps (flask/psutil/aiohttp/bs4/selenium/mitmproxy/
angr/pwntools/fastmcp) are **not** installed and **not** a VIGIL dependency.

## What VIGIL took from it (design credit)

The tool-effectiveness heuristics, the target-profiling model, the per-tool parameter tables, and the
named attack-pattern playbooks are hexstrike-ai's design. VIGIL's `hexstrike_brain.py` adapts that
**design** — curated to recon/safe classes, with all evasion/stealth, credential-poisoning, and
live-exploit/persistence stages removed — and runs it **propose-only**: it emits a proposed tool list +
parameters + ordered chain as LEADs. Every proposal then crosses VIGIL's conjunctive gate + egress gate
and is executed only through the gated external-tool runner; every finding is minted a FACT only by a
deterministic VIGIL oracle. The brain computes no facts and self-authorizes nothing.
