# The two-env boundary / FATAL-2

> One of the four VIGIL invariants. Siblings: [architecture (living KB)](./architecture.md) ·
> oracle authority · gate of record · determinism + append-only.

## 1. What it is

VIGIL runs as **two isolated OS processes that must never co-load in one Python interpreter** — a
violation is codenamed **FATAL-2**. The **offense** plane (`.venv-offense`, *keyless*: no owner
signing key — `engine/crucible` + `vendor/strix` + `gateway` + `integration`) crawls, fires oracles,
and runs live Kali tools against targets. The **sovereign** plane (`.venv-sovereign`, *holds the owner
key*: `apps/sigil` + `packages/core/vigil_core` + `integration`) is the owner-signed action broker,
memory, and cockpit. They share no live handle — no DB connection, no agent object, no imported
module. They bridge **only** by (a) `subprocess` dispatch, or (b) a **signed, inert file spool** that
carries *bytes, never code*. The whole reason offense is keyless and sovereign holds the key is so that
a compromised offense worker can *produce evidence* but can never *authorize an action* or *touch the
owner's data core*. The boundary is declared in the root `pyproject.toml` under
`[tool.vigil.environments]` (`sovereign.forbids = ["framework", "strix"]`;
`offense.owner_key = false`).

## 2. Authoritative code paths

The boundary is enforced structurally (which packages are installed where) and guarded at runtime.

- **Environment declaration** — root `pyproject.toml`, `[tool.vigil.environments.sovereign]`
  (members = `vigil_core`, `apps/sigil`, `integration`; `forbids = ["framework", "strix"]`) and
  `[tool.vigil.environments.offense]` (`owner_key = false`). This is the machine-readable source of
  truth the boundary test reads.
- **Runtime sovereignty guard** — `apps/sigil/sigil/reuse/__init__.py:assert_no_offense()` (line 49).
  It scans `sys.modules` for the barred namespaces `_OFFENSE_NAMESPACES = ("framework", "strix")`
  (line 46) and raises `RuntimeError("SIGIL sovereignty violation: …")` if any is loaded. Called at
  sovereign-process entry — a fail-closed tripwire, not the primary defense.
- **The inert seam (sovereign side)** — `integration/vigil_integration/inert_finding.py`.
  `validate_inert_finding()` / `validate_inert_detection()` → `_parse_envelope()` (line 167) parse the
  inbound blob with **`json.loads` ONLY — never pickle/eval/yaml** (line 192), size-bounded to
  `MAX_ENVELOPE_BYTES = 256*1024`, strict top-level allowlist, then verify anchor-1 (`verify_signature`,
  lines 76 / 130) with **`vigil_core.verify_threshold` — no `framework` import**. This module depends on
  `vigil_core` alone; it is importable in *both* venvs by construction.
- **Spool producer (offense side)** — `integration/vigil_integration/finding_spool.py:spool_envelope()`
  (line 35). Takes a pre-built envelope **`str`** (refuses any non-`str` live object, line 41), writes it
  0600 via `mkstemp` + `os.replace` atomic rename into a 0700 `incoming/` dir, content-addressed name
  `sha256(envelope)[:32].json` (idempotent re-spool). It imports **stdlib + `inert_finding` only** — no
  `framework`/`strix`/`sigil`.
- **Spool watcher (sovereign side)** — `apps/sigil/sigil/inbound/spool_watcher.py:SpoolWatcher.drain()`
  (line 132). Claims each `incoming/*.json` by atomic rename into `working/` *before* reading (line 149),
  reads it as a bounded **regular** UTF-8 file via `_read_regular()` (line 98 — `O_NOFOLLOW`+`O_NONBLOCK`,
  `S_ISREG`, size cap, so a planted symlink/FIFO/device/non-UTF-8 blob cannot hang or crash ingest),
  dedups on `sha256` of the **actual bytes** (not the producer filename), routes by `kind` to an
  owner-delegated `FindingReceiver`, and moves the file to `processed/` on success or `rejected/` (with a
  `.reason` sidecar) on **any** failure. Fail-closed: a missing delegation for the file's kind is itself
  a refusal (lines 73, 80).
- **The boundary test** — `integration/tests/test_two_env_boundary.py` (see §4).
- **Lazy-import exemplars** — `integration/vigil_integration/conjunctive_gate.py:build_offense_gate()`
  (the `framework` imports are function-local inside `crucible_authorize()`, lines 123–124) and
  `integration/vigil_integration/learn_drain.py` (framework imports inside the drain step, lines
  125–127). These are the pattern to copy (§4).

## 3. Invariants it must preserve, and why

1. **No offense namespace ever loads in a sovereign interpreter.** `framework.*` (CRUCIBLE) and
   `strix.*` are barred from any `apps/sigil` process. *Why:* the sovereign plane holds the owner key;
   loading attacker-adjacent offense code into that address space would put the key one memory-safety bug
   away from an offense worker. Keeping them in separate interpreters makes the boundary a property of the
   OS process, not of careful coding.

2. **`vigil_integration` is installed in BOTH venvs, so anything it touches that lives in `framework.v2`
   must be imported LAZILY (function-local).** *Why:* a *module-scope* `import framework…` in any
   `vigil_integration` module would execute the moment that module is imported in a sovereign process —
   instantly tripping FATAL-2. The rule: `vigil_integration` modules import `vigil_core` and stdlib at
   module scope; they import `framework`/`strix` **only inside the function that actually runs offense-side**.
   The boundary test asserts this for six specific modules by checking `"framework" not in sys.modules`
   *after* importing them (test lines 53–65).

3. **Planes bridge only by subprocess or the signed inert file spool — never a shared live handle.** The
   only thing that crosses the spool is **inert bytes**: a JSON envelope parsed with `json.loads` only,
   size-bounded, allowlisted, and anchor-1 signature-verified with `vigil_core` before it reaches the
   spine. *Why:* if the offense worker is fully compromised, the worst it can do across the seam is send a
   *malformed or unsigned envelope*, which the sovereign validator rejects to `rejected/`. It can never
   execute code sovereign-side and never forge a signed FACT (no owner key; anchor-1 is m-of-n
   governance-signed or owner-delegated-spine-signed).

4. **Fail-closed at every seam step.** The producer refuses a non-`str`, empty, oversized, or non-JSON
   envelope. The watcher refuses a non-regular file, an oversized/non-UTF-8 blob, a missing delegation,
   an expired delegation (checked against a **local** clock, never the envelope), a failed signature, or
   an out-of-scope engagement — moving the file to `rejected/` and appending nothing. *Why:* the seam
   treats every inbound byte as hostile; the default for anything it does not fully understand is *drop*,
   not *ingest*.

## 4. How to extend it safely

**Adding a `vigil_integration` module that uses CRUCIBLE (`framework.v2`).** Copy the
`build_offense_gate` / `learn_drain` pattern exactly:

```python
# integration/vigil_integration/my_thing.py
from __future__ import annotations
from vigil_core import verify_one          # OK at module scope — sovereign-safe

def run_offense_step(...):
    # LAZY — only ever reached in env-offense; a sovereign import of this module
    # must not pull framework into sys.modules.
    from framework.v2.something import do_the_offense_thing
    ...
```

Never write `from framework… import …` (or `import strix…`) at module scope in *any* module under
`integration/` (or `packages/core/vigil_core`, or `apps/sigil`). If a sovereign-side consumer must
import your module (e.g. a producer/consumer pair like `learn_grant`/`learn_drain`), the *sovereign*
half must be offense-free too — verified by the same `"framework" not in sys.modules` assertion.

**Adding a new envelope kind to the spool.** Do not add a network endpoint — the boundary is a
directory. Follow the finding/detection precedent:
- Producer side: build the envelope with a sovereign-safe builder (`inert_finding.build_envelope` /
  `build_detection_envelope`), then hand the **`str`** to `finding_spool.spool_envelope()`. Sign the
  certificate with the offense governance / delegated-spine identity — the producer writes bytes, it does
  not hold the owner key.
- Consumer side: add a `validate_inert_<kind>()` + a `_<KIND>_REQUIRED_FIELDS` / `_<KIND>_ALLOWED_TOP`
  profile in `inert_finding.py`, keep `json.loads`-only parsing and the 256 KiB cap, require a distinct
  `kind` tag so shapes can't be mis-parsed, and route it in `SpoolWatcher._ingest_text()` (line 61)
  through an **owner-delegated** `FindingReceiver` — refuse with `InertFindingError` if no delegation for
  that kind is configured.

**Tests to add (all in `integration/tests/`):**
- Extend the `_PROBE` in `test_two_env_boundary.py` with a line importing your new module + an
  `assert "framework" not in sys.modules, "…"` (mirror lines 53–65). This is the load-bearing regression
  guard.
- If your module is a sovereign member's dependency, `test_no_sovereign_member_declares_offense_dependency`
  (line 105) already catches an offense dep declared in `pyproject.toml` — keep your dep list clean.
- For a new envelope kind, add fail-closed unit tests: malformed JSON, oversized, wrong `kind`, unsigned /
  bad signature, missing delegation → each must reject and append nothing (see
  `test_finding_spool.py` and the receiver tests for the shape).

## 5. Gotchas

- **PYTHONPATH-scrubbing is NOT a proof of the boundary.** The original test scrubbed `PYTHONPATH` and ran
  under the ambient interpreter — but in a correctly-built offense venv, `engine/crucible` and
  `vendor/strix` are editable-installed, so their `.pth` files import `framework`/`strix` at startup
  regardless of `PYTHONPATH` (red-pen P5 BLOCK-1). The boundary is a property of **which packages are
  installed**, so the real test builds an *actual* sovereign venv (only `vigil_core` + `integration`
  installed, crucible/strix deliberately absent) and probes it —
  `test_real_sovereign_venv_cannot_reach_offense` (line 136). It is skipped only when a venv/pip build is
  impossible (offline).
- **Keep the negative control alive.** `test_guard_is_not_vacuous_negative_control` (line 157) puts
  `engine/crucible` on the path, actually loads a real offense module, and asserts `assert_no_offense()`
  fires. A guard that never fires is worthless — if you touch the guard, keep this green.
- **A module-scope offense import is invisible until a sovereign process imports the module.** It won't
  fail your offense-side smoke test; it fails only when SIGIL imports it — which is exactly when it
  matters. The `sys.modules` probe is your only cheap early-warning; add the probe line for every new
  cross-plane module.
- **The dedup identity is the sha256 of the read bytes, never the producer's filename** (watcher line
  160). A compromised producer must not be able to suppress a real finding by naming it after an
  already-processed marker. Preserve this if you refactor `drain()`.
- **Delegation expiry is checked against the LOCAL clock**, never anything derived from the envelope
  (watcher `now_fn`, line 42; `_ingest_text` line 71). Don't "helpfully" read a timestamp out of the
  certificate to decide validity.
- **The spool is a directory, not an API.** Do not add an HTTP/RPC endpoint to bridge the planes — that
  reintroduces a live attack surface across the boundary the file-spool exists to avoid. `subprocess`
  dispatch (via `vigil_integration/cli.py`) and the signed spool are the only two sanctioned bridges.
- **Both halves of a producer/consumer pair must be offense-free.** It's easy to remember the offense
  consumer (`learn_drain`) needs a lazy import and forget that the sovereign producer (`learn_grant`) must
  never import `framework` at all — the test asserts both (lines 53–55).
