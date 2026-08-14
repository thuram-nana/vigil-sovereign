# ADR 0003 — The tool waves, and why `ncat` is refused rather than driven

- **Status:** Accepted
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`)
- **Enforced by:** [`../../docs/tests/test_out_of_scope_is_honest.py`](../../docs/tests/test_out_of_scope_is_honest.py),
  run inside the **required** `integration two-env boundary (P5)` job — it reads THIS file and fails when
  it disagrees with the code. It runs there rather than in the docs job because it needs both trust
  domains on the path; in the docs job it skipped, and an earlier version of this line claimed
  enforcement that did not exist. `VIGIL_REQUIRE_FRONTIER_CHECK=1` makes an import failure in that job a
  failure rather than a skip, so the guard cannot go dark silently again.

## Context

The catalogue holds more tools than the engine can drive, and that is fine — provided the gap is
**stated, exact, and checkable**. It had become none of those things.

The record of which tools remained undriven existed in exactly one place: the body of a merged pull
request (#309). A merged PR body is not reachable from the working tree, cannot be reviewed alongside
the code it describes, and cannot be wrong in a way anything notices. When it was measured against the
code, it was wrong in both directions:

- it said **"twelve further tools"** but **named eleven**; and
- the true count of tools with no driver at all was **fifteen** — it never mentioned `katana`, `naabu`
  or `subfinder`.

An undercount is the more damaging error: it describes the system as closer to complete than it is.
Nothing in CI could catch either, because nothing in CI had ever read the list.

There is a second, subtler failure this ADR closes. "Undriven" was being used to mean "has no typed
argv builder", but `_BUILDERS` is only one of four ways a tool is driven. `semgrep` and `joern` have
been driven for a long time — as **analyzers**, through `analysis/analyzers/`. Listing them as pending
work would have been an *under*claim, and the plan for this program did exactly that until the code was
read.

## Decision

### 1. A tool is "driven" through exactly one of four control surfaces

`framework/v2/tools/profile.py` already names them, and they are the definition used here:

| Surface | Meaning | Registry |
|---|---|---|
| `cli` | the live executor builds and gates a validated argv | `live/executor.py::_BUILDERS` |
| `sensor` | a gated sensor runs it and normalizes its output | `profile._SENSOR_DRIVEN_TOOLS` |
| `analyzer` | the analysis orchestrator runs it over a source tree | `profile._ANALYZER_DRIVEN_TOOLS` |
| `browser` | the DOM-XSS confirmation launches it | `profile._BROWSER_DRIVEN_TOOLS` |

A tool on none of these is **undriven**, and the admission gate refuses it with a reason. That refusal
is correct behaviour, not a defect — it is the system declining to pretend.

### 2. Source scanners are analyzers, not builders

`execute()` fail-closes without a network target (`"no target host/url in tool_args"`). A source scanner
takes a **directory**. Giving one a synthetic host to satisfy a network pin would corrupt the meaning of
the scope pin — the one control that makes the executor safe. Wave 2 therefore lands on the **analyzer**
contract (`is_available` → `analyze` → normalized findings), which already exists, already degrades
visibly when a binary is absent, and already takes a directory as its target.

### 3. The waves

**Wave 1 — shipped.** Nine typed builders, ten live-fire rows, all passing:
`nmap`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `hydra` (two rows), `nikto`, `wapiti`, `zaproxy`.

**Wave 2 — shipped in this program.** Source scanners, as analyzers: `bandit`, `gitleaks`,
`trufflehog`. (`semgrep` and `joern` were already analyzer-driven and were never pending.)

**Wave 3 — deferred.** Web-surface discovery: `arjun`, `dirsearch`, `gospider`, `wafw00f`, `katana`.

**Wave 4 — deferred.** Recon and specialist: `subfinder`, `naabu`, `trivy`, `jwt_tool`, `caido-cli`,
`interactsh-client`.

Deferred means **no driver, refused by the admission gate, and named here**. It does not mean planned
for any date.

### 4. `ncat` is refused by design, permanently

`ncat` is not deferred work. It is declined.

It is a general-purpose networking primitive: arbitrary connections, arbitrary listeners, arbitrary
bytes. A typed builder for it could only be one of two things. Either it is **genuinely constrained** —
in which case it is not `ncat`, it is a narrow tool wearing its name, and the honest move is to build
that narrow tool. Or it is **a thin wrapper** that passes operator-supplied arguments through, in which
case every safety property the executor provides (the loopback resolution pin, the argv allowlist, the
per-tool refusals) is bypassed by construction, because the arguments *are* the attack surface.

`interactsh-client` sits behind the same reasoning for a different reason: it exists to receive
**out-of-band callbacks from a third-party collaborator**, which the charter's no-egress limit forbids
outright. It is listed in Wave 4 for completeness and cannot be built without the charter changing.

`ncat` remains in the catalogue (an operator may run it themselves; it is on the destructive-tool floor
in `tools/governance.py`), and the engine refuses to drive it. That refusal is the feature.

## Consequences

- The frontier is in the tree, versioned, reviewable, and **enforced**: the honesty test fails if a tool
  named here as deferred gains a driver, if `ncat` gains one, or if a Wave 2 tool is still listed as
  pending. Code and this document cannot drift apart silently.
- The count is now derived from code rather than transcribed, so "twelve" cannot silently mean fifteen.
- Anyone can re-derive the undriven set: subtract the four registries above from the tool roster.

## Related

- Deferred design notes, linked from `framework/v2/console/README.md` with their status:
  `CHAT-VISION.md` and `MODEL-SELECTION.md` are **design only, not built**; `ATTACHMENT-SAFETY.md`
  describes shipped behaviour.
- [ADR 0002](0002-verifiable-fact-program.md) — the same discipline applied to remediation claims.
