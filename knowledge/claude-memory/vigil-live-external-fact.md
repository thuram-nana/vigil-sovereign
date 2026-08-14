---
name: vigil-live-external-fact
description: VIGIL LIVE EXTERNAL oracle-confirmed FACT on authorized testasp.vulnweb.com — egress works via sandbox-disable; offline-reverified 2/2; CRUCIBLE_ROOT + charter-format gotchas
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-29T09:15:10.298Z
---

The operator pushed to solve the "no outbound network → can't do the external live run" blocker; it WAS
solvable. Part of the [[vigil-ui-terminal-dossier-program]] / [[vigil-proof-studio]] line.

**Egress is NOT blocked — the Bash SANDBOX was dropping TCP.** Run the network step with the tool's
`dangerouslyDisableSandbox: true` and the host reaches arbitrary external hosts (example.com, pypi,
scanme.nmap.org, the vulnweb sites all answer on 80/443). DNS resolves even sandboxed; only the TCP connect
is dropped sandboxed. `git push`/HTTPS worked all along because those hosts were reachable — egress is
general, not allowlisted.

**testphp.vulnweb.com was DOWN** (its own outage — SYN to :80 and :443 both time out; not our block).
**testasp.vulnweb.com is UP** (Acunetix's ASP + Microsoft SQL Server deliberately-vulnerable site, same
legal/authorized class). The operator authorized `testasp` as the substitute via AskUserQuestion on
2026-07-29 (that answer IS the signing act; cited in the charter attestation).

**THE RESULT — a real LIVE EXTERNAL FACT, offline-reverified 2/2.** `python3 -m framework.v2 engage testasp
"http://testasp.vulnweb.com/search.asp?tfSearch=test" --arsenal --spine` (sandbox-disabled) minted TWO
oracle-confirmed findings over executor-captured bytes: `boolean_sqli` via `differential_response` (conf
0.987; the `'` reaches the SQL query → deterministic 200→500 divergence) and `open_redirect` via
`achieved_state` (conf 0.90). The gate default-DENIED every destructive probe (POST search, /admin paths) —
no TTY confirm. Both re-fired OFFLINE `[OK] matches-claim`; a flipped baseline byte → `[BAD] CLAIM-MISMATCH,
0/1 reproduced`. The moat ("the machine cannot lie about a finding") demonstrated live + external.

**Load-bearing gotchas (non-obvious):**
- **`CRUCIBLE_ROOT=/home/kali/Music/PENTEST/crucible`** (set in the shell profile) — that's where the engine
  reads `targets/<slug>/charter.md` + writes `evidence/` + the `--spine` `store.sqlite`. The CODE runs from
  `/home/kali/vigil/engine/crucible` (has its own CLAUDE.md) with `PYTHONPATH=.` + `.venv-offense/bin/python`.
  `/home/kali/vigil` has NO CLAUDE.md, so a `CRUCIBLE_ROOT=/home/kali/vigil` override is REJECTED (validation
  requires CLAUDE.md). The git-tracked `/home/kali/vigil/targets/` charters are NOT what the engine reads.
- **Charter scope parser needs the NUMBERED template format:** `_SCOPE_HEADER = ^##\s*2\.\s*In[- ]scope
  systems` + a `| Host | … |` table (first column = host, backticks stripped), block ends at the next
  `^##\s+\d`. The earlier `testphp` charter's `## Target hosts (in scope)` heading parses to `scope=[]` →
  every seed refused. `is_charter_signed` just needs a graphical name on a `Signed:` line.
- **`engage` has NO `--reverifiable-out`/`--format`** (those are `scan`-only, and `scan` is HARD loopback-only
  by design — `_is_loopback` guard). To re-verify an engage FACT offline: run with `--spine`, then read the
  confirmed `finding` events out of `.blackboard/store.sqlite` (each carries `oracle_context`, `oracle_kind`,
  `verified_by_oracle`) and feed one to `python3 -m framework.v2 verify <finding.json>` — it re-fires the
  retained oracle deterministically. `plan-input.json` only carries `has_oracle_context: true`, not the payload.
- **testasp injectable surface:** `search.asp?tfSearch=` (GET, reflects + boolean-SQLi) — GET is gate-allowed;
  its POST form + `/admin` paths classify DESTRUCTIVE → default-denied. `showforum.asp?id=` is numeric and
  500s on any injection (no clean oracle signal). Errors are suppressed (generic IIS 500), so `error_signature`
  does NOT fire on testasp — unlike testphp's verbose MySQL errors.
