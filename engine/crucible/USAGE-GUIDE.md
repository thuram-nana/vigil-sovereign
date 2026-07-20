# CRUCIBLE — Usage Guide

A task-oriented guide for the operator: *how do I actually use this?* It assumes you have read the
[README](README.md) for the "what and why." Every command below is the real CLI — run
`python3 -m framework.v2 <subcommand>` from the repository root. Where a command needs a live LLM
backend versus runs fully offline, this guide says so.

The one rule that shapes every workflow: **a claim is a fact only when a deterministic oracle re-fires
over data a real target produced.** The LLM (if any is reachable) *advises*; the oracle *confirms*.
Nothing you run here can promote a finding the oracle refused.

> **Setup path note.** The one-time setup script is **`bin/init.sh`** (there is no
> `framework/scripts/bootstrap`). The rest of this guide uses the real subcommands verified against the
> tree at commit `c7d9814`.

---

## Contents

1. [Install and check governance](#1-install-and-check-governance)
2. [Authorization first — the charter workflow](#2-authorization-first--the-charter-workflow)
3. [Core workflows](#3-core-workflows)
   - [3.1 Loopback quick scan](#31-loopback-quick-scan)
   - [3.2 The full gated engagement](#32-the-full-gated-engagement)
   - [3.3 The opt-in autonomous loop](#33-the-opt-in-autonomous-loop)
   - [3.4 Reports and machine export (SARIF/JSON)](#34-reports-and-machine-export-sarifjson)
   - [3.5 Re-verify a saved report offline](#35-re-verify-a-saved-report-offline)
   - [3.6 Recon / intel](#36-recon--intel)
   - [3.7 Running a sensor / importing third-party output](#37-running-a-sensor--importing-third-party-output)
   - [3.8 The defender (purple-team) pass](#38-the-defender-purple-team-pass)
4. [AEGIS — the defensive dual (embedding it)](#4-aegis--the-defensive-dual-embedding-it)
5. [Operator surfaces: console, API, MCP](#5-operator-surfaces-console-api-mcp)
6. [Trust: benchmark and the regression gate](#6-trust-benchmark-and-the-regression-gate)
7. [The controls: entitlement, kill-switch, sovereignty](#7-the-controls-entitlement-kill-switch-sovereignty)
8. [Offline vs live — what needs an LLM backend](#8-offline-vs-live--what-needs-an-llm-backend)

---

## 1. Install and check governance

```bash
# From the repository root, once per host (idempotent):
bash bin/init.sh
#   → rewrites embedded paths for this host, seeds the intake-authorization ledger,
#     and prints the CRUCIBLE_ROOT export line to add to your shell rc.

pip install --break-system-packages -r framework/v2/requirements.txt
```

Dependencies are deliberately lean (pydantic, httpx/requests, structlog, PyYAML, beautifulsoup4,
Jinja2, cryptography). No numpy, no SMT solver, no browser-automation library is required. The optional
heavy extras (`numpy`, `z3-solver`, `sentence-transformers`) are **default-absent** — CRUCIBLE runs
fully without them, and they can only *accelerate/enrich*, never change a verdict.

**Choose your sovereignty tier before the first run** — it gates which LLM backends may even be
constructed (fail-closed, *before* any cloud SDK is imported):

```bash
export CRUCIBLE_SOVEREIGNTY_TIER=PERMISSIVE   # dev default
#   AIR_GAPPED       — local backends only (ollama, claude-code, dryrun)
#   SOVEREIGN_CLOUD  — adds regional Bedrock/Vertex/Mistral
#   TRUSTED_CLOUD    — adds Anthropic zero-data-retention
#   PERMISSIVE       — adds plain consumer Anthropic / Claude Code
```

Then confirm the environment and the **governance state**:

```bash
python3 -m framework.v2 status
```

```
CRUCIBLE v2 status
------------------
  CRUCIBLE_ROOT     : <repo>/crucible
  v2 root           : <repo>/crucible/framework/v2
  memory db         : <repo>/crucible/framework/v2/.memory/store.sqlite
  dryrun dir        : <repo>/crucible/framework/v2/.dryrun

  LLM backends      :
    · anthropic  construct failed: BackendUnavailable: anthropic SDK not installed
    ✓ claude-code ready (binary=…/claude, model=haiku, per-call cap=$0.20)
    ✓ dryrun     always available; no network

  Governance        :
    sovereignty tier : PERMISSIVE (unsealed — env-mutable)
    entitlement      : ⚠ UNGOVERNED — enforcement INACTIVE — no trust root provisioned; baseline
                       core runs, gated capabilities permitted with a logged warning
```

Read that governance block every time. Two things matter:

- **Sovereignty tier** — and whether it is `[SEALED]`. Sealing pins the tier for the process lifetime
  (it can only tighten, never relax).
- **Entitlement** — `ENFORCED` vs `⚠ UNGOVERNED`. Out of the box it is **UNGOVERNED**: baseline
  reasoning and intake always work, but high-impact capabilities run *unentitled with a logged
  warning* until you provision a trust root and set `CRUCIBLE_ENTITLEMENT_ENFORCED` (§7). `status`
  surfaces this loudly so you are never *unknowingly* ungoverned.

If no cloud SDK / API key is present, `dryrun` is always available and the reasoning kernel falls back
to deterministic fixtures — the scanner and oracles need no LLM at all, so everything in §3 still runs
offline (with reasoning quality bounded accordingly).

---

## 2. Authorization first — the charter workflow

**Nothing active-tests without a signed, in-scope `charter.md`.** This is enforced in code
(`common/ethics.py`), not by convention: an unsigned charter or an out-of-scope host is *refused before
a single byte leaves the box*, and the refusal is recorded as evidence.

The fast path scaffolds a target from a URL you own:

```bash
# 1. Attest authorization (writes to the intake-authorization ledger — scaffolding requires this first):
python3 -m framework.v2 intake authorize https://your-app.example.com --operator "you@example.com"

# 2. Scaffold the engagement (passive, SSRF-guarded, ethics-gated):
python3 -m framework.v2 intake run https://your-app.example.com --operator "you@example.com" --slug your-app
#   → writes targets/your-app/charter.draft.md, threat-model.md, attack-tree.md, recon/fingerprint.json
```

Then **you** review `targets/your-app/charter.draft.md` and save it as
`targets/your-app/charter.md` with the in-scope host list, hard/soft limits, stop conditions, and your
signature line filled in. Until that signed `charter.md` exists, `engage` refuses. (You can also copy
`targets/_template/` by hand instead of using `intake`.)

`intake fingerprint <url>` does the passive stack-fingerprint only, scaffolding nothing.

---

## 3. Core workflows

### 3.1 Loopback quick scan

`scan` is a **loopback-only** quick web scan (it refuses any non-loopback host — use `engage` for
remote in-scope targets). It needs no charter because it can only reach `127.0.0.1` / `localhost` /
`::1`, and no LLM. Point it at a local app you are running:

```bash
python3 -m framework.v2 scan http://127.0.0.1:8080/ --format json --strict-evidence
```

- `--format {text,json,sarif,html}` — the export states each finding's **live grounding**
  (`fact` / `ungrounded` / `contradicted`); it re-executes each certificate at render time.
- `--strict-evidence` — withhold any finding that does not re-ground as a fact at render, but keep it in
  `--reverifiable-out <file>` for the record.
- Other flags: `--targeted`, `--domxss`, `--browser-xss` (real headless-browser DOM-XSS execution),
  `--spa` (recover fetch/XHR endpoints), `--arsenal` (advanced modules), `--progress-log <file>`,
  `--bandit-file <file>` (persist/warm-start the check-ordering learner).

Every finding it prints is oracle-confirmed and carries a re-runnable certificate.

### 3.2 The full gated engagement

`engage` is the authorized, remote, end-to-end runner. **Every request passes the 6-gate safety chain**
(kill-switch → scope → destructive-confirm → budget → rate-limit → egress). The seed host must be in
`targets/<slug>/charter.md`'s in-scope list or it refuses before sending anything.

```bash
python3 -m framework.v2 engage your-app https://your-app.example.com/ --recon --spine
```

What that does (mechanically, per README §5.1): crawl → decompose insertion points → select checks →
audit through the gated executor → **oracle confirmation** → project into the world-model → chain
attack paths (no traffic) → run the veracity firewall over every finding → score confidence.

Useful opt-in flags (all off by default; off = byte-identical runs):

| Flag | Effect |
|---|---|
| `--recon` | Run the OSINT intel engine alongside the scan into the shared world-model. Sends **no** traffic to the target. |
| `--spine` | Mirror the whole engagement onto the immutable event spine (phases, findings + grounding verdict, refusals, per-finding rewards). |
| `--arsenal` | Content/JS discovery, request-smuggling, WebSocket-hijack — raw-socket modules host-gated through the full chain. |
| `--waf-adaptive` | On a blocked probe, synthesize a bypass (evasion ladder → small GA) that **still fires the same oracle**. |
| `--grammar-fuzz N` | Audit N extra structurally-valid synthesized requests induced from the crawl. |
| `--browser-xss` / `--spa` | Headless-browser DOM-XSS execution / SPA endpoint recovery (browser confined to the in-scope host). |
| `--transfer-archetype NAME` | Warm-start the check-ordering bandit from smoothed cross-engagement priors for this archetype. |
| `--oob-relay-url URL` | Poll an operator-hosted `collaborator` relay to unlock blind-class (SSRF/XXE/OOB-SQLi) confirmation on remote targets. The relay host must be charter-allowlisted. |
| `--no-chaining` | Skip the forward attack-path reasoning pass. |
| request/page budgets | `--request-budget`, `--max-pages`, `--max-audit-requests`. |

### 3.3 The opt-in autonomous loop

`engage --autonomous` runs one bounded **OODA cycle** over the authoritative scan result: it constructs
the goal-tree planner over the run's world-model, picks the highest-value next action (a leaf on the
best route to a crown jewel), drives it as a **gated tool call**, folds the observation back in, and
re-orients. This is the one place the ACP planner actually runs — the default `engage` loop does not
drive it.

```bash
python3 -m framework.v2 engage your-app https://your-app.example.com/ \
    --autonomous --autonomous-cycles 2 --autonomous-budget 8 --spine
```

The first tool slice is the **safe** built-in `reverify_finding` (re-fire a finding's own certificate —
deterministic, no egress). With a reachable LLM backend it also consults the advisory reasoning hook
(which surface/hypothesis to prioritise); with no backend it runs on the deterministic planner alone.
Honest scope: this is a **one-cycle, localhost/authorized** loop, not an unattended frontier-autonomy
engine (README §13). Off by default = byte-identical.

### 3.4 Reports and machine export (SARIF/JSON)

`report` deterministically assembles the three operator documents (executive / technical / remediation)
from the blackboard, or exports machine formats over the *same* graded findings:

```bash
# The three Markdown documents into targets/your-app/reports/:
python3 -m framework.v2 report your-app

# SARIF 2.1.0 for a CI code-scanning dashboard (or --format json for any structured consumer):
python3 -m framework.v2 report your-app --format sarif --out ./out/

# From a saved JSON findings doc instead of the blackboard, straight to stdout:
python3 -m framework.v2 report --from-json report.json --format json --stdout
```

Every exported finding states its `grounding` — `fact` (its retained proof re-fired at export),
`demoted` (recorded confirmed but no longer reproduces), or `lead` (no oracle signal). In SARIF, only a
FACT is levelled by its severity; a LEAD is capped at `note` and tagged `grounding=lead`, so a CI gate
is never *blocked* by an unproven lead yet still sees it.

### 3.5 Re-verify a saved report offline

Because oracles are pure, **anyone** can re-verify a saved engagement with no target, months later:

```bash
python3 -m framework.v2 verify report.json
```

It re-fires each finding's retained oracle certificate. Exit `0` iff every one reproduces *and* matches
its claim (it refuses to re-confirm a relabelled certificate — SQLi evidence cannot be re-stamped as
RCE). Fully offline, no LLM. For signed, tamper-evident bundles, use `evidence keygen | certify |
verify`.

### 3.6 Recon / intel

The intel engine *reasons over* OSINT into the shared world-model. **Offline by default** — a disabled
transport raises on any fetch; live sources are an explicit code-level opt-in, never a surprise flag.

```bash
# Offline (bundled/captured fixtures), persisted under an engagement slug:
python3 -m framework.v2 intel ingest --seed your-app.example.com --slug your-app

# Live third-party sources (DNS / crt.sh / RDAP / ASN) — GATED opt-in; collector hosts must be
# disjoint from the target scope:
python3 -m framework.v2 intel ingest --seed your-app.example.com --live --slug your-app

# File-ingest adapters (all offline):
python3 -m framework.v2 intel ingest-cloud --file cloud-inventory.json --slug your-app
python3 -m framework.v2 intel ingest-sbom  --file sbom.json            --slug your-app
python3 -m framework.v2 intel ingest-intel --file feed.json --format misp --slug your-app

# Reason over the result:
python3 -m framework.v2 intel resolve --slug your-app     # resolved entities + merge explanations
python3 -m framework.v2 intel plan --seed your-app.example.com   # recon plan ranked by value-of-info
```

None of this touches the target itself; collectors query third-party sources, and predictions are
**gated** (never auto-scanned). `engage --recon` runs the same engine inline against the *same*
world-model the findings chain over.

### 3.7 Running a sensor / importing third-party output

CRUCIBLE integrates external tools as **gated sensors** that mint *leads*; a lead becomes a *fact* only
when a CRUCIBLE oracle re-verifies it. List the catalog (read-only, deterministic):

```bash
python3 -m framework.v2 capabilities
```

```
CRUCIBLE capability catalog
===========================
sensors (13):
  nmap              T2 active_recon   Drive `nmap` (gated) against a single in-scope target …
  sbom_vuln         T1 ungated        Ingest a grype / osv-scanner JSON report → vulnerable-dependency leads.
  kube_bench        T1 ungated        Ingest a kube-bench `--json` report → CIS-control-failure LEADS.
  fuzz_harness      T3 exploit_execution destructive   Drive a bounded fuzz against an authorized LOCAL binary …
  …
tools (1):
  reverify_finding  T1 ungated        Re-verify a finding's retained oracle certificate OFFLINE, on demand.
oracles (19): …
```

Each sensor lists its **tier** (T1 ungated / T2 active-recon / T3 exploit-execution) so you know what
gate it trips. Import a third-party tool export as re-verifiable leads:

```bash
# Dry (prints the leads it would create):
python3 -m framework.v2 imports nuclei-out.jsonl --format nuclei

# Persist to the intel store under a slug:
python3 -m framework.v2 imports zap-report.json --format zap --slug your-app --persist
```

Formats: `nuclei`, `zap`, `burp`, `sqlmap`, `generic`. The tool's own verdict is never trusted — it is
a provenance-tagged lead until an oracle re-fires over the retained evidence.

### 3.8 The defender (purple-team) pass

The `defender` subsystem is the constructive alternative to evasion: it models *how loud you are* and
where the operator's detections have gaps. Standalone:

```bash
python3 -m framework.v2 defender score --kind injection_probe --surface /login --method POST
python3 -m framework.v2 defender rules      # list the active detection ruleset
```

Or fold it into a real engagement (opt-in; read-only; sends no traffic; off = byte-identical):

```bash
python3 -m framework.v2 engage your-app https://your-app.example.com/ \
    --defender --defender-sigma ./sigma-rules/ --defender-log ./siem-export.log
```

That reports detection **gaps** over the confirmed findings, synthesizes a candidate Sigma rule per
miss, scores an operator Sigma ruleset's efficacy (mapped to ATT&CK), and evaluates it against
operator-supplied **offline** logs. A test asserts no evasion vocabulary ever appears — this measures
detection, it never defeats it.

---

## 4. AEGIS — the defensive dual (embedding it)

AEGIS points the same prove-don't-guess core *inward*: it detects **AI-application attacks** against an
app you run — prompt injection / jailbreak, system-prompt disclosure, automated access (honeypot-
proven), and credential stuffing / account takeover — and returns an **oracle-confirmed verdict with a
re-runnable certificate**. It is defensive-only, lazy-imported, and never touched by
`scan`/`engage`/`benchmark`.

See it work end-to-end, fully offline:

```bash
python3 -m framework.v2 aegis demo
```

```
certificate re-verifies offline: True
{
  "decision": "confirmed",
  "attack_class": "system_prompt_disclosure",
  "confidence": 0.99877,
  "top_alternative": ["benign-instruction-echo", 0.00086],
  "certificate": { "cert_id": "aegis-cert:…", "confirmed_by": "system_prompt_disclosure", … },
  "provenance": "grounded:aegis:system_prompt_disclosure",
  "action": "observe"
}
```

`decision == "confirmed"` guarantees a re-runnable certificate; `provenance == "grounded:…"` guarantees
an oracle fired *and* the veracity firewall re-admitted it. The `top_alternative` is the MECE benign
twin — the honest false-positive guard.

**Detecting over your own telemetry**, one envelope at a time:

```bash
python3 -m framework.v2 aegis detect ./telemetry-envelope.json \
    --canary "YOUR-PLANTED-CANARY" --honeypot "/seeded/trap/path"
```

**Embedding it in a web app.** Wire the middleware/guard (`framework/v2/aegis/middleware.py`,
`aegis/guard.py`) to hand each request's telemetry to `detect()` in-process, or shell out to
`aegis detect` from your own service. The verdict is deterministic (same evidence → byte-identical
verdict + certificate id), so you can log the certificate and re-verify any alert offline later.

---

## 5. Operator surfaces: console, API, MCP

All three are loopback/stdio, gated, and read-only-or-gated-action — none can promote a claim the oracle
refused.

```bash
# Read-only operator console — a UI over the run (live progress; three SAFE actions only:
# launch a gated loopback scan, re-verify a saved run, trip the kill-switch). 127.0.0.1 only.
python3 -m framework.v2 console --open        # default port 8787

# Loopback gated external API — a read core plus gated actions through the SAME fail-closed chain
# as a local action. Optional bearer / X-Relay-Key auth:
export CRUCIBLE_API_KEY="$(head -c32 /dev/urandom | base64)"   # optional; fail-closed if set-but-empty
python3 -m framework.v2 api --port 8799        # 127.0.0.1 only

# MCP tool-server — expose this engagement's charter-bound gated capabilities as MCP tools (stdio),
# or preview them without serving:
python3 -m framework.v2 mcp list  --slug your-app
python3 -m framework.v2 mcp serve --slug your-app
```

An unauthorized action over the API or MCP is REFUSED exactly as it would be locally — the gate chain is
the same code path, not a re-implementation.

---

## 6. Trust: benchmark and the regression gate

CRUCIBLE holds *itself* to prove-don't-guess. The credibility spine runs it against a labelled
in-process benchmark app (real single-class bugs **plus safe controls a precise scanner must leave
alone** — the controls are the false-positive ruler) and fails on any regression versus the committed
baseline. No Docker, no external tools:

```bash
make gate           # regression-gate (CI): exit non-zero on a new FP, a missed finding, or a precision drop
make bench          # print the full benchmark table + write benchmark-report.md
make test           # the full framework/v2 suite (~270 test files, almost all deterministic + offline)
make bench-corpus   # dockerized multi-app corpus (needs Docker; skips heavy apps honestly)
```

Determinism is a *testable* invariant: there is no wall-clock or global RNG in the
learning/reward/spine/normalization math, so every capability change must keep `make gate`
byte-identical. That is why so much of §3 is flagged "off = byte-identical."

---

## 7. The controls: entitlement, kill-switch, sovereignty

**Kill-switch** — a file on disk, so a trip survives a process restart and halts the *next* request
anywhere (this CLI, another process, the console). Fail-closed: an ambiguous read counts as tripped.

```bash
python3 -m framework.v2 authority halt   --slug your-app --reason "pausing — investigating a 5xx spike"
python3 -m framework.v2 authority status --slug your-app
python3 -m framework.v2 authority clear  --slug your-app --by "you@example.com"   # deliberate, logged
```

**Capability entitlement** — high-impact capabilities (exploit execution, deep static analysis,
defender telemetry, full-chain exploitation) require a valid, host-bound, unrevoked, m-of-n
Ed25519-signed entitlement over a capability ladder. Baseline reasoning and intake always work;
everything else fails closed *once enforcement is on*.

```bash
python3 -m framework.v2 entitlement status
```

```
CRUCIBLE entitlement status
---------------------------
  enforced     : False
  granted tier : —
  summary      : enforcement INACTIVE — no trust root provisioned; baseline core runs, gated
                 capabilities permitted with a logged warning
```

Out of the box it is **UNGOVERNED** (as shown). To govern it, provision a trust root and set
`CRUCIBLE_ENTITLEMENT_ENFORCED`; `entitlement capabilities` then shows per-capability availability, and
`entitlement verify` health-checks the provisioned material.

**Sovereignty tiers** — the *data* counterpart to the *action* gates: they control which LLM backends
may even be constructed (§1). `status` shows the tier and whether it is `[SEALED]`. Sealing can only
tighten the tier, never relax it, for the process lifetime.

The doctrine-maximum **Tier-3 validation layer** (`agents/tier3_validation.py`) is **entitlement-gated
OFF by default** and does exactly one thing when everything says yes: re-fire the minimal proof an
oracle already fired on, against a localhost/authorized target, with a human approving that action. It
mints no payloads and does no lateral movement — it *validates*, it does not weaponize.

---

## 8. Offline vs live — what needs an LLM backend

| Workflow | Runs offline (no LLM)? | Notes |
|---|---|---|
| `scan`, `engage` (confirmation path) | **Yes** | The scanner and oracles need no LLM. Confirmation is pure deterministic code. |
| `verify`, `evidence`, `report`, export | **Yes** | Re-execution of retained certificates; deterministic rendering. |
| `intel ingest` (default), file-ingest | **Yes** | Offline by default; `--live` is a gated opt-in. |
| Sensors, `imports`, `capabilities` | **Yes** | Sensors mint leads; oracles re-verify. Some sensors need the external binary (nmap/tshark/…). |
| `aegis detect` / `demo` | **Yes** | Fully deterministic; the demo self-verifies offline. |
| `make gate` / `make test` | **Yes** | Deterministic, no network (a couple of opt-in integration tests aside). |
| `kernel` bindings, `--autonomous` reasoning hop, self-consistency, no-oracle severity/chain judgments | **Bounded offline** | With no reachable backend the reasoning kernel returns deterministic **DryRun** fixtures — everything runs, reasoning *quality* is bounded. A reachable backend (per your sovereignty tier) improves the *advisory* half only; it can never promote a finding. |

The takeaway: the parts that decide *what is true* are deterministic and offline; a live LLM backend
only improves the parts that decide *where to look* — and even then, the oracle remains the sole
authority.

---

*Last reconciled against the tree: `c7d9814` (2026-07-11). If a command's flags have drifted, the
dispatch table in `framework/v2/__main__.py` and each subcommand's arg parser are the contract.*
