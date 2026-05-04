# CRUCIBLE — Offensive security framework

A reusable, multi-target, reasoning-driven framework for self-directed
penetration testing and adversary emulation across all your owned
applications.

Open in **Claude Code**. The agent reads `CLAUDE.md` automatically and
operates as **OBSIDIAN**, a senior offensive security operator who
follows a structured cognitive loop (observe → orient → hypothesize →
test → update → critique → pivot) rather than a static checklist.

This is not specific to any one application. Each application you own
becomes a target instance under `targets/<name>/`, sharing the
framework's playbooks, knowledge base, scripts, and templates.

---

## What's different from a checklist tool

- **Reasoning-driven, not script-driven.** OBSIDIAN forms hypotheses,
  designs falsifying tests, and updates its model from results.
  Checklists are coverage receipts at the end, not the engine in the
  middle.
- **Multi-target.** One framework, many engagements. Migrate between
  targets without re-installing tooling.
- **Standard-aligned.** OWASP WSTG / ASVS / API Top 10 / LLM Top 10,
  MITRE ATT&CK, PTES, NIST 800-115, PASTA — mapped explicitly so
  findings translate to compliance and detection contexts.
- **Self-aware.** Built-in critique routines force the agent to ask
  "what am I missing?" at every phase boundary and every 30 minutes
  of stuck thread.
- **Persistent.** The agent doesn't quit on a target — only on a
  thread. Pivot protocols generate alternatives systematically when
  blocked.
- **Coverage across all modern surfaces.** Web, API, auth/identity,
  cloud, containers, CI/CD, microservices, mobile, LLM/AI, supply
  chain, source code review, post-exploitation — playbook for each.

---

## Quick start

```bash
# 1. Open the framework in Claude Code
cd crucible
claude

# 2. Tell OBSIDIAN which target you're working on (or to start a new one)
#    See HOW-TO-START.md for the literal first message text.

# 3. OBSIDIAN reads CLAUDE.md, locates or creates the target's working
#    directory, walks you through the charter, and begins.
```

If you have not yet installed tools:
```bash
bash framework/tools/install.sh
bash framework/tools/verify.sh
```

---

## Layout

```
crucible/
├── CLAUDE.md                       # Agent constitution (read first)
├── README.md                       # This file
├── HOW-TO-START.md                 # First-message text for new sessions
├── ENGAGEMENT-LIFECYCLE.md         # Stage-by-stage flow
│
├── framework/                      # Shared, target-agnostic
│   ├── cognitive/                  # How OBSIDIAN thinks
│   │   ├── reasoning-loops.md
│   │   ├── threat-modeling.md
│   │   ├── hypothesis-driven.md
│   │   ├── pivot-protocols.md
│   │   ├── self-critique.md
│   │   ├── kill-chain.md
│   │   ├── opsec-discipline.md
│   │   └── decision-frameworks.md
│   │
│   ├── playbooks/                  # What OBSIDIAN tests, per domain
│   │   ├── 00-pre-engagement.md
│   │   ├── 01-passive-recon.md
│   │   ├── 02-active-recon.md
│   │   ├── 03-attack-surface-mapping.md
│   │   ├── 04-web-application.md
│   │   ├── 05-api-security.md
│   │   ├── 06-authentication-identity.md
│   │   ├── 07-authorization.md
│   │   ├── 08-injection.md
│   │   ├── 09-client-side.md
│   │   ├── 10-business-logic.md
│   │   ├── 11-cryptography.md
│   │   ├── 12-network-infrastructure.md
│   │   ├── 13-cloud-native.md
│   │   ├── 14-container-kubernetes.md
│   │   ├── 15-cicd-supply-chain.md
│   │   ├── 16-microservices.md
│   │   ├── 17-mobile.md
│   │   ├── 18-llm-ai-security.md
│   │   ├── 19-sso-federated.md
│   │   ├── 20-source-code-review.md
│   │   ├── 21-post-exploitation.md
│   │   ├── 22-data-exfiltration-impact.md
│   │   ├── 23-remediation-validation.md
│   │   ├── 24-reporting-deliverables.md
│   │   ├── 25-continuous-testing.md
│   │   └── 26-incident-response-pivot.md
│   │
│   ├── knowledge-base/             # What OBSIDIAN knows
│   │   ├── attack-techniques/      # Per-technique deep refs
│   │   ├── standards-mapping.md    # OWASP/MITRE/PTES/NIST cross-ref
│   │   ├── platform-fingerprints.md
│   │   ├── default-credentials.md
│   │   ├── common-misconfigurations.md
│   │   └── defense-patterns.md
│   │
│   ├── tools/                      # Tooling layer
│   │   ├── tool-catalog.md
│   │   ├── install.sh
│   │   └── verify.sh
│   │
│   ├── scripts/                    # Reusable scripts (not target-specific)
│   ├── templates/                  # Charter, threat model, finding, reports
│   ├── checklists/                 # Coverage receipts
│   └── wordlists/                  # Pointers to SecLists + custom lists
│
└── targets/                        # Per-engagement working directories
    ├── README.md
    ├── _template/                  # Copy this to start a new target
    └── <your-target-name>/         # e.g. app1, app2, internal-crm, ...
        ├── charter.md
        ├── threat-model.md
        ├── attack-tree.md
        ├── recon/
        ├── findings/
        ├── evidence/
        ├── notes/
        ├── loot/
        └── reports/
```

---

## Starting a new target

```bash
# Copy the template
cp -r targets/_template targets/<new-target-name>

# Tell OBSIDIAN about the new target — see HOW-TO-START.md
```

Then OBSIDIAN walks you through stage 0 (charter) for the new target.

---

## Working with multiple targets

Each session, tell OBSIDIAN which target is active. Working files
are isolated per-target; shared framework files are read-only from
the engagement perspective. You can pause a target mid-engagement
and resume later — the working directory carries the state.

---

## Standards and references

Findings carry standards mappings where applicable:

- **OWASP** Web Security Testing Guide (WSTG), Application Security
  Verification Standard (ASVS), API Security Top 10, LLM Top 10,
  Mobile Application Security Verification Standard (MASVS).
- **MITRE ATT&CK** Enterprise tactics and techniques.
- **PTES** (Penetration Testing Execution Standard) phases.
- **NIST SP 800-115** technical guide to information security
  testing.
- **CWE** Common Weakness Enumeration for finding root cause.
- **CVSS 3.1** for severity, with explicit contextual adjustment.
- **CIS Benchmarks** for cloud and container hardening.

See `framework/knowledge-base/standards-mapping.md`.

---

## Safety

Read `CLAUDE.md` § II (Authorization) and `framework/cognitive/opsec-discipline.md`
before authorizing any engagement. The framework is designed for
**owner-test** of systems you own and have the authority to test.
Default OPSEC posture is identifiable, throttled, and tagged so you
can correlate scan traffic in your own logs.

The agent will refuse to attack systems not in scope, decline to
disable OPSEC controls without explicit charter authorization, and
stop on signs of degraded service or evidence of prior compromise.

---

## Where to read first

If you are the operator about to use this:

1. `README.md` — this file (already done).
2. `HOW-TO-START.md` — the literal first message to give OBSIDIAN.
3. `ENGAGEMENT-LIFECYCLE.md` — what an engagement looks like.
4. `framework/templates/charter.md` — preview the charter you'll fill
   in for the first target.

If you are OBSIDIAN booting up:

1. `CLAUDE.md` — your constitution.
2. The active target's `charter.md` and `notes/engagement-log.md`.
3. The relevant cognitive framework file for the current stage.
4. The relevant playbook for the current domain.

---

## CRUCIBLE v2

`framework/v2/` adds an executable layer on top of v1 without
modifying any v1 file. Five working subsystems ship today:

- **URK** (`framework/v2/kernel/`) — wraps each cognitive doc as a
  typed callable. `hypothesize / critique / pivot / decide / opsec /
  threat_model` take inputs, prompt an LLM (Anthropic / Claude Code /
  Ollama / a deterministic DryRun fallback), and return Pydantic-
  validated results.
- **MLS** (`framework/v2/memory/`) — persistent SQLite + embeddings
  store of every engagement, finding, hypothesis, payload, and dead
  end. Queryable from the CLI; biases future intakes toward what
  actually paid off.
- **UTI** (`framework/v2/intake/`) — drop *any* operator-authorised
  URL, get a fully scaffolded `targets/<slug>/` directory with
  charter draft, threat model, attack tree, and structured
  fingerprint JSON. Honours the ethics gates: no scaffolding without
  operator-attested authorization; no active testing until the
  operator signs `charter.md`.
- **MAO** (`framework/v2/agents/`) — blackboard + coordinator + 5
  specialist agents (recon, hypothesis, exploit, critique, reporter)
  + memory-agent. Append-only event log; critique gate vetoes weak
  findings before they reach the report.
- **ACP** (`framework/v2/planner/`) — goal-tree-driven autonomous
  campaign planner with budget, pruner, watchdog, and resume.
  Drives MAO end-to-end from URL to report.

Three further subsystems (DAA, DEL, SIL) are designed but deferred.
See `V2-MANIFEST.md` for status and `V2-LIMITATIONS.md` for what v2
*cannot* do.

```bash
# one-time setup
bash bin/init.sh
pip install --break-system-packages -r framework/v2/requirements.txt

# verify
python3 -m framework.v2 status

# the universal command — drop any operator-authorised URL
python3 -m framework.v2 intake authorize https://your-app.example.com --operator yourname
python3 -m framework.v2 intake https://your-app.example.com

# query the memory substrate
python3 -m framework.v2 memory similar --text "describe a stack you care about"
python3 -m framework.v2 kernel critique --claim "..."
```
