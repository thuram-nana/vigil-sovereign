# `targets/` — Per-Engagement Workspaces

> Each subdirectory under `targets/` is an **isolated engagement workspace**. The `framework/` is shared and read mostly; everything you produce during an engagement (recon data, findings, evidence, drafts, reports) lives under your target's directory.

---

## Why This Separation?

- **Reuse without contamination.** The framework is the playbook; the target directory is the case file. A new engagement starts by copying `_template/` to `targets/<name>/`, not by reaching into the framework.
- **OPSEC.** Loot, credentials, and PII never leave their target directory. `.gitignore` keeps `loot/` out of any repo by default.
- **Reporting clarity.** Each target produces its own `reports/` artifacts referencing its own findings. Cross-target generalizations belong in the framework knowledge base, not in any single target.
- **Multi-target operators.** OBSIDIAN must be able to switch from `targets/clientA/` to `targets/clientB/` without state bleed.

---

## Structure

```
targets/
├── README.md                    ← this file
├── _template/                   ← skeleton; copy this to start a new engagement
│   ├── README.md                ← explains how to instantiate
│   ├── charter.md               ← scope & authorization (REQUIRED — fill before any test)
│   ├── threat-model.md          ← actor/asset/attack analysis
│   ├── attack-tree.md           ← top objectives broken down to leaf attacks
│   ├── recon/                   ← passive & active recon outputs
│   ├── findings/                ← FINDING-NNN-slug.md and CHAIN-NNN-slug.md
│   ├── evidence/                ← screenshots, request/response captures, PoC outputs
│   ├── notes/                   ← engagement-log.md, command-log.md, hypotheses.md, etc.
│   ├── loot/                    ← extracted credentials, tokens — gitignored
│   └── reports/                 ← deliverables for the client
│
└── <target-name>/               ← one per engagement
```

## Starting a New Engagement

```
# 1. Copy the template.
cp -r targets/_template targets/clientname

# 2. Fill the charter FIRST. No reconnaissance, no scanning, until charter is signed/agreed.
$EDITOR targets/clientname/charter.md

# 3. Build the threat model and attack tree from charter assumptions.
$EDITOR targets/clientname/threat-model.md
$EDITOR targets/clientname/attack-tree.md

# 4. Begin engagement-log.md and command-log.md as you work.
# 5. Follow the methodology: framework/playbooks/00-pre-engagement.md → 26-incident-response-pivot.md.
```

## Naming Convention

Use a short, lowercase, hyphen-or-underscore-free slug for the target directory: `acme-portal`, `clientb`, `acme-prod`. Keep it stable across an engagement so paths in reports remain valid.

If the same client has multiple distinct apps, use multiple target dirs: `clientb-portal`, `clientb-api`, `clientb-mobile`. Cross-link in their charters.

## Lifecycle States (visible in `engagement-log.md` header)

| State | Meaning |
|---|---|
| `INITIATED` | Target dir exists, charter incomplete. No testing yet. |
| `AUTHORIZED` | Charter signed/agreed, ready to begin Phase 1. |
| `ACTIVE` | Engagement in progress. |
| `REMEDIATION-VALIDATION` | Findings reported; client patching; retests pending. |
| `CLOSED` | All retests complete, final report delivered. |
| `ARCHIVED` | Workspace frozen, read-only. |

## Cross-Engagement Knowledge

If you discover something during an engagement that is **broadly applicable** (a novel attack pattern, a tool quirk, a defensive configuration that worked or didn't), promote it to the framework:

- New attack technique → `framework/knowledge-base/attack-techniques/<name>.md`.
- New misconfiguration pattern → `framework/knowledge-base/common-misconfigurations.md`.
- New defense idea → `framework/knowledge-base/defense-patterns.md`.
- New tool → `framework/tools/tool-catalog.md`.
- New script → `framework/scripts/<category>/<name>.{py,sh}`.

The framework grows over time; individual targets close.

## Don't

- Don't put framework-wide knowledge in a target dir.
- Don't put target-specific evidence (real users, real URLs) in `framework/`.
- Don't share a target dir between unrelated engagements.
- Don't commit `loot/` or any actual credentials anywhere.
