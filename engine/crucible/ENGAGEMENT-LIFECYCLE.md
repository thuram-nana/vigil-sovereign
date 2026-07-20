# Engagement lifecycle

The full lifecycle from first contact with a new target to long-term
continuous testing. Most engagements pass through every stage, in
roughly this order, though stages 4–6 are heavily interleaved in
practice.

This is not a phase gate where you must finish stage N completely
before starting stage N+1. It is a structure that guarantees nothing
is forgotten.

---

## 0. Charter — authorization and intent

**Goal:** establish written, scope-bounded authorization and clear
objectives.

**Output:** `targets/<name>/charter.md` (signed by operator).

Includes:
- Operator's attestation of ownership / authority.
- In-scope hosts, services, surfaces.
- Out-of-scope (explicit list — third parties, sister sites, etc.).
- Hard limits (no DoS, no real money beyond $X, no withdrawals, etc.).
- Soft limits (off-peak window, max scan concurrency, no Tor).
- Posture (TEST / AUDIT / EMULATE).
- Objectives (what would success look like?).
- Stop conditions.
- Communication channels.
- Source-code delivery point (typically stage 7).

**Gate to next stage:** operator confirms charter is final.

---

## 1. Threat model — where will adversaries push

**Goal:** map assets, actors, trust boundaries, and the attack tree.

**Output:** `targets/<name>/threat-model.md`,
`targets/<name>/attack-tree.md`.

Read `framework/cognitive/threat-modeling.md`. Build the model in
this order:

1. Assets (what would adversaries want?)
2. Actors (who would attack?)
3. Trust boundaries (where do data and control cross privilege?)
4. STRIDE per boundary (six classes)
5. Attack tree (root: adversary objectives; leaves: testable
   techniques)

The attack tree drives stages 4–6. You will mark each leaf as you
test it.

**Gate to next stage:** operator reviews threat model and confirms
priorities.

---

## 2. Recon — passive then active

**Goal:** complete external picture of the target without missing
hosts, surfaces, or technology hints.

**Outputs:** `targets/<name>/recon/passive/`,
`targets/<name>/recon/active/`.

### 2.1 Passive

- Cert transparency, subdomain enum (no direct queries).
- Wayback / archive.
- Search engine and GitHub dorks.
- Paste / leak site sweep.
- Public API doc review.
- Asset and platform fingerprinting from public artifacts.

Playbook: `framework/playbooks/01-passive-recon.md`.

### 2.2 Active (touches target)

- HTTP probe of in-scope hosts.
- TLS audit, header audit.
- Light port scan of in-scope hosts.
- Web fingerprinting (whatweb, httpx tech-detect).
- Low-noise nuclei sweep (exposures, misconfigurations, technologies).
- "Obvious leaks" pass (`.env`, `.git`, backups, debug pages).
- robots.txt, sitemap, security.txt, well-known.

Playbook: `framework/playbooks/02-active-recon.md`.

**Gate to next stage:** asset inventory complete; immediate criticals
from leaks pass surfaced.

---

## 3. Attack surface mapping

**Goal:** enumerate every endpoint, parameter, role, and data flow.
The mapping is the foundation for stages 4–6.

**Outputs:** `targets/<name>/recon/enum/inventory.md`,
`role-matrix.md`, `dataflow.md`.

- Authenticated crawl per role (manual + Burp + katana).
- Content discovery (ffuf with curated wordlists).
- API endpoint enum from JS bundles.
- Parameter discovery (arjun, burp-parameter-names).
- HTTP method enum on interesting endpoints.
- Build the role × endpoint matrix.
- Map data flows (user input → controller → DB → output).

Playbook: `framework/playbooks/03-attack-surface-mapping.md`.

**Gate to next stage:** every endpoint and parameter has a row;
every cell of the role matrix has been observed once.

---

## 4. Vulnerability hunting (per domain)

**Goal:** for every applicable surface, run the relevant playbook.
This is where most calendar time goes.

Domains (run those that apply to the target):

| Domain | Playbook |
|--------|----------|
| Web application | `04-web-application.md` |
| API security | `05-api-security.md` |
| Authentication & identity | `06-authentication-identity.md` |
| Authorization | `07-authorization.md` |
| Injection (SQL/NoSQL/OS/SSTI/XXE) | `08-injection.md` |
| Client-side (XSS/CSRF/clickjacking/postMsg) | `09-client-side.md` |
| Business logic | `10-business-logic.md` |
| Cryptography | `11-cryptography.md` |
| Network / infrastructure | `12-network-infrastructure.md` |
| Cloud (AWS/GCP/Azure) | `13-cloud-native.md` |
| Container / Kubernetes | `14-container-kubernetes.md` |
| CI/CD / supply chain | `15-cicd-supply-chain.md` |
| Microservices / service mesh | `16-microservices.md` |
| Mobile (Android/iOS) | `17-mobile.md` |
| LLM / AI integration | `18-llm-ai-security.md` |
| SSO / federated identity | `19-sso-federated.md` |

Use the cognitive framework throughout: hypothesis-driven testing,
critique cadence, pivot when stuck.

Findings go to `findings/NNN-slug.md` the moment they're confirmed.

**Gate to next stage:** every surface in the inventory has been
tested by every relevant domain; every attack tree leaf has a
status (tested / vulnerable / blocked / deferred).

---

## 5. Exploitation — confirm impact, chain bugs

**Goal:** for each finding, confirm real-world impact (don't stop at
"theoretically exploitable"). For bugs that look small individually,
search for chains that compose them into something larger.

- Reproduce each finding from a clean state.
- Quantify impact (time, privilege gained, data accessed, money
  moved).
- Identify chains: which findings unlock which?
- Document chains as `findings/CHAIN-NNN-slug.md`.

Read `framework/cognitive/kill-chain.md`. The chain narrative is what
makes the executive report compelling.

**Gate to next stage:** every finding has a working PoC; chains are
identified and documented.

---

## 6. Post-exploitation (per ROE)

**Goal:** demonstrate consequences in keeping with the charter. Most
owner-tests stop here at "proven exploitable" without actually post-
exploiting on production. Charters that authorize post-exploit
detail the limits.

Playbook: `framework/playbooks/21-post-exploitation.md`,
`22-data-exfiltration-impact.md`.

Skip this stage entirely unless the charter authorizes it.

---

## 7. Source code review (white-box)

**Goal:** with source in hand, verify black-box hypotheses, find
bugs the black-box pass missed, and prepare patches.

**Trigger:** operator delivers source to `targets/<name>/loot/source/`.

Playbook: `framework/playbooks/20-source-code-review.md`.

Outputs:
- Re-ranked finding list (some upgrade, some downgrade after seeing
  the actual code).
- New findings only visible from source.
- Per-finding: file:line and proposed minimal patch.

**Gate to next stage:** source review complete; finding list final.

---

## 8. Reporting

**Goal:** deliver three reports the operator can act on.

- **Executive** (`reports/executive.md`) — 2 pages, plain language,
  business-impact framing.
- **Technical** (`reports/technical.md`) — full findings list, PoCs,
  remediation, appendices.
- **Remediation roadmap** (`reports/remediation-roadmap.md`) —
  prioritized by impact × effort, sequencing, dependencies.

Optional: **Threat model document** as a deliverable
(`reports/threat-model.md`).

Playbook: `framework/playbooks/24-reporting-deliverables.md`.

**Gate to next stage:** operator confirms reports are clear and
actionable.

---

## 9. Remediation validation (retest)

**Goal:** for each finding, verify the fix works and didn't introduce
regression.

Per finding:
- Re-run the original PoC.
- Status: Verified Fixed / Partially Fixed (with sub-finding) /
  Bypassed / Risk Accepted / Will Not Fix.
- Variants: try encoding/case/whitespace variants to ensure pattern-
  matching fixes aren't trivially bypassed.

Output: `reports/retest.md`.

Playbook: `framework/playbooks/23-remediation-validation.md`.

**Gate to next stage:** every finding has a final status; retest
report delivered.

---

## 10. Continuous testing

**Goal:** keep the security posture from regressing as the product
evolves. Unlike one-shot pentests, ongoing posture management is what
keeps real adversaries out long-term.

Cadence options:

- **Quarterly self-driven re-engagement** using this same framework
  against a snapshot of the target.
- **Per-release smoke tests** running a curated subset of the
  playbooks against new endpoints / changed flows.
- **Monitoring** of the public-facing surface for new exposures
  (subdomain takeovers, leaked secrets, exposed services) — semi-
  automated.
- **Annual external pentest** by an independent firm at a major
  release or before institutional partnerships.

Playbook: `framework/playbooks/25-continuous-testing.md`.

The continuous-testing structure is set up in
`targets/<name>/notes/continuous-testing-plan.md` after stage 9.

---

## 11. Engagement closure

When stages 0–9 are complete:

- Confirm all test artifacts are cleaned up
  (`notes/test-artifacts.md`).
- Rotate any credentials shared during the engagement.
- Archive the working directory (consider gitignored remote backup).
- Update the threat model with what was actually learned for use in
  future re-tests.
- Brief the operator on the continuous-testing plan.

Engagement is closed. The target's working directory persists for
re-tests.

---

## Stage-by-stage outputs reference

| Stage | Primary output | Location |
|-------|---------------|----------|
| 0 | Charter | `targets/<name>/charter.md` |
| 1 | Threat model + attack tree | `targets/<name>/threat-model.md`, `attack-tree.md` |
| 2 | Recon outputs | `targets/<name>/recon/{passive,active}/` |
| 3 | Inventory + role matrix | `targets/<name>/recon/enum/` |
| 4 | Findings | `targets/<name>/findings/NNN-*.md` |
| 5 | Chain findings | `targets/<name>/findings/CHAIN-NNN-*.md` |
| 6 | Post-exploit notes (if any) | `targets/<name>/notes/post-exploit.md` |
| 7 | Source-review notes | `targets/<name>/notes/source-review.md` |
| 8 | Reports | `targets/<name>/reports/{executive,technical,remediation-roadmap}.md` |
| 9 | Retest | `targets/<name>/reports/retest.md` |
| 10 | Continuous plan | `targets/<name>/notes/continuous-testing-plan.md` |
