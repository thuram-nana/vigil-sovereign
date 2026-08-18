# SECURITY — reporting a vulnerability in VIGIL itself

This document is about **VIGIL the software**. It is not about the systems you point
VIGIL at.

- A flaw **in VIGIL** (it leaks a key, it escapes its scope gate, it mints a fact its
  oracle never proved) → report it here.
- A flaw **in a target** that VIGIL found for you → that belongs to the target's owner,
  under your engagement's disclosure terms. Do not send it here.

There is a second, narrower security document at
[`engine/crucible/SECURITY.md`](engine/crucible/SECURITY.md): supply-chain attestation,
the sovereignty-tier ladder, and the sovereign-deployment hardening checklist for the
offense engine. This root document governs the whole monorepo. Where both address the
same subject — the reporting channel and the 90-day coordinated-disclosure window —
they say the same thing, and the engine document is the deeper reference.

---

## 1. Why a VIGIL compromise is high impact

VIGIL is not a scanner you throw at a host and forget. A VIGIL install is a host that
holds, at the same time, **a sovereign signing key** and **another organisation's raw
data**. Treat it as a crown-jewel host and read a bug in it accordingly.

What an attacker who gets code execution or arbitrary file read on a VIGIL host can
reach, as the code stands on this branch:

| Asset | Where | Protection actually in force |
|---|---|---|
| Owner Ed25519 private key — the 1-of-1 sovereign trust root | `~/.sigil/spine/keys/owner.priv` | Sealed at rest **only after** `sigil vault provision` has run against a real TPM. Unprovisioned it is **plaintext behind mode 0600** (`apps/sigil/sigil/governor/identity.py:16-39`, `apps/sigil/sigil/platform/vault.py:19-33`) |
| Offense-plane identity keys (`operator.key`, `offense-spine.key`, `offense-governance.key`) | `.vigil-live/` | Same: sealed only if the offense vault is provisioned; the source states plainly that unprovisioned they are plaintext at rest (`integration/vigil_integration/live/governance_identity.py:14-16, 22-35`) |
| **Client-derived raw HTTP response bodies** | `targets/<slug>/evidence/<action_id>/response.body` | **Not redacted.** Only credential *headers* are masked; the body is protected by owner-only file permissions alone (`engine/crucible/framework/v2/agents/http_executor.py:744-752`, `engine/crucible/framework/v2/common/redact.py:17-49`) |
| Findings and evidence certificates | offense spine + blackboard under `.vigil-live/` | Signed and hash-chained, but a finding's `certificate` is a **documented plaintext boundary** — sealing it would break offline re-verification (`apps/sigil/sigil/spine/envelope.py:58-60`) |
| API keys / service passwords | OS keyring, else sealed `~/.sigil/secrets.sealed`, else **plaintext `~/.sigil/sigil.env` (0600)** | Tiered; the plaintext tier is the fallback when no keyring and no provisioned vault exist (`apps/sigil/sigil/platform/secrets.py:1-7, 82-112`; `bootstrap.sh:341`) |
| Operator identity (OS login, git name/email, hostname, key fingerprint) | every row of `.vigil-live/usage-ledger.jsonl` | Signed plaintext **by design** — the ledger refuses to mint a record with no human handle (`integration/vigil_integration/attestation/models.py:24-45`) |
| Per-user account records (username, role, enrolled public key, sealed TOTP secret, scrypt password hash) | owner-signed grants on `~/.sigil/spine/spine.jsonl` | Credentials are hashed or sealed; **usernames, roles and public keys are plaintext in the record** (`apps/sigil/sigil/governor/accounts.py:207-221`) |

The short version: a VIGIL host compromise is simultaneously a **key compromise**, a
**client-data breach**, and an **audit-trail credibility event**. That is why we would
rather hear about a boring path-traversal here than a clever one anywhere else.

## 2. Supported versions

This repository carries **no release tags** as of this branch (`git tag` returns
nothing). There is consequently no maintained "1.x" line and no backport branch.

| Version | Supported |
|---|---|
| `main`, current HEAD | Yes — fixes land here |
| Any older commit / vendored snapshot | No. Rebase onto `main` to get a fix |

If you vendored a commit, include the **commit SHA** in your report; we cannot infer it.

## 3. How to report

**Preferred — private GitHub Security Advisory** on the repository
(<https://github.com/thuram-nana/vigil-sovereign>), which keeps the discussion and the
patch private until disclosure.

**Alternative — email.**

| Channel | Detail |
|---|---|
| Security address | `security@thuramnana.com` — *placeholder: confirm this mailbox is monitored before relying on it* |
| Fallback (published maintainer address) | `thuram@thuramnana.com`, subject `VIGIL security report` |
| PGP key | *Not yet published.* Fingerprint placeholder: `<PGP FINGERPRINT — TO BE PUBLISHED>`. Until a key is published, treat email as unencrypted and send only what is needed to triage; hold the full proof-of-concept until we can exchange keys |

**Do not open a public issue, discussion, or pull request that demonstrates the flaw.**
Public-disclosure timing is coordinated between you, the maintainer, and any deployment
known to be affected.

A useful report contains: the commit SHA; which plane is affected (sovereign / offense /
gateway / console); a reproduction; what boundary it crosses (see § 5); and your view of
the impact. A proof-of-concept that runs against **your own** installation is welcome.

## 4. Response window

These are **targets** the maintainer aims at, not a contractual SLA. VIGIL is maintained
by one person; there is no 24/7 rota and no institutional vulnerability-coordination home
yet (`engine/crucible/SECURITY.md` § 5 says the same).

| Stage | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Triage — reproduced or rejected, with reasoning, and a severity | 10 business days |
| Fix for a critical / key-or-client-data-exposing issue | 30 days from triage, or a written explanation of why longer |
| Fix for everything else | The next change landing on `main`, or 90 days |
| Coordinated public disclosure | **90 days** from initial report, extendable by mutual agreement — the same window as `engine/crucible/SECURITY.md` § 3.4 |

If you do not hear back within the acknowledgement window, resend. Silence is a failure
of the process, not a decision.

## 5. In scope — what counts as a VIGIL vulnerability

Anything that breaks a boundary VIGIL claims to hold:

- **Charter / scope gate bypass** — reaching a host the signed charter does not authorise
  (`engine/crucible/framework/v2/common/ethics.py:129, 283, 357`,
  `engine/crucible/framework/v2/agents/scope_gate.py`).
- **Egress gate bypass** — traffic leaving the sandbox other than via the gateway proxy,
  or reaching a denied range such as cloud metadata (`gateway/README.md`,
  `gateway/vigil_gateway/`).
- **Sovereignty-tier bypass** — a model call made under a tier that forbids it
  (`engine/crucible/framework/v2/kernel/sovereignty.py`,
  `integration/vigil_integration/live/think_claude.py`). See § 6 for what is *not* this.
- **Two-env boundary break** — the sovereign environment importing offense code
  (`integration/tests/test_two_env_boundary.py`).
- **Signature / ledger integrity** — forging an owner signature, editing the spine without
  detection, replaying a governance record to resurrect a revoked grant, or defeating the
  monotonic anti-back-dating anchor.
- **Authorization bypass** — RBAC admission, the WARDEN gate, the kill-switch, or the
  approval queue letting through an action the operator did not authorise.
- **Secret disclosure** — a key, token, or sealed secret reaching a log, a network payload,
  a report, or another engagement's directory.
- **Cross-engagement leakage** — one target's evidence, findings, or priors visible to
  another engagement.
- **A false FACT** — VIGIL asserting a finding as oracle-verified when the oracle did not
  fire, or asserting CLEAN where coverage was not established. Under
  [`docs/CLAIM-DISCIPLINE.md`](docs/CLAIM-DISCIPLINE.md) that is a security bug, not a
  quality bug, and a false CLEAN is the worse of the two.
- **Prompt injection with real consequence** — target-controlled or document-controlled
  text that causes an action outside the charter, an egress, or a fact-mint. Injection that
  only produces wrong prose is a quality issue.

## 6. Out of scope, or already documented

Not vulnerabilities. Reporting a *bypass* of any of these still is.

- **The default sovereignty tier is `PERMISSIVE`.** With no tier set, the offense engine
  may call a commercial cloud model provider, and prompt content can include target data
  and findings (`engine/crucible/framework/v2/kernel/sovereignty.py:195`; the installer
  writes every tier line **commented out**, `bootstrap.sh:326-336`). This is documented,
  deliberate, and the operator's decision to change. A path that egresses to a cloud model
  *after* the operator set `AIR_GAPPED` **is** in scope.
- **A tier stored only in `~/.sigil/sigil.env` does not reach an offense process that
  `vigil up` did not launch.** The engine reads `CRUCIBLE_SOVEREIGNTY_TIER` from the process
  environment and from nowhere else
  (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`); the sovereign settings
  bridge is what carries the stored value into the children `vigil up` spawns
  (`integration/vigil_integration/uiproxy.py:1631, 1712-1739`) — and it carries it **only at `vigil up`
  start**: the runtime env is resolved once at bring-up (`uiproxy.py:2104`), so a tier changed in
  Settings while the UI is already running reaches only the offense children of a *subsequent*
  `vigil up`. A run launched from the UI after the change keeps the tier the UI started with; restart
  `vigil up` (or the `vigil-command` service) for it to take effect. Anything else falls back to
  `PERMISSIVE` silently — **fail-open**. That gap is documented here and in `/PRIVACY.md`
  § 5.1a, so "the tier was set" above means *present in that process's environment*.
- **An unprovisioned vault leaves keys plaintext at rest.** Documented above and in
  `packages/core/vigil_core/vigil_core/vault.py:73-75`. Provision the vault.
- **The finding `certificate` is stored plaintext even with a provisioned vault.** A
  deliberate boundary so a client can re-verify offline.
- **Evidence response bodies are unredacted.** Deliberate — redacting evidence would break
  re-verification. Handle the directory accordingly.
- **Missing hardening the operator chose not to apply** — see the checklist in
  `engine/crucible/SECURITY.md` § 4.
- **A CVE in an upstream dependency** — report upstream first, then tell us once a patch
  exists so we can move the lock.
- **A flaw in a vendored third party** (`vendor/strix/`, `vendor/hexstrike-ai/`) — upstream
  first; tell us if VIGIL's use makes it worse.
- **Findings about a target.** Those go to the target's owner.
- **Anything requiring the attacker to already be the owner.** The owner key is the trust
  root; "with the owner key I can do owner things" is the design.

## 7. Safe harbour for good-faith research

If you research VIGIL in good faith, **against an installation you own or are authorised to
test**, and you follow this document, then the maintainer will not initiate or support
legal action against you, and will treat your report as authorised research.

Good faith means all of:

1. You test **only your own installation** — never someone else's VIGIL deployment, never
   the maintainer's infrastructure, never a host you found running VIGIL.
2. You avoid privacy violation, data destruction, and service degradation. If you
   encounter someone else's data, you stop and tell us.
3. You give us a reasonable window (§ 4) before publishing, and you coordinate timing.
4. You do not exfiltrate, retain, or publish data that is not yours, and you do not use a
   finding to extort.

Limits, stated honestly: this is a commitment from the maintainer of this project only.
It **cannot** bind a third party — not your employer, not a hosting provider, not a
government, not the owner of a system you touch. It is **not** authorization to test
anyone else's deployment, and it does not make an unlawful act lawful. If the law where
you are is unclear, get your own advice first.

## 8. What not to do

- Do not test another organisation's VIGIL instance, hosted console, or gateway. Finding a
  VIGIL deployment on the internet is not an invitation.
- Do not attack the maintainer's own hosts, accounts, mail, or repositories.
- Do not social-engineer the maintainer, contributors, or any user.
- Do not run denial-of-service or resource-exhaustion tests against anything you do not own.
- Do not use real client engagement data — the evidence tree, the spine, the usage ledger —
  as material in a report. Reproduce on synthetic data.
- Do not publish before the coordinated date, and do not use an unfixed flaw against anyone.

---

*Contact:* `security@thuramnana.com` *(placeholder — confirm before publication)* ·
`thuram@thuramnana.com` · <https://thuramnana.com>

*This document describes the maintainer's process and the code as it exists on this
branch. It is not legal advice, and it is not a warranty. Related: the licence terms in
[`LICENSING.md`](LICENSING.md), the acceptable-use rules in
[`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md), what the software stores in
[`PRIVACY.md`](PRIVACY.md), and the liability position in
[`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md).*
