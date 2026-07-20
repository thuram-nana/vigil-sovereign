# SECURITY — supply chain, vulnerability reporting, sovereign-deployment hardening

CRUCIBLE is offensive-security tooling intended for eventual donation to
governments and national CERTs. The bar for supply-chain integrity, vulnerability
reporting, and operational discipline is therefore higher than for a personal or
commercial tool. This document is what a sovereign reviewer reads before
deploying.

This document covers:

1. The trust delegation model — what CRUCIBLE asks operators to trust.
2. Supply-chain attestation — how dependencies are pinned, verified, and rotated.
3. Vulnerability reporting — how to report a security issue in CRUCIBLE itself.
4. Hardening recommendations — what a sovereign deployment must do.

The deeper threat-model document covering CRUCIBLE-as-target — prompt injection,
MLS poisoning, planner-checkpoint tampering, LLM-substrate compromise, operator
credential leakage — lives at [`SOVEREIGNTY-THREAT-MODEL.md`](SOVEREIGNTY-THREAT-MODEL.md).

---

## 1. Trust delegation model

A sovereign deployment of CRUCIBLE asks the operator to trust:

| Component | What's trusted | Mitigation |
|---|---|---|
| Python interpreter + stdlib | Trust delegated to OS distribution | Use a curated distro (Ubuntu LTS, RHEL, etc.); pin minor version |
| Direct runtime dependencies (7) | See `framework/v2/sbom.json` | Hash-pinned via `framework/v2/requirements.lock.txt`; verified by `bin/verify-supply-chain.sh` |
| Transitive dependencies (~30+) | Same | Same |
| LLM substrate | The model weights + the inference daemon | **Sovereign mode forces local-only**; see `SOVEREIGNTY-THREAT-MODEL.md` § "LLM substrate compromise" |
| Filesystem (engagement working dirs) | Trust delegated to OS | OS-level permissions; SELinux / AppArmor profile recommended |
| Operator | The legal-authorization chain | Charter signature gate ([`framework/v2/common/ethics.py`](framework/v2/common/ethics.py)); intake authorization ledger |
| Source repository (this codebase) | What you cloned | Git commit signing recommended; reproducible-build-style attestation deferred |

CRUCIBLE itself does NOT ask the operator to trust:

- A telemetry endpoint (none — egress audit confirms zero "anything else" calls).
- A package mirror chosen by CRUCIBLE (operator picks).
- An update server (no auto-update mechanism exists).

Anything the framework reaches outside the operator's host is either (a) a target
covered by a signed charter (HttpExecutor, UTI fetcher) or (b) an LLM substrate
the operator explicitly opted into (Ollama, Anthropic API in permissive mode).
See [`framework/v2/SOVEREIGNTY-EGRESS-AUDIT.md`](framework/v2/SOVEREIGNTY-EGRESS-AUDIT.md) for the source-level enumeration.

---

## 2. Supply-chain attestation

### 2.1 Files that compose the chain

| File | Role |
|---|---|
| `framework/v2/requirements.in` | Source spec — direct runtime + test dependencies, version-bounded. |
| `framework/v2/requirements.lock.txt` | Hash-pinned, fully-resolved lock. Operator generates with `pip-compile --generate-hashes` (see § 2.2). |
| `framework/v2/sbom.json` | CycloneDX 1.5 SBOM listing every direct + transitive dependency with versions. Operator regenerates with `cyclonedx-py requirements`. |
| `bin/verify-supply-chain.sh` | CI verification — re-resolves the lock, re-generates the SBOM, exits non-zero on any drift. |

### 2.2 First-time supply-chain setup (operator runs once)

```bash
# 1. Install build-time tooling. Intentionally NOT in requirements.in;
#    expanding the runtime install would add attack surface for no
#    runtime feature gain. These tools live on CI / dev hosts only.
pip install pip-tools cyclonedx-bom

# 2. Generate the hash-pinned lock from requirements.in.
pip-compile --generate-hashes \
    --output-file=framework/v2/requirements.lock.txt \
    framework/v2/requirements.in

# 3. Regenerate the SBOM from the lock so they describe the same set.
cyclonedx-py requirements \
    --output-format json \
    -o framework/v2/sbom.json \
    framework/v2/requirements.lock.txt

# 4. Verify everything matches.
bash bin/verify-supply-chain.sh

# 5. Commit the generated lock + SBOM.
git add framework/v2/requirements.lock.txt framework/v2/sbom.json
git commit -m "supply-chain: regenerate lock + SBOM for deployment cut <date>"
```

### 2.3 Recurring CI verification

`bin/verify-supply-chain.sh` runs on every commit. It:

1. Re-resolves `requirements.in` (dry-run; ensures no version conflict).
2. Re-generates the lock and `diff`s it against the committed lock — drift fails the build.
3. Re-generates the SBOM and compares the component set to `sbom.json` — drift fails the build.

A PR that touches dependencies must include the regenerated lock + SBOM. The
verification script exits non-zero otherwise. There is no "force merge" override
— a dependency change without an updated lock is a supply-chain incident.

### 2.4 Dependency rotation cadence

| Trigger | Action |
|---|---|
| CVE published against a direct or transitive dep | Bump within 24h, regenerate lock, regenerate SBOM, smoke-test. |
| Sovereign-deployment cut (release candidate) | Refresh lock + SBOM regardless of CVE state. |
| Quarterly | Refresh lock + SBOM regardless. Drift in older deployments is a known-state risk. |

### 2.5 Build-time tooling is intentionally not pinned

`pip-tools` and `cyclonedx-bom` are not in `requirements.in`. They run only on CI
/ developer hosts during the lock-generation and verification steps. Bundling
them into the runtime install would expand the deployed attack surface without
adding deployed feature value. Sovereign reviewers can confirm: a target machine
running CRUCIBLE in production never imports `pip_tools` or `cyclonedx`.

---

## 3. Vulnerability reporting

### 3.1 In-scope

A vulnerability in CRUCIBLE itself: any flaw that lets an attacker compromise
the operator's host, exfiltrate data outside scope, bypass the ethics or
sovereignty gates, or poison engagement state.

Examples that qualify:

- A path that bypasses `scope_gate.validate_action()`.
- A path that bypasses `SovereigntyPolicy.assert_permitted()`.
- A code injection in a URK prompt that influences an LLM call's behaviour
  beyond its declared schema.
- An MLS query that returns priors the requester should not see (cross-engagement leak).
- A planner checkpoint format that allows code execution on resume.
- A structured-event log entry that escapes its container into another field.

### 3.2 Out of scope (handle differently)

- A flaw in an upstream dependency: report to the upstream first, then file
  here once a patch lands.
- A flaw in an LLM model's reasoning quality: not a CRUCIBLE bug per se;
  document in [`framework/v2/kernel/tests/fixtures/sovereignty-comparison.md`](framework/v2/kernel/tests/fixtures/sovereignty-comparison.md).
- A flaw in a target that CRUCIBLE found: that's a finding for the target, not for CRUCIBLE.

### 3.3 How to report

Until CRUCIBLE has an institutional home, report security issues to the
operator (the GitHub repository owner) via one of:

- Encrypted email to the operator's published key.
- A private GitHub Security Advisory on the repository.

**Do not file a public issue for a security flaw.** Public-disclosure timing is
coordinated between the reporter, the operator, and any affected sovereign
deployments.

### 3.4 Disclosure timeline

Default coordinated-disclosure window: **90 days** from initial report to
public disclosure, extendable by mutual agreement if a fix needs longer to
land in deployed sovereign installations.

A patch lands in the public repository at disclosure; sovereign deployments
that chose to vendor CRUCIBLE pull the patch into their own pipelines.

---

## 3.5 Substrate selection — pick before first run

CRUCIBLE supports four sovereignty tiers. Operators pick one before
first engagement; the choice trades sovereignty against reasoning
quality. The tier is enforced at backend *construction* — a
misconfigured deployment fails closed at startup.

| Tier | Set via | Backends permitted | Sovereignty property | Reasoning quality | Use case |
|---|---|---|---|---|---|
| `AIR_GAPPED` | `CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED` (or legacy `CRUCIBLE_SOVEREIGN_MODE=1`) | Ollama / vLLM / llama-cpp / TGI / DryRun | No external trust | Lower (local 32B model) | Highest-sensitivity workloads |
| `SOVEREIGN_CLOUD` | `CRUCIBLE_SOVEREIGNTY_TIER=SOVEREIGN_CLOUD` | + AWS Bedrock (regional), GCP Vertex (regional), Mistral La Plateforme | Jurisdictional (regional infra, data residency) | Frontier (Claude on Bedrock/Vertex) or High (Mistral) | Most government workloads |
| `TRUSTED_CLOUD` | `CRUCIBLE_SOVEREIGNTY_TIER=TRUSTED_CLOUD` | + Anthropic Zero-Data-Retention (`CRUCIBLE_ANTHROPIC_ZDR=1`) | Contractual data-handling (ZDR contract with Anthropic) | Frontier | Trusted-vendor organisational use |
| `PERMISSIVE` (default) | Default; or `CRUCIBLE_SOVEREIGNTY_TIER=PERMISSIVE` | + plain consumer Anthropic / Claude Code OAuth | None | Best-available | Development, personal use |

### Per-tier configuration

**AIR_GAPPED** requires a local LLM substrate (Ollama is the
recommended default). Run `ollama pull qwen2.5-coder:32b` on a host
with ≥20GB VRAM or 64GB RAM. Or vLLM / llama.cpp / TGI configured to
listen on `localhost`.

**SOVEREIGN_CLOUD** requires *one* of:

- **AWS Bedrock**: set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
  (or use IAM role / instance profile),
  `CRUCIBLE_BEDROCK_REGION=eu-west-1` (or another region from the
  allowlist: us-gov-east-1, us-gov-west-1, eu-west-1, eu-west-3,
  eu-central-1, ap-northeast-1, us-east-1, us-west-2). Override
  the allowlist via `CRUCIBLE_BEDROCK_REGION_ALLOWLIST` if your
  deployment context permits a non-default region. Install
  [`boto3`](https://github.com/boto/boto3) alongside `anthropic`.
- **Google Vertex**: set `GOOGLE_APPLICATION_CREDENTIALS` (or use
  workload identity / metadata server),
  `CRUCIBLE_VERTEX_PROJECT=<project-id>`,
  `CRUCIBLE_VERTEX_REGION=europe-west4` (or another from the
  allowlist: us-central1, us-east5, europe-west4, europe-west9,
  asia-northeast1). Install `google-auth` alongside `anthropic`.
- **Mistral La Plateforme**: set `MISTRAL_API_KEY`. No SDK install
  needed — the backend uses httpx-direct.

**TRUSTED_CLOUD** uses everything from SOVEREIGN_CLOUD plus:

- **Anthropic Zero-Data-Retention**: confirm with Anthropic that
  your API key is associated with a ZDR-enabled organisation, then
  set `CRUCIBLE_ANTHROPIC_ZDR=1` and `ANTHROPIC_API_KEY`. ZDR is
  contractual, not request-scoped — CRUCIBLE has no programmatic
  way to verify the contract is in place; setting this flag is an
  **operator attestation**.

**PERMISSIVE** is the default. Used in development. Sovereign
deployments must NOT run in PERMISSIVE.

### Auto-selection per tier

When `CRUCIBLE_LLM_BACKEND` is unset, the framework picks the first
*available* backend in the tier's preference order:

| Tier | Preference order |
|---|---|
| AIR_GAPPED | ollama → vllm → llama-cpp → tgi → dryrun |
| SOVEREIGN_CLOUD | bedrock → vertex → mistral → ollama → vllm → ... → dryrun |
| TRUSTED_CLOUD | anthropic-zdr → bedrock → vertex → mistral → ollama → ... → dryrun |
| PERMISSIVE | anthropic → claude-code → anthropic-zdr → bedrock → ... → dryrun |

In the lower tiers, local fallbacks remain available — sovereign
deployments running primarily on Bedrock can still run their unit-
test suites with the DryRun backend without changing tier.

---

## 4. Sovereign-deployment hardening checklist

A sovereign deployment runs through this list before exposing CRUCIBLE to
real-engagement work:

### 4.1 Sovereignty tier

- [ ] `CRUCIBLE_SOVEREIGNTY_TIER=<chosen-tier>` set globally (systemd unit, container env, OS profile). Sovereign deployments are NEVER PERMISSIVE.
- [ ] Verified: `python3 -m framework.v2 status` reports the chosen tier.
- [ ] Verified: attempting a backend outside the chosen tier's permitted set raises `SovereigntyViolation` at startup.
- [ ] Backend for chosen tier is reachable (Ollama on localhost / Bedrock region / Vertex project / Mistral key / ZDR-enrolled key).
- [ ] If TIER_TRUSTED_CLOUD: operator has confirmed the Anthropic API key is ZDR-enrolled with the vendor (cannot be verified programmatically).
- [ ] If running in lower tiers, quality verification per binding has been run from [`framework/v2/kernel/tests/fixtures/sovereignty-comparison.md`](framework/v2/kernel/tests/fixtures/sovereignty-comparison.md) and operator accepts the numbers.

### 4.2 Supply chain

- [ ] `framework/v2/requirements.lock.txt` regenerated from `requirements.in` on this host.
- [ ] `bin/verify-supply-chain.sh` exits 0.
- [ ] `framework/v2/sbom.json` regenerated and committed.
- [ ] Container / VM image built from `requirements.lock.txt` with `pip install --require-hashes`.
- [ ] Image hashes recorded in deployment ledger.

### 4.3 Filesystem + permissions

- [ ] CRUCIBLE runs as a non-root, non-shared service account.
- [ ] `targets/<slug>/loot/` and `targets/<slug>/evidence/` are mode 0700 owned by the service account.
- [ ] `framework/v2/.memory/store.sqlite` is mode 0600.
- [ ] No external mount writes to `framework/`.

### 4.4 Network

- [ ] Egress allowlist enforced at OS firewall: only LLM substrate (`localhost:11434` / configured port) and target hosts (per signed charter) reachable from the service account.
- [ ] DNS resolution restricted similarly.
- [ ] [`SovereignHttpxTransport`](framework/v2/agents/egress_guard.py) wired into HttpExecutor and UTI Fetcher constructors.
- [ ] Periodic `bin/verify-supply-chain.sh` run via cron / CI hook.

### 4.5 Ethics + sovereignty gates verified live

- [ ] `pytest framework/v2/` passes.
- [ ] Test that `CRUCIBLE_SOVEREIGN_MODE=1 CRUCIBLE_LLM_BACKEND=anthropic python3 -m framework.v2 status` raises and prints the policy explanation.
- [ ] Test against a known out-of-scope URL that the framework refuses with `OutOfScope`.
- [ ] Test an unsigned charter that the framework refuses with `CharterNotSigned`.

### 4.6 Operator hygiene

- [ ] Operator workstation has no API keys for cloud LLM vendors when in sovereign mode.
- [ ] `.bashrc` / shell rc files audited for accidentally-leaked keys.
- [ ] Engagement logs sanitised before sharing externally (loot/evidence stay local).
- [ ] Charter signing process documented and dated per engagement.

---

## 5. What this document does NOT promise

CRUCIBLE has **not** yet been:

- Audited by a third-party security firm.
- Fuzzed against its parsers (charter parser, fingerprint parser, schema validators).
- Run through a reproducible-build verification chain (multiple builders → identical artifacts).
- Adopted by an institutional home that maintains a permanent vulnerability-coordination process.

These are real gaps for a sovereign-grade artefact. The operator's roadmap to
close them is in [`V2-LIMITATIONS.md`](V2-LIMITATIONS.md) under "Sovereign-grade roadmap." None of them is engineering work this codebase can do alone.
