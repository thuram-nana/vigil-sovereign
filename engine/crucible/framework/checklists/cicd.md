# CI/CD & Supply Chain Security Checklist

> Reference checklist for engagements covering build pipelines, source repositories, package registries, and software supply chain. Cross-reference with `playbooks/15-cicd-supply-chain.md`. Aligned with **OWASP Top 10 CI/CD Security Risks**, **SLSA framework**, **NIST SP 800-218 (SSDF)**, and MITRE ATT&CK.

---

## How to Use This Checklist

- Phrase each item as a question. Answer with evidence (screenshot, command output, config snippet).
- Mark each: ✅ secure | ❌ vulnerable (open finding) | ⚠️ partial | ⏭ out of scope | 🚫 N/A.
- **Authorization:** repository read access and CI logs are typically gray/white-box. Pipeline injection or build-time RCE testing requires explicit charter approval — these are **production-impacting** by definition.
- Many CI/CD findings are CRITICAL severity because they yield codepath compromise affecting all downstream consumers.

---

## OWASP Top 10 CI/CD Security Risks (CICD-SEC-1 .. CICD-SEC-10)

The skeleton below is organized around OWASP's CI/CD Top 10. Use it as the spine and add tool-specific checks per environment.

### CICD-SEC-1: Insufficient Flow Control Mechanisms

- [ ] Can a developer merge to `main` / `master` without review? (Branch protection bypassed.)
- [ ] Can a single approver approve their own PR? (Self-approval allowed.)
- [ ] Are required status checks enforced on protected branches?
- [ ] Can force-push rewrite history on protected branches?
- [ ] Can administrators bypass branch protection?
- [ ] Are signed commits enforced (verified GPG/Sigstore signatures)?
- [ ] Is direct push to release branches blocked?
- [ ] Can `CODEOWNERS` be modified by non-owners?
- [ ] Pull request approvals dismissed when new commits pushed?
- [ ] Can workflow files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) be modified in a PR by the same workflow that runs on the PR? (TOCTOU.)
- [ ] Can a forked PR run privileged workflows (pull_request_target on GitHub)?
- [ ] Auto-merge enabled with insufficient guardrails?
- [ ] Direct pushes from CI/automation to protected branches?

### CICD-SEC-2: Inadequate Identity and Access Management

- [ ] SSO enforced for all developers (vs personal accounts)?
- [ ] MFA enforced for all members of the org?
- [ ] Inactive / former employee accounts cleaned up?
- [ ] Personal access tokens (PATs) — inventory, scopes, expiration, IP restriction.
- [ ] SSH keys per user — count, age, last used.
- [ ] Deploy keys per repo — write access? scope?
- [ ] OAuth applications installed in org reviewed for permissions.
- [ ] GitHub Apps / GitLab integrations / Bitbucket installations reviewed.
- [ ] Service accounts / bot accounts inventoried, ownership documented.
- [ ] Cross-org or cross-tenant access (forks, organization secrets exposure).
- [ ] Shared credentials between humans (forbidden).
- [ ] Admin role assignments justified.
- [ ] Outside collaborators on private repos.
- [ ] Account recovery process / break-glass account secured.

### CICD-SEC-3: Dependency Chain Abuse

- [ ] Dependency confusion: internal package names registered on public registries (npm, PyPI, RubyGems, Maven Central, Crates.io)?
- [ ] Typosquatting risk: are common typos of internal packages registered?
- [ ] `package.json`, `requirements.txt`, `pom.xml`, `go.mod`, `Gemfile` review for unmaintained / abandoned packages.
- [ ] Lockfiles committed (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`)?
- [ ] Lockfile integrity verified (`npm ci` vs `npm install`)?
- [ ] Private registry configured to **not** fall through to public on miss (scope-based routing, upstream blocking).
- [ ] Mirror / proxy registry (Artifactory, Nexus, Verdaccio) configuration.
- [ ] Package signature verification (Sigstore, Maven GPG, npm Sigstore).
- [ ] SBOM generated for every build (CycloneDX, SPDX)?
- [ ] Vulnerability scanning of dependencies (Snyk, Dependabot, Renovate, Trivy, OWASP Dependency-Check).
- [ ] Auto-merge of dependency updates without review (could pull a poisoned version)?
- [ ] Pinning to mutable tags (e.g., `actions/checkout@v3`) vs immutable digest (`@sha256:...`).
- [ ] `npm install --save` without `--save-exact` allowing range updates.
- [ ] Post-install scripts allowed (`npm install` with `--ignore-scripts`?).
- [ ] Container base images: `:latest` tags, mutable.

### CICD-SEC-4: Poisoned Pipeline Execution (PPE)

- [ ] Direct PPE: can a PR modify `.github/workflows/*.yml` and have the modification execute on PR trigger?
  - [ ] On forked PRs (fork takes over)?
  - [ ] Via `pull_request_target` (runs in base context with secrets)?
  - [ ] Via `workflow_run` triggered by untrusted input?
- [ ] Indirect PPE: build scripts (`Makefile`, `package.json` scripts, `setup.py`, `build.gradle`, `Dockerfile`) modifiable in PR and invoked by CI?
- [ ] Pre-commit hooks installed by checkout action automatically run?
- [ ] CI runner has access to secrets when running untrusted PR code?
- [ ] CI runner network egress unrestricted (data exfil path)?
- [ ] Tests / linters that load YAML / parse Markdown can be poisoned?
- [ ] Cache poisoning: GitHub Actions cache, GitLab cache — can attacker write to cache key?
- [ ] Custom GitHub Actions / GitLab CI components from untrusted sources.
- [ ] Container build context includes `.git/` or other sensitive files.

### CICD-SEC-5: Insufficient PBAC (Pipeline-Based Access Controls)

- [ ] Job tokens / OIDC tokens scoped per job (vs broad).
- [ ] CI service account permissions in cloud / k8s — least privilege?
- [ ] Production deploys require separate environment / approval gate?
- [ ] Same runner pool for production and untrusted workloads?
- [ ] Self-hosted runners scoped per repo (not shared org-wide for public repos)?
- [ ] Self-hosted runner ephemeral (destroyed after each job) vs persistent?
- [ ] Secrets scoped per environment (production secrets not available to PR builds).
- [ ] Environment protection rules (required reviewers, wait timers)?

### CICD-SEC-6: Insufficient Credential Hygiene

- [ ] Hardcoded secrets in repo history (`git log -p`, `truffleHog`, `gitleaks`, `detect-secrets`).
- [ ] Secrets in environment variables visible in logs (`echo $SECRET`).
- [ ] Pre-receive / push protection (GitHub Push Protection, GitLab secret detection).
- [ ] Secret scanning enabled at the org level.
- [ ] Secret rotation cadence / process.
- [ ] Long-lived static credentials vs short-lived OIDC federation (preferred).
- [ ] CI vendor secret storage encrypted at rest with customer-managed keys.
- [ ] Secret access audit logs reviewed.
- [ ] Inline secrets in `Dockerfile` (`ARG`, `ENV`).
- [ ] Secrets in build args bleeding into final image layers.
- [ ] Secrets in CI artifacts.
- [ ] Secrets in release tarballs.

### CICD-SEC-7: Insecure System Configuration

- [ ] CI platform version (self-hosted Jenkins/GitLab) — known CVEs.
- [ ] Plugins / extensions inventory (Jenkins plugins are notorious).
- [ ] Default credentials (Jenkins `admin/admin`, Sonatype Nexus, Artifactory, etc.).
- [ ] Anonymous read on Jenkins, Bamboo, TeamCity dashboards (info disclosure).
- [ ] CSRF protection enabled (Jenkins).
- [ ] Script Security plugin / approval (Jenkins) configured.
- [ ] Build artifact retention and access controls.
- [ ] Webhook URLs exposed (path leak via repo issues/wiki).

### CICD-SEC-8: Ungoverned Usage of 3rd Party Services

- [ ] GitHub Apps installed in org — permissions reviewed.
- [ ] GitLab integrations.
- [ ] OAuth apps with org access.
- [ ] CI service account access to cloud — federated via OIDC vs static keys.
- [ ] 3rd party SaaS scanners reading source (review their auth scopes).
- [ ] Cross-org access via shared marketplace apps.

### CICD-SEC-9: Improper Artifact Integrity Validation

- [ ] Container images signed (Cosign / Notary v2)?
- [ ] Signature verification at deploy time (Kyverno, OPA Gatekeeper, AdmissionPolicy)?
- [ ] Build provenance attestations (SLSA Level 3+, in-toto, GitHub artifact attestations)?
- [ ] Package signature verification at install time (npm provenance, PyPI sigstore).
- [ ] Hash verification on downloaded build tools (`curl | sh` patterns?).
- [ ] Reproducible builds where applicable.
- [ ] Tamper-evident build logs / immutable storage.

### CICD-SEC-10: Insufficient Logging and Visibility

- [ ] Audit logs for source code platform (GitHub Audit Log, GitLab Audit Events).
- [ ] CI run logs retained — for how long?
- [ ] Logs include who ran what, who approved what.
- [ ] Anomaly detection on CI activity (off-hours pushes, unusual destinations).
- [ ] Webhook delivery logs.
- [ ] Package registry access logs.
- [ ] Logs forwarded to SIEM.
- [ ] Detection rules for known attack patterns (PPE attempts, credential dumps).

---

## Source Code Platform Specific

### GitHub

- [ ] Repository visibility (public/private/internal).
- [ ] Branch protection on `main` (required reviews, status checks, signed commits, linear history).
- [ ] CODEOWNERS reviewed.
- [ ] Actions permissions: `Allow all actions` vs allow-listed.
- [ ] `GITHUB_TOKEN` default permissions: `read` (preferred) vs `write`.
- [ ] Secrets accessibility: repo / environment / org-level.
- [ ] Self-hosted runner labels and access.
- [ ] Repository-level Dependabot/CodeQL configuration.
- [ ] OIDC trust policy in cloud accounts (audience claim, sub claim restrictions).
- [ ] Forked PR workflows (`pull_request` not `pull_request_target` for untrusted code).
- [ ] Default workflow permissions org policy.

### GitLab

- [ ] Project visibility and group settings.
- [ ] Protected branches and tags.
- [ ] Push rules (commit message, file size, secret detection).
- [ ] CI/CD variables: protected, masked, scope (instance, group, project, environment).
- [ ] Runners: shared vs group vs project, tags, untagged jobs.
- [ ] Container registry per project.
- [ ] Merge request approval rules.
- [ ] Approval reset on new commits.
- [ ] Push-to-CI without approval allowed?

### Bitbucket / Azure DevOps / Other

- [ ] Equivalent branch protection / pull request policies.
- [ ] Pipeline approvers and gates.
- [ ] Variable groups / library scope.
- [ ] Service connections / service principals.

## Build Tool Specific

### Jenkins

- [ ] Version (Jenkins LTS often lags; check CVEs).
- [ ] Anonymous access disabled.
- [ ] Matrix Authorization or Project-based Matrix Authorization in use.
- [ ] Script Security: approved scripts only.
- [ ] Pipeline scripts reviewed for `shell` / `bat` injection from PR titles, branch names.
- [ ] Agent-to-controller access controls.
- [ ] Plugins inventory + CVE check.
- [ ] Credentials stored in Jenkins credential store, not inline.
- [ ] Jenkins URL exposed publicly.
- [ ] Jenkins `/script` console access (RCE if accessible).
- [ ] Jenkins `/manage/configureSecurity/` settings.

### CircleCI / Travis / Drone / Buildkite / Tekton / Argo Workflows

- [ ] Project / pipeline configuration secured.
- [ ] Context / environment scope.
- [ ] Self-hosted vs SaaS runner trust model.
- [ ] Secrets injection mechanism.

## Container Build & Registry

- [ ] Dockerfile review: `USER` directive present (not running as root).
- [ ] Multi-stage builds to avoid leaking build secrets.
- [ ] `--mount=type=secret` instead of `ARG` for secrets.
- [ ] Image scanning in CI (Trivy, Grype, Snyk).
- [ ] Registry authentication (no anonymous push).
- [ ] Image signing pre-push.
- [ ] Image immutability / retention policy.
- [ ] Public registry exposure (Docker Hub, GHCR, GCR, ECR public).
- [ ] Pull-through cache configuration (avoid public registry latency / outage = avoid blind trust).

## IaC (Terraform / CloudFormation / Pulumi / Ansible)

- [ ] State files: where stored, who has access (S3 bucket policy).
- [ ] State files encrypted at rest.
- [ ] State files contain secrets in plaintext (often true) — access logged?
- [ ] `tflint`, `tfsec`, `checkov`, `kics`, `terrascan` in CI.
- [ ] Module sources: verified registry vs random GitHub repo.
- [ ] Module versions pinned.
- [ ] Provider versions pinned.
- [ ] Auto-apply on merge vs manual gated apply.
- [ ] Plan output exposed in PR comments may leak secrets.

## Package Manager Configurations to Inspect

- [ ] `.npmrc` — registry URL, auth tokens, scope routing.
- [ ] `.yarnrc.yml` — equivalent.
- [ ] `pip.conf` / `pip.ini` — index-url, extra-index-url order.
- [ ] `Gemfile`, source URLs.
- [ ] `nuget.config`.
- [ ] `~/.m2/settings.xml`.
- [ ] `.gitconfig` `insteadOf` URL rewrites (supply chain hijack vector).
- [ ] Composer `repositories` order.

## Common Findings to Hunt

- [ ] `pull_request_target` workflow that checks out PR HEAD and runs build commands.
- [ ] Self-hosted runner on persistent VM with cluster-admin kubeconfig.
- [ ] Org-level secret accessible from public-fork PR workflow.
- [ ] Static AWS access key in CI vars when OIDC could be used.
- [ ] PAT with `repo` scope used for automation that only needs read.
- [ ] Webhook secret blank — replay attack on CI triggers.
- [ ] Build artifact server (e.g., Nexus, Artifactory) with anonymous read on internal artifacts.
- [ ] `npm publish` token with no IP restriction shared across team.
- [ ] Unsigned commits accepted on production branch.
- [ ] CI cache restored from untrusted PR fork (cache poisoning).

## Cross-References

- Playbook: `framework/playbooks/15-cicd-supply-chain.md`
- Playbook: `framework/playbooks/20-source-code-review.md`
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- SLSA Framework: https://slsa.dev/
- NIST SP 800-218 SSDF.
- Sigstore: https://www.sigstore.dev/
