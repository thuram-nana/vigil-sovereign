# Deploying VIGIL on AWS (single EC2) + merge-to-deploy CD

This is the AWS-specific companion to `docs/DEPLOY.md` (which takes a fresh machine to a working install)
and the go-live quickstart (secrets, DNS, flags). It stands `vigil` up on **one EC2 instance** — the same
host-process model the old VPS used — and wires **opt-in continuous delivery**: once configured, a merge to
`main` that passes `vigil-ci` deploys itself to the box, with a health gate and automatic rollback.

Nothing here is required to run VIGIL. The CD workflow (`.github/workflows/deploy-ec2.yml`) ships **inert**
and stays off until you set three repo variables. Until then VIGIL deploys exactly as before (`git pull`
then `make deploy-console` / `bootstrap.sh` on the box).

> **Why EC2 and not ECS/EKS?** `vigil` runs as two isolated OS processes (`vigil up`) with keys sealed to a
> TPM and the offense side driving Docker for strix. A single hardened EC2 is the closest, lowest-risk match
> to the proven VPS setup. Containers / ECS / EKS / Firecracker are a *later* option (scale or multi-tenant
> isolation), not a prerequisite — don't reach for them to start.

---

## What you get

```
 merge to main ──> vigil-ci (required) ──────────success──> deploy-ec2 workflow
        │                                                          │  OIDC (no stored keys)
        │                                                          ▼
        │                                                   AWS SSM SendCommand
        │                                                          ▼
        └── three DNS records ──> Caddy (TLS) ──>  EC2:  tools/remote-deploy.sh
              vigil.<you>            :443              git reset --hard origin/main
              app.vigil.<you>                          make deploy-console / restart unit
              console.vigil.<you>                      make smoke  (+ optional health probe)
                                                        └─ on failure: roll back to prior commit, fail
```

One `vigil up` serves **all three origins** (public site :8735, customer app :8734, console :8770) on
loopback; Caddy is the only public listener.

---

## Part A — stand up the box (one time)

### A1. Launch the instance
- **Type:** 4 vCPU / 16 GB to build the Rust WARDEN kernel + run both venvs + Qdrant comfortably
  (`t3.xlarge` / `m7i.xlarge`; `t3.large` works if you pre-build). 40+ GB gp3 root.
- **AMI:** Ubuntu 24.04 LTS (or Debian 12). x86-64.
- **TPM (recommended):** enable **NitroTPM** (a Nitro instance + "TPM 2.0" in launch settings) so
  `bootstrap.sh` can seal keys to hardware, exactly like the TPM path in `docs/DEPLOY.md`.
- **IAM instance profile:** attach a role with the **`AmazonSSMManagedInstanceCore`** managed policy — this
  is what lets the CD workflow run commands on the box via SSM (no inbound SSH needed).

### A2. Security group
| Port | Source | Why |
|------|--------|-----|
| 443 (and 80) | `0.0.0.0/0` | Caddy — public TLS for the three origins. 80 is for the ACME challenge + redirect. |
| 22 | **your IP only**, or none | optional break-glass SSH. With SSM you can omit 22 entirely. |
| 8734 / 8735 / 8770 | **nowhere** | the app ports stay on `127.0.0.1`; never put them in the SG. |

Egress: allow 443 out (Let's Encrypt, GitHub, Stripe at go-live, the AI provider).

### A3. Install VIGIL
SSH in once (or use SSM Session Manager) and:
```bash
sudo apt-get update && sudo apt-get install -y git caddy
git clone <your-fork-url> ~/vigil && cd ~/vigil
./bootstrap.sh --production --yes      # builds both venvs + kernel, installs the user systemd units + timers
```
`--production` installs the `vigil-command.service` user unit and the backup/recovery timers. Enable linger
so the user unit runs without a login session:
```bash
sudo loginctl enable-linger "$USER"
```
Confirm it serves locally: `curl -fsS http://127.0.0.1:8770/healthz` (console) should answer.

> **One tree vs two.** `remote-deploy.sh` auto-detects: if you run `vigil up` straight from `~/vigil`
> (the simple default), it restarts `vigil-command.service` in place. If you keep a separate running tree,
> set `VIGIL_DEPLOY_DIR` to it and it uses `make deploy-console` (mirror + restart) instead.

### A4. DNS + TLS
Point three records at the instance's elastic IP:
```
vigil.<you>            A   <EIP>
app.vigil.<you>        A   <EIP>
console.vigil.<you>    A   <EIP>
```
Copy `infra/edge/Caddyfile.example` to `/etc/caddy/Caddyfile`, set the three hostnames and the console
allow-list CIDR, then `sudo systemctl reload caddy`. Caddy fetches + renews certificates automatically.

### A5. Secrets
Set the real secrets as the go-live quickstart describes (owner Ed25519 key, Stripe keys, provisioning hop
key, the GitHub App at go-live). Two options:
- **Env files (simplest, what the VPS used):** the `~/.sigil/*.env` and `~/.vigil-live/service.env` files,
  `chmod 600`, owned by the vigil user; keys sealed to NitroTPM by `bootstrap.sh`.
- **AWS SSM Parameter Store / Secrets Manager (hardening):** store each as a `SecureString`, give the
  instance role `ssm:GetParameter` on `*/vigil/*`, and fetch them into the env files at boot with a
  oneshot unit. Optional — adopt it when you want secrets off the disk.

Then flip only the flags you want on (see the go-live quickstart). Everything is default-OFF / fail-closed.

---

## Part B — turn on merge-to-deploy CD (one time, optional)

### B1. Create the deploy role (OIDC, least-privilege)
Deploy the CloudFormation template — it creates an IAM role a GitHub Actions run **from this repo's `main`
branch** can assume, scoped to `ssm:SendCommand` (RunShellScript) against your one instance and reading the
result. Nothing else.
```bash
aws cloudformation deploy \
  --template-file infra/aws/github-oidc-deploy-role.cfn.yaml \
  --stack-name vigil-cd-deploy \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      GitHubRepo=thuram-nana/vigil-sovereign \
      TargetInstanceId=i-0123456789abcdef0 \
      CreateOIDCProvider=true        # set false + pass ExistingOIDCProviderArn if the account already has one
aws cloudformation describe-stacks --stack-name vigil-cd-deploy \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text
```

### B2. Set the three repo variables (NOT secrets — they're identifiers, and they're the on-switch)
In GitHub → Settings → Secrets and variables → Actions → **Variables**:
| Variable | Value |
|----------|-------|
| `VIGIL_DEPLOY_AWS_ROLE_ARN` | the `RoleArn` from B1 |
| `VIGIL_DEPLOY_AWS_REGION` | e.g. `us-east-1` |
| `VIGIL_DEPLOY_SSM_TARGET` | the instance id, `i-0123...` |
| `VIGIL_DEPLOY_OS_USER` *(optional)* | the box user that owns `vigil up` (default `vigil`) |

The moment all three are set, the `deploy-ec2` workflow becomes live. With any one missing it prints
"CD not configured" and does nothing.

### B3. That's it
Now: **merge a PR → `vigil-ci` runs → on green, `deploy-ec2` assumes the role, SSM-runs
`tools/remote-deploy.sh` on the box → it fast-forwards to `origin/main`, re-serves, runs `make smoke`, and
rolls back + fails the job if anything is wrong.** You can also trigger it by hand from the Actions tab
(**Run workflow** → `deploy-ec2`).

---

## Deploying / rolling back by hand

On the box, the exact thing CD runs:
```bash
cd ~/vigil && bash tools/remote-deploy.sh         # pull origin/main, re-serve, smoke, rollback-on-fail
```
To pin a known-good commit after a bad deploy:
```bash
cd ~/vigil && git reset --hard <good-sha> && make deploy-console   # (or: systemctl --user restart vigil-command.service)
```

---

## Safety properties (enforced by `docs/tests/test_deploy_ec2_workflow.py`)
- The workflow **never runs on a pull request**, and fires **only after `vigil-ci` is green on `main`** — a
  red or non-main CI never deploys.
- **Opt-in + fail-closed:** no variables → no-op. Every side-effecting step is gated on the preflight.
- **No long-lived AWS keys:** auth is GitHub OIDC → a 15-minute role session. No SSH port is opened by CD.
- **Rollback:** a failed mirror / restart / smoke / health probe restores the previous commit's served tree
  and fails the job.
- The job is registered in `KNOWN_NONPR_ADVISORY`, so the required-checks drift guard stays honest.

## Owner to-do checklist
- [ ] Launch the EC2 (NitroTPM on; SSM instance-profile attached)
- [ ] Security group: 443/80 public, 22 your-IP-or-none, app ports closed
- [ ] `git clone` + `./bootstrap.sh --production --yes` + `enable-linger`
- [ ] 3 DNS records → Caddy (`Caddyfile.example`) → reload
- [ ] Set real secrets + flip the go-live flags you want on
- [ ] (CD) deploy `github-oidc-deploy-role.cfn.yaml`, set the 3 repo variables
- [ ] Merge a trivial PR and watch `deploy-ec2` roll it out
