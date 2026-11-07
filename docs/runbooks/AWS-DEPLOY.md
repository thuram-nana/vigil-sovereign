# AWS + Cloudflare deployment (vigilguard.net)

The exact, ordered steps that put VIGIL on **AWS EC2** (owner key sealed by **KMS**, backups in **S3**,
locked by **security groups**) with **Cloudflare** in front of the public site on **vigilguard.net** (bought
on Namecheap). This is the cloud profile companion to `GO-LIVE-quickstart.md` (the host-level command
sequence, which this layers AWS onto) and `hosting-and-persistence.md` (the *why* — §4 owner-key custody,
§3 backups). It changes **no** sovereignty invariant: the owner-signed spine stays the system of record on a
single writer host; AWS provides durable storage + KMS + object storage; Cloudflare provides the CDN/DDoS
edge for the keyless public plane only.

> **What you provide (VIGIL cannot):** an AWS account; the Namecheap-registered domain `vigilguard.net`; a
> Cloudflare account (free tier is fine); `awscli` v2 + `jq` + `curl` on your workstation for the one-time
> provisioning. **Secrets never go in this repo or on a command line** — the owner key is KMS-sealed, the
> Flutterwave secret is injected at the provisioner (`hosting-and-persistence.md` §7).

The three origins (unchanged from the base topology) — only the **public** one goes behind Cloudflare:

| Host | Serves | Public? | Front |
|---|---|---|---|
| `vigilguard.net` | pubui `127.0.0.1:8735` (marketing / tools / CVE — keyless) | yes | **Cloudflare → EC2 nginx** |
| `app.vigilguard.net` | custui `127.0.0.1:8734` (tenant app) | yes | EC2 nginx (its own vhost; Cloudflare optional, DNS-only or proxied — your call) |
| `console.vigilguard.net` | `vigil up` `127.0.0.1:8770` (operator) | **no** | keep private / SSO / VPN — never Cloudflare, never a public A record |

---

## 0. One-time AWS provisioning

Run `apps/sigil/deploy/aws/provision.sh` (review it first), or the equivalent commands below, with an AWS
identity that may create KMS/S3/IAM/EC2 resources. It is idempotent (checks before it creates) and prints
the env values you wire in later.

```bash
cd apps/sigil/deploy/aws
REGION=eu-west-1 PROJECT=vigil ADMIN_SSH_CIDR=<your.admin.ip>/32 ./provision.sh
```

It creates, each least-privilege:

1. **KMS CMK** `alias/vigil-owner-kek` — a symmetric key that envelope-encrypts VIGIL's 32-byte KEK (which
   in turn seals the owner Ed25519 key + all secrets). The owner key never leaves the host as plaintext and
   never enters KMS; KMS only wraps the KEK at rest. → `VIGIL_KMS_KEY_ID`.
2. **S3 bucket** `vigil-backups-<acct>` — versioned, default SSE-KMS (under the same CMK), public access
   fully blocked. The off-host backup push writes the already-encrypted parts here. → `VIGIL_PUSH_DEST`.
3. **IAM role + instance profile** `vigil-host` — the EC2 host assumes it (NO static keys on disk). Policy:
   `kms:Encrypt`/`Decrypt`/`DescribeKey` on **that CMK only**, `s3:PutObject`/`GetObject` on **that bucket
   only**, `s3:ListBucket` on the bucket. Nothing else.
4. **Security group** `vigil-edge` — inbound **443 + 80 only from Cloudflare's current IP ranges** (fetched
   live from `cloudflare.com/ips`), **22 only from `ADMIN_SSH_CIDR`**. So the origin is unreachable except
   through Cloudflare (and your admin IP for SSH). Everything else is denied.
5. **Elastic IP** — a stable public IPv4 you point DNS at. → the `A` record target.

Note the printed `VIGIL_KMS_KEY_ID`, `BUCKET`, `EIP`, and `SECURITY_GROUP_ID`.

## 1. Launch the EC2 host

- An Amazon Linux 2023 / Ubuntu LTS instance (a `t3.small`+ is enough to start — the spine is cheap; size to
  your tenant load per `hosting-and-persistence.md` §6), in the SG `vigil-edge`, with the `vigil-host`
  instance profile attached, and a **separate durable EBS volume** for `$SIGIL_HOME` (the one irreplaceable
  asset — never instance store).
- **Associate the Elastic IP** with the instance:
  ```bash
  aws ec2 associate-address --region eu-west-1 \
      --instance-id <i-…> --allocation-id <eipalloc-…>
  ```
- Mount the EBS volume and point `SIGIL_HOME` at it (e.g. `/mnt/vigil-data/.sigil`).

## 2. Bring VIGIL up on the host

Follow `GO-LIVE-quickstart.md` §1–§6 on the instance (clone, build the venvs, `SIGIL_HOME` on the durable
volume, the systemd units, nginx). Then the three AWS-specific wirings:

### 2a. Seal the owner key with KMS (AWS-1)

```bash
export VIGIL_KEK_BACKEND=kms
export VIGIL_KMS_KEY_ID=alias/vigil-owner-kek      # or the key id/arn printed by provision.sh
export VIGIL_AWS_REGION=eu-west-1
sigil vault provision        # wraps a fresh KEK under the CMK (kms:Encrypt via the instance role)
sigil vault status           # -> "sealed (KMS-wrapped KEK (key …, eu-west-1))"
vigil doctor                 # the "vault" control now reads SEALED
```
Put those three `VIGIL_*` vars in the sovereign services' EnvironmentFile so every boot unwraps the KEK via
`kms:Decrypt`. (Default stays TPM if you ever unset `VIGIL_KEK_BACKEND` — the host is unchanged.)

### 2b. Off-host backups to S3 (AWS-2)

In `~/.config/vigil/backup-push.env` (0600):
```ini
VIGIL_BACKUP_PASSPHRASE=<a long random passphrase — the ONLY key to the backups; store it in your own secret manager>
VIGIL_PUSH_DEST=s3://vigil-backups-<acct>/vigil
VIGIL_BACKUP_S3_SSE_KMS_KEY_ID=alias/vigil-owner-kek   # optional 2nd at-rest layer (the parts are already encrypted)
VIGIL_AWS_REGION=eu-west-1
```
```bash
systemctl --user enable --now vigil-backup-push.timer   # pushes encrypted parts to S3 + verifies the landed copy
systemctl --user start vigil-backup-push.service        # run once now; check journalctl --user -u vigil-backup-push
```
Then **test a restore from S3** (a backup you have not restored is not a backup):
```bash
aws s3 cp --recursive s3://vigil-backups-<acct>/vigil/<latest-timestamp>/ ./restore-check/
sigil restore ./restore-check --expect-governance-pubkey <your governance pubkey, out of band> && sigil verify
```

### 2c. nginx for the public origin

Install `apps/sigil/deploy/reverse-proxy/vigil-public.nginx.conf` (it already carries the Cloudflare
real-IP block). Give the origin a cert for the Cloudflare→origin hop — either Let's Encrypt
(`certbot certonly -d vigilguard.net -d www.vigilguard.net`) or a **Cloudflare Origin CA** cert (longer
lived, only trusted by Cloudflare). `nginx -t && systemctl reload nginx`.

## 3. Point Namecheap at Cloudflare, Cloudflare at the Elastic IP

Cloudflare fronts the domain by becoming its DNS authority, so you delegate DNS from Namecheap to Cloudflare
**once**, then manage records in Cloudflare.

1. **Cloudflare:** add the site `vigilguard.net` (free plan). Cloudflare shows you **two nameservers**, e.g.
   `xxx.ns.cloudflare.com` / `yyy.ns.cloudflare.com`.
2. **Namecheap → Domain List → `vigilguard.net` → Manage → Nameservers:** choose **Custom DNS** and enter
   Cloudflare's two nameservers. Save. (Propagation is usually minutes to a few hours.) This hands DNS to
   Cloudflare; Namecheap stays the registrar.
3. **Cloudflare → DNS → Records** — create, all **Proxied (orange cloud)** except the operator host:
   | Type | Name | Content | Proxy |
   |---|---|---|---|
   | A | `vigilguard.net` (`@`) | **your Elastic IP** | Proxied |
   | CNAME | `www` | `vigilguard.net` | Proxied |
   | A | `app` | your Elastic IP | Proxied (or DNS-only if you front custui yourself) |
   | A | `console` | your Elastic IP | **DNS-only, or omit** — keep the operator plane off the public edge |
4. **Cloudflare → SSL/TLS:** mode **Full (Strict)** (Cloudflare verifies the origin cert from §2c). Enable
   **Authenticated Origin Pulls** and install Cloudflare's client cert check at the origin so the origin only
   accepts connections carrying Cloudflare's certificate — defense-in-depth with the SG lock.
5. **Cloudflare → caching / rules:** the public plane is static + read-only JSON, so a cache rule on
   `vigilguard.net/*` is safe and desirable; **do not** cache `app.vigilguard.net` (authenticated, cookies) —
   add a bypass rule. Turn on the WAF managed ruleset.

Verify the chain: `curl -sI https://vigilguard.net` returns `200` with the pubui headers and a `cf-ray`
header (served through Cloudflare); a direct hit to the Elastic IP on 443 from anywhere but a Cloudflare
range is refused by the security group.

## 4. Go-live gates (unchanged — do not skip)

Finish with `GO-LIVE-quickstart.md` §9–§11 / `hosting-and-persistence.md` §7:

- `vigil doctor` green: **vault SEALED** (now KMS-wrapped) · sovereignty non-permissive · entitlement active
  · **backups ON** (the S3 push timer) · charter present.
- Catalog prices confirmed against real COGS; subscription `price_id`s bound to real Flutterwave payment-plan
  ids; the real payment-provider verifier provisioned at the provisioner (secret injected there, never here).
- **Only then**, as deliberate separate owner acts: flip `VIGIL_CUSTOMER_PROD_EXECUTION` after the K4-6
  acceptance matrix is green. (This runbook never flips it.)

---

### Operational notes

- **Cloudflare IP ranges change.** When they do, refresh both the nginx `set_real_ip_from` block
  (`vigil-public.nginx.conf`) and the security group (re-run `provision.sh`, which pulls the current list).
- **Rotating the owner KEK's CMK:** `sigil key rotate-kek` re-wraps the KEK under a fresh KEK; to move to a
  new CMK, set the new `VIGIL_KMS_KEY_ID` and re-provision on a staging home first. The spine + every owner
  signature are untouched by a KEK rotation (only the wrapping key moves).
- **HA:** the spine is single-writer (`hosting-and-persistence.md` §6). HA today = the durable EBS volume
  (snapshots/replication) + a warm standby that attaches it on failover; the Elastic IP re-associates to the
  standby. Writes remain single-host.
