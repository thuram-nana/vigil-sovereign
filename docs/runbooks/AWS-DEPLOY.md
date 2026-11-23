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

The three origins (unchanged from the base topology) plus the payment-webhook host — only the **public** site
and the webhook host go behind Cloudflare:

| Host | Serves | Public? | Front |
|---|---|---|---|
| `vigilguard.net` | pubui `127.0.0.1:8735` (marketing / tools / CVE — keyless) | yes | **Cloudflare → EC2 nginx** |
| `app.vigilguard.net` | custui `127.0.0.1:8734` (tenant app) | yes | EC2 nginx (its own vhost; Cloudflare optional, DNS-only or proxied — your call) |
| `console.vigilguard.net` | `vigil up` `127.0.0.1:8770` (operator) | **no** | keep private / SSO / VPN — never Cloudflare, never a public A record |
| `hooks.vigilguard.net` | ONLY `POST /webhooks/stripe` + `POST /webhooks/billing` → the `vigil up` proxy `127.0.0.1:8770` | yes (two exact requests) | **Cloudflare → EC2 nginx** (`vigil-hooks.nginx.conf`); everything else is 404 |

Stripe (and Flutterwave) cannot be on the console's private network, so they deliver to the dedicated
`hooks` host instead: the live Stripe endpoint is `https://hooks.vigilguard.net/webhooks/stripe`. The console
stays fully private with no webhook exception. The hooks vhost forwards exactly those two `POST`s, byte-exact on
the raw request line, with a 1 MB body cap and `Host` / `Stripe-Signature` unchanged; the proxy's webhook routes
answer ahead of its Host/Origin gate, so they accept `Host: hooks.vigilguard.net` while every console path still
refuses it. It is safe to expose because the body never credits anything: the proxy checks the
`Stripe-Signature` HMAC before it spools a byte, and the billing drain re-verifies it and re-fetches every
Checkout Session / Invoice / Subscription from Stripe with the restricted key before the owner catalog mints.

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
   `kms:Encrypt`/`Decrypt`/`GenerateDataKey`/`DescribeKey` on **that CMK only** (S3 SSE-KMS uploads call
   `GenerateDataKey` under the host's own identity — without it every backup PUT is denied),
   `s3:PutObject`/`GetObject` on **that bucket only**, `s3:ListBucket` on the bucket, and `ssm:GetParameter` on
   **the one provider-key parameter** (`/vigil/anthropic-api-key`, or `PROVIDER_KEY_PARAMETER`; §2b′ creates
   it). Nothing else.
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
# `vigil restore` (the two-plane CLI) restores into FRESH dirs and RE-VERIFIES both planes; a non-zero exit = FAIL.
# (--sigil-home exercises the sovereign leg that holds the KMS-wrapped KEK / owner key.)
vigil restore ./restore-check --base-dir ./restore-base --crucible-root ./restore-crucible \
      --sigil-home ./restore-sigil-home --expect-governance-pubkey <your governance pubkey, out of band>
```
(Use `vigil restore`, not `sigil restore` — restore already re-verifies the RESTORED dirs; a trailing
`sigil verify` would check the live host instead. For an explicit re-check add `vigil verify --base-dir ./restore-base`.)
`--crucible-root` takes either the CRUCIBLE root (the dir holding `framework/v2` and `targets/`, what
`$CRUCIBLE_ROOT` names) or its `framework/v2`; a fresh dir is laid out exactly like the engine's: `targets/` (every
engagement + its evidence) at the root, and the proof db, runs, MLS learning memory (every `tenants/<t>` shard),
entitlement trust root, DestructionAuthority (kill-switches) and authority root under `framework/v2/`. The
crypto-shred evidence keystore (`framework/v2/.evidence-keys`) is never in a backup (W16-8).

### 2b′. The model provider key in AWS SSM (from a phone browser)

The model gateway's provider key lives in AWS SSM Parameter Store as a **SecureString**, never in a file on the
host. The owner creates it once from the AWS console (a phone browser is enough):

1. **Systems Manager → Parameter Store → Create parameter.**
2. Name `/vigil/anthropic-api-key`, tier **Standard**, type **SecureString**, KMS key `alias/aws/ssm` (the
   default) or `alias/vigil-owner-kek`; paste the key as the value; **Create parameter**. Never paste the key
   into a chat, a ticket, an email or any file on the host.

`provision.sh` already lets the host's instance role read that one parameter (`ssm:GetParameter`, statement
`ProviderKeyParameter`; re-run it on an existing setup to add the statement). Someone with server access then
puts `VIGIL_ANTHROPIC_KEY_SSM_PARAMETER=/vigil/anthropic-api-key` and `VIGIL_AWS_REGION` in the environment file
of the process that runs the gateway (`infra/systemd/vigil-calibration.env.example`) and restarts it. With the
parameter set, SSM is the gateway's only key source: a key in the environment or `sigil.env` is ignored, and a
missing region or `aws` CLI, a parameter that is not a SecureString, or one the role cannot read stops the gateway
from starting (metered runs then fail closed), so for the process that runs the gateway its start is the check.
`vigil doctor` reads only its own environment and `$SIGIL_HOME/sigil.env`: it checks the parameter's type and
access, without reading the key, when the gateway is enabled there with the parameter set — not for a gateway
configured in another environment file (such as the calibration one). **Rotate** by editing the parameter's value, then restart that
process (the key is read at start). The cockpit's own gateway stays off in production; this parameter does not go
in `cockpit.env`.

### 2c. nginx for the public origin and the webhook host

Install `apps/sigil/deploy/reverse-proxy/vigil-public.nginx.conf` (it already carries the Cloudflare
real-IP block). Give the origin a cert for the Cloudflare→origin hop — either Let's Encrypt
(`certbot certonly -d vigilguard.net -d www.vigilguard.net`) or a **Cloudflare Origin CA** cert (longer
lived, only trusted by Cloudflare). `nginx -t && systemctl reload nginx`.

Install `apps/sigil/deploy/reverse-proxy/vigil-hooks.nginx.conf` the same way (same Cloudflare real-IP block,
same commented per-zone AOP lines), with its own cert for `hooks.vigilguard.net` (Let's Encrypt
`certbot certonly -d hooks.vigilguard.net`, or a Cloudflare Origin CA cert that lists `hooks.vigilguard.net`).

### 2d. Supervised SaaS background runtime (the drains)

The customer-SaaS pipeline runs as owner-tied **background drains** that must run continuously + recover
unattended. They ship as **opt-in systemd user timer-oneshots** (each fires its drain on a tight cadence,
writes a heartbeat, and is watched by the `vigil alerts` staleness dead-man). They are **not** enabled by
bootstrap — each needs a per-deployment **owner-signed delegation**, so you enable them only after
provisioning that. Enable the two load-bearing "nothing-lost" drains first:

```bash
# findings crossing (offense→sovereign confirmed FACTs → the tenant's spine) + settle-on-completion
# (completed⇒charge, canceled/failed⇒refund, owner-keyed + idempotent)
for d in finding-drain settle-drain; do
  cp infra/systemd/vigil-$d.{service,timer} ~/.config/systemd/user/
  cp infra/systemd/vigil-$d.env.example     ~/.config/vigil/$d.env
  # Set ONLY the owner-signed delegation path, as an ABSOLUTE path. The spool, scope and (for settle) the
  # credit-lease seam VIGIL_BASE_DIR (the SAME value every seam unit sets — GO-LIVE §6) ship as working
  # %h-expanded defaults in the .service — override them in the env
  # file ONLY with an absolute path. Do NOT put the ENABLE flag here (it is read by the monitor, below).
  # A %h or relative path in an env file does NOT expand and the drain refuses it (fails loud), so keep paths absolute.
  $EDITOR ~/.config/vigil/$d.env
done
# Arm the staleness dead-man by setting the watch flags in the MONITOR's env (this is the one place they are
# read — they are inert in the drains' own env files):
printf 'VIGIL_FINDING_DRAIN_ENABLED=1\nVIGIL_SETTLE_DRAIN_ENABLED=1\n' >> ~/.config/vigil/alerts.env
systemctl --user daemon-reload
systemctl --user enable --now vigil-finding-drain.timer vigil-settle-drain.timer vigil-alerts.timer
systemctl --user list-timers 'vigil-*'                  # confirm next run
vigil alerts --once --require-push                       # a fresh drain heartbeat ⇒ no alarm
vigil alerts --test-delivery                             # push ONE labelled test alert: proves alarms REACH you
# NOTE: `vigil alerts` proves LIVENESS (the drain ran), not DELIVERY. Confirm the pipeline end-to-end by
# driving a real completion/finding through and checking it crosses (the tenant surface updates / the lease
# settles) — a drain pointed at the wrong directory would run "healthy" yet move nothing.
```

A drain crash loses nothing (slice 1: the finding drain reclaims its own in-flight work + de-duplicates;
settle is idempotent per `(slug,nonce)`), and the dead-man alarms if a timer stops firing — so the pipeline
both runs and recovers without a human. The money-IN `billing-drain` ships its own opt-in
`vigil-billing-drain.timer` — enable it only once the payment-processor secrets are provisioned (GO-LIVE §9).
(The remaining drains — `monitoring-drain`, `ops-sweep`, and the offense-plane `launch-drain`/`webhook-drain` —
follow the same pattern.)

> **Persisted queue root (#75).** The drains enqueue each `SecurityJob` under the canonical root
> **`<base_dir>/jobs`** (the default when `--queue-root` is omitted) — it lives UNDER `--base-dir`, so the
> offense backup (§2b) captures the live queue (`queue/ running/ leases/ delivery/ fingerprint/`) and a host
> loss never strands an in-flight **paid** job (credits reserved + launch lease signed). Its `jobs/done/`
> completed-job audit trail is excluded by design (unbounded, not needed to re-drive). Keep
> `launch-drain`/`webhook-drain`/`reconcile`/`pr-bot` on that default; an **out-of-tree** `--queue-root` is NOT
> backup-covered (`vigil doctor` flags a `VIGIL_QUEUE_ROOT` resolving outside `--base-dir`). CI's GitHub Action
> default `.vigil-queue` is deliberately **ephemeral**/uncovered — idempotency within a single CI run only.

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
   | A | `app` | your Elastic IP | Proxied |
   | A | `hooks` | your Elastic IP | Proxied |
   | A | `console` | — | **OMIT — no public record** |

   Keep every public-serving record **Proxied** so DNS only ever resolves to Cloudflare, consistent with the
   Cloudflare-only SG lock. Do **not** create a `console` record on public DNS: a `DNS-only` (grey-cloud)
   record IS a public A record — it publishes the operator cockpit's IP to the internet and (per the SG
   caveat in §3.4) is then reachable by any Cloudflare tenant, contradicting the §topology rule "never a
   public A record". Reach the console over **VPN / SSH local-forward / split-horizon (internal-only) DNS**.
   Likewise do not switch `app` to DNS-only unless you deliberately widen the SG to serve 443 publicly — that
   removes the Cloudflare-only origin lock for that plane.
4. **Cloudflare → SSL/TLS:** mode **Full (Strict)** (Cloudflare verifies the origin cert from §2c). Then lock
   the origin to THIS zone. The SG admits **all** Cloudflare ranges and Cloudflare's **default**
   Authenticated-Origin-Pulls CA is **shared across every Cloudflare tenant** — so neither is a per-tenant
   lock: another tenant pointing their own zone at your Elastic IP would pass both and bypass your WAF /
   rate-limits / cache rules. Enforce ONE of:
   - **(a) per-hostname AOP with your OWN uploaded origin-pull certificate** (unique to this zone;
     Cloudflare → SSL/TLS → Origin Server → Authenticated Origin Pulls), enforced at the origin by
     uncommenting the `ssl_client_certificate` + `ssl_verify_client on` block in `vigil-public.nginx.conf`
     so the origin rejects any connection not bearing THIS zone's client cert; or
   - **(b) a Cloudflare Tunnel** (`cloudflared`) — then there is no public 443 at all and the SG needs no
     inbound 443/80.

   Cloudflare's *shared* AOP cert alone is **not** a sufficient origin lock.
5. **Cloudflare → Caching → Cache Rules — exactly these two, each matching exact host names.** Never write a
   rule whose expression could match `app.vigilguard.net`: no `*.vigilguard.net`, no
   `ends_with(http.host, "vigilguard.net")`, no `contains`, no URL pattern without the host. The three host sets
   below do not overlap, so their order does not matter.

   Cloudflare's labels (EXTERNAL) may be worded slightly differently; the settings are what matter.

   | Rule name | When incoming requests match (expression editor) | Then |
   |---|---|---|
   | `VIGIL app — bypass` | `(http.host eq "app.vigilguard.net")` | Cache eligibility: **Bypass cache** |
   | `VIGIL hooks — bypass` | `(http.host eq "hooks.vigilguard.net")` | Cache eligibility: **Bypass cache** |
   | `VIGIL public site — cache` | `(http.host in {"vigilguard.net" "www.vigilguard.net"})` | Cache eligibility: **Eligible for cache**; Edge TTL: **Use cache-control header if present, bypass cache if not**; Browser TTL: **Respect origin TTL** |

   - Never set "Ignore cache-control header and use this TTL" (an override TTL) on anything that matches `app`.
   - **Caching → Configuration → Browser Cache TTL: Respect Existing Headers.** EXTERNAL (Cloudflare
     behaviour): with any other value Cloudflare may raise a response's browser `max-age` to that value, which
     would keep the public pages (`max-age=0`) in browsers for hours.
   - What the origins send, which these rules respect: the public site's pages `public, max-age=0,
     s-maxage=60` + ETag (a page is at most 60 s old at the edge), its `?v=<hash>` assets
     `public, max-age=31536000, immutable` (any other `v` is a 404 + `no-store`), its `/version.json` and 404s
     `no-store`; the customer origin's `/api/*`, `/version.json` and probes `no-store`, its page and bare
     assets `no-cache` + ETag. EXTERNAL: Cloudflare caches `.js`/`.css` by default even without origin headers —
     the bypass rule is what keeps `app` out of the edge cache, and the origin's `no-store` on every tenant
     response is the backstop if that rule is ever missing (the customer vhost has no Authenticated Origin Pulls
     block, so the origin's headers, not Cloudflare, are the real control).
   - Turn on the WAF managed ruleset.
6. **Recommended — purge the public pages after every release and every public-site swap.** Without it a page can
   be up to 60 s old at the edge (`s-maxage=60`), and that page names the previous build's `?v=<hash>` assets,
   which the new origin answers with 404 + `no-store`: at a Cloudflare location that holds the old page but not
   its assets, visitors get the page without its styles and scripts until it expires. The purge, run right after
   the new public edge serves (`EDGE-SWAP.md`), closes that window for every public page. The customer app is
   never cached, so there is nothing of it to purge. To purge from the host:
   - In Cloudflare → My Profile → API Tokens, create a **custom token** with one permission,
     **Zone → Cache Purge → Purge**, and **Zone Resources: Include → Specific zone → vigilguard.net**. Nothing
     else: it cannot read or change DNS, rules or settings.
   - Keep it **on the host only** (never in this repository, never in GitHub secrets or Actions), as a curl
     header file readable by the deploy user alone, so the token is never typed into the shell history or seen
     in a process list (paste it at the silent prompt):
     ```
     install -m 600 /dev/null ~/.sigil/cloudflare-purge.header
     read -rs CF_TOKEN && printf 'Authorization: Bearer %s\n' "$CF_TOKEN" > ~/.sigil/cloudflare-purge.header
     unset CF_TOKEN
     ```
   - After a release (or an edge swap of the public site, `EDGE-SWAP.md`), purge everything the zone holds
     (`<zone-id>` is on the zone's Overview page; it is not a secret):
     ```
     curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/<zone-id>/purge_cache" \
       -H @"$HOME/.sigil/cloudflare-purge.header" -H "Content-Type: application/json" \
       --data '{"purge_everything":true}'
     ```
     This purges exactly the public site: the rules in item 5 make the public site the only host this zone
     caches (`app` and `hooks` are Bypass, `console` has no public record, and the `www` redirect carries no
   Cache-Control),
     so nothing else is in the cache. It reaches every page, which a list of URLs cannot: `/privacy`, `/careers`,
     every `/vs/…`, `/tools/…`, `/blog/…` and `/cve/…` page, and each query-string variant (`?utm_…`), which
     Cloudflare keeps under its own cache key. A purged object is fetched from the origin again on its next
     request. If a later rule ever makes another host cacheable on this zone, purge by host name instead where
     the plan offers it (`--data '{"hosts":["vigilguard.net"]}'`; EXTERNAL: Cloudflare plan feature).
     Rotate the token by deleting it in Cloudflare and writing a new one into the same file.
7. **The webhook host (`hooks`) — what Cloudflare must let through.** Register exactly
   `https://hooks.vigilguard.net/webhooks/stripe` in Stripe (go-live quickstart §9b). The record is Proxied (item
   3), so Stripe reaches the origin through Cloudflare and the security group stays Cloudflare-only; the cache
   rule is Bypass (item 5). Stripe's servers are not browsers, so nothing on the zone may challenge them on this
   host. EXTERNAL (Cloudflare behaviour — check your plan's options): a JavaScript or managed challenge, "I'm
   Under Attack" mode or a bot-blocking setting that applies to `hooks.vigilguard.net` turns a delivery into a
   challenge page Stripe cannot pass; where your plan allows, add a WAF custom rule
   `(http.host eq "hooks.vigilguard.net" and http.request.uri.path in {"/webhooks/stripe" "/webhooks/billing"})`
   that **skips** those features, and otherwise keep them off for the zone. Confirm with a test event sent by
   Stripe to the endpoint (Dashboard or Stripe CLI; EXTERNAL): the delivery must show `202` (the proxy spooled
   it). A `401` means the signing secret differs from `VIGIL_STRIPE_WEBHOOK_SECRET`; a `403` or an HTML page means
   Cloudflare challenged it; a `404` means a path other than the exact one (or the Stripe lane is not mounted on
   the proxy).

Verify the chain: `curl -sI https://vigilguard.net` returns `200` with the pubui headers and a `cf-ray`
header (served through Cloudflare); a direct hit to the Elastic IP on 443 from anywhere but a Cloudflare
range is refused by the security group. And once you enforce per-zone AOP (§3.4a): a request that reaches the
origin from a Cloudflare range **without your zone's origin-pull client cert is refused** (HTTP 400/496) —
so the only accepted path is through *your* Cloudflare zone, not merely "some Cloudflare tenant".

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

- **Cloudflare IP ranges change.** When they do, refresh the nginx `set_real_ip_from` block in BOTH
  `vigil-public.nginx.conf` and `vigil-customer.nginx.conf` (they must stay identical; a test pins it) and the
  security group (re-run `provision.sh`, which pulls the current list).
- **Rotating the owner KEK's CMK:** `sigil key rotate-kek` re-wraps the KEK under a fresh KEK; to move to a
  new CMK, set the new `VIGIL_KMS_KEY_ID` and re-provision on a staging home first. The spine + every owner
  signature are untouched by a KEK rotation (only the wrapping key moves).
- **HA:** the spine is single-writer (`hosting-and-persistence.md` §6). HA today = the durable EBS volume
  (snapshots/replication) + a warm standby that attaches it on failover; the Elastic IP re-associates to the
  standby. Writes remain single-host.
