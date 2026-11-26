# AEGIS-SaaS tenant onboarding (managed gateway)

Status: **default-OFF**. Every step below is inert unless `VIGIL_CUSTOMER_MONITORING_ENABLED=1` is set on the
sovereign host. Hard blocking stays OFF until the flag-hold criteria are met (`VIGIL_AEGIS_SAAS_ENFORCE`).

## Roles and keys

| Component | Holds | Never holds |
|---|---|---|
| Sovereign provisioner | owner key; report secrets (`VIGIL_MONITORING_SECRETS_DIR`) | — |
| Customer edge (custui) | session only (tenant org comes from the server session) | owner key, report secrets |
| Managed gateway | owner trust root (pubkey), published authorities (read-only), ONE report secret file | any signing key |

## Prerequisites

1. The tenant has a CURRENT ownership proof for the exact host (asset-ownership flow).
2. The tenant has an active monitoring plan with a free host slot (and a respond tier if `block` is wanted).
3. The `vigil/aegis-gateway:local` image is built (`docker compose --profile aegis build aegis-gateway`) or the
   engine venv is installed at `/opt/aegis/venv` for the systemd path.

## 1. Tenant authorizes monitoring

The tenant org_admin calls `POST /api/customer/monitoring/authorize` (`{host, mode}`) from custui. The
provisioner owner-signs a `SignedMonitoringAuthority` and publishes it (0600, hashed filename) into
`VIGIL_MONITORING_PUBLISH_DIR`. The tenant org is taken from the session, never the body.

## 2. Provision the per-(org, host) report secret (sovereign host)

```
VIGIL_CUSTOMER_MONITORING_ENABLED=1 sigil monitoring-secret --org <org_id> --host <host> \
    --export-to /path/to/staging/<org_id>-<host>.secret
```

Provisions the secret (0600 in a 0700 dir, hashed name) and exports a 0600 copy, atomically, to the file you name.
The command prints fixed confirmation text only: never the secret and never its on-disk location. Use
`--export-only --export-to ...` to re-export an existing secret, and `--overwrite` to replace an existing export
file. Move the exported file, unchanged, to the gateway host as `AEGIS_SAAS_SECRET_FILE`, mode 0600, owned by the
gateway user, over an authenticated channel (scp over WireGuard/SSH), then delete the staging copy. `--rotate` replaces it; the deployed gateway's reports stop verifying until the new file
is deployed and the gateway restarted.

## 3. Deploy the gateway

The gateway flags are `--saas-tenant`, `--saas-host`, `--monitoring-spool`, `--monitoring-secret-file`. The secret
is read from the file; the loader refuses symlinks, non-regular files, group/world-readable files, and secrets
shorter than 16 bytes (exit 2).

**Compose:** set `AEGIS_SAAS_UPSTREAM`, `AEGIS_SAAS_TENANT`, `AEGIS_SAAS_HOST`, `AEGIS_SAAS_DEPLOYMENT_SECRET`,
`AEGIS_SAAS_PUBLISH_DIR`, `AEGIS_SAAS_AUTHORITY_ROOT_DIR`, `AEGIS_SAAS_SECRET_FILE`, `AEGIS_SAAS_SPOOL_DIR`, then
`docker compose --profile aegis-saas up -d aegis-saas-gateway`. Missing env refuses to start.

**systemd (R15 isolated unit — AS-2j):** `infra/systemd/aegis-saas-gateway@.service` is the hardened unit.
It is `DynamicUser=yes` (a distinct uid per instance — TT-B's uid cannot reach TT-A), `PrivateNetwork=yes`
with `RestrictAddressFamilies=AF_UNIX` + `IPAddressDeny=any` (no route/DNS/IMDS — the gateway cannot create
an IP socket at all), serves ingress over a `--listen-unix` socket (SO_PEERCRED = the ALB-front's uid; no
TCP), mounts the publish dir + trust root read-only, and bounds memory (`MemoryMax`/`MemoryHigh`/`TasksMax`).
Both secrets come through `LoadCredential=` (never the environment — the N-A fix), so provision them as
root-owned 0600 files the unit loads: `/etc/aegis-saas/<instance>.report.secret` (the export from §2) and
`/etc/aegis-saas/<instance>.gw.secret` (the pseudonymization secret, >=16 random bytes). Then
`/etc/aegis-saas/<instance>.env` from `infra/systemd/aegis-saas-gateway.env.example` (NO secrets in it) and
`systemctl enable --now aegis-saas-gateway@<instance>`.

Lint the unit before shipping any change to it (fail-closed; CI runs it too):
`python -m vigil_integration.aegis_unit_lint infra/systemd/aegis-saas-gateway@.service` (GREEN == hardened).

> DEFERRED (owner/infra-gated, AS-2c/2d/26 + a provisioned host): the gateway's `--listen-unix` ingress
> (SO_PEERCRED) and broker egress over a unix socket are gateway-v2 (AS-2c) + broker (AS-2d); live
> `systemctl enable --now`, `systemd-analyze security`, and the EACCES / no-IMDS probe
> (`docs/runbooks/aegis-saas-gateway-r15-probe.sh`) run on a provisioned host. Until then the unit ships
> validated OFFLINE by the lint + `integration/tests/test_aegis_gateway_unit_hardening.py`; it is not yet
> `systemctl`-activatable. The pre-AS-2j TCP/env-secret unit is frozen as the N-A negative control at
> `integration/tests/fixtures/aegis-saas-gateway-NA-negative-control.service.txt`.

Keep the gateway in `observe` mode. Without a valid authority for (tenant, host) the gateway passes traffic
through uninspected and spools nothing.

## 4. Drain monitoring reports (sovereign host)

The spool must be reachable by the sovereign host (shared volume or periodic sync into `<spool>/incoming`).

```
VIGIL_CUSTOMER_MONITORING_ENABLED=1 sigil monitoring-drain drain --spool <spool>
VIGIL_CUSTOMER_MONITORING_ENABLED=1 sigil monitoring-drain watch --spool <spool> --interval 5
```

Each report must verify under its (org, host) secret, be fresh, and match an ACTIVE authority; anything else is
moved to `<spool>/rejected/` with a `.reason` sidecar. Accepted reports become tenant monitoring events, visible
to that tenant only at `GET /api/customer/monitoring/events`.

Billing bounds monitoring continuously. AEGIS plans bill on their own monitoring-subscription line and never
touch the credit plan. Every grant expires at the end of the plan period. Cancel or past_due retires every
grant for the org. A plan change retires block grants when the new plan has no respond tier, and retires grants
beyond the slot count (the earliest-issued grants are kept). A renewal re-mints the surviving grants for the
new period. The `watch` loop above also runs the reconcile sweep, which catches a lapse when no webhook arrives.
To run the sweep by hand:

```
VIGIL_CUSTOMER_MONITORING_ENABLED=1 sigil monitoring-reconcile
```

## 5. Verify

- Send a benign request through the gateway: it is forwarded.
- `sigil monitoring-drain drain` reports `0 rejected`; check `<spool>/rejected/` is empty.
- The tenant sees events only for its own org.

## Offboarding / revoke

1. Tenant (or operator) revokes: `POST /api/customer/monitoring/revoke`. The artifact is unpublished; the gateway
   returns to pass-through on the next request, and queued reports are rejected at drain.
2. Stop the instance (`systemctl disable --now aegis-saas-gateway@<instance>` or `docker compose ... down`).
3. Delete the gateway's secret file and, on the sovereign host, the matching file in the secrets dir.

### Down-event routing and renewal grace (AE-5 fold 2)
- Cancel / payment_failed events are routed by the FULL catalog (flag-independent): a known AEGIS price only ever
  touches the monitoring line, never the credit plan. The Stripe adapter (the default provider) needs
  `metadata.price_id` on the subscription so `invoice.payment_failed` carries the AEGIS price; without it the event
  falls back to the pre-AEGIS (credit-line) behaviour.
- When a monitoring period ends with no down event, grants (clamped to `period_end`, so already inert at the
  gateway) are kept for `VIGIL_MONITORING_RENEWAL_GRACE_SECONDS` (default 72h). A renewal within grace re-mints
  them via `monitor_plan_changed`; after grace the sweep retires them. Cancel / past_due cascade immediately.
