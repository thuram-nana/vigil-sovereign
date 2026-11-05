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
VIGIL_CUSTOMER_MONITORING_ENABLED=1 sigil monitoring-secret --org <org_id> --host <host>
```

Prints the secret FILE path only (0600 in a 0700 dir, hashed name). Copy that file, unchanged, to the gateway
host as `AEGIS_SAAS_SECRET_FILE`, mode 0600, owned by the gateway user. Transfer over an authenticated channel
(scp over WireGuard/SSH). `--rotate` replaces it; the deployed gateway's reports stop verifying until the new file
is deployed and the gateway restarted.

## 3. Deploy the gateway

The gateway flags are `--saas-tenant`, `--saas-host`, `--monitoring-spool`, `--monitoring-secret-file`. The secret
is read from the file; the loader refuses symlinks, non-regular files, group/world-readable files, and secrets
shorter than 16 bytes (exit 2).

**Compose:** set `AEGIS_SAAS_UPSTREAM`, `AEGIS_SAAS_TENANT`, `AEGIS_SAAS_HOST`, `AEGIS_SAAS_DEPLOYMENT_SECRET`,
`AEGIS_SAAS_PUBLISH_DIR`, `AEGIS_SAAS_AUTHORITY_ROOT_DIR`, `AEGIS_SAAS_SECRET_FILE`, `AEGIS_SAAS_SPOOL_DIR`, then
`docker compose --profile aegis-saas up -d aegis-saas-gateway`. Missing env refuses to start.

**systemd:** `infra/systemd/aegis-saas-gateway@.service` + `/etc/aegis-saas/<instance>.env` from
`infra/systemd/aegis-saas-gateway.env.example`; `systemctl enable --now aegis-saas-gateway@<instance>`.

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

## 5. Verify

- Send a benign request through the gateway: it is forwarded.
- `sigil monitoring-drain drain` reports `0 rejected`; check `<spool>/rejected/` is empty.
- The tenant sees events only for its own org.

## Offboarding / revoke

1. Tenant (or operator) revokes: `POST /api/customer/monitoring/revoke`. The artifact is unpublished; the gateway
   returns to pass-through on the next request, and queued reports are rejected at drain.
2. Stop the instance (`systemctl disable --now aegis-saas-gateway@<instance>` or `docker compose ... down`).
3. Delete the gateway's secret file and, on the sovereign host, the matching file in the secrets dir.
