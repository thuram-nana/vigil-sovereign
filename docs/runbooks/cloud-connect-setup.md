# Operator runbook — enabling customer cloud-connect (AWS / GCP / Azure / Cloudflare)

This runbook is for the **VIGIL operator** (whoever deploys the VIGIL server), not for an end
customer. It answers one question: *what must be provisioned, and which environment variables
must be set, for the self-serve "connect a cloud account" screen to actually work?*

A connected cloud account is a **read-only** asset record — it is NEVER, by itself, an offense
authorization (see `apps/sigil/sigil/governor/cloud_connect.py`). Everything here is OFF by
default; a deployment that sets none of these variables offers no cloud-connect flow and every
attempt fails closed with "not available on this deployment".

## 1. Turn the surface on (required for every provider)

| Variable | Meaning |
| --- | --- |
| `VIGIL_CUSTOMER_CONNECT` | Master switch for the unified connect surface. Must be affirmative (`1`/`true`/`yes`). |
| `VIGIL_CUSTOMER_CLOUD_CONNECT` | The cloud leg of that surface. Must be affirmative AND the master switch on. |

With only these two set, **Cloudflare** already works (it needs no operator credential — see §5).
AWS, GCP and Azure each additionally need the operator to provision VIGIL's own connector identity
for that cloud, below. A provider whose connector identity is unset is simply not offered, so you
can enable exactly the providers you have provisioned.

## 2. AWS — a cross-account AssumeRole connector principal

VIGIL assumes the **customer's** read-only role with a per-challenge external id. You provision the
IAM principal that does the assuming, and tell VIGIL its ARN and credentials.

1. In VIGIL's own AWS account, create an IAM principal (user or role) VIGIL will run as.
2. Give it only `sts:AssumeRole` (the customer's role trust policy, shown on the connect screen,
   restricts *which* roles it may assume and under which external id).

| Variable | Value |
| --- | --- |
| `VIGIL_CLOUD_CONNECT_AWS_PRINCIPAL_ARN` | That principal's ARN (printed into the customer's trust policy). |
| `VIGIL_CLOUD_CONNECT_AWS_ACCESS_KEY_ID` | Its access key id. |
| `VIGIL_CLOUD_CONNECT_AWS_SECRET_ACCESS_KEY` | Its secret access key. |
| `VIGIL_CLOUD_CONNECT_AWS_SESSION_TOKEN` | Optional — only if the identity is a temporary/STS session. |

## 3. GCP — a connector service account + its private key

VIGIL impersonates a **customer-created** service account whose id encodes the per-challenge
external id, by minting a token AS it under a `roles/iam.serviceAccountTokenCreator` grant. You
provision VIGIL's connector service account and give VIGIL its signing key.

1. In VIGIL's own GCP project, create a service account (VIGIL's connector SA).
2. Create a JSON/RSA key for it. The customer grants THIS connector SA the token-creator role on
   the SA they create (the connect screen prints the exact `gcloud` commands).

| Variable | Value |
| --- | --- |
| `VIGIL_CLOUD_CONNECT_GCP_CONNECTOR_SA` | The connector SA email (`name@project.iam.gserviceaccount.com`). |
| `VIGIL_CLOUD_CONNECT_GCP_PRIVATE_KEY` | Its private key, PEM text. |

## 4. Azure — a multi-tenant app registration

VIGIL ships one multi-tenant Azure AD app; the **customer's** Global Admin admin-consents it into
their tenant and sets the external id as a tag on VIGIL's enterprise application. You provision
that app registration and give VIGIL its client id plus one credential.

1. Register a multi-tenant Azure AD application (VIGIL's connector app).
2. Give it a client **secret** OR a client **certificate/assertion**. Its only consented
   permission needs to be a read-only Microsoft Graph read.

| Variable | Value |
| --- | --- |
| `VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ID` | The app's client id (GUID), printed into the customer's admin-consent URL. |
| `VIGIL_CLOUD_CONNECT_AZURE_CLIENT_SECRET` | A client secret — **or** set the assertion below instead. |
| `VIGIL_CLOUD_CONNECT_AZURE_CLIENT_ASSERTION` | A client assertion (JWT) — alternative to the secret. |

## 5. Cloudflare — nothing for the operator to provision

Cloudflare is the exception: **VIGIL holds no Cloudflare credential of its own.** The customer
creates a read-only, single-account API token named `vigil-verify-<external_id>` and pastes it
once; VIGIL reads it twice to verify it and then never stores it (only its public id and a sha256
are recorded). So once `VIGIL_CUSTOMER_CLOUD_CONNECT` is on, Cloudflare connect works with no
further operator setup.

## 6. Egress

Each live fetcher reaches only a fixed host allowlist (enforced before any socket), so the cloud
leg never widens the server's outbound posture:

- AWS → `sts.amazonaws.com`
- GCP → `oauth2.googleapis.com`, `iamcredentials.googleapis.com`
- Azure → `login.microsoftonline.com`, `graph.microsoft.com`
- Cloudflare → `api.cloudflare.com`

If your deployment runs behind an egress policy, allow exactly the hosts for the providers you
enable.

## 7. Verifying a deployment

- `customer_connect_overview(...)["available"]["cloud_connect"]` is `true` only when at least one
  provider is fully wired (flags on + that provider's connector identity present, or Cloudflare
  with the flags on).
- A provider that is enabled but mis-provisioned fails closed on the first connect attempt rather
  than offering a dead-end flow.

## Residuals (registered, not operator-blocking)

The live round-trip against each real cloud API is not exercised in CI (there is no live cloud
account in the hash-locked CI environment); the pure protocol + the deterministic verdict are
proven offline for every provider. See `docs/limitations/inventory.json`:
`LIMIT-cloud-connect-gcp-livefire`, `LIMIT-cloud-connect-azure-live-fire`,
`LIMIT-cloud-connect-cloudflare-livefire`.
