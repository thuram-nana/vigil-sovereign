# Default credentials reference

A reference of vendor / product default credentials. Use sparingly
and only after confirming lockout / rate-limit behavior on the target.
This list is a starter; expand per engagement as new platforms appear.

| Product | Username | Password |
|---------|----------|----------|
| MySQL | `root` | (blank), `root`, `mysql`, `password` |
| PostgreSQL | `postgres` | `postgres`, (blank) |
| MongoDB | (no auth) | (no auth) |
| Redis | (no auth or `default`) | (blank) |
| ElasticSearch | `elastic` | `changeme` |
| RabbitMQ | `guest` | `guest` |
| Kibana | `kibana` | `changeme` |
| Memcached | (no auth) | (no auth) |
| Tomcat / Manager | `tomcat` | `tomcat`, `s3cret`, `admin` |
| JBoss | `admin` | `admin` |
| Jenkins | `admin` | `admin` (rare in modern installs) |
| GitLab | `root` | `5iveL!fe` (older), or auto-generated |
| Grafana | `admin` | `admin` |
| Kubernetes Dashboard | (token) | (token) |
| AWS / GCP / Azure | (root / admin not creds-based) | n/a |
| Pi-hole | `pi` | `raspberry` |
| Synology | `admin` | (blank) |
| QNAP | `admin` | `admin` |
| Routers (consumer) | `admin` | `admin`, `password`, `1234` |
| Cisco devices | `cisco` / `admin` | `cisco` / `admin` |
| Juniper | `root` / `admin` | (blank) / various |
| pfSense | `admin` | `pfsense` |
| OpenWRT | `root` | (blank) |
| WordPress (post-install) | `admin` / first user | (set during install) |
| phpMyAdmin | `root` | (blank) — if MySQL has no password |
| Adminer | (DB creds) | (DB creds) |
| GitLab Runner | (token) | (token) |
| HAProxy stats | `haproxy` | `haproxy` |
| OpenStack | `admin` | `secret` |
| VMware vCenter | `administrator@vsphere.local` | various |
| Splunk | `admin` | `changeme` |
| ELK | `elastic` | `changeme` |
| Prometheus | (no auth typically) | (no auth) |
| Apache Druid | (no auth) | (no auth) |

Common SSH / OS-level defaults:

| Distribution | Default | Password |
|--------------|---------|----------|
| Raspbian | `pi` | `raspberry` |
| Kali | `kali` | `kali` |
| Ubuntu / Debian | (none) | (none) |
| AWS Linux | `ec2-user` | (key only) |
| RHEL / CentOS | `centos` / `cloud-user` | (key only) |

Common SaaS / appliance vendor defaults: see vendor-specific docs.
This list is intentionally short; the operator can extend with
their own stack.

---

## Usage cautions

- **Lockout-aware**: try ≤3 default credential attempts per account
  per host. Many appliances permanently lock after small numbers of
  failed attempts.
- **Tag attempts**: source-IP correlatable, User-Agent identifiable
  (TEST posture).
- **Prefer fail-fast**: a single curl with default creds is better
  than multi-account fuzzing on a target that may permanently
  alarm.
- **Don't escalate without operator approval**: even if creds work,
  most owner-tests stop at "default cred works"; pivoting deeper
  requires explicit go-ahead in the charter.

---

## Where these come from

This list is curated from common defaults seen across pentest
engagements; not exhaustive. For comprehensive vendor lists:

- SecLists `Passwords/Default-Credentials/`.
- Routerpasswords.com.
- Vendor documentation.

When you find a product not on this list with a default password,
add it here for future engagements.
