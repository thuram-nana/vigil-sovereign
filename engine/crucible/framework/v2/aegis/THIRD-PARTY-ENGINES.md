# AEGIS third-party engines — licence ledger (AS-7a)

This is the human-readable face of the machine ledger in [`engine-pins.json`](./engine-pins.json).
It records, for every engine, dependency, rule set and distributed artefact AEGIS deploys, the
licence it carries and the **use mode** it reaches a user through — the one distinction §7 of the
plan turns on:

- **service** — run behind the SaaS network; nothing is handed to the customer. GPL / LGPL /
  Apache / BSD / MIT impose nothing here; AGPL §13 bites only when the engine is *modified*;
  SSPL / Elastic-2.0 / BUSL / Commons-Clause / CC-BY-NC are **denied**.
- **distribution** — shipped to the customer (the CloudFormation template, the kit, the
  forwarder/SDK, rule content pushed to customers). Strong copyleft (GPL / AGPL) is denied for
  kits by default; permissive and weak-copyleft carry a NOTICE / relink obligation; DRL-1.1 and
  first-party artefacts carry an attribution / customer-terms obligation.

The policy that turns a (licence, use mode) pair into *allow / allow-with-obligation / deny* lives
in [`license_policy.json`](./license_policy.json); it is applied by
[`license_policy.py`](./license_policy.py), and the deploy-time completeness/consistency gate is
[`license_gate.py`](./license_gate.py). Run the gate with:

```
python -m framework.v2.aegis.license_gate
```

It exits non-zero (fail-closed) unless the ledger is **complete** (a record for every deployed
artefact — R1), **consistent** (the deployed use mode matches the ledgered one), and
**policy-clean** (every non-advisory record passes §7). An **advisory** entry is tracked here but
never blocks a deploy — it must be resolved to a non-advisory record before it can ship without
the advisory flag. Obligations (NOTICE, relink, DRL attribution, customer terms) are tracked as
non-blocking advisories and are discharged in the distribution slices (NOTICE / kit).

> This table is kept consistent with `engine-pins.json` by
> `tests/test_license_gate.py::test_third_party_doc_lists_every_ledgered_artefact`.

## Service-use engines, dependencies and rules

| Artefact | Kind | Licence | Notes |
|---|---|---|---|
| `vigil-aegis-gateway` | engine | PolyForm-Noncommercial-1.0.0 | first-party AEGIS gateway; commercial terms under D10 |
| `aegis-siem-notify-connector` | engine | PolyForm-Noncommercial-1.0.0 | AS-20 first-party outbound SIEM/notify emitter (broker-sealed credential, AS-9a); service-use only, commercial terms under D10 |
| `coraza-v3` | engine | Apache-2.0 | front WAF engine (DetectionOnly) |
| `caddy` | engine | Apache-2.0 | front reverse proxy (pin [U]) |
| `coreruleset-crs-4x` | rule | Apache-2.0 | CRS 4.x rule corpus, gated for tenants |
| `vectorscan` | dependency | BSD-3-Clause | Hyperscan-compatible matcher (Hyperscan ≥5.5 proprietary is not used) |
| `haproxy` | engine | GPL-2.0 | service-use only; GPL imposes nothing on service use |
| `suricata` | engine | GPL-2.0 | runs as a separate process; service-use only |
| `sigmahq-rules` | rule | DRL-1.1 | DRL-1.1 requires author attribution in match views [W] |
| `pysigma` | dependency | LGPL-3.0 | **advisory** — dev-only, not shipped (tracked, non-blocking) |

## Distributed artefacts

| Artefact | Kind | Licence | Bundle | Notes |
|---|---|---|---|---|
| `aegis-cfn-template` | artifact | PolyForm-Noncommercial-1.0.0 | aegis-kit | distributed CloudFormation template; customer terms under D10 |
| `aegis-forwarder-sdk` | artifact | Apache-2.0 | aegis-kit | forwarder/SDK shipped to customers (no framework); NOTICE obligation |
| `pushed-crs-rules` | rule | Apache-2.0 | pushed-rules | CRS-derived rule content pushed to customers carries its notices |
| `pushed-sigma-rules` | rule | DRL-1.1 | pushed-rules | Sigma-derived pushed rules carry DRL attribution |
