# Enterprise cloud (AWS / GCP / Kubernetes) assessment — Pwned Labs

An enterprise-grade, end-to-end assessment and benchmark of VIGIL's cloud-security capability against
[Pwned Labs](https://pwnedlabs.io) — a legal, intentionally-vulnerable cloud training platform whose labs are
real cloud accounts provisioned to the tester (your own authorized instance, not an attack on the platform).
The goal: find every gap between the real cloud-attack surface and what VIGIL can prove, and drive VIGIL to
close it.

## Contents

| Artifact | What it is |
|---|---|
| [`technique-catalogue.json`](./technique-catalogue.json) | 120 real cloud-attack techniques (AWS 56 / GCP 35 / K8s 29), each tagged with kill-chain phase, the primitive it exploits, `posture` vs `exploitation` class, the achieved effect an oracle must confirm, and which scanner families flag its posture precursor. Built from the Pwned Labs catalogue + MITRE ATT&CK Cloud/Containers, HackTricks Cloud, Rhino/PACU IAM-privesc, CIS. |
| [`gap-analysis.md`](./gap-analysis.md) | What VIGIL actually detects today (each claim tied to the exact oracle firing predicate, independently red-penned), the DETECTS / PARTIAL / MISSES map, and the E1–E5 build prioritization. The "report that guides improvement." |
| `benchmark-*.md` / `.json` | Signed per-lab benchmark scorecards (VIGIL vs prowler / scout-suite / checkov), produced by `vigil_integration.live.cloud_benchmark`. Fixture-tested offline; live once lab creds land. |

## The core finding

VIGIL today proves **static achieved-state posture** (public exposure, encryption-off-on-sensitive,
wildcard/anonymous principals) and **static IAM grant PATHS**, plus a narrow set of K8s control-plane flags
and anon→dangerous-role RBAC bindings. It oracle-confirms **no exploitation chain** — the live action that
turns a misconfiguration into a proven compromise. 97 of the 120 catalogued techniques are exploitation-class.
That gap is the E1–E5 build:

- **E1** SSRF/foothold → IMDS/metadata credential capture
- **E2** IAM privilege-escalation path proven exploitable
- **E3** GCP service-account impersonation / token forgery
- **E4** Kubernetes RBAC exploitation
- **E5** exposed-secret validation & exfil-path

Each is built the VIGIL way: a deterministic oracle that CONFIRMS the achieved effect over the runner's own
gated, live evidence → a signed, offline-re-verifiable achieved-effect FACT; WARDEN-A2-gated + kill-switch;
scoped to the authorized lab; NO evasion; independently red-penned.

## Status

- **Phase 1** technique catalogue — complete.
- **Phase 2** gap analysis — complete (red-penned).
- **Phase 3** signed benchmark harness — `cloud_benchmark.py`, fixture-tested; live scorecard once creds land.
- **Phase 0** lab access — the Pwned Labs login mechanism is mapped (Laravel Sanctum, no CAPTCHA); awaiting
  valid operator credentials + started labs (each lab's cloud credentials, configured as ambient
  env/ADC/kubeconfig for the read-only collectors).
- **Phase 4** live-fire coverage — gated on Phase 0 credentials + a per-lab charter (`## 2b. Cloud scope`).
- **Phase 5** E1–E5 exploitation build — fixture-first per wave, operator scope-confirmed before each lands.

## Authorization

Only a Pwned Labs lab environment the operator has provisioned (and configured its credentials as ambient) is
ever a target. The `pwnedlabs.io` platform itself is out of scope. Every live capture is D5-scope-gated
against a signed charter, WARDEN-gated, kill-switch-honoured, correlatable (recognizable UA), and throttled.
