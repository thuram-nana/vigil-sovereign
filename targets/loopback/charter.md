# Engagement Charter — `loopback`

> The binding authorization document (OBSIDIAN constitution §II). VIGIL-LIVE validates the full fused
> pipeline against a **self-hosted, deliberately-vulnerable loopback target on 127.0.0.1 that VIGIL
> stands up and owns**. There is no third party and no external host in scope.

## Target hosts (in scope)

| Host | Port | What it is |
|---|---|---|
| `127.0.0.1` | 18080 (default; see `/tmp/vigil-loopback-port`) | `infra/loopback/vulnapp.py` — a controlled vulnerable app VIGIL runs itself |

**Nothing else is in scope.** Only `127.0.0.0/8` may be touched by any tool.

## Operator attestation

- The operator authorized live end-to-end validation against **a loopback test app only** (this session,
  explicit answer to the VIGIL-LIVE scoping question).
- The target is created and owned by the operator's own machine (`127.0.0.1`); no external system,
  third-party service, or non-owned host is authorized or touched.
- Authorization is current for the duration of the VIGIL-LIVE validation.

## Hard limits (inviolable)

- **Loopback only.** Every tool invocation MUST resolve its target to `127.0.0.0/8`; the live executor
  refuses (DENY, fail-closed) any non-loopback target BEFORE a packet leaves — enforced app-layer via
  `vigil_gateway.denylist` + a loopback assertion, on top of the conjunctive gate + WARDEN tier.
- **No external egress.** No tool, no DNS, no callback may leave the host. Passive OSINT / external
  scanning is out of scope.
- **Destructive tools (metasploit/sqlmap/hydra) require the m-of-n threshold gate** even against loopback.
- **No real data.** The target holds only fake rows and returns a decoy on traversal; no real file/secret
  is ever read.

## Soft limits

- Throttle to sane rates; the target is a single local process.
- Tag every artifact `VIGIL-LIVE-`; track created accounts/rows in `notes/test-artifacts.md`.

## Stop conditions

- Any tool attempting a non-loopback target → hard stop (should be impossible; the executor denies it).
- Evidence of a real (non-test) compromise artifact → incident-response pivot.
- The operator says stop.

## Objectives

Prove the fused pipeline end-to-end: recon → injection → credential attacks against the loopback app,
every finding oracle-confirmed + signed, every action gated, each attack's signature proven by the AEGIS
Detection Mirror over the app's own logs (dual offense+detection certs), a confirmed finding auto-patched
and re-verified (AIxCC), and every run bound to a signed usage-attestation ledger entry (who/when/what).
