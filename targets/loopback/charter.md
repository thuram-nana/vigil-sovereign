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

## Addendum — the tool-driver range (authorized 2026-08-13)

The engine is gaining typed argv builders so it can drive its whole toolset. A builder that produces a
plausible-looking command line proves nothing, so each driver has to be run against a target with a
KNOWN answer: the tool must actually execute, actually find the planted weakness, and its output must
actually parse into observations. The single `vulnapp.py` above is too small a surface for that.

**The operator has therefore additionally authorized the use of purpose-built, open-source,
deliberately-vulnerable applications for tool-driver validation.** Every one of them is published by
its authors for exactly this purpose, and every one runs LOCALLY in a container this repository's
harness starts and destroys, bound to loopback. **There is still no third party and no external host in
scope, and no public test site is contacted.** Nothing in this addendum widens the hard limits below;
it adds hosts on `127.0.0.1`, which `127.0.0.0/8` already covers.

Brought up and torn down by `tools/livefire/range.sh` (`up` / `status` / `verify` / `down`), from the
manifest `tools/livefire/range_targets.json`:

| Target | Port(s) on `127.0.0.1` | Application | Image, pinned by tag AND digest |
|---|---|---|---|
| `juice` | 19000 | OWASP Juice Shop | `bkimminich/juice-shop:v20.2.0@sha256:8739101a…` |
| `dvwa` | 19001 | Damn Vulnerable Web Application | `vulnerables/web-dvwa:latest@sha256:dae203fe…` |
| `webgoat` | 19002, 19003 | OWASP WebGoat (+ WebWolf) | `webgoat/webgoat:v2025.3@sha256:3101bd9e…` |
| `mutillidae` | 19004 | OWASP Mutillidae II (NOWASP) | `citizenstig/nowasp:latest@sha256:8bf6f283…` |
| `vampi` | 19005 | VAmPI (vulnerable REST API) | `erev0s/vampi:latest@sha256:0a5a224b…` |
| `vulnapp` | 19006 | this repository's own `infra/loopback/vulnapp.py` | no image — a local process |

Ports are fixed and recorded in that one manifest, which both the shell and the Python harness read, so
the two cannot drift. Images are digest-pinned because a tag is a mutable pointer: a range whose targets
can be retagged underneath it makes every result it ever produced unreproducible, with no diff and no
signal. The pins follow the convention in `infra/supply-chain/`.

**Loopback is enforced, not remembered.** The manifest cannot express a host address — ports are plain
integers, and one function (`range_targets.publish_args`) turns them into a docker flag with `127.0.0.1`
written into the format string. After start, the binding is re-read from docker's own view, then from
the host's listening sockets, and then MEASURED: the harness connects from this host's routable address
and requires the connection to be REFUSED. Any of those failing tears the target down.

**Source-code range.** Several tools (bandit, gitleaks, trufflehog, semgrep, joern) analyse code rather
than traffic. `tools/livefire/range_source.py` GENERATES — no download — a deliberately-weak tree and a
clean twin under `.vigil-data/range/src/` (gitignored). Its planted credentials are FABRICATED and
marked as test fixtures; they authenticate to nothing. Secret scanners must be run against it with
verification disabled (e.g. `trufflehog --no-verification`), because verification would produce exactly
the external network calls this charter forbids.

**Standing artifacts.** Containers are labelled `vigil.range=1` and named `vigil-range-*`; `range.sh
down` removes them and asserts the machine was left clean. These targets hold only their own shipped
fixture data. No real user data, credential, or third-party account is involved at any point.

## Objectives

Prove the fused pipeline end-to-end: recon → injection → credential attacks against the loopback app,
every finding oracle-confirmed + signed, every action gated, each attack's signature proven by the AEGIS
Detection Mirror over the app's own logs (dual offense+detection certs), a confirmed finding auto-patched
and re-verified (AIxCC), and every run bound to a signed usage-attestation ledger entry (who/when/what).
