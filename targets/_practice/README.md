# Practice-target registry — KNOWN-LEGAL, still-not-pre-authorized

> **Read this whole section before you touch any host in this file.**

This directory is a **reference list** of deliberately-vulnerable systems whose owners have
**published them for authorized testing**. It exists so a new engineer knows which public
learning targets are legitimate — and, more importantly, **how much ceremony each one still
requires** before VIGIL will send it a single packet.

## This is NOT an auto-allowlist. Say it out loud.

Listing a host here grants it **nothing**. VIGIL has exactly **one** pre-authorized target:

- **`127.0.0.1` loopback**, and only loopback, via [`../loopback/charter.md`](../loopback/charter.md).
  That charter is signed, operator-attested, and scoped to `127.0.0.0/8` and nothing else.

Every host in the registry below is a **remote** target. Before VIGIL engages any of them, an
operator (a human) must do two independent things, in this order:

1. **Author a signed charter** — a binding authorization document per the OBSIDIAN constitution
   **§II**, with the **operator-attestation block filled in by the operator**. Copy the template
   at [`../../engine/crucible/targets/_template/charter.md`](../../engine/crucible/targets/_template/charter.md).
   No console, no agent, no "just to check" auto-flow ever fills that attestation for you.
   The published-for-testing status of a target is a *precondition* for writing the charter —
   it is **not a substitute** for it.
2. **Mint the signed machine-scope** — run `vigil provision --slug <s> --scope <host>` so the
   deterministic gate has a signed CRUCIBLE authority matching the charter. `provision` signs
   *exactly* the `--scope` the operator typed (`_cmd_provision` →
   `provision_authority`, `integration/vigil_integration/live/wiring.py:108`). It does **not**
   write a charter, and it does **not** attest anything on the operator's behalf.

**Why two artifacts?** The charter is the *human* authorization (OBSIDIAN §II — the thing the
operator is legally and ethically on the hook for). The signed authority is the *machine-enforced*
scope the gate checks on every action. Neither implies the other. A minted authority with no
operator-attested charter is an out-of-process action; a charter with no minted authority never
reaches the executor.

### The console can never mint a remote charter

`vigil up` (`integration/vigil_integration/cli.py:496`, `_cmd_up`) is **EXEC-only**: it spawns the
three backends in their own venvs and imports no framework/strix/sigil. It serves a UI; it does not
author authorization. A charter is a file a human writes and attests. There is no button — in the
console or anywhere — that manufactures authorization for a host you do not own. The agent itself
cannot either: `vigil engage --scope` is enforced against the *signed* authority, not against
whatever a prompt-injected model would prefer (`_cmd_engage`, `cli.py:87`; the default scope is
`127.0.0.1`, `cli.py:102`).

### The never-liftable egress floor still applies to every target here

Even with a perfect charter, the gateway's Tier-1 deny set is **charter-independent and never
liftable** (`gateway/vigil_gateway/denylist.py`, `_ALWAYS_DENY_V4`/`_ALWAYS_DENY_V6` at line ~48):
cloud metadata (`169.254.169.254`, `fd00:ec2::/32`), link-local, multicast, reserved, and
broadcast are dropped no matter what any charter or authority says. RFC1918 / CGNAT / ULA are
denied *unless the exact resolved IP* is charter-authorized. The forward proxy re-checks every
**resolved** connection IP, so a practice hostname that (maliciously or by accident) resolves into
private/metadata space is dropped before a packet leaves — DNS rebinding does not defeat this. A
practice target can never become a pivot into your host's cloud credentials or LAN.

---

## The registry

For each target: **what it is**, **why it is legal** (owner-published), a **charter template
block** to paste into `targets/<slug>/charter.md`, and the **exact provision ceremony**.

> Conventions used below: `--slug` is a short local name for the engagement's files and signed
> authority; `--scope` is the **literal** host the authority is signed for. The scope matcher has
> **no CIDR** — pass a literal hostname or `*.`wildcard, never a block (`cli.py:655`;
> `gateway/vigil_gateway/scope_source.py:host_matches_scope`). `--base-dir` (default `.vigil-live`)
> is the engagement home; keep it identical between `provision` and `engage` so the same signed
> anchor covers both (`wiring.py:provision_authority` docstring, S7).

---

### 1. `testphp.vulnweb.com` — Acunetix "Acuart" test site

**What it is.** A deliberately-vulnerable PHP/MySQL demo web app (the "Acuart" store) that
Acunetix hosts and publishes specifically so people can point a scanner at it. Full of classic
SQLi, XSS, and auth flaws. Resolves to a **public** IP.

**Why it is legal.** Acunetix publishes it **explicitly for testing** — the site's own pages state
it is intentionally vulnerable and provided for scanner evaluation. You are testing the *owner's*
published practice target, not a third party.

**Charter block** (`targets/testphp/charter.md`):

```markdown
# Engagement Charter — `testphp`

## Target hosts (in scope)
| Host | Port | What it is |
|---|---|---|
| `testphp.vulnweb.com` | 80/443 | Acunetix "Acuart" — owner-published deliberately-vulnerable PHP app |

Nothing else is in scope. Only `testphp.vulnweb.com` may be touched.

## Operator attestation   <!-- OBSIDIAN §II — the operator fills + signs this; no tool may -->
- The operator confirms `testphp.vulnweb.com` is a target its owner (Acunetix) has
  publicly published for authorized security testing.
- The operator authorizes VIGIL to test THIS host only, for this engagement.
- Authorization is current for: __________  Signed: __________  Date: __________

## Hard limits
- `testphp.vulnweb.com` only. No pivot to any other host. Tier-1 egress floor is inviolable.
- No DoS / flooding. Throttle — it is a shared community resource.
- Destructive tools (sqlmap/metasploit/hydra) still require the m-of-n threshold gate.

## Stop conditions
- Any tool attempting a non-scope target → hard stop. Operator says stop → stop.
```

**Provision + engage ceremony:**

```bash
# 1) mint + sign the CRUCIBLE authority matching the charter scope
vigil provision --slug testphp --scope testphp.vulnweb.com --base-dir .vigil-live

# 2) engage — --scope must equal the signed scope; --approve-offense is the human gate leg
vigil engage http://testphp.vulnweb.com/ --slug testphp \
    --scope testphp.vulnweb.com --base-dir .vigil-live --approve-offense
```

---

### 2. OWASP Juice Shop — self-hosted

**What it is.** OWASP's modern, deliberately-insecure JavaScript web app, the reference training
target for the OWASP Top 10. It is **software you run yourself** (Docker / npm), not a host someone
else operates.

**Why it is legal.** It is MIT-licensed and *designed to be self-hosted*. You own the instance you
stand up, so you own the target — the same ownership story as the loopback app.

**Preferred path — run it on loopback, which is already pre-authorized.** If you bind Juice Shop to
`127.0.0.1` (e.g. `docker run -p 127.0.0.1:3000:3000 bkimminich/juice-shop`), it is covered by the
existing [`../loopback/charter.md`](../loopback/charter.md) once you point the engagement at the
right port — **no new remote charter, no new provision** (loopback is the one pre-authorized scope).
Prefer this. Only write a separate charter if you deliberately expose it off-loopback.

```bash
# loopback instance — reuses the pre-authorized loopback charter; NO new authority needed
vigil engage http://127.0.0.1:3000/ --slug loopback --scope 127.0.0.1 --approve-offense
```

**If you bind it to a LAN IP instead** (e.g. `192.168.x.x`): that is RFC1918 space, **denied unless
the exact IP is charter-authorized** (`denylist.py` Tier-2). You must author a `juiceshop` charter
attesting you own that host **and** provision that literal IP — and even then the metadata/link-local
floor still holds:

```bash
vigil provision --slug juiceshop --scope 192.168.1.50 --base-dir .vigil-live
vigil engage http://192.168.1.50:3000/ --slug juiceshop --scope 192.168.1.50 --approve-offense
```

---

### 3. DVWA (Damn Vulnerable Web Application) — self-hosted

**What it is.** A classic PHP/MySQL training app with tunable difficulty levels for SQLi, XSS,
command injection, file inclusion, etc. Like Juice Shop, it is **software you host yourself**.

**Why it is legal.** GPL, distributed expressly for learning; you own the instance you deploy. Same
ownership story as loopback.

**Preferred path — loopback.** Bind it to `127.0.0.1` and it is already covered by
[`../loopback/charter.md`](../loopback/charter.md):

```bash
# loopback instance — reuses the pre-authorized loopback charter
vigil engage http://127.0.0.1:8080/ --slug loopback --scope 127.0.0.1 --approve-offense
```

For a LAN-bound instance, follow the same "own it → charter it → provision the literal IP" path
shown for Juice Shop above (`--slug dvwa`, `--scope <your.lan.ip>`). RFC1918 stays denied until the
exact IP is charter-authorized.

---

### 4. `testfire.net` (Altoro Mutual) — HCL/IBM AppScan demo bank

**What it is.** "Altoro Mutual," a deliberately-vulnerable demo online-banking app published as an
AppScan test/training site. Fake accounts, fake money, classic web + auth flaws. Public IP.

**Why it is legal.** The vendor publishes it **for testing/demo**, and the site itself states it is
a fictional company provided to demonstrate web-app scanning. You test the owner's published
practice site — never a real bank.

**Charter block** (`targets/testfire/charter.md`) — same shape as the `testphp` block, substituting:

```markdown
## Target hosts (in scope)
| Host | Port | What it is |
|---|---|---|
| `testfire.net` | 80/443 | Altoro Mutual — owner-published deliberately-vulnerable demo bank |

## Operator attestation   <!-- OBSIDIAN §II — operator fills + signs; no tool may -->
- The operator confirms `testfire.net` is published by its owner for authorized testing.
- The operator authorizes VIGIL to test THIS host only.
- Signed: __________  Date: __________
```

**Provision + engage ceremony:**

```bash
vigil provision --slug testfire --scope testfire.net --base-dir .vigil-live
vigil engage https://testfire.net/ --slug testfire \
    --scope testfire.net --base-dir .vigil-live --approve-offense
```

> The data is fake by design — but the OBSIDIAN "no real PII / no real money" rule (constitution
> §XI) still governs your conduct: treat it as if it could be real.

---

### 5. `scanme.nmap.org` — Nmap project scan target

**What it is.** A single host the Nmap project operates and publishes with the standing message:
*"You are authorized to scan this machine with Nmap."* Intended for **network scanning practice**
(port discovery, service/version detection) — **not** web-app or brute-force abuse.

**Why it is legal.** The Nmap project (the owner) explicitly authorizes Nmap scans of this host, and
asks that you not hammer it. Scope your charter to *scanning only*.

**Charter block** (`targets/scanme/charter.md`):

```markdown
## Target hosts (in scope)
| Host | Port | What it is |
|---|---|---|
| `scanme.nmap.org` | (as discovered) | Nmap project host, published for a few Nmap scans |

## Operator attestation   <!-- OBSIDIAN §II — operator fills + signs; no tool may -->
- The operator confirms scanme.nmap.org is published by the Nmap project for authorized scanning.
- Scope is limited to LIGHT Nmap scanning; no brute-force, no DoS, no flooding.
- Signed: __________  Date: __________

## Soft limits
- A few scans only — the Nmap project asks not to be hammered. Throttle hard.
```

**Provision + engage ceremony:**

```bash
vigil provision --slug scanme --scope scanme.nmap.org --base-dir .vigil-live
# scanning-only; keep it light per the owner's request
vigil engage http://scanme.nmap.org/ --slug scanme \
    --scope scanme.nmap.org --base-dir .vigil-live --approve-offense
```

---

## Adding a new practice target safely (the pattern to copy)

1. **Confirm owner-published status yourself**, first-hand — read the target's own published
   statement that it is provided for authorized testing. "Someone on a forum said it's fine" is not
   authorization. If you cannot find the owner's own published statement, it does not belong here.
2. **Prefer loopback.** If the target is self-hostable (Juice Shop, DVWA, WebGoat, bWAPP, …), run it
   on `127.0.0.1` and reuse [`../loopback/charter.md`](../loopback/charter.md). No remote charter, no
   new authority, smallest blast radius. This is almost always the right answer.
3. **Author the charter** from
   [`../../engine/crucible/targets/_template/charter.md`](../../engine/crucible/targets/_template/charter.md)
   at `targets/<slug>/charter.md`. The **operator** fills and signs the attestation block (§II). Add
   the row to this registry with the same three parts (what / why-legal / ceremony).
4. **Provision the literal scope:** `vigil provision --slug <slug> --scope <host>`. Literal hosts
   only — no CIDR. Keep `--base-dir` consistent with the `engage` you will run.
5. **Engage with a matching `--scope`.** If `engage --scope` and the signed authority disagree, the
   gate refuses — that is the system working, not a bug to route around.

## Gotchas

- **Registry membership ≠ authorization.** The only thing pre-authorized is loopback. A row here is
  a note that *a charter is permissible to write*, not that one exists.
- **`provision` mints an authority, not a charter.** It signs the `--scope` you pass and writes a
  signed authority (`wiring.py:provision_authority` → `save_signed_authority`). It never creates or
  attests `charter.md`. Skipping the human charter is an OBSIDIAN §II violation even though the tool
  will happily mint the authority.
- **No CIDR in scope.** `--scope 10.0.0.0/24` does not do what you think — the matcher only
  understands literal hosts and `*.`wildcards (`cli.py:655`, `scope_source.py`). Provision each
  literal host/IP.
- **A `*.`wildcard is a deliberately broad grant.** `vigil engage --scope` warns that a wildcard
  authorizes reaching whatever public IP any matching subdomain currently resolves to (`cli.py:600`).
  For practice targets, always prefer the exact literal host.
- **The egress floor cannot be scoped open.** You cannot charter `169.254.169.254`, a LAN metadata
  endpoint, or multicast into scope — `denylist.py` Tier-1 drops them regardless. A practice
  engagement can never pivot to your host's cloud credentials.
- **Destructive tools still gate.** `sqlmap`, `metasploit`, `hydra` require the m-of-n threshold gate
  even against a deliberately-vulnerable practice host (same rule as
  [`../loopback/charter.md`](../loopback/charter.md)).
- **Shared community targets are shared.** `testphp`, `testfire`, and `scanme` are hit by thousands
  of learners. Throttle, tag your artifacts (`VIGIL-LIVE-` / your charter's prefix), and do not run a
  heavy scanner in a tight loop. Being publishable-for-testing is not a license to degrade the host.
- **`engage` fails closed and honest.** With no `ANTHROPIC_API_KEY` and no `--replay`, an engagement
  still attests first and completes with nothing proposed — it never fabricates activity (`cli.py`
  module docstring). A REFUSED engagement exits non-zero; that is the gate protecting you.
