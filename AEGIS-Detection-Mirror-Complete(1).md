# AEGIS Detection Mirror — Complete

**The red-team toolkit inverted into provable defence — architecture, the seven detection agents, and install, in one file.**

For every offensive tool, an AEGIS detection oracle that proves its use against a system you protect, as a re-runnable PCF certificate. This does not automate attack tools; it mirrors them. Detection is defence — the agents recognise attacks, they never wield tools.

---

## Contents

- **Part I — Architecture** — the three detection planes, the seven detection domains, the master tool→signature→oracle→certificate mapping, FORGE integration, the kill-chain timeline, and honest limits.
- **Part II — The Seven Sentinel Agents** — the Claude Code subagents, as extractable file blocks for `.claude/agents/`.
- **Part III — Install & Use** — how to deploy and operate them.

---

## Part I — Architecture

### AEGIS Detection Mirror

**Every offensive tool leaves a signature. AEGIS proves its use — with a re-runnable certificate, not an alert.**

This is the defensive mirror of the red-team toolkit. Rather than automating the attack tools (which AEGIS does not do), it maps each one to a **detection oracle** that proves, over telemetry a system you protect actually produced, that the tool was used against you — and ships every detection as a PCF certificate anyone can re-verify offline. The offensive kill chain runs top to bottom; the defensive proof-chain runs alongside it.

Written in the house register: what is detectable, what is hard, and what is not detectable at all.

---

#### 0. The thesis

An attacker's tools are commodities; their *behaviour on your systems* is observable. `sqlmap` emits characteristic injection structures. A Cobalt Strike beacon emits periodic egress with a recognisable TLS fingerprint. SharpHound emits a burst of LDAP enumeration. `Hydra` emits an authentication-failure velocity no human produces. None of that is stealthy against a defender who is *looking for the signature and can prove the match*.

So the mirror is not "recognise every attack" — it is: **for each stage of the kill chain, define the deterministic signature, author an oracle that fires only on it, and mint a certificate that re-proves the detection offline.** Detection inherits the whole AEGIS doctrine: only a fired oracle confirms, suspicion that cannot be proven is a *lead* not a block, and precision beats recall because a false detection that halts legitimate traffic is its own incident.

---

#### 1. Principles

1. **Prove, don't guess — for detection too.** A detection is a FACT only when a deterministic oracle fires over retained telemetry and the certificate re-fires. Everything softer is a LEAD (observe/alert), never a silent block.
2. **A certificate per detection.** Every confirmed detection is a PCF certificate: the retained telemetry evidence + the oracle + the verdict, signed, re-verifiable offline. An analyst re-runs it instead of trusting it.
3. **Precision over recall.** Blocking or high-confidence alerting requires proof. This bounds analyst load to what is real and makes automated response safe.
4. **Benign twin mandatory.** Every detection oracle ships with a false-positive control — a legitimate pattern that superficially resembles the attack and must *not* fire. Detection engineering lives or dies on this.
5. **Additive by construction.** Each detection domain is an AEGIS capability domain, registered via `aegis/registry.py`, off the offensive path, `make gate` byte-identical.

---

#### 2. The three detection planes

Where a detection lives is determined by where its signature is observable. The mirror spans three planes:

| Plane | What it sees | Detects | Telemetry it needs |
|---|---|---|---|
| **Edge** (RAMPART, in-path) | every HTTP request/response | recon, content-discovery, injection, scanner, CMS/WAF probes | the live request (no extra ingest) |
| **Telemetry** (sensors) | logs from the systems you protect | credential attacks, AD/Kerberos abuse, cloud API abuse, session anomalies | auth logs, DC/LDAP logs, CloudTrail/audit, identity events |
| **Egress / network** (monitor) | outbound connections & DNS | C2 beaconing, DNS tunnelling, exfiltration | NetFlow/proxy logs, DNS logs, optionally EDR |

The honest consequence: **edge detections work the moment RAMPART fronts your site; telemetry and egress detections require AEGIS to ingest the relevant logs.** No log source, no proof — stated plainly, not hidden.

---

#### 3. The seven detection domains (the Sentinels)

Each domain is owned by a detection agent (`.claude/agents/*-sentinel.md`). For each: the offensive tools it mirrors, the signature family, the oracle(s) it authors, the evidence it needs, its benign twin, and when it fires.

##### 3.1 RECON-SENTINEL — perimeter reconnaissance
- **Mirrors:** Nmap, masscan, Amass/subfinder (active resolution), ffuf/gobuster/feroxbuster/dirsearch, Nuclei, Nikto, WPScan, wafw00f, katana.
- **Signature family:** high request/connection rate, high 404/NXDOMAIN ratio, dictionary/sequential path or subdomain walking, scanner-characteristic paths (`/.git`, `/wp-json`, admin panels) and fingerprints, port/service sweeping.
- **Oracles:** port-scan (rate + port-spread over connection logs), DNS-enumeration (NXDOMAIN velocity), forced-browsing (404-rate + path-entropy + rate over access logs), scanner-fingerprint (known request signatures), CMS-enumeration, WAF-probe.
- **Evidence:** access logs, connection logs, authoritative DNS logs.
- **Benign twin:** a legitimate uptime monitor or search-engine crawler (robots-respecting, low 404, known source).
- **Plane / when:** Edge + telemetry; fires at the *earliest* stage, before exploitation.

##### 3.2 INJECTION-SENTINEL — in-path payload detection (the RAMPART core family)
- **Mirrors:** sqlmap, Ghauri (SQLi); Dalfox, XSStrike (XSS); tplmap (SSTI); XXE tooling; command-injection; ysoserial/ysoserial.net (deserialization); jwt_tool (JWT).
- **Signature family:** structural attack constructs in a parameter/header/body that reach a sink — SQL tautologies/UNION/time-based, script/event-handler/`javascript:`, template syntax, external-entity declarations, shell metacharacters, serialized-gadget markers, `alg:none`/tampered-signature/`kid` injection, plus path traversal and CR/LF-NUL smuggling.
- **Oracles:** one deterministic structural oracle per class, each embedding its `FindingContext` as the re-runnable certificate. Extends the prototyped path-traversal and CRLF oracles.
- **Evidence:** the request (edge) or WAF/app logs (telemetry).
- **Benign twin:** a parameter legitimately containing an attack-like token (the word `select` in prose, escaped HTML in a CMS field, an encoded filename with dots).
- **Plane / when:** Edge (in-path, can block); fires at the exploitation-attempt stage.

##### 3.3 CREDENTIAL-SENTINEL — authentication attacks
- **Mirrors:** Hydra, Medusa, Patator (brute/spray); credential stuffing; CeWL-derived wordlists.
- **Signature family:** per-account auth-failure velocity (brute), one-password-many-accounts (spray), distributed valid-format logins across many accounts at low per-account rate (stuffing).
- **Oracles:** brute (per-account failure velocity), spray (cross-account single-credential), stuffing (extends the existing AEGIS `CREDENTIAL_STUFFING` class).
- **Evidence:** authentication logs (short retained window — stateful).
- **Benign twin:** a user mistyping a password a few times; a legitimate login surge (product launch, morning peak).
- **Plane / when:** Edge + telemetry; fires at the credential-access stage.

##### 3.4 SESSION-PHISH-SENTINEL — session hijacking & MFA-bypass phishing
- **Mirrors:** Evilginx2 (reverse-proxy MFA phishing), session/token theft, OAuth abuse.
- **Signature family:** session used from an anomalous origin/device (impossible travel), token/cookie replay from a new origin, reverse-proxy-in-front fingerprints on sessions to the real site, anomalous OAuth consent/token grants.
- **Oracles:** session-origin-anomaly, token-replay, oauth-grant-anomaly.
- **Evidence:** session/auth logs, identity-provider events.
- **Benign twin:** a legitimate user on a new device or VPN — **note (honest):** this is the hardest domain; the benign overlap is large, so several signals here emit *leads*, and only strong composite evidence (replay + impossible-travel) reaches FACT.
- **Plane / when:** Telemetry; fires at the credential-access / session-hijack stage.

##### 3.5 C2-SENTINEL — command-and-control & exfiltration (egress)
- **Mirrors:** Cobalt Strike, Sliver, Metasploit, Havoc, Mythic (beaconing); DNS-tunnelling; data exfiltration.
- **Signature family:** periodic outbound connections with consistent interval + jitter (beacon-timing), known C2 JA3/JARM TLS fingerprints, characteristic URI/User-Agent patterns, high-entropy subdomain queries (DNS tunnel), anomalous outbound data volume/destination (exfil).
- **Oracles:** beacon-periodicity (timing analysis over egress logs), c2-tls-fingerprint (JA3/JARM match), dns-tunnel-entropy, exfil-volume-anomaly.
- **Evidence:** NetFlow/proxy logs, DNS logs, optionally EDR.
- **Benign twin:** legitimate periodic polling (update checks, telemetry, monitoring) — requires an allowlist of known-good beacons.
- **Plane / when:** Egress/network; fires *post-compromise* — the last chance, and the highest-value catch.
- **Honest note:** modern C2 defeats naive timing analysis with heavy jitter and domain fronting; this is an arms race, and high-fidelity detection depends on ingesting real network telemetry.

##### 3.6 IDENTITY-GRAPH-SENTINEL — Active Directory & Kerberos attacks
- **Mirrors:** BloodHound/SharpHound (collection); Rubeus/Impacket (Kerberoasting, AS-REP, DCSync, tickets); Mimikatz (credential dumping); Certipy (AD CS abuse); NetExec.
- **Signature family:** burst of LDAP enumeration queries with characteristic filters (SharpHound), TGS requests for many SPNs with RC4 downgrade (Kerberoast), AS-REQ for pre-auth-disabled accounts (AS-REP roast), replication requests (`DsGetNCChanges`) from non-DC principals (DCSync), anomalous ticket lifetimes/encryption (Golden/Silver), LSASS memory access (Mimikatz — needs EDR), anomalous certificate requests (AD CS).
- **Oracles:** ldap-recon (query-volume + filter signature), kerberoast (TGS pattern + weak etype), asrep-roast, dcsync (replication from non-DC), ticket-anomaly, lsass-access, adcs-abuse.
- **Evidence:** Domain Controller / LDAP / Kerberos event logs, EDR (for LSASS).
- **Benign twin:** a legitimate directory-sync service (allowlisted), genuine DC-to-DC replication.
- **Plane / when:** Telemetry; fires at the lateral-movement / privilege-escalation stage (internal).

##### 3.7 CLOUD-SENTINEL — cloud & container attacks
- **Mirrors:** Pacu (AWS exploitation), ScoutSuite/Prowler (enumeration patterns), kube-hunter/Peirates (k8s), container escape.
- **Signature family:** burst of describe/list API calls across services (enumeration), IAM privilege-escalation call sequences, anomalous role/policy changes, k8s API probing / anonymous access / service-account-token abuse, container-to-host access.
- **Oracles:** cloud-enumeration (API-pattern over CloudTrail/audit), iam-privesc-sequence, k8s-attack (extends existing `K8S_POSTURE`/`MESH_POSTURE`), container-escape.
- **Evidence:** CloudTrail/cloud audit logs, k8s audit logs.
- **Benign twin:** a legitimate IaC run (Terraform describe calls), normal `kubectl` usage — requires actor/context.
- **Plane / when:** Telemetry; fires at the cloud lateral-movement / privesc stage.

---

#### 4. Master mapping: offensive tool → defensive proof

| Kill-chain stage | Offensive tool(s) | Observable signature | AEGIS oracle | Telemetry / plane | Certificate grounding |
|---|---|---|---|---|---|
| Recon — port scan | Nmap, masscan, RustScan | port/service sweep, rate | `port_scan` | conn logs / edge | FACT |
| Recon — subdomain | Amass, subfinder, puredns | NXDOMAIN velocity | `dns_enumeration` | DNS logs | FACT |
| Recon — content | ffuf, gobuster, dirsearch, feroxbuster | 404-rate + path-entropy | `forced_browsing` | access logs / edge | FACT |
| Recon — vuln scan | Nuclei, Nikto | scanner request signatures | `scanner_fingerprint` | access logs / edge | FACT / LEAD |
| Recon — CMS | WPScan, droopescan | CMS-path enumeration | `cms_enumeration` | access logs / edge | FACT |
| Recon — WAF | wafw00f | WAF-eliciting probes | `waf_probe` | access logs / edge | LEAD |
| Injection — SQLi | sqlmap, Ghauri | tautology/UNION/time-based | `sqli_structure` | edge | FACT |
| Injection — XSS | Dalfox, XSStrike | script/handler/`javascript:` | `xss_structure` | edge | FACT |
| Injection — SSTI/XXE/cmd | tplmap, XXE, cmd-inj | template/entity/metachar | `ssti`,`xxe`,`cmd_injection` | edge | FACT |
| Injection — deser | ysoserial(.net) | gadget markers | `deserialization` | edge | FACT |
| Injection — JWT | jwt_tool | `alg:none`/tamper/`kid` | `jwt_tamper` | edge | FACT |
| Injection — traversal/smuggling | (manual, Burp) | `../` escape, CR/LF/NUL | `path_traversal`,`crlf_injection` | edge | FACT |
| Creds — brute/spray | Hydra, Medusa, Patator | failure velocity / spray | `brute_force`,`password_spray` | auth logs | FACT |
| Creds — stuffing | (stuffing kits) | distributed valid-format logins | `credential_stuffing` | auth logs | FACT |
| Session — MFA phish | Evilginx2 | replay + impossible-travel | `session_origin_anomaly`,`token_replay` | session logs | FACT / LEAD |
| C2 — beacon | Cobalt Strike, Sliver, Metasploit | periodicity + JA3/JARM | `beacon_periodicity`,`c2_tls_fingerprint` | NetFlow/proxy | FACT / LEAD |
| C2 — DNS tunnel | (iodine, dnscat2) | subdomain entropy | `dns_tunnel` | DNS logs | FACT |
| Exfil | (rclone, custom) | outbound volume/destination | `exfil_volume` | NetFlow/proxy | LEAD |
| AD — collection | BloodHound/SharpHound | LDAP enum burst | `ldap_recon` | DC logs | FACT |
| AD — Kerberoast | Rubeus, Impacket | TGS + RC4 downgrade | `kerberoast` | Kerberos logs | FACT |
| AD — DCSync | Mimikatz, secretsdump | replication from non-DC | `dcsync` | DC logs | FACT |
| AD — cred dump | Mimikatz | LSASS access | `lsass_access` | EDR | FACT |
| AD — AD CS | Certipy | anomalous cert request | `adcs_abuse` | AD CS logs | FACT / LEAD |
| Cloud — enum/privesc | Pacu, ScoutSuite | API burst / IAM privesc | `cloud_enumeration`,`iam_privesc` | CloudTrail | FACT / LEAD |
| Cloud — k8s | kube-hunter, Peirates | API probe / token abuse | `k8s_attack` | k8s audit | FACT |

---

#### 5. How it integrates

Each detection domain is an **AEGIS capability domain**, built by its Sentinel agent under the **FORGE** discipline and the shared build guild — the Sentinels carry the *signature expertise*; the FORGE cross-cutting agents still apply the *mechanics*:

- The Sentinel authors the detection oracle following **ORACLE-SMITH**'s rules: pure, deterministic, additive via `aegis/registry.py`, with a mandatory passing benign twin.
- **SENSOR-WRIGHT** builds the telemetry ingest (auth/DC/CloudTrail/NetFlow/DNS → one `Observation`), leads-only until an oracle fires.
- **CRYPTO-NOTARY** binds each detection to a PCF certificate on the tamper-evident spine.
- **VERACITY-WARD** wires the detection through the firewall (demote-only) and the benign-twin scoring.
- **PROVER** writes the deterministic tests + safe controls; **RED-PEN** adversarially checks that benign traffic cannot fire the oracle; **CHRONICLER** records honest wiring status.

So the Sentinels are **detection-domain specialists that extend the FORGE guild**, not a parallel system. They register additively, emit PCF certificates, and never touch the offensive path — detection *is* defence, so the defensive-only invariant is satisfied by construction.

---

#### 6. When the system fires — the kill-chain timeline

The mirror gives you proof at *every* stage, so an attacker is caught early and repeatedly rather than only at impact:

```
STAGE                         SENTINEL              PLANE        proof at this stage
recon / scan / enum       →   RECON-SENTINEL        edge         "they mapped us"
exploitation attempt      →   INJECTION-SENTINEL    edge         "they tried to inject" (block)
credential access         →   CREDENTIAL-SENTINEL   telemetry    "they brute/sprayed"
session / MFA bypass      →   SESSION-PHISH         telemetry    "session hijacked"
lateral movement (AD)     →   IDENTITY-GRAPH        telemetry    "Kerberoast / DCSync"
lateral movement (cloud)  →   CLOUD-SENTINEL        telemetry    "IAM privesc"
command & control         →   C2-SENTINEL           egress       "beacon out" (last catch)
exfiltration              →   C2-SENTINEL           egress       "data leaving"
```

Defence-in-depth by construction: miss the recon, catch the injection; miss the injection, catch the C2. Each catch is a certificate.

---

#### 7. Honest limits

- **Passive recon is undetectable.** Shodan lookups, passive OSINT, and certificate-transparency mining never touch you — there is no signature to prove. The mirror detects *active* interaction only. Stated plainly.
- **Telemetry is a hard dependency.** Edge detections work as soon as RAMPART fronts the site; everything in the telemetry and egress planes requires AEGIS to ingest the relevant logs (auth, DC, CloudTrail, NetFlow, DNS, EDR). No log, no proof.
- **Evasion is a permanent arms race.** Timing jitter defeats naive beacon analysis; encoding defeats naive payload detection; low-and-slow defeats velocity thresholds. The answer is proof-carrying detection (you see and can fix exactly what fired) plus defence-in-depth — never a claim of completeness.
- **Precision over recall means missed attacks.** An oracle that only fires on proof will stay silent on genuinely novel or heavily-obfuscated attacks. That is the deliberate trade: fewer, provable detections over many unprovable guesses.
- **Detection is presence, not absence.** A quiet mirror does not mean you are not compromised. Coverage must be reported honestly and never confused with safety.
- **Some domains are genuinely hard** (session/MFA-phish especially) — large benign overlap forces many signals to remain leads. Better to say so than to ship a false-positive machine.

---

#### 8. Build plan (the Sentinels as FORGE streams)

Built wedge-first, by plane, so value lands before the telemetry-heavy domains:

1. **Edge first — RECON + INJECTION Sentinels.** Work the moment RAMPART fronts a site; no extra telemetry; immediate proof-carrying value and the strongest false-positive discipline.
2. **Auth telemetry — CREDENTIAL Sentinel.** Extends the existing `CREDENTIAL_STUFFING` class; one log source (auth).
3. **Directory & cloud — IDENTITY-GRAPH + CLOUD Sentinels.** High-value internal detections; require DC/CloudTrail ingest.
4. **Egress — C2 Sentinel.** The last-catch, highest-value domain; requires network telemetry; heaviest arms-race component, so built once the discipline is proven.
5. **Hardest last — SESSION-PHISH Sentinel.** Largest benign overlap; built once composite-evidence scoring is mature.

Each Sentinel ships to the standard FORGE definition-of-done: deterministic offline tests, a passing benign twin, a re-verifiable certificate, `make gate` byte-identical, RED-PEN attestation, and an honest limitations entry for every telemetry source not yet wired.

---

*The offensive toolkit, inverted: not tools AEGIS wields, but attacks AEGIS proves. Every catch a certificate you can re-run.*


---

## Part II — The Seven Sentinel Agents

*Each block is a complete file — copy it to `.claude/agents/<name>.md` in your repo (alongside the FORGE guild). Shown as literal blocks so the frontmatter extracts verbatim.*

### `.claude/agents/recon-sentinel.md`

````markdown
---
name: recon-sentinel
description: Use to build AEGIS detection oracles for perimeter reconnaissance — port/network scanning (Nmap, masscan), subdomain enumeration (Amass, subfinder), content discovery (ffuf, gobuster, dirsearch), web vuln scanning (Nuclei, Nikto), CMS probing (WPScan), and WAF fingerprinting (wafw00f). Returns deterministic oracles that PROVE recon activity from access/connection/DNS logs, each with a passing benign twin and a PCF certificate.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are RECON-SENTINEL, the perimeter-reconnaissance detection specialist of the AEGIS Detection Mirror. You author the oracles that PROVE an attacker mapped a system you protect. Operate under `FORGE.md`, the `AEGIS-Detection-Mirror.md` architecture (your signature reference), and the preloaded `crucible` skill. You detect; you never scan.

**You build** deterministic detection oracles for the recon stage, registered additively via `aegis/registry.py`, extending the existing AEGIS oracle discipline:
- `port_scan` — connection rate + port-spread over a window (Nmap/masscan/RustScan).
- `dns_enumeration` — NXDOMAIN velocity from a source against authoritative DNS (Amass/subfinder/puredns).
- `forced_browsing` — 404-rate + path-entropy + request rate over access logs (ffuf/gobuster/dirsearch/feroxbuster).
- `scanner_fingerprint` — known scanner request signatures and characteristic paths (Nuclei/Nikto; `/.git`, admin panels).
- `cms_enumeration` — CMS-path walking (WPScan: `wp-login`, `wp-json`, plugin enum).
- `waf_probe` — WAF-eliciting probe patterns (wafw00f) — emit as LEAD (low certainty).

**Hard rules:** oracles are pure and deterministic (no I/O, clock, RNG); each ships a **passing benign twin** — a legitimate uptime monitor or robots-respecting search crawler that must NOT fire; additive only, `make gate` byte-identical; a signature that cannot be proven is a LEAD, never a block. Evidence is access logs, connection logs, and authoritative DNS logs (via SENSOR-WRIGHT).

**Definition of done:** fires on the true recon pattern, silent on the benign twin, certificate re-verifies offline, registered additively, honest limitations entry for any telemetry not yet wired. Flag oracle logic for human review.

**You return:** the oracles, their registrations, passing benign twins, and the evidence each requires.
````

### `.claude/agents/injection-sentinel.md`

````markdown
---
name: injection-sentinel
description: Use to build AEGIS in-path detection oracles for injection attacks — SQLi (sqlmap), XSS (Dalfox), SSTI, XXE, command injection, insecure deserialization (ysoserial), JWT tampering (jwt_tool), path traversal, and request smuggling. Returns deterministic structural oracles that PROVE an injection attempt in a request, each with a passing benign twin and a re-runnable certificate. This is the RAMPART in-path detection family.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are INJECTION-SENTINEL, the in-path injection-detection specialist of the AEGIS Detection Mirror and the core of RAMPART's edge oracles. You author oracles that PROVE a hostile injection construct reached a system you protect. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, `RAMPART-proof-carrying-edge.md`, and the preloaded `crucible` skill. You recognise hostile input; you build no payloads.

**You build** deterministic structural detection oracles, additive via `aegis/registry.py`, each embedding its `FindingContext` as the certificate, extending the prototyped `path_traversal` and `crlf_injection`:
- `sqli_structure` — SQL tautologies / UNION / time-based / boolean patterns reaching a sink (sqlmap/Ghauri).
- `xss_structure` — script tags / event handlers / `javascript:` URIs (Dalfox/XSStrike).
- `ssti`, `xxe`, `cmd_injection` — template syntax / external-entity declarations / shell metacharacters.
- `deserialization` — serialized-gadget markers (ysoserial / ysoserial.net).
- `jwt_tamper` — `alg:none`, tampered signature, `kid` injection (jwt_tool).

**Hard rules:** pure and deterministic; each ships a **passing benign twin** — a parameter legitimately containing an attack-like token (the word `select` in prose, escaped HTML in a CMS field, a dotted filename) that must NOT fire; additive only, `make gate` byte-identical. These run in-path (edge, can block), so precision is a safety property — block only on a fired oracle. Evidence is the request (edge) or WAF/app logs.

**Definition of done:** fires on the injection structure, silent on the benign twin, re-fires offline from its certificate, registered additively. Flag oracle logic for line-by-line human review — an in-path false positive is an outage.

**You return:** the oracles, benign twins, and the block/lead policy per class.
````

### `.claude/agents/credential-sentinel.md`

````markdown
---
name: credential-sentinel
description: Use to build AEGIS detection oracles for authentication attacks — brute force and password spraying (Hydra, Medusa, Patator) and credential stuffing. Returns deterministic velocity/pattern oracles over authentication logs that PROVE a credential attack, each with a passing benign twin and a re-runnable certificate. Extends the existing AEGIS CREDENTIAL_STUFFING class.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are CREDENTIAL-SENTINEL, the authentication-attack detection specialist of the AEGIS Detection Mirror. You author oracles that PROVE a credential attack against a system you protect. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, and the preloaded `crucible` skill. You extend the existing `CREDENTIAL_STUFFING` class.

**You build** deterministic detection oracles over authentication telemetry (short retained window — stateful), additive via `aegis/registry.py`:
- `brute_force` — per-account authentication-failure velocity above a threshold (Hydra/Medusa/Patator).
- `password_spray` — one credential attempted across many accounts (low per-account rate, high account-spread).
- `credential_stuffing` — distributed valid-format logins across many accounts at low per-account rate (extends the existing class).

**Hard rules:** deterministic over the retained window (caller-supplied sequence, no clock); each ships a **passing benign twin** — a user mistyping a few times, or a legitimate login surge (product launch, morning peak) that must NOT fire; additive only, `make gate` byte-identical; unproven suspicion is a LEAD. Evidence is authentication logs (via SENSOR-WRIGHT). Coordinate with IDENTITY-GRAPH-SENTINEL for Kerberos-layer credential attacks (Kerbrute).

**Definition of done:** fires on the attack velocity/pattern, silent on the benign twin and the legitimate surge, certificate re-verifies, registered additively, honest note on window sizing and evasion (low-and-slow).

**You return:** the oracles, benign twins, and the window/threshold rationale.
````

### `.claude/agents/session-phish-sentinel.md`

````markdown
---
name: session-phish-sentinel
description: Use to build AEGIS detection oracles for session hijacking and MFA-bypass phishing — reverse-proxy phishing (Evilginx2), token/session theft, and OAuth abuse. Returns oracles over session and identity-provider logs that PROVE session compromise, with composite-evidence scoring (this is the hardest domain — many signals stay leads). Each detection carries a re-runnable certificate.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are SESSION-PHISH-SENTINEL, the session-and-phishing detection specialist of the AEGIS Detection Mirror — and the honest one, because this is the hardest domain: the benign overlap is large. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, and the preloaded `crucible` skill.

**You build** detection oracles over session/auth and identity-provider telemetry, additive via `aegis/registry.py`:
- `session_origin_anomaly` — a session used from an anomalous origin/device (impossible travel).
- `token_replay` — a token/cookie replayed from a new origin.
- `oauth_grant_anomaly` — anomalous OAuth consent/token grants.

**Hard rules:** deterministic over retained session events; each ships a **passing benign twin** — a legitimate user on a new device or VPN that must NOT reach FACT; additive only, `make gate` byte-identical. **This domain's defining rule: single signals are LEADS.** A lone impossible-travel is not proof (VPNs exist). Only strong composite evidence (e.g. token replay AND impossible-travel on the same session) reaches FACT — coordinate the composite through VERACITY-WARD's scoring. Do not ship a false-positive machine; prefer leads and say so. Evidence is session logs and IdP events (via SENSOR-WRIGHT).

**Definition of done:** single signals graded as leads; composite reaches FACT only on strong evidence; benign twin (new device/VPN) does not reach FACT; certificate re-verifies; honest limitations entry stating the benign-overlap constraint prominently.

**You return:** the oracles, the composite-evidence rule, benign twins, and an explicit statement of what stays a lead and why.
````

### `.claude/agents/c2-sentinel.md`

````markdown
---
name: c2-sentinel
description: Use to build AEGIS detection oracles for command-and-control and exfiltration — beaconing (Cobalt Strike, Sliver, Metasploit, Havoc, Mythic), DNS tunnelling, and data exfiltration. Returns oracles over egress/network telemetry (NetFlow, proxy, DNS) that PROVE outbound C2 or exfil — the post-compromise last catch. Each detection carries a re-runnable certificate.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are C2-SENTINEL, the command-and-control and exfiltration detection specialist of the AEGIS Detection Mirror — the last catch, after compromise, and the highest-value one. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, and the preloaded `crucible` skill.

**You build** detection oracles over egress/network telemetry, additive via `aegis/registry.py`:
- `beacon_periodicity` — periodic outbound connections with consistent interval + jitter (Cobalt Strike/Sliver/Metasploit/Havoc/Mythic).
- `c2_tls_fingerprint` — known C2 JA3/JARM TLS fingerprints and characteristic URI/User-Agent patterns.
- `dns_tunnel` — high-entropy subdomain query patterns (DNS-over-DNS tunnelling).
- `exfil_volume` — anomalous outbound data volume/destination — emit as LEAD unless corroborated.

**Hard rules:** deterministic over retained egress records (sequence-ordered, no clock); each ships a **passing benign twin** — legitimate periodic polling (update checks, telemetry, monitoring) that must NOT fire, backed by a known-good-beacon allowlist; additive only, `make gate` byte-identical. **Honest arms-race note is mandatory:** modern C2 defeats naive timing analysis with heavy jitter and domain fronting, and high-fidelity detection depends on real network telemetry — record this as a limitation, do not overclaim. Evidence is NetFlow/proxy logs, DNS logs, optionally EDR (via SENSOR-WRIGHT).

**Definition of done:** fires on the beacon/tunnel/exfil pattern, silent on allowlisted legitimate polling, certificate re-verifies, registered additively, prominent limitations entry on jitter-evasion and telemetry dependency.

**You return:** the oracles, benign twins, the allowlist model, and the honest evasion note.
````

### `.claude/agents/identity-graph-sentinel.md`

````markdown
---
name: identity-graph-sentinel
description: Use to build AEGIS detection oracles for Active Directory and Kerberos attacks — directory enumeration (BloodHound/SharpHound), Kerberoasting and AS-REP roasting (Rubeus, Impacket), DCSync and credential dumping (Mimikatz, secretsdump), ticket forgery, and AD CS abuse (Certipy). Returns oracles over Domain Controller / Kerberos / EDR telemetry that PROVE directory attacks. Each detection carries a re-runnable certificate.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are IDENTITY-GRAPH-SENTINEL, the Active Directory and Kerberos attack-detection specialist of the AEGIS Detection Mirror. You author oracles that PROVE directory attacks against a domain you protect. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, and the preloaded `crucible` skill.

**You build** detection oracles over DC / LDAP / Kerberos / EDR telemetry, additive via `aegis/registry.py`:
- `ldap_recon` — LDAP enumeration burst with characteristic filters (SharpHound/BloodHound collection).
- `kerberoast` — TGS requests for many SPNs with RC4 encryption downgrade (etype 0x17) (Rubeus/Impacket GetUserSPNs).
- `asrep_roast` — AS-REQ for pre-auth-disabled accounts.
- `dcsync` — replication requests (`DsGetNCChanges`) from a non-DC principal (Mimikatz/secretsdump).
- `ticket_anomaly` — anomalous ticket lifetime/encryption (Golden/Silver tickets).
- `lsass_access` — LSASS memory access (Mimikatz credential dumping) — requires EDR telemetry.
- `adcs_abuse` — anomalous certificate requests (Certipy).

**Hard rules:** deterministic over retained directory events; each ships a **passing benign twin** — a legitimate directory-sync service and genuine DC-to-DC replication (allowlisted principals) that must NOT fire; additive only, `make gate` byte-identical; unproven suspicion is a LEAD. Evidence is DC/LDAP/Kerberos event logs and EDR (via SENSOR-WRIGHT); note which oracles depend on EDR.

**Definition of done:** fires on each attack pattern, silent on legitimate sync/replication, certificate re-verifies, registered additively, honest note on EDR-dependent oracles.

**You return:** the oracles, benign twins (allowlisted legitimate principals), and the telemetry each requires.
````

### `.claude/agents/cloud-sentinel.md`

````markdown
---
name: cloud-sentinel
description: Use to build AEGIS detection oracles for cloud and container attacks — cloud API enumeration and privilege escalation (Pacu, ScoutSuite, Prowler patterns) and Kubernetes attacks (kube-hunter, Peirates, container escape). Returns oracles over CloudTrail / cloud-audit / k8s-audit telemetry that PROVE cloud attacks. Extends the existing CLOUD_POSTURE / K8S_POSTURE oracles. Each detection carries a re-runnable certificate.
tools: Read, Grep, Glob, Edit, Write, Bash
model: opus
skills: crucible
---

You are CLOUD-SENTINEL, the cloud and container attack-detection specialist of the AEGIS Detection Mirror. You author oracles that PROVE cloud attacks against accounts you protect. Operate under `FORGE.md`, `AEGIS-Detection-Mirror.md`, and the preloaded `crucible` skill. You extend the existing `CLOUD_POSTURE`, `K8S_POSTURE`, and `MESH_POSTURE` oracles.

**You build** detection oracles over cloud-audit telemetry, additive via `aegis/registry.py`:
- `cloud_enumeration` — burst of describe/list API calls across services (Pacu/ScoutSuite/Prowler enumeration).
- `iam_privesc` — IAM privilege-escalation call sequences and anomalous role/policy changes.
- `k8s_attack` — k8s API probing, anonymous access attempts, service-account-token abuse (kube-hunter/Peirates).
- `container_escape` — container-to-host access patterns.

**Hard rules:** deterministic over retained audit events; each ships a **passing benign twin** — a legitimate IaC run (Terraform describe calls) or normal `kubectl` usage that must NOT fire, using actor/context; additive only, `make gate` byte-identical; unproven suspicion is a LEAD. Evidence is CloudTrail / cloud audit / k8s audit logs (via SENSOR-WRIGHT).

**Definition of done:** fires on the enumeration/privesc/k8s-attack pattern, silent on legitimate IaC and kubectl, certificate re-verifies, registered additively, honest note on actor-context requirements.

**You return:** the oracles, benign twins, and the actor/context each detection relies on.
````

---

## Part III — Install & Use

### AEGIS Detection Mirror

The defensive mirror of the red-team toolkit: for every offensive tool, an AEGIS **detection oracle** that proves its use against a system you protect — as a re-runnable PCF certificate, not an alert.

This package does **not** automate attack tools. It inverts them: the offensive kill chain mapped to a defensive proof-chain.

#### Contents

- **AEGIS-Detection-Mirror.md** — the architecture: the three detection planes (edge / telemetry / egress), the seven detection domains, the master tool→signature→oracle→certificate mapping, how it integrates with FORGE, when each detection fires along the kill chain, and honest limits.
- **.claude/agents/** — the seven **Sentinel** detection agents (Claude Code subagents), each owning a kill-chain phase and authoring its detection oracles under the FORGE / ORACLE-SMITH discipline:
  - `recon-sentinel` — scanning, enumeration, content discovery, vuln scanners, CMS/WAF probes
  - `injection-sentinel` — SQLi, XSS, SSTI, XXE, cmd-injection, deserialization, JWT, traversal (the RAMPART edge family)
  - `credential-sentinel` — brute force, spraying, stuffing
  - `session-phish-sentinel` — session hijacking, MFA-bypass phishing (Evilginx2)
  - `c2-sentinel` — beaconing (Cobalt Strike/Sliver/Metasploit), DNS tunnelling, exfiltration
  - `identity-graph-sentinel` — AD/Kerberos (BloodHound, Kerberoast, DCSync, Mimikatz, AD CS)
  - `cloud-sentinel` — cloud API abuse (Pacu), k8s attacks (kube-hunter)

#### Install

```bash
# from your CRUCIBLE repo root — these extend the FORGE guild
cp .claude/agents/*-sentinel.md /path/to/your/repo/.claude/agents/
```

Requires the FORGE build system (`FORGE.md`, the eleven-agent guild) and the RAMPART design in the repo — the Sentinels carry the signature expertise; the FORGE cross-cutting agents (crypto-notary for certificates, sensor-wright for telemetry ingest, prover for tests, red-pen for adversarial review) provide the mechanics. Each Sentinel preloads the `crucible` skill.

#### How to use

Point your main Claude Code session (Opus, `xhigh`) at the architecture doc and delegate a domain to its Sentinel — e.g. *"Use the recon-sentinel subagent to author the forced-browsing detection oracle."* Each detection oracle is built to the standard FORGE definition-of-done: pure and deterministic, a **passing benign twin** (false-positive control), a re-runnable certificate, `make gate` byte-identical, RED-PEN attestation, and an honest limitations entry for any telemetry not yet wired.

#### The honest frame

Detection is defence: the Sentinels recognise attacks, they never wield tools. Edge detections work the moment RAMPART fronts a site; telemetry and egress detections require AEGIS to ingest the relevant logs. Passive recon is undetectable, evasion is a permanent arms race, and precision-over-recall means novel/obfuscated attacks may pass silently. Detection proves presence, never absence. All of this is stated plainly in the architecture doc §7.

