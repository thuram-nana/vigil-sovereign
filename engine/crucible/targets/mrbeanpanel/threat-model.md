# Threat model — `mrbeanpanel.com`

**Status:** DRAFT (pre-engagement). Refine after recon (Phase 1–2) when concrete attack surface is mapped.

This document is the operator's view of what we're protecting, who would attack it, how they'd attack it, and what we'd consider catastrophic. It feeds the **attack tree** (`attack-tree.md`) which is the prioritized work queue.

Method: PASTA-light + STRIDE per asset.

---

## 1. Business context

`mrbeanpanel.com` is a Social Media Marketing (SMM) reseller panel. Customers buy "engagement" services — followers, likes, views, watch time, plays, members — for accounts they manage on Instagram, TikTok, YouTube, Twitter, Facebook, Telegram, Twitch, Spotify, and Discord. The panel orchestrates against upstream providers and tracks order fulfillment.

**Revenue model:** prepaid balance. Customers top up via Cryptomus, Coinbase Commerce, Payeer, Perfect Money, card processor (Visa/Mastercard), or manual USDT/BTC. They place orders that consume balance.

**Scale (pre-engagement estimate):** ~44k registered users, ~967k orders historically.

**Operator situation:** users have reported account takeovers. Those reports are the proximate cause of this engagement. The operator does not yet know the takeover vector.

## 2. Assets — what are we protecting?

| # | Asset | Rationale | Priority |
|---|---|---|---|
| A1 | **User account integrity** (login, recovery, MFA, session) | Direct user harm; the takeover problem lives here | P0 |
| A2 | **User balance** (DB account balances, stored credit) | Direct financial loss; refund liability | P0 |
| A3 | **Payment intake integrity** (incoming top-up confirmations from Cryptomus, Coinbase, Payeer, Perfect Money) | If forged → free balance creation → unbounded loss | P0 |
| A4 | **Order placement & fulfillment** | If forged → unauthorized service consumption / chargebacks | P1 |
| A5 | **Admin / reseller account boundary** | Vertical privilege escalation = total platform compromise | P0 |
| A6 | **User PII** (email, IP, possibly tax/billing info) | Privacy / regulatory; reputational | P1 |
| A7 | **Upstream provider API credentials** (the panel's own keys to Smm-X, JustAnotherPanel-style APIs) | If leaked → operator's funds at upstream are spent | P0 |
| A8 | **Underlying server / database** | Catastrophic; web-shell, mass DB exfil | P0 |
| A9 | **Email / domain reputation** | If hijacked for spam/phishing → blacklisting | P2 |
| A10 | **Operator's own admin credentials & 2FA** | Final gate; if compromised → A8 in one step | P0 |

## 3. Adversaries — who'd attack and why?

| ID | Actor | Goal | Capability | Notes |
|---|---|---|---|---|
| T1 | **Credential-stuffer / spray attacker** | Credential reuse → balance theft | Low: existing creds + automation | Most plausible cause of reported ATOs |
| T2 | **Targeted account takeover crew** | Specific user takeover (e.g., reseller with high balance) | Low–Medium: phishing, password reset abuse, OAuth flaw | Plausible cause of reported ATOs |
| T3 | **Drained-balance fraud** | Get free balance via payment forgery | Medium: reverse-engineering webhooks, signature flaws | Direct $$ |
| T4 | **Reseller / ex-customer with grudge** | Damage / data exfil / revenge fraud | Low–Medium: knows panel internals | Common in this niche |
| T5 | **Competitor** | Disrupt service / steal customer list | Medium | Known bad-blood culture in SMM space |
| T6 | **Skiddie / opportunistic scanner** | Whatever automated scanners find | Low | Background noise; still produces real findings |
| T7 | **Sophisticated panel-targeting actor** | Mass exfil of all user creds / payment data → resell | High | Has happened to peer panels |
| T8 | **Insider / former operator/dev** | Whatever they want; they have or had access | High; trust-based | Ensure no leftover backdoors / accounts |
| T9 | **Compromised upstream provider** | Pivot from upstream into panel via callbacks | Medium | SSRF / webhook reflection class of bugs |

## 4. Attack vectors & STRIDE per asset

This section maps adversary capability to asset via STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

### A1 — User account integrity

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Credential stuffing | T1, T6 | S | No or weak rate limit / no MFA option |
| Password reset abuse (token entropy, host header injection, no rate limit, race) | T2 | S, E | Strong hypothesis given ATO reports |
| Session fixation / token weakness | T2, T7 | S, E | Cookie flags, token PRNG |
| OAuth / social login flaw | T2, T7 | S | If integrated; redirect_uri, state |
| 2FA absent / bypassable | T1, T2 | S, E | If MFA exists at all, is it enforced? |
| Account recovery via support spoofing | T2 | S | Out-of-band; harder to test, document anyway |

### A2 — User balance

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Race in balance crediting | T3 | T | Top-up double-spend; double-credit on retried webhook |
| Race in order placement | T3 | T | Negative balance via concurrent orders |
| Direct DB tampering via SQLi | T6, T7 | T, I, E | Unrestricted writes if DB compromise |
| Admin override visible at user side | T2 (post-ATO) | T | If the ATO actor reaches admin |

### A3 — Payment intake integrity

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Webhook signature bypass / missing | T3 | S, T | The single highest-impact category |
| Replay attack on webhooks | T3 | S | No nonce / no timestamp validation |
| Currency confusion (USD vs satoshi etc.) | T3 | T | Logic bug class |
| Underpay → still credit (rounding / off-by) | T3 | T | Logic bug class |
| Manual approval workflow abuse (USDT/BTC manual confirmations) | T3, T4 | S, E | If admin can be tricked / impersonated |

### A4 — Order placement & fulfillment

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Order forgery via unauthenticated / weak-auth API | T6 | S, E | API-direct attacks |
| IDOR on `orders/<id>` (read other users' orders, modify status) | T1, T4 | I, T | Plausible; SMM panels are heavy on numeric IDs |
| Refund exploitation (partial-refund credits the full amount) | T3, T4 | T | Logic bug class |
| Cross-tenant order pollution (reseller modifies another reseller's orders) | T4 | T, I, E | If multi-tenant separation is weak |

### A5 — Admin / reseller account boundary

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| URL-based admin path discovery | T6, T7 | E | `/admin`, `/panel`, `/manage` |
| RBAC enforcement only in UI, not API | T2 (post-ATO), T7 | E | Endpoint-level role check absence |
| Mass-assignment of role on profile update | T2 (post-ATO), T7 | E | `role` field accepted in `PATCH /me` |
| Admin login with weak credentials / no MFA | T1 | S, E | Operator's own account is highest-stakes A10 |

### A6 — User PII

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| SQLi exfil | T7 | I | Mass dump risk |
| IDOR on profile / order history | T1, T4 | I | Targeted enumeration |
| Logging of PII in shared / accessible logs | T8, T7 | I | Log review at white-box |
| Backups exposed (DB dumps, S3 buckets) | T7 | I | Recon target |

### A7 — Upstream provider API credentials

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Leak via debug endpoint / error message | T6, T7 | I | Tech-stack quirks |
| Leak via SSRF-able local service | T7 | I | Cloud metadata, internal config endpoint |
| Source code leak / Git config exposure | T7 | I | `.git/`, `.env`, backup files |
| RCE → full disk read | T7 | I, E | Goes to A8 first |

### A8 — Underlying server / database

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| RCE via file upload / template injection / deserialization | T7 | E, T, I, D | Catastrophic |
| Web shell from prior compromise | (already-T7) | E, I | **Hunt explicitly** — operator reports ATOs may indicate prior breach |
| Outdated panel core (Perfect Panel / fork) with public CVE | T6, T7 | E | Recon item |
| Privileged container / cloud IAM breakout | T7 | E | If hosted on cloud |

### A9 — Email / domain reputation

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| SPF / DKIM / DMARC missing → spoofing | T2 | S | DNS recon |
| Mail-from injection / SMTP relay abuse | T6 | S | If SMTP is operator-run |
| Subdomain takeover | T7 | S | Cert/DNS recon |

### A10 — Operator's admin credentials

| Vector | Adversaries | STRIDE | Notes |
|---|---|---|---|
| Phishing operator | T2 | S | OOB but real |
| Operator's password in any leak | T1, T2 | S | HIBP check |
| Admin session leak via shared device / browser | T8 | S | OOB |
| MFA absence | T1, T2 | S, E | **Verify MFA is enforced on operator's own account** |

## 5. What "catastrophic" looks like

Ranked from worst:

1. **Mass user account takeover** (A1 + A2 → all balances drained, all PII exfiltrated). Triggers A9 fallout (mail blacklisting, customer flight).
2. **Free balance creation via payment forgery** (A3 → unbounded liability before detection).
3. **Operator account takeover** (A10 → access to A8 in one step → web shell, DB dump, all of the above).
4. **Mass DB exfil via SQLi/RCE** (A8 → public dump → all users' creds publicly available).
5. **Single high-balance reseller compromise** (A1 single-target → six-figure direct loss possible).
6. **Reputation hit even without confirmed compromise** (defacement, fake announcements, social media takeover of operator's accounts).

## 6. What's NOT in the threat model (and why)

- **Nation-state level adversary.** Not the realistic threat profile for an SMM panel. We harden against T1–T9 and accept T7-but-state-sponsored as residual risk.
- **Physical access to operator's machine.** Out of scope for app assessment; addressed at operator OPSEC level.
- **Supply-chain attack on Cryptomus / Coinbase / Payeer infrastructure.** Out of scope by charter; we test for *resilience* (signature validation, replay prevention) on the panel's side.
- **Pure DoS / volumetric.** Out of scope by charter; DoS protection is a hosting / CDN concern.

## 7. Defensive priorities derived from this model

Top 5 things to verify / harden, derived directly from above:

1. **Account takeover surface is closed** — login + reset + session + MFA enforced and provably resistant to T1, T2.
2. **Webhook integrity is cryptographically guaranteed** — every payment provider's webhook is signed and verified, replay-proof, idempotent.
3. **Authorization is enforced at the API layer** — no UI-only RBAC, no IDOR, no mass-assignment.
4. **Prior-compromise indicators are checked** — any web shell, unauthorized admin, unfamiliar cron job, modified core file, suspicious DB row gets surfaced.
5. **Operator's own account is hardened** — MFA on, unique password, no shared sessions.

These are the seeds of `attack-tree.md`'s priority queue.

## 8. Refresh

This document is **DRAFT**. Refresh after each major phase:
- After Phase 1 (passive recon): correct stack assumptions; update T7 capability.
- After Phase 3 (attack-surface map): add concrete endpoints to A4, A5.
- After Phase 5 (auth/authz pass): collapse A1 hypotheses to confirmed/disconfirmed.
- After Phase 7 (source review): correct everything against ground truth.
