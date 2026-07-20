# Target: `mrbeanpanel`

> Engagement workspace for `mrbeanpanel.com`, an SMM (Social Media Marketing) reseller panel. This is the primary engagement initiating the CRUCIBLE framework, owned and operated by the same engineer (Satoshi). Self-directed assessment with the goal of finding and fixing every fault before further user harm.

---

## Engagement State

`AUTHORIZED` — operator owns the asset; written self-authorization captured in `charter.md`.

## Quick Facts (filled at boot — verify against current state in recon)

- **Domain:** `mrbeanpanel.com` (primary), `beansms.com` (sister site).
- **Stack indicators (pre-engagement):** `cdn.glycon.net`, `storage.perfectcdn.com` — suggests Perfect Panel codebase or fork.
- **Service:** SMM reseller — engagement metrics across Instagram, TikTok, YouTube, Twitter, Facebook, Telegram, Twitch, Spotify, Discord.
- **Payments:** Cryptomus, Coinbase, Payeer, Perfect Money, card processor (Visa/MC), manual USDT/BTC.
- **Reported incidents prior to engagement:** users reporting account takeovers — primary concern driving this assessment.
- **Approximate scale:** ~44k users, ~967k orders.

## Engagement Goal (from operator)

> Find every fault. Patch every fault. Source code provided at white-box stage. The whole point is to make every user safe.

## Phase Plan

| Phase | Playbook | Notes |
|---|---|---|
| 0 | `00-pre-engagement.md` | Charter + threat model + attack tree (see this directory). |
| 1 | `01-passive-recon.md` | What's already public; surface enumeration. |
| 2 | `02-active-recon.md` | Subdomain, port, content, parameter discovery against owned scope only. |
| 3 | `03-attack-surface-mapping.md` | Consolidate; feed into `attack-tree.md`. |
| 4 | `04-web-application.md` + `05-api-security.md` | Black-box pass over UI + API. |
| 5 | `06-authentication-identity.md` + `07-authorization.md` | **Priority focus: account takeover root-cause.** |
| 6 | `08-injection.md` + `10-business-logic.md` + `11-cryptography.md` | Cross-class hunting. |
| 7 | `20-source-code-review.md` | White-box pass once source is in hand. |
| 8 | `23-remediation-validation.md` | Patch and retest. |

## Top Hypotheses (entered at boot, refine with evidence)

1. Account takeover may be enabled by **password reset flow weakness** (token entropy, scoping, host header injection, race in token consumption).
2. Account takeover may be enabled by **session fixation or weak session token** generation.
3. Account takeover may be enabled by **OAuth/social-login provider misconfiguration** if any are integrated.
4. Account takeover may be enabled by **2FA bypass / not enforced**.
5. Funds-related logic may have **race conditions** in balance crediting (top-up, refund) or order creation.
6. Webhook handlers from payment providers may **trust unauthenticated requests** or have **HMAC validation flaws**.
7. **IDOR** is plausible across orders, tickets, profile views (heavy ID-based URL surface in panel CMSes).
8. Admin panel separation: **vertical privilege escalation** path from reseller → admin.

These are starting hypotheses, not conclusions. Move evidence into `findings/` only after confirmed reproduction.

## File Status

| File | Status |
|---|---|
| `charter.md` | DRAFT (template) — operator must fill scope/authorization before scanning. |
| `threat-model.md` | DRAFT (template) — initial pass needs to be done before scanning. |
| `attack-tree.md` | DRAFT (template) — initial pass needs to be done before scanning. |
| `notes/engagement-log.md` | Empty — start at first command. |
| `notes/command-log.md` | Empty — every command goes here. |
| `notes/hypotheses.md` | Port the list above and expand. |
| `findings/` | Empty. |
| `evidence/` | Empty. |

## Operator Notes (private)

- This is a self-assessment. There is no third-party client. The charter section "Authorization" is operator self-authorization with a file containing the operator's signed attestation.
- "Other web apps" exist; each will be its own target dir when started.
- Source code will be added at Stage 7 (`source/` subdirectory under recon, or as a sibling depending on size).
