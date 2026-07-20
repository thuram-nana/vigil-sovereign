# Pre-Engagement Checklist

Use this checklist **before any active testing**. Every item must be
explicitly satisfied or explicitly waived (with reason logged) before
OBSIDIAN may issue a single packet against the target.

## Authorization

- [ ] **Charter signed.** A `targets/<name>/charter.md` exists, completed,
      and acknowledged by the asset owner. Date and identity recorded.
- [ ] **Asset ownership confirmed.** Domain WHOIS / company registration /
      payment record confirms the target belongs to the requester.
      *Why:* Never test on borrowed authority.
- [ ] **Subdomain ownership clarified.** If subdomains belong to third
      parties (SaaS providers, partners), they are excluded from scope or
      separately authorized.
- [ ] **Third-party providers identified.** SaaS, CDN, payment gateway,
      auth provider — listed with their ToS implications. Cloudflare,
      Cloudfront, Stripe, Auth0 etc. require provider-side authorization
      for non-trivial testing.
- [ ] **Hosting provider AUP reviewed.** AWS, GCP, Azure, DigitalOcean
      each have their own pentest notification rules.

## Scope

- [ ] **In-scope assets enumerated.** Domains, subdomains, IPs, repos,
      mobile bundles — explicit list in `scope.md`.
- [ ] **Out-of-scope assets enumerated.** Third-party logins (Google,
      Facebook OAuth providers themselves), customer data, production
      databases (vs. read-only replicas), legacy systems explicitly
      flagged "do not touch."
- [ ] **Test data defined.** What test accounts will be used. What test
      transactions are permissible. Real money? Real customer data?
- [ ] **Time windows.** When may testing occur. Quiet hours / business
      hours preference.
- [ ] **Rate limits / volume caps.** What load is acceptable.
- [ ] **OPSEC posture chosen.** TEST / AUDIT / EMULATE — see
      `framework/cognitive/opsec-discipline.md`.

## Communication

- [ ] **Primary contact** for the engagement, with phone + email.
- [ ] **Emergency stop contact** — who to call at 3 AM if production
      breaks.
- [ ] **Reporting cadence.** Daily / weekly / on-finding / final-only.
- [ ] **Critical-finding protocol.** How OBSIDIAN reports critical
      vulnerabilities mid-engagement. Phone? Encrypted email? Signal?
- [ ] **Out-of-band channel.** A non-target channel for communication
      (in case the target's email is what you've compromised).

## Test Account Hygiene

- [ ] **Test accounts created.** All prefixed `OBSIDIAN-TEST-`.
- [ ] **Test accounts isolated.** Not shared with real users. Real
      payment methods only if explicitly authorized (and refundable).
- [ ] **Test account disposable.** Engagement-only emails (e.g.,
      `obsidian-test+<eng>-<n>@your-domain.tld`).
- [ ] **Test data is fake.** No real PII, real KYC documents, real
      payment cards.

## Legal & Documentation

- [ ] **Engagement charter** stored under `targets/<name>/charter.md`.
- [ ] **Local law reviewed.** Computer-misuse statutes for the operator's
      jurisdiction *and* the target's hosting jurisdiction.
- [ ] **Contractual indemnity** in place if engagement involves third
      party data or third party systems.
- [ ] **NDA signed** if target is not the operator.

## Technical Setup

- [ ] **Working environment isolated.** OBSIDIAN runs from a dedicated
      VM / VPS. Not from a personal machine.
- [ ] **Source IP documented.** Static egress IP recorded in charter
      (some clients want to allow-list).
- [ ] **Toolchain verified.** `framework/tools/verify.sh` exits 0.
- [ ] **Time synced.** `chrony` or `systemd-timesyncd` running. Findings
      need accurate timestamps.
- [ ] **Filesystem encrypted.** LUKS / FileVault / equivalent on the
      operator workstation.
- [ ] **Backups configured** for engagement evidence (encrypted).
- [ ] **Network egress logged.** All outbound traffic captured to PCAP
      or proxy log for the engagement duration.

## Threat Model First Pass

- [ ] **Asset inventory.** What does this target *do*? What's the crown
      jewel? (Money, PII, IP, reputation, availability.)
- [ ] **Adversary inventory.** Who would attack this? With what
      capability? Logged in `targets/<name>/threat-model.md`.
- [ ] **Initial attack tree.** First-pass attack tree drafted. Will
      evolve through engagement.
- [ ] **Top 3 risks identified.** A priority queue exists before
      starting. Avoid spending day 1 on "let's see what comes up."

## Pre-Flight Self-Critique

- [ ] **Could I lose data?** Have I confirmed read-only access, or are
      writes acceptable?
- [ ] **Could I lock anyone out?** Account lockout policies acknowledged.
      Recovery path validated.
- [ ] **Could I trigger a billing event?** Crypto withdrawals, SMS sends,
      transactional emails — what produces real-world cost?
- [ ] **What's my rollback?** If something goes wrong, who restores it?
- [ ] **Am I rushing?** Why does the timeline feel tight? Is the
      timeline more important than safety?

## Sign-Off

```
Engagement: <name>
OBSIDIAN: <operator handle>
Asset owner: <name>
Date: <YYYY-MM-DD>
OPSEC posture: TEST | AUDIT | EMULATE
Charter ref: targets/<name>/charter.md
```

If any unchecked box exists without a logged waiver, **DO NOT START**.
