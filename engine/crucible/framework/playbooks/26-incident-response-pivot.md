# Playbook 26 — Incident response pivot

**Goal:** when an offensive engagement reveals signs of *prior or
ongoing* compromise — a real attacker is or has been in the system —
the engagement transforms. Stop offense. Pivot to incident response.

**Trigger:** evidence of prior or current compromise. Possible
indicators:

- Webshells in webroot, especially named generically (`x.php`,
  `wp-content/uploads/<random>.php`, `up.php`).
- Modified core / framework files (eval(base64) at top of
  index.php; tampered vendor files).
- Unknown admin / staff accounts.
- Unknown OAuth clients / API keys / SSH keys.
- Suspicious cron entries.
- Connections to unknown C2-like hosts in egress logs.
- Customer reports of unauthorized actions (the "users getting
  hacked" signal).
- Outbound traffic from app servers to crypto mining pools, IRC,
  Tor exits.

If you suspect compromise, stop and proceed below.

---

## 26.1 Stop offensive activity

The moment you suspect prior compromise:

1. Stop sending offensive traffic. The intruder may be watching;
   your scans could tip them off.
2. Tell the operator immediately. Do not theorize or "verify a bit
   more" — the operator needs to decide whether to engage incident
   response now.
3. Switch posture from offensive to forensic-aware: read-only,
   minimal footprint, preserve evidence.

---

## 26.2 Initial triage

What you can do safely:

- Document indicators (file paths, hashes, account names, IPs)
  exactly as you found them, with timestamps.
- Note your own footprint — distinguish your authorized actions from
  the intruder's.
- Suggest the operator engage incident response (in-house, MSSP,
  retained DFIR firm).

What you don't do:

- Don't delete suspect files. They're evidence.
- Don't kick out the intruder yet (they may have multiple persistence
  mechanisms; surprise removal warns them and you lose them all).
- Don't share findings outside the operator + their authorized IR
  team.

---

## 26.3 Operator decision tree

The operator chooses one of:

- **Engage external IR firm** — best for serious or unclear
  compromise; expensive but thorough.
- **In-house IR with framework support** — operator's team handles
  containment / eradication; framework agent provides observation
  capacity, doc, and adversarial perspective.
- **Quick rotate-and-hope** — for a small business with a clearly
  scoped intrusion (e.g., one stolen API key with bounded blast
  radius), rotation + monitoring may suffice. Not appropriate for
  webshells / persistence indicators.

---

## 26.4 If you (the agent) continue assisting

If operator wants the agent to help during IR:

### 26.4.1 Evidence preservation

- Snapshot disks / VMs / containers before any cleanup.
- Capture process listings (`ps auxf`, `lsof`, `ss -tlnp`).
- Memory image if possible (volatility for forensic analysis).
- Logs: webserver, app, system, cloud audit, DB.
- Image-of-image preserved off-system in IR storage.

### 26.4.2 Indicators of compromise

Compile to `notes/ioc.md`:
- File paths + hashes of suspicious files.
- Account names / emails added.
- Timestamps of admin actions, especially outside working hours.
- IPs accessing admin endpoints, especially anomalous geos.
- API keys created or used unexpectedly.
- DB queries / large exports observed.
- Outbound connections to unknown hosts.

### 26.4.3 Timeline

Build a chronological timeline:
- Earliest indicator (when did the attacker first appear?).
- Likely initial access vector (cross-reference with your findings;
  Critical or High issues you found may be the entry point).
- Lateral movement events.
- Persistence created.
- Data accessed / exfiltrated.
- Most recent activity.

### 26.4.4 Eradication plan

Once the operator + IR team have visibility:

- Plan removal of all persistence mechanisms simultaneously
  (sudden removal signals; staged removal lets them re-establish).
- Rotate every credential the attacker may have touched (DB, API
  keys, SSH keys, OAuth clients, cloud keys, JWT signing keys).
- Patch the entry point (your finding).
- Re-image affected hosts where possible.
- Review user accounts for stealth admins.

---

## 26.5 Customer / regulatory notification

The operator's call, with their counsel:
- GDPR: Art. 33 — 72 hours to authority if personal data breach.
- US state laws — varies (CCPA, NY SHIELD, etc.).
- Sector-specific (PCI, HIPAA).
- Customer notification timing per contract.

The agent advises but does not draft notifications without the
operator's counsel.

---

## 26.6 After IR concludes

Reframe the engagement:
- Original offensive findings are still valid (and likely include
  the entry point).
- Add an IR appendix to the technical report with the timeline and
  IoCs.
- Update threat model with the actual realized attack — this is
  ground-truth for future testing.
- Update charter for a return to normal offensive engagement once
  IR is closed and posture re-established.

---

## 26.7 Documenting the pivot

In `notes/engagement-log.md`:

```
## YYYY-MM-DD HH:MM — IR pivot
- Indicator(s): <list>
- Operator notified at: HH:MM
- Operator decision: engage external IR firm / in-house / etc.
- Offensive activity: STOPPED
- Posture: forensic-aware, minimal footprint
- Next steps: <as per operator>
```

The pivot is itself a finding (often Critical) — that the operator
had a real intrusion was discovered during a posture engagement.

---

## 26.8 Output

`notes/ir.md`, `notes/ioc.md`, timeline file, updated engagement-log.
Coordination with operator's IR team. Eventual return to offensive
engagement when IR is complete and operator authorizes.
