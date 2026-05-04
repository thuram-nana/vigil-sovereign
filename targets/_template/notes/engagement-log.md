# Engagement log — `<target-name>`

A chronological log of session activity. Append-only. One entry per
material event: session start, session end, hypothesis opened,
finding confirmed, charter change, post-exploit action, etc.

The log is the audit trail. Future-you and the operator both rely
on it to reconstruct what happened, in what order, and why.

---

## Format

```
## YYYY-MM-DD HH:MM (UTC) — <event title>

- **Stage:** <lifecycle stage at time of event>
- **Posture:** <TEST / AUDIT / EMULATE>
- **Action:** <what was done>
- **Outcome:** <what was observed>
- **Next:** <what this drives next, if anything>
```

For minor events (running a tool, reading a page), one-line entries
are fine:

```
- HH:MM — Ran subfinder; 47 new subdomains added to recon/passive/.
```

For material events (finding confirmed, charter change, post-
exploit), use the full block.

---

## Entries

## YYYY-MM-DD HH:MM (UTC) — Engagement opened

- **Stage:** 0 Pre-engagement
- **Action:** Charter v1.0 reviewed; operator attestation confirmed.
- **Outcome:** Posture set to `TEST`. Test windows agreed: any time.
- **Next:** Begin Stage 1 threat modeling.

## YYYY-MM-DD HH:MM (UTC) — Threat model v1 drafted

- **Stage:** 1
- **Action:** Drafted attack tree with root "Adversary takes over
  any user account."
- **Outcome:** 23 leaves identified across auth (8), authz (6),
  injection (4), business logic (3), infrastructure (2).
- **Next:** Stage 2 reconnaissance to validate which leaves are
  reachable.

## YYYY-MM-DD HH:MM (UTC) — Stage 2 passive recon complete

- **Stage:** 2.1
- **Action:** subfinder, amass, gau, github search, crt.sh.
- **Outcome:** 142 unique subdomains, 3 candidates for takeover,
  fingerprint suggests Laravel 9.x stack.
- **Next:** Active recon (Stage 2.2).

(Continue chronologically.)
