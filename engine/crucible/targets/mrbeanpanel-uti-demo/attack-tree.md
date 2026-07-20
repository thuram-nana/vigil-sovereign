# Attack tree — `mrbeanpanel.com`

**Version:** 1.0 (UTI draft)
**Date:** 2026-05-04
**Archetype:** `php-smarty-smm-panel-fork`

Initial decomposition seeded from the archetype's `attack_tree_seeds`
and `common_vulnerabilities` list. Mark each leaf as you progress:

- `[?]` not yet tested
- `[~]` partially tested
- `[X]` ruled out
- `[√]` confirmed exploitable

---

## G1 — Take over a customer account

```
G1. Take over a customer account
├── [?] L1.1 webhook-forgery
├── [?] L1.2 IDOR
├── [?] L1.3 mass-assignment
├── [?] L1.4 race
├── [?] L1.5 SQLi
├── [?] L1.6 vertical-privesc
├── [?] L1.7 source-disclosure
├── [?] L1.8 reset-token
```

## G2 — Manipulate balance / orders without paying

```
G2. Manipulate balance / orders without paying
├── [?] L2.1 webhook-forgery
├── [?] L2.2 IDOR
├── [?] L2.3 mass-assignment
├── [?] L2.4 race
├── [?] L2.5 SQLi
├── [?] L2.6 vertical-privesc
├── [?] L2.7 source-disclosure
├── [?] L2.8 reset-token
```

## G3 — Take over the platform itself

```
G3. Take over the platform itself
├── [?] L3.1 webhook-forgery
├── [?] L3.2 IDOR
├── [?] L3.3 mass-assignment
├── [?] L3.4 race
├── [?] L3.5 SQLi
├── [?] L3.6 vertical-privesc
├── [?] L3.7 source-disclosure
├── [?] L3.8 reset-token
```

## Update log

| Date | Version | Change |
|------|---------|--------|
| 2026-05-04 | 1.0 | UTI draft from archetype `php-smarty-smm-panel-fork`. |
