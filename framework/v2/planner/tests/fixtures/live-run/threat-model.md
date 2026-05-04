# Threat model — `fix-target.invalid`

**Status:** DRAFT (URK fallback). Archetype: **PHP-Smarty SMM-panel fork** (`php-smarty-smm-panel-fork`).

URK was unavailable; this skeleton was synthesized from the archetype and the intake fingerprint. Refresh by hand or re-run with a live LLM.

## Archetype-derived top concerns

- webhook-forgery
- IDOR
- mass-assignment
- race
- SQLi
- vertical-privesc
- source-disclosure
- reset-token

## Fingerprint signals

```
target_url: https://fix-target.invalid
api: rest (0.70)
auth: oidc (0.95)
cms: perfect-panel (0.95)
framework: perfect-panel (0.90)
payment: cryptomus (0.95)
server: nginx (0.95)
```
