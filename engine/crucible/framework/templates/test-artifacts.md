# `<Target>` — Test artifacts index

This file is the manifest of all evidence captured during the engagement. Every
PoC, screenshot, request/response capture, log excerpt, or extracted file MUST
be referenced here with chain-of-custody metadata.

Artifacts live under `targets/<target>/evidence/` (one subdirectory per finding
or chain) and `targets/<target>/loot/` (extracted data — kept out of any
deliverables and out of git via `.gitignore`).

---

## Conventions

- **Filenames:** `<finding-id>__<short-slug>__<YYYYMMDDTHHMMSSZ>.<ext>`
  e.g. `F-007__idor-order-12345__20260504T142312Z.har`
- **Hashes:** SHA-256 of every artifact, recorded below at capture time.
- **Times:** UTC, ISO 8601 with `Z` suffix.
- **Originator:** OBSIDIAN unless otherwise noted.

---

## Index

| # | Finding | Type | Path | SHA-256 (truncated) | Captured (UTC) | Notes |
|---|---------|------|------|---------------------|----------------|-------|
| 1 | `F-XXX` | `<har / png / json / pcap / txt / log / video / raw>` | `evidence/F-XXX/<file>` | `<first 16 hex>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<context>` |

---

## Artifact types & integrity

| Type | Captured via | Verification |
|------|--------------|--------------|
| HTTP request/response | Burp / mitmproxy / curl with `-v` saved | re-issue and diff response |
| HAR | browser devtools or proxy export | JSON-validate, check timing fields |
| Screenshots | OS screenshot tool or browser | inspect EXIF, ensure no terminal creds visible |
| PCAP | tcpdump / Wireshark | open in Wireshark, validate flow |
| Log excerpts | server log or app log | record source path, line range |
| Extracted files | downloaded from target | hash, scan with clamscan if executable |
| Tokens / cookies | captured during PoC | redact in evidence; full value goes to loot/ only |
| Source extracts | from §2.6 repos | record commit SHA |

---

## Hash verification command

```bash
# Generate / verify hashes for every file under evidence/
( cd targets/<target>/evidence && find . -type f -print0 | xargs -0 sha256sum ) \
  > targets/<target>/evidence/SHA256SUMS

# Verify later
( cd targets/<target>/evidence && sha256sum -c SHA256SUMS )
```

---

## Redaction policy

Before any artifact leaves `targets/<target>/` (e.g. attached to a report PDF),
redact:

- Real user PII (emails, phone numbers, addresses) → `█████` overlays in PNG, regex-replace in text
- Real session tokens, JWTs, API keys → `<REDACTED:JWT>` placeholder
- Internal IPs and hostnames not necessary to the finding → `<INTERNAL_HOST>`
- Database identifiers that could enable replay → keep ID class, redact value (`order_id=█████`)

OBSIDIAN-TEST-* identifiers may remain in the clear; that is their purpose.

---

## Chain of custody

| Event | Who | When (UTC) | Notes |
|-------|-----|------------|-------|
| Captured | OBSIDIAN | `<>` | source: `<host>` |
| Hashed | OBSIDIAN | `<>` | SHA-256 recorded |
| Reviewed | `<name>` | `<>` | included in report v`<>` |
| Delivered | OBSIDIAN | `<>` | report bundle SHA-256 `<>` |
| Retained until | — | `<YYYY-MM-DD>` | per scope §10 |
| Purged | `<name>` | `<>` | confirm with `shred -u` for loot/ |
