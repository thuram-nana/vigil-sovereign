# `evidence/`

Raw captures supporting findings. Organize by finding ID:

```
evidence/
├── FINDING-001-idor-on-orders/
│   ├── 01-baseline-request.http       ← raw HTTP request/response
│   ├── 02-attack-request.http
│   ├── 03-attack-response.http
│   ├── screenshot-burp-repeater.png
│   ├── screenshot-rendered-page.png
│   ├── poc.py                         ← scripted reproduction
│   └── notes.md                       ← operator-narrated walkthrough
├── FINDING-002-jwt-none-algorithm/
│   └── ...
├── CHAIN-001-account-takeover/
│   ├── step-01-leak-token.http
│   ├── step-02-replay.http
│   └── ...
└── recon/                              ← recon evidence not yet promoted to a finding
```

## Capture Standards

- **HTTP captures:** prefer raw `.http` (request blank-line response, exact bytes). Burp's "Copy as raw" is fine. Strip any unrelated cookies/headers that aren't needed for reproduction; keep what's needed for fidelity.
- **Screenshots:** PNG, named `<NN>-<short-description>.png`, included in finding markdown via relative reference.
- **Tool output:** `.txt` for stdout, `.json` for structured.
- **PoC:** runnable script (`.py`, `.sh`, `.js`) at the path the finding references. Should print a clear success indicator.

## Redaction

- Real user data, even from authorized test accounts, must be redacted in any artifact that may leave the engagement environment (e.g., in client deliverables in `reports/`).
- Internal IPs and hostnames may be sensitive depending on charter; check `charter.md` "Disclosure" section.
- Tokens, session IDs, and credentials in raw captures: leave intact in `evidence/` for reproducibility, but redact (`Authorization: Bearer eyJ***REDACTED***`) in anything copied into `reports/`.

## Hash Manifest

Optionally maintain `evidence/MANIFEST.sha256` updated on each commit so a reader can verify nothing has been tampered with retroactively.

```
cd evidence && find . -type f -not -name MANIFEST.sha256 -print0 | xargs -0 sha256sum > MANIFEST.sha256
```
