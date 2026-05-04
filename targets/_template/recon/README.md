# `recon/`

Outputs from `framework/playbooks/01-passive-recon.md` and `02-active-recon.md`.

## Suggested Layout

```
recon/
├── passive/
│   ├── whois.txt
│   ├── dns/                  ← DNS enum outputs (subfinder, amass, dnsx, massdns)
│   ├── certificates/         ← cert transparency dumps (crt.sh, censys)
│   ├── search-engine/        ← Google/Bing/Shodan dorks results
│   ├── leaks/                ← github-search results, paste site grabs (output of leaks.sh)
│   ├── archive/              ← waybackurls, gau output
│   ├── third-party/          ← BuiltWith, Wappalyzer, BuiltWith
│   └── README.md             ← what was queried, when, with what scope
├── active/
│   ├── ports/                ← nmap, naabu, masscan output
│   ├── http-probe/           ← httpx, eyewitness, aquatone output
│   ├── content-discovery/    ← ffuf, feroxbuster, dirsearch
│   ├── crawl/                ← katana, hakrawler, gospider
│   ├── tech-fingerprint/     ← whatweb, wappalyzer-cli
│   ├── api-discovery/        ← swagger, postman, GraphQL introspection
│   └── parameters/           ← arjun, paramspider
├── wordlists/                ← target-specific wordlists derived from above
└── attack-surface.md         ← consolidated summary fed into attack-tree.md
```

## Capture Discipline

- Every active scan command goes in `notes/command-log.md` with timestamp and rationale.
- Raw output lives here; analysis lives in `attack-surface.md` and `notes/`.
- Don't rely on stdout to terminal; redirect to file.

## OPSEC Posture

- TEST posture: standard rate, identifiable test UA where applicable.
- AUDIT posture: throttle, off-hours; coordinate with client SOC.
- EMULATE posture: mimic known threat actor TTPs per charter.
