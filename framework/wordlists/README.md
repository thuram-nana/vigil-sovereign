# Wordlists

> This directory is intentionally **empty in the framework distribution**. Wordlists are not committed because they are large, often licensed, sometimes regenerated, and frequently target-specific.

---

## Standard Wordlists (install via `framework/tools/install.sh`)

The installer places **SecLists** at `/usr/share/seclists` and provides the convenience symlinks below in this directory after install. If you've run the installer, you can ignore the rest of this file. If you haven't, run:

```
sudo bash framework/tools/install.sh
```

Common collections you will reach for:

| Purpose | Path (after install) |
|---|---|
| Subdomain enumeration | `/usr/share/seclists/Discovery/DNS/` (e.g. `subdomains-top1million-110000.txt`, `bitquark-subdomains-top100000.txt`) |
| Web content discovery | `/usr/share/seclists/Discovery/Web-Content/` (`raft-large-words.txt`, `directory-list-2.3-medium.txt`, `common.txt`) |
| API path enumeration | `/usr/share/seclists/Discovery/Web-Content/api/`, `/usr/share/seclists/Discovery/Web-Content/swagger.txt` |
| Backup files | `/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt` |
| Username enumeration | `/usr/share/seclists/Usernames/` |
| Password spraying | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-*.txt` |
| Default creds | `/usr/share/seclists/Passwords/Default-Credentials/` |
| Fuzzing payloads | `/usr/share/seclists/Fuzzing/` |
| XSS payloads | `/usr/share/seclists/Fuzzing/XSS/` |
| SQLi payloads | `/usr/share/seclists/Fuzzing/SQLi/` |
| LFI payloads | `/usr/share/seclists/Fuzzing/LFI/` |
| Special character | `/usr/share/seclists/Fuzzing/special-chars.txt` |

Other collections to consider:

- **assetnote wordlists** — https://wordlists.assetnote.io (specialized: tech-fingerprint-driven).
- **dirsearch built-ins** — bundled with the tool.
- **fuzzdb** — https://github.com/fuzzdb-project/fuzzdb (older, still useful).
- **PayloadsAllTheThings** — https://github.com/swisskyrepo/PayloadsAllTheThings (categorized by attack class).
- **cewl-generated** — custom wordlist from a target's site content (`cewl https://target -m 6 -w custom.txt`).

---

## Per-Target Custom Wordlists

For each engagement, build a target-specific wordlist that is more effective than any generic list. Store these in `targets/<name>/recon/wordlists/`. Sources:

1. **Site crawl extraction:** crawl with Burp / Katana / hakrawler; extract every distinct URL path component, parameter name, and form field name.
2. **JavaScript extraction:** extract endpoints, parameter names, and string literals from JS bundles (`linkfinder`, `subjs`, `getjs`).
3. **Documentation:** any public API docs, OpenAPI/Swagger specs, postman collections.
4. **Wayback / archive:** historical paths (`waybackurls`, `gau`, `katana -ps`).
5. **Source repo (if accessible):** route definitions, controller method names.
6. **Org-specific terms:** product names, internal codenames, acronyms.
7. **CeWL on the target site:** spider the public site and extract words.

This produces a wordlist of the form `target-paths.txt`, `target-params.txt`, `target-words.txt` that is small (often hundreds to low thousands of entries) and high-signal. Use it before reaching for `directory-list-2.3-big.txt`.

---

## OPSEC Note

Hosting copies of large licensed wordlists in your repo is a copyright and disk-space liability. Reference the canonical install path; commit only **target-specific derivatives** that you've generated from public information about the target.
