# MERIDIAN — presenter script (government demo)

A 10–15 minute walkthrough that shows VIGIL finding, proving, mapping, and remediating real
vulnerabilities against a realistic government service — then producing an auditor-verifiable record.

> Everything runs on **loopback only**, on synthetic data. MERIDIAN is a *fictional* agency. Say this once,
> up front: *"This is a deliberately-vulnerable practice target — a safe copy of a permits service — so we
> can show the tool working end to end without touching anything real."*

## 0 · Before the room arrives
```
cd <repo> && make setup          # builds the offense env; installs `target`
target up                        # MERIDIAN :19010  +  Range Control :19011
```
Open two browser tabs: **http://127.0.0.1:19010/** (the service) and **http://127.0.0.1:19011/** (Range
Control). Leave MERIDIAN in the default (vulnerable) mode.

## 1 · "This looks like a real government service" (1 min)
Show **:19010** — the Government of Meridia permits portal: a register with thousands of licences, a citizen
front-office (apply / pay / track / search), a five-role staff back office. *"A citizen applies here; staff
review and issue. It holds identity records, payments, documents — exactly the data a real permits service
holds."*

## 2 · "Now we point VIGIL at it" (1 min)
Switch to **Range Control (:19011)**. *"This is the operator console. It drives our security engine against
the service and shows what it finds — and, importantly, proves it."* Click **Run all ▸**, then narrate as
each step streams:

| Step | Say this |
|---|---|
| 1 Recon | "It maps the service — every page, form and parameter." |
| 2 SQLi + XSS | "It doesn't *guess*. A deterministic oracle **confirms** SQL injection and cross-site scripting as **facts**." (point at the green FACT badges in the **Findings** tab) |
| 3 IDOR/BOLA | "It proves one citizen can read another citizen's full identity record — a personal-data breach." |
| 4 SSRF | "It proves the server can be made to call out to attacker infrastructure." |
| 5 Verify offline | "This is the part auditors care about: it **re-proves** every finding from evidence, with no trust in the tool." |
| 6 SARIF | "It exports in SARIF — the standard format your existing security tooling and CI already read." |
| 7–8 Evidence | "It signs the evidence and re-verifies it **offline** — an independent auditor can check it without our software. **Bundle SOUND.**" |
| 9 Detect | "The same engine, on defense: it reads the service's own logs and **detects** the attack — brute force, injection, scanning." |
| 10–12 Harden → re-prove | "We fix the flaws and re-run: **zero** findings, on a live check — a signed **Certificate of Non-Exploitability**, not just silence." |

## 3 · The three tabs that matter to government (3 min)
After the run, click through the **Assessment results** tabs:
- **Compliance** — *"Every finding is mapped to the frameworks you procure against: OWASP ASVS, NIST 800-53,
  ISO 27001, CIS, MITRE ATT&CK. This is the language of your auditors and your ATO."*
- **Business impact** — *"And here is what it means in plain terms: a full citizen-register breach; permits
  issued without payment; back-office takeover. Not 'a scanner flagged something' — a chain to real harm."*
- **Evidence** — *"A signed, hash-linked bundle. An auditor re-verifies it offline. This is sovereign proof —
  you don't have to trust us, or be online, to check it."*

## 4 · The remediation story (1 min)
*"Finding bugs is half of it. Watch the fix."* If you didn't run the full tour, run steps **10–12** now, or
from a terminal: `target harden on`, then re-run **Confirm SQLi + XSS** — it now returns **0 confirmed
findings on a live channel**. *"Same routes, same requests — the weakness is gone, and the tool proves the
negative is real."* Then `target harden off` to reset.

## 5 · Close
*"One engine: it finds, it proves, it maps to your compliance regime, it produces auditor-verifiable
evidence, it detects the same attacks in your logs, and it validates the fix — all sovereign, all offline-
verifiable, nothing leaving your control."*

---

### Reset between demos
```
target harden off        # back to vulnerable
target down && target up # fresh state (rebuilds the synthetic register)
```

### If a step is slow
A full crawl can take a few minutes. The tour uses **focused** scans so each step returns in ~1 minute. If
the room is short on time, run steps 2 (SQLi/XSS), 7–8 (evidence), and 10–11 (harden → re-prove) — that is
the whole story in three clicks.
