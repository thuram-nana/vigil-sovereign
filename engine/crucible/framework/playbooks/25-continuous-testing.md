# Playbook 25 — Continuous testing

**Goal:** turn one-shot engagement into ongoing posture management.
Real adversaries don't time their attacks to your last pentest;
neither does fresh code from your last sprint. The right cadence
keeps the security baseline alive.

**Stage in lifecycle:** 10.

---

## 25.1 Why continuous

A one-shot pentest captures a snapshot. Within weeks of the report:
- New code has shipped.
- New endpoints have been added.
- Dependencies have updated (or stayed stale longer).
- New cloud resources have been provisioned.
- Customer scale has changed (new abuse patterns).
- Threat landscape has changed (new public exploits in your stack).

Without continuous testing, the operator gets a snapshot of safety
that ages out within a quarter.

---

## 25.2 Continuous-testing modes

| Mode | Cadence | Effort | What it covers |
|------|---------|--------|----------------|
| Daily lightweight monitoring | Daily | Minimal | New subdomains, exposed services, leaked secrets |
| Per-release smoke tests | Per-release | Hours | New / changed endpoints, regression on fixed findings |
| Quarterly self-driven re-engagement | Quarterly | Days | Full playbooks against current snapshot |
| Annual external pentest | Yearly | Weeks (third-party) | Independent validation, fresh perspective |

A healthy operator runs all four.

---

## 25.3 Daily monitoring (semi-automated)

```bash
# In a cron job, runs the daily pass
cd /path/to/crucible/targets/<name>

# New subdomains
subfinder -d <root.tld> -all -silent | sort -u > /tmp/subs-today
diff <(sort recon/passive/all-subdomains.txt) /tmp/subs-today | tee notes/changes-today.txt

# Subdomain takeover candidates
nuclei -t takeovers/ -l /tmp/subs-today -o notes/takeovers-today.txt

# Leaked secrets in public repos / paste sites
trufflehog github --org <org> --json > /tmp/trufflehog-today.json

# Cert transparency new entries
curl -s "https://crt.sh/?q=%25.<root.tld>&output=json" | jq -r '.[].name_value' \
  | sort -u > /tmp/crt-today.txt
diff <(sort recon/passive/crtsh.txt) /tmp/crt-today.txt | tee notes/crt-changes-today.txt

# Notify operator if anything changes
```

These cheap checks find:
- New unauthorized cloud resources.
- Leaked secrets newly committed.
- Subdomain takeover opportunities (new pointers to unclaimed
  resources).
- New certs (which also reveals new infrastructure).

---

## 25.4 Per-release smoke tests

Hook into deploy pipeline. After each production deploy:

1. Re-fetch endpoint inventory (`recon/enum/inventory.md`) and
   diff. New endpoints get a fast pass through the relevant
   playbooks (auth, authz, injection, business logic).
2. Re-run PoCs for previously-fixed findings to catch regressions.
3. Run `nuclei` against new endpoints with curated templates.
4. Run a SAST gate (semgrep / CodeQL) in CI.

Output: ticket per new issue assigned to the deploy author.

---

## 25.5 Quarterly self-driven re-engagement

Run the full lifecycle against a current snapshot:

- New charter (date-stamped) — same scope or expanded.
- Stage 1 threat model: refresh.
- Stages 2–4: re-run with prior inventory as starting point.
- Stage 5: focus on diffs (what's new since last engagement).
- Reports.

Aim to detect drift / regression / new exposures.

---

## 25.6 Annual external pentest

Independent firm. Fresh eyes catch things your own framework misses
because of pattern blindness. Use independent firm output to refine
your own playbooks for next time.

---

## 25.7 Continuous testing plan template

```markdown
# Continuous testing plan — <target>

## Daily
- [ ] Subfinder + diff against last
- [ ] CRT diff
- [ ] Nuclei takeovers
- [ ] TruffleHog org repos
- [ ] Notification: <channel>

## Per-release
- [ ] CI gate: semgrep / dependency scan / SAST
- [ ] Endpoint diff + targeted playbooks on new endpoints
- [ ] Regression test on fixed findings

## Quarterly
- [ ] Full re-engagement (date: __ )
- [ ] Reports refreshed

## Annual
- [ ] External firm engaged (vendor: __ , date: __ )
- [ ] Bug bounty program review

## Owner: <person>
## Last reviewed: <date>
```

`targets/<name>/notes/continuous-testing-plan.md`.

---

## 25.8 Output

`continuous-testing-plan.md`. Operator briefed on the cadence.
Engagement closure formalized.
