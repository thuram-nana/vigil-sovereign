# Command log — `<target>`

> Append-only log of every meaningful command run during the
> engagement. Used as the audit trail and to reproduce behavior on
> retest.

Format per row:

```
[YYYY-MM-DD HH:MM:SS UTC | phase | tool | host] command — note
```

Phase: `0-charter / 1-threat / 2.1-passive / 2.2-active / 3-mapping /
4-<domain> / 5-exploit / 6-postexploit / 7-source / 8-report /
9-retest / 10-cont`.

---

```
2026-MM-DD 09:14:32 UTC | 2.1-passive | curl       | crt.sh           | curl 'https://crt.sh/?q=%25.<target>&output=json' — subdomain enum
2026-MM-DD 09:15:08 UTC | 2.1-passive | subfinder  | <target>         | subfinder -d <target> -all -silent — passive enum
2026-MM-DD 09:18:45 UTC | 2.2-active  | httpx      | subs-list        | httpx -l subs.txt -tech-detect -tls-probe — live host probe
2026-MM-DD 09:21:02 UTC | 2.2-active  | nmap       | <target>         | nmap -sS -T2 --top-ports 1000 — port scan
2026-MM-DD 09:32:18 UTC | 2.2-active  | testssl    | <target>         | testssl.sh https://<target>/ — TLS audit
2026-MM-DD 09:48:11 UTC | 2.2-active  | curl       | <target>         | obvious-leaks loop — files .env, .git, backup* — none returned 200
2026-MM-DD 10:04:55 UTC | 3-mapping   | katana     | <target>         | authenticated crawl as userA, depth 4
2026-MM-DD 10:21:09 UTC | 3-mapping   | ffuf       | <target>         | ffuf raft-medium-directories — auth & unauth diff
2026-MM-DD 11:02:34 UTC | 4-auth      | curl       | <target>/login   | rate-limit probe per-account — 50 attempts userA, no lockout
2026-MM-DD 11:03:48 UTC | 4-auth      | python     | <target>/login   | auth-probe.py timing-side-channel — 95ms delta valid vs invalid → finding-005
2026-MM-DD 11:11:22 UTC | 4-auth      | curl       | <target>/forgot  | host header injection probe — REPRODUCED → finding-007
...
```

---

> Continue appending. Do not edit history. Use UTC. Use 24-hour clock.
