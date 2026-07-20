# SIGIL Operator Runbook

Production operations for a SIGIL install: run the daemons, self-check,
**back up the irreplaceable spine**, upgrade, and troubleshoot.

SIGIL is local-first and owner-only. All runtime state lives under
`~/.sigil/` (mode `0700`); the code lives in this repo. Nothing here reaches
the network except the loopback Qdrant container and, if you enable it, the
WireGuard-bound phone bridge (which binds a private/tunnel IP only — never a
public address).

Deployment assets referenced below live in [`deploy/`](deploy/).

---

## 1. Install

Full walk-through with prerequisites is in the [README](README.md#setup)
(Linux, Python 3.13, Rust for the kernel, Docker for Qdrant). Summary:

```bash
# 1. venv + dependencies (README canonical layout: venv under ~/.sigil)
python3 -m venv ~/.sigil/venv
~/.sigil/venv/bin/pip install -e .          # installs the `sigil` console command
#   add optional stacks as needed:  pip install -e ".[all]"   (voice, secrets, capture)
#   or the minimal runtime only:    pip install -r requirements.txt   (no console script)

# 2. Local vector store (Qdrant on loopback)
docker run -d --name sigil-qdrant --restart unless-stopped -p 127.0.0.1:6333:6333 \
    -v ~/.sigil/vectors:/qdrant/storage qdrant/qdrant

# 3. Build the Rust authorization kernel
cd kernel && cargo build --release && cd ..     # → kernel/target/release/sigil-kernel

# 4. Build the memory loop
sigil ingest        # Claude history + subagents (+ --git --docs) → spine
sigil index         # spine → vectors (incremental)
sigil graph         # rebuild the deterministic entity graph
sigil sign          # anchor the spine (Ed25519 signed head)

# 5. Register the MCP memory server (read-only, cited recall) with Claude
#    add to ~/.claude.json and ~/.config/Claude/claude_desktop_config.json under "mcpServers":
#    "sigil-memory": { "command": "/home/<you>/.sigil/venv/bin/python",
#                      "args": ["-m","sigil.mcp.server"],
#                      "env": {"SIGIL_HOME": "/home/<you>/.sigil"} }

# 6. Verify the install
sigil doctor
```

> `sigil <cmd>`, `~/.sigil/venv/bin/sigil <cmd>`, and
> `~/.sigil/venv/bin/python -m sigil <cmd>` are equivalent. The systemd units
> use an absolute venv path so they do not depend on a login `PATH`.

---

## 2. Run the daemons

SIGIL has two long-lived surfaces. Ship both as **user-level** systemd units
(no root) from [`deploy/systemd/`](deploy/systemd/).

### 2a. Phone bridge (`sigil-bridge@.service`)

Serves the WireGuard-bound phone transport. **The instance name is the bind
address** — always a WireGuard/Tailscale/loopback IP, never `0.0.0.0` and
never public (the server fails closed on anything else).

```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd/sigil-bridge@.service ~/.config/systemd/user/
cp deploy/bridge.env.example            ~/.sigil/bridge.env    # then edit
chmod 600 ~/.sigil/bridge.env
systemctl --user daemon-reload

systemctl --user enable --now sigil-bridge@10.13.13.1   # 10.13.13.1 = your WG IP
loginctl enable-linger "$USER"        # optional: keep running after logout
```

Manage / observe:

```bash
systemctl --user status  sigil-bridge@10.13.13.1
systemctl --user stop    sigil-bridge@10.13.13.1     # graceful SIGTERM (drains + closes socket)
systemctl --user restart sigil-bridge@10.13.13.1
journalctl  --user -u    sigil-bridge@10.13.13.1 -f  # follow logs
journalctl  --user -u 'sigil-bridge@*' -e            # all bridge instances
```

On first start the bridge prints its **self-signed TLS fingerprint** — pin it
once on the phone; it is stable across restarts, so a later change means MITM.
Pair a phone (owner, at the desktop):

```bash
sigil mesh authorize phone-1 <device-pubkey>   # confirm the fingerprint the phone shows
sigil mesh list-devices
sigil mesh revoke phone-1 <device-pubkey>      # takes effect on the next request
```

> IPv6 tunnel address? Escape it: `sigil-bridge@$(systemd-escape fd7a::1)`.

### 2b. Nightly consolidation (`sigil-consolidate.timer`)

Runs `sigil consolidate --provider heuristic` off-peak — **offline, no
frontier/API spend**. Oneshot service driven by a timer.

```bash
cp deploy/systemd/sigil-consolidate.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sigil-consolidate.timer
systemctl --user list-timers 'sigil-*'               # confirm next run
systemctl --user start sigil-consolidate.service     # run once, now
```

### 2c. MCP memory server

Not a daemon you run — Claude Code / Claude Desktop spawn it on demand via the
registration in step 5 above (stdio, read-only, loopback). Nothing to
enable/start; if recall stops working, re-check the JSON registration and that
the `command`/`env` paths are correct, then restart the Claude client.

### 2d. Local cockpit (optional, on demand)

`sigil serve` starts a loopback-only web UI and prints a one-time token; it is
interactive, not a managed service. Run it when you want the cockpit.

---

## 3. Self-check — `sigil doctor`

`sigil doctor` prints one line per check plus the effective config (secrets
redacted) and exits non-zero if any check fails.

| Check | Means | If it fails |
|-------|-------|-------------|
| `sigil_home_writable` | `~/.sigil` exists and is writable | fix ownership/permissions: `chmod 700 ~/.sigil` (see §4 for the full mode map) |
| `kernel_binary` | the Rust WARDEN kernel was found | build it (`cd kernel && cargo build --release`) or set `SIGIL_KERNEL_BIN` to its path |
| `claude_cli` | the `claude` CLI is on PATH | only needed for LLM-backed consolidate/agents; install it or set `SIGIL_CLAUDE_BIN`. Harmless if you only run the heuristic provider |
| `qdrant` | vector store reachable | embedded mode always passes; server mode probes `SIGIL_QDRANT_URL/readyz` — start the container (`docker start sigil-qdrant`) |
| `keyring` | an OS keyring backend is present | optional — without it, secrets fall back to `~/.sigil/sigil.env` (`0600`). Install the `secrets` extra for a real keyring |

Run it after every install, upgrade, and reboot.

---

## 4. Backup & restore — CRITICAL

**The spine and the owner keys are irreplaceable.** The spine is an
append-only, hash-chained ledger of everything SIGIL knows; the owner Ed25519
key is the trust root that signs the head and every approval. Lose the key and
you **permanently lose the ability to sign approvals or re-anchor the head** —
existing signatures still verify, but you can never produce new ones.

### What to back up (irreplaceable)

Everything under **`~/.sigil/spine/`**:

| Path | What it is |
|------|-----------|
| `~/.sigil/spine/spine.jsonl` | the append-only, hash-chained event ledger |
| `~/.sigil/spine/head.json` | the Ed25519-signed head anchor (anti-truncation) |
| `~/.sigil/spine/keys/` | the owner + WARDEN keypairs (**the trust root**) |

Also worth capturing (convenient, but **rebuildable** — see below):
`~/.sigil/sigil.env` (config + secrets fallback), `~/.sigil/bridge/` (pinned
TLS cert), `~/.sigil/qdrant/` (vectors), `~/.sigil/graph/` (entity graph).
Vectors and the graph are *deterministic projections of the spine* — after a
restore you can regenerate them with `sigil index` and `sigil graph` instead of
restoring them. The spine + keys you cannot regenerate.

The simplest correct backup is a copy of the **whole `~/.sigil/` tree**.

### How to back up

The spine is append-only and hash-chained, so a plain file copy taken while the
process is quiescent is a consistent snapshot — no database dump needed.

```bash
# Stop writers first (bridge + timer) so the snapshot is clean:
systemctl --user stop 'sigil-bridge@*' sigil-consolidate.timer

# Snapshot everything (preserve permissions with -p / --numeric-ids):
tar -C "$HOME" -cpzf ~/sigil-backup-$(date +%F).tar.gz .sigil
#   or incrementally:
rsync -aH --delete ~/.sigil/ /path/to/backup/sigil/

# Resume:
systemctl --user start 'sigil-bridge@*' sigil-consolidate.timer
```

A snapshot taken while writers are running is *usually* fine (append-only means
a torn write can only be a truncated tail, which reads self-recover — see §6),
but stopping writers guarantees a clean point-in-time copy.

### How to restore

```bash
tar -C "$HOME" -xpzf ~/sigil-backup-YYYY-MM-DD.tar.gz     # restores ~/.sigil/

# Re-assert owner-only permissions (a restore can widen them):
chmod 700 ~/.sigil ~/.sigil/spine ~/.sigil/spine/keys
chmod 600 ~/.sigil/spine/keys/*  ~/.sigil/sigil.env 2>/dev/null || true

# Validate integrity BEFORE trusting the restore:
sigil verify        # chain + signed head; exits non-zero on any break
sigil status        # record counts + live integrity

# Regenerate the projections if you did not restore them:
sigil index && sigil graph
```

`sigil verify` re-walks the hash chain and checks the signed head; a clean
`chain OK` / `head OK` confirms the restore is intact and untampered.

---

## 5. Upgrade

```bash
git -C ~/sigil pull                       # (run git yourself; the runbook does not)
cd ~/sigil
~/.sigil/venv/bin/pip install -e .        # or -e ".[all]"
cd kernel && cargo build --release && cd ..   # rebuild the kernel if it changed
sigil doctor                              # re-check the install
~/.sigil/venv/bin/pytest -q               # run the test suite before trusting the upgrade
systemctl --user restart 'sigil-bridge@*' # pick up the new code
```

Back up (§4) before a major upgrade. The spine format is append-only and
forward-compatible; an upgrade never rewrites existing records.

---

## 6. Troubleshooting

| Symptom | Check | Fix |
|---------|-------|-----|
| Bridge exits immediately / "refusing to bind" | the `--addr` (instance name) is public or `0.0.0.0` | bind a WireGuard/Tailscale/loopback IP: `sigil-bridge@10.13.13.1`. `bind_ok` allows loopback, RFC1918 private, and Tailscale CGNAT (`100.64.0.0/10`) only |
| `doctor`: `kernel_binary` not found / relay fails | the Rust kernel is unbuilt or off-PATH | `cd kernel && cargo build --release`, or set `SIGIL_KERNEL_BIN=/…/sigil-kernel` in `~/.sigil/bridge.env` |
| `doctor`: `qdrant` unreachable (server mode) | the Qdrant container is down | `docker start sigil-qdrant` (or unset `SIGIL_QDRANT_URL` to use embedded mode) |
| `search`/recall returns nothing | vectors not indexed after new ingest | `sigil index`; confirm with `sigil status` (`last_indexed_seq`) |
| `verify` / `status` reports a torn spine tail | a write was interrupted (power loss mid-append) | reads self-recover past a torn trailing line; re-run `sigil verify` — a clean `chain OK` confirms recovery. If the chain still fails mid-file, restore from backup (§4) |
| `chain FAIL` mid-file (not the tail) | the ledger was edited/corrupted | do NOT append further; restore `~/.sigil/spine/` from the last good backup and `sigil verify` |
| Phone can't pair / requests rejected | device not authorized, or TLS fingerprint mismatch | re-run `sigil mesh authorize <id> <pubkey>` confirming the fingerprint the phone shows; check `sigil mesh list-devices`; a changed TLS fingerprint means MITM — investigate, do not blindly re-pin |
| Bridge denies every request (403/401) | anti-rebind Host/Origin gate, or a revoked device | reach it via the exact bound `IP:PORT` (not a hostname); confirm the device is still in `list-devices` |
| `keyring` check fails | no OS keyring backend | optional — secrets fall back to `~/.sigil/sigil.env` (`0600`); install the `secrets` extra for a real backend |
| Unit won't start under systemd | wrong `ExecStart` path | ensure the venv `sigil` exists (`pip install -e .`), or switch the unit's `ExecStart` to the `python -m sigil` alternative line |

---

## 7. Log levels & observability

- **Where logs go.** SIGIL logs to **stderr** (`sigil/obs.py`). Under the
  systemd units that stderr is captured by **journald** — use
  `journalctl --user -u sigil-bridge@<ip>`. journald handles rotation; cap it
  with `journalctl --user --vacuum-size=200M` or `journald.conf`. Only if you
  redirect stderr to a file (e.g. `~/.sigil/logs/*.log`) do you need the
  [`deploy/logrotate/sigil`](deploy/logrotate/sigil) template.
- **Verbosity.** Set `SIGIL_LOG_LEVEL` (`DEBUG`|`INFO`|`WARNING`|`ERROR`) — in
  `~/.sigil/bridge.env` for the units, or the environment for ad-hoc runs.
  Default `INFO`. An unknown value falls back to `INFO` rather than erroring.
- **What SIGIL logs on the bridge.** Accepted effectful actions at `INFO`,
  denials at `WARNING` — enough to answer "who did what" over the tunnel.
- **What is NEVER logged.** Secrets, tokens, API keys, device signatures,
  request bodies, relayed command text, or full public keys. Device pubkeys are
  logged as a **12-char prefix only** (correlate, not reconstruct). The stdlib
  HTTP access log is suppressed on purpose (an auth envelope can ride in a query
  string). Use `sigil doctor`'s effective-config view for configuration —
  it redacts every secret-named value.
```
