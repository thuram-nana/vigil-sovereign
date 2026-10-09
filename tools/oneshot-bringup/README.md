# VIGIL one-shot production bring-up

`vigil-oneshot.sh` stands the **whole** system up end-to-end in **full production
posture** on this host (loopback-only) and **proves it green** before any UI
testing. It is **idempotent** (safe to re-run; no-ops where state already holds)
and **fail-closed** (aborts non-zero on any un-green gate; it never fakes a
control green and never `|| true`-swallows a gate).

```
chmod +x tools/oneshot-bringup/vigil-oneshot.sh
export ANTHROPIC_API_KEY=sk-ant-...      # REQUIRED
export CRUCIBLE_ANTHROPIC_ZDR=1          # operator ZDR attestation (see "Sovereignty tier" below)
tools/oneshot-bringup/vigil-oneshot.sh   # full bring-up + prove
```

Other modes: `--status` (health-only, no mutation), `--down` (stop the UI units),
`--bootstrap` / `--skip-bootstrap`, `--help`.
Env overrides: `SLUG`, `SOVEREIGNTY_TIER`, `SIGIL_HOME`, `CRUCIBLE_ROOT`,
`VIGIL_WITNESS_ROSTER`, `ENTITLEMENT_INSTITUTION_ID/NAME/TIER/VALID_DAYS`,
`CRUCIBLE_ANTHROPIC_ZDR`, `CRUCIBLE_ANTHROPIC_MODEL`.

> This script runs **mutations** (bootstrap, systemd, provisioning, `target up`).
> It is meant to be run by the **operator** on a system they own and are
> authorized to operate. It binds **loopback only** and never a public listener.

---

## Prerequisites

| Need | Why | If missing |
|------|-----|-----------|
| `ANTHROPIC_API_KEY` in the env | `deploy-acceptance` **check 1** does a real Anthropic `think()` and **blocks** without it (`integration/vigil_integration/sovereign_deploy/acceptance.py:301-302`) | script **stops early** in preflight |
| docker running | `vigil-bringup` (qdrant/gateway) + some acceptance checks | warn; acceptance may block if a check needs a service |
| `systemctl --user` (user D-Bus) | the UI unit + backup timers are **user** units | script aborts with remedy |
| `VIGIL_BACKUP_PASSPHRASE` in `~/.config/vigil/backup.env` | the seeded backup run encrypts with it | warn; `backups` won't reach ON → gate refuses |
| a usable **TPM** (device + tpm2-tools) | the `vault` control seals keys at rest | honest boundary — see below |

---

## What it runs, step by step (each grounded in code)

Phases 0→9. Every external command's failure is caught and aborts with a clear
message + remediation.

0. **Preflight** — require `ANTHROPIC_API_KEY`; check venv python 3.12/3.13;
   docker; `systemctl --user`; backup passphrase; sovereignty/ZDR consistency;
   git HEAD (warn only).
1. **Bootstrap** — `./bootstrap.sh --production --yes` when a prerequisite is
   missing (both venvs, Rust WARDEN kernel, the `target` range CLI, the egress
   binary) or on `--bootstrap`; else a no-op. Grounded: `bootstrap.sh`
   (`--production` ⇒ `PRODUCTION=1; DO_SYSTEMD=1` at `bootstrap.sh:66`; builds via
   `envs/build_envs.sh` at `:362`; enables timers `:559`; its own WS4 acceptance
   `:637-680`). The production env is exported **before** bootstrap so its WS4
   acceptance inherits the same posture. After bootstrap, if `.venv-offense/bin/target`
   is still absent the script installs `-e ./range` (declared `envs/offense.txt:18`).
2. **Provision the 8 controls** (idempotent; details below).
3. **Seed `.vigil-live/service.env`** — the `EnvironmentFile=-` both UI units load
   (`infra/systemd/vigil-command.service:67`, `vigil-bringup.service:49`). Nothing
   in the tree writes this file; the script is the writer (0600, atomic).
4. **Production gate — `vigil doctor`** — run **before** starting the UI so a red
   control aborts with the exact unmet list. `vigil doctor --json` exposes
   `.production_gate.unmet[].control` (`_cmd_doctor` `integration/vigil_integration/cli.py:3187`;
   exit `0 if report.ok else 1`). The UI unit also self-gates at ExecStart
   (`_enforce_production_gate("up")` `cli.py:3012`) — defense in depth.
5. **Start the UI** — `systemctl --user enable --now vigil-command.service`
   (ExecStart `vigil up --port 8770 --no-browser`) and `vigil-bringup.service`
   (`vigil services up --all`, best-effort). `loginctl enable-linger`. Then poll
   `http://127.0.0.1:8770/readyz` for HTTP 200 (`uiproxy.py:1382/1791`).
6. **MERIDIAN** — `target up meridian --no-browser` (loopback :19010 + :19011,
   `range/vigil_range/launcher.py`; config `range/vigil_range/meridian/config.py:28-29`).
   Launched with `nohup`+`disown` so it persists for UI-driven testing. Polls
   `http://127.0.0.1:19010/`.
7. **Acceptance** — `vigil deploy-acceptance --target-port 19010` (==
   `python -m vigil_integration.sovereign_deploy.acceptance`). 6 fail-closed
   checks; **exit 0 == HANDOVER-READY** (`acceptance.py:557,571`). Its exit is
   never swallowed. Needs MERIDIAN already up (it does **not** start the range).
8/9. **Summary** — `/readyz`, `/__vigil/plane/status` (token-guarded; the HTTP
   code is informative), `target status`, and the `vigil doctor` verdict.

---

## The 8 production refuse-to-start controls

Authoritative registry: `packages/core/vigil_core/vigil_core/doctor.py:69-99`
(`REQUIRED_CONTROLS`). Each must read its good-state under `VIGIL_POSTURE=production`.
`vigil doctor` reads these from its **own process env** (it does **not** source
`service.env`), so the script **exports** the same values it writes to `service.env`.

| # | control | good-state | exact command / env the script runs | grounded at |
|---|---------|-----------|--------------------------------------|-------------|
| 1 | **vault** | `SEALED` | `SIGIL_HOME=$SIGIL_HOME sigil vault provision` (sovereign venv), only when a TPM device exists; else honest boundary | probe `integration/.../doctor.py:429-446` (reads `$SIGIL_HOME/vault/kek.tpm.{pub,priv}`, consts `:229-230`); `bootstrap.sh:581-582` |
| 2 | **sovereignty** | one of `AIR_GAPPED`/`SOVEREIGN_CLOUD`/`TRUSTED_CLOUD` | `export CRUCIBLE_SOVEREIGNTY_TIER=TRUSTED_CLOUD` (+ in `service.env`) | probe `doctor.py:311-316`; tier map `engine/crucible/framework/v2/kernel/sovereignty.py:106-110` |
| 3 | **entitlement** | `ACTIVE` | `export CRUCIBLE_ENTITLEMENT_ENFORCED=1` **and** (if trust root absent) `python -m framework.v2 entitlement provision --institution-id <id> --institution-name <name> --tier offensive --valid-days 365` (offense venv) | probe `doctor.py:340-358` (env truthy ⇒ ACTIVE at `:344-345`, else `trust-root.json` present); CLI `engine/crucible/framework/v2/entitlement/cli.py:215,401-410`; docs `engine/crucible/framework/v2/docs/ENTITLEMENT-PROVISIONING.md:54-59` |
| 4 | **backups** | `ON` | `systemctl --user enable vigil-backup.timer vigil-backup-drill.timer`; then **seed** `systemctl --user start vigil-backup.service` **and** `vigil-backup-drill.service` (each must exit 0) | probe `doctor.py:581-630`; alternatives/required sets `:512-513`; timer→service map `:530`; passphrase `VIGIL_BACKUP_PASSPHRASE` (`infra/systemd/vigil-backup.env.example:34`) |
| 5 | **charter** | `PRESENT` | pin `export VIGIL_ENGAGEMENT=loopback`; ensure `<crucible_root>/targets/<slug>/charter.md` **and** `<crucible_root>/framework/v2/.authority/<slug>.authority.json`. If authority absent: `vigil provision --slug <slug> --scope 127.0.0.1 --base-dir .vigil-live` (offense venv) | probe `doctor.py:643-687` (needs **both** files); mint `cli.py:4319-4327` → `_cmd_provision` → `live/wiring.py:139` |
| 6 | **legacy-owner-token** | `DISABLED` | `export SIGIL_LEGACY_OWNER_TOKEN=0` (+ in `service.env`) | probe `doctor.py:694-716` |
| 7 | **egress-supervisor** | `ARMED` | ensure `tools/egress-guard/egress_guard` exists (else `make -C tools/egress-guard`); `export VIGIL_EGRESS_GUARD=require` (production forces it anyway) | probe `doctor.py:716-736`; binary path `integration/vigil_integration/live/egress_guard.py:175-182` (default `tools/egress-guard/egress_guard`); Makefile target `all`→`egress_guard` |
| 8 | **witness** | `DISTINCT-QUORUM` | if `python -m vigil_integration.witness_provision --repo <repo> status` is not already DISTINCT-QUORUM: `… add --key .vigil-live/witness-w0.key` and `… add --key .vigil-live/witness-w1.key` (two **distinct** keys) | probe `doctor.py:739-750` → `witness_provision.roster_posture` (`DISTINCT-QUORUM` == split-view-resistant **and** n≥2); CLI `witness_provision.py:383-395`; roster `.vigil-live/witness-roster.json` (`:68,88-101`) |

**Charter note:** `vigil provision` mints the **authority** but not `charter.md`
(`live/wiring.py`). For a **loopback** slug the charter either ships or is written
by a `vigil engage` pass (`ensure_loopback_charter` `wiring.py:1186-1228`). On this
repo `loopback` already has **both** files under `engine/crucible`, so the control
is PRESENT with nothing to mint. For a **non-loopback** scope you must author a real
signed `charter.md` by hand.

**Witness idempotency:** re-running `add` on an **existing** key file errors
(`_cmd_add` does not catch the duplicate `RosterError`), so the script checks
`status` first and only mints key files that do not yet exist.

---

## Honest boundaries (the script surfaces these; it never fakes a control)

- **TPM / `vault`.** The vault seals only on a host with a usable TPM. If sealing
  fails (e.g. a TPM device exists but `tpm2-tools` are not installed — the state
  of this host today: `/dev/tpm0` present, `tpm2_createprimary` absent), keys rest
  **plaintext** and the `vault` control stays `UNPROVISIONED`. The script reports
  it and the `vigil doctor` gate **refuses** — a full green bring-up is not
  possible until the vault is SEALED. Remedy:
  `sudo apt-get install -y tpm2-tools && sudo usermod -aG tss $USER` (then re-login),
  or run on a TPM-backed host.
- **Witness independence.** Two locally-minted keys are arithmetically distinct
  (split-view **resistant**), reaching `DISTINCT-QUORUM`. True split-view
  **prevention** requires the keys held by **independent parties** on separate
  hosts — a deployment property code cannot verify
  (`witness_provision.py:36-41,306-309`). For real independence, `register` an
  out-of-band witness pubkey from another operator's box.
- **Entitlement trust root.** `CRUCIBLE_ENTITLEMENT_ENFORCED=1` makes the control
  `ACTIVE` (a code-honored path named in the requirement text itself) but does not
  by itself **grant** a capability tier. The script also provisions a real
  `trust-root.json` for actual enforcement; if that provisioning does not complete
  it warns and the env flag still satisfies the gate control — provide a real trust
  root for full capability enforcement. The generated `authorizer-keys.json` is
  crown-jewel private material — move it **off-host**.
- **Sovereignty tier vs the Anthropic path.** The gate only needs a non-PERMISSIVE
  tier. But `deploy-acceptance` check 1 needs a **direct** Anthropic `think()`, and
  `kernel/sovereignty.py:170-180` classifies a direct Anthropic client as
  `cloud_only` (refused above PERMISSIVE) **unless** `CRUCIBLE_ANTHROPIC_ZDR` is
  set, which reclassifies it `trusted_cloud`. So the chosen default is
  **`TRUSTED_CLOUD` + operator `CRUCIBLE_ANTHROPIC_ZDR=1`**, the lowest tier that is
  both non-PERMISSIVE and admits the direct-Anthropic path acceptance requires.
  `AIR_GAPPED`/`SOVEREIGN_CLOUD` would make check 1 **BLOCK** unless you wire a
  local/sovereign backend. **ZDR is an operator attestation** (that your Anthropic
  endpoint is zero-data-retention/Enterprise); the script passes it through only if
  you set it — it never fabricates it.
- **`CRUCIBLE_ROOT` reconciliation.** The pre-existing `service.env` on this host
  pointed `CRUCIBLE_ROOT` at `/home/kali/Music/PENTEST/crucible` (a different tree).
  The script pins the repo-canonical `<repo>/engine/crucible` (matches
  `bootstrap.sh:40`) so the authority mint, the charter probe and `vigil doctor`
  all read the same tree. Override `CRUCIBLE_ROOT` to keep a different tree
  (`loopback` is provisioned under both on this host).

---

## FATAL-2 (two-env) discipline

`sigil vault provision` runs from `.venv-sovereign`; every `vigil …`,
`python -m framework.v2 …` and `python -m vigil_integration …` runs from
`.venv-offense`. The script never crosses the two venvs.

## Verifying this file

Author-time check only: `bash -n tools/oneshot-bringup/vigil-oneshot.sh` (syntax).
The script itself is the live arbiter — run it on the target host.
