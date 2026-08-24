# VIGIL — Incident Response

**Status: an operational runbook plus a description of the mechanisms this software actually ships.
Not legal advice. No claim of compliance with any statute is made here. Notification duties and their
deadlines are jurisdiction-specific — this document tells you what to consider, never what the law
requires of you.**

Every command and behaviour below was read from the source on this branch and carries a `path:line`
citation. Companion documents: [`/PRIVACY.md`](../../PRIVACY.md) (what data exists and where),
[`DATA-RETENTION.md`](DATA-RETENTION.md) (what can and cannot be deleted),
[`DATA-GROUND-TRUTH.md`](../../DATA-GROUND-TRUTH.md) (the engineering reference).

Fill the placeholders in §6 **before** you need them.

---

## 1. Which incident is this?

| Direction | Meaning | Go to |
|---|---|---|
| **A — VIGIL is the victim** | The machine running VIGIL is compromised, a key or token is exposed, evidence containing client data leaks, or a backup is lost | §2 |
| **B — the target was already compromised** | During an authorized engagement you find signs that a real attacker is or has been in the client's system | §5 |

They are different incidents with different first moves. If both are true, do §2 first — you cannot
investigate a client's compromise from a host you no longer trust.

---

## 2. Direction A — VIGIL itself is compromised, or client data is exposed

### 2.1 Contain — the first moves

Run these from the affected host in this order. Each is a real, shipped command.

**1. Halt the agent mesh.**

```
sigil warden kill --reason "<incident id>"
sigil warden status
```

Engaging the kill switch is the *safe* direction and is honoured from any event, while **release
requires a valid owner signature and a strictly-fresh `issued_at`** — so an attacker who can append to
the ledger cannot un-halt it, and a replayed old release is refused
(`apps/sigil/sigil/governor/killswitch.py:1-19`; CLI at `apps/sigil/sigil/cli.py:330-340, 1468-1473`,
where `--reason` is recorded on the ledger).
Perception and memory-read stay alive by design; this is not a global process kill.

**2. Take the interfaces down — `vigil down` now contains a systemd-managed unit.**
<!-- CLAIM:W14-1-containment --> On a systemd-managed install, `vigil down` disables and cleanly stops
the `vigil-command` unit so `Restart=always` cannot revive the stack, and `vigil panic` additionally
masks the unit and disables the cadence sidecars (W10-5 #477, #478). The shipped
`infra/systemd/vigil-command.service` runs `vigil up` under `Restart=always` / `RestartSec=5`
(`infra/systemd/vigil-command.service:77-78`), so a *bare* pid-kill would be undone within ~5 seconds —
but `vigil down` no longer does a bare pid-kill. It runs `_contain_service_unit`, which
`systemctl --user disable`s the unit and issues a **clean** `stop` (a clean stop does not trigger
`Restart=`), before reaping the tracked backends and proxy
(`integration/vigil_integration/cli.py:2442` → `integration/vigil_integration/uiproxy.py:3403` →
`:2693`; the unit's own `ExecStop=vigil down` at `infra/systemd/vigil-command.service:69`). The
`StartLimit*` crash-loop caps live in `[Unit]`, where systemd reads them
(`infra/systemd/vigil-command.service:55-56`).

```
vigil down                 # contains: disables + cleanly stops a managed unit, then reaps backends + proxy
vigil services down        # stops the gateway container and root services
```

Containment is **conditional**, not a blind always-fire: if systemd does not know the unit (a `vigil up`
you started by hand, no user manager), no disable/stop/mask is issued and the pid-kill is the whole
containment. For an emergency **hard-stop** that additionally **masks** the unit (so even a manual
`systemctl --user start` is refused), trips every engagement's kill-switch, and disables the cadence
sidecars, use `vigil panic` (`integration/vigil_integration/cli.py:2493` →
`integration/vigil_integration/uiproxy.py:3426`); it stays masked until
`systemctl --user unmask vigil-command.service`. If you enabled linger for boot-without-login
(`loginctl enable-linger`, per the unit's install notes), also run `loginctl disable-linger "$USER"`.

**3. Close the remote paths.** The command UI unit was handled in step 2. Stop the remaining units you
deployed — the cockpit (`apps/sigil/deploy/systemd/sigil-cockpit.service`) and the phone bridge
(`apps/sigil/deploy/systemd/sigil-bridge@.service`), both **user** units on `Restart=on-failure` (a
clean stop holds — on-failure does not restart a clean stop — but `disable` keeps them down across a
reboot):

```
systemctl --user disable --now sigil-cockpit.service
systemctl --user disable --now sigil-bridge@<instance>.service   # each instance you enabled, e.g. sigil-bridge@10.13.13.1.service
```

Then bring down the tunnel itself (WireGuard/Tailscale) and any reverse proxy in front of it. VIGIL
never binds a public interface; remote reach exists only through a tunnel plus reverse proxy you
configured (`docs/DEPLOY.md`, "Hosting on a server you own"), so shutting the tunnel closes the path
even if a service is still running.

**4. Revoke every credential you can revoke locally.**

```
sigil accounts list
sigil accounts revoke <username>          # per-user account grant
sigil warden revoke <agent> --scope <scope>   # agent promotion grants (scope defaults to '*')
sigil mesh list-devices
sigil mesh revoke <device_id> <pubkey>    # phone/companion device keys
```

(`apps/sigil/sigil/cli.py:1480-1487, 1596-1602`; promotion revoke at `:344-346`.) Revocation is
honoured **even unsigned**, deliberately, so a fail-safe can never fail open
(`apps/sigil/sigil/governor/accounts.py:389-398, 459-460`), and the account fold is recomputed per
request, so a revoke takes effect immediately (`accounts.py:482-493`).

Two things to know while doing this:

- **Session bearer tokens have no expiry.** A leaked bearer stays valid until the account is revoked or
  re-minted (`apps/sigil/sigil/governor/accounts.py:366-387`;
  `apps/sigil/sigil/ui/server.py:129-142`). Revoke, do not wait it out.
- **The legacy embedded shared owner token is full owner authority** and always resolves to the owner
  principal (`apps/sigil/sigil/ui/server.py:129-138`). If it may have been exposed, treat the
  deployment's trust root as exposed (§2.4).

**5. Rotate provider credentials at the provider.** Any API key held by this host — Anthropic, GitHub,
ElevenLabs, cloud, Neo4j — must be revoked in the provider's own console. Replacing the local copy is
not revocation. Where they live locally: OS keyring, else sealed `~/.sigil/secrets.sealed`, else
plaintext `~/.sigil/sigil.env` (`apps/sigil/sigil/platform/secrets.py:1-19`).
Do **not** run `sigil settings check <NAME>` during containment — it live-probes the provider and
generates egress from a host you are trying to quiet.

**6. Stop model egress while you investigate.** If the tier was unset it was `PERMISSIVE` and prompt
content was eligible to leave (`ACCEPTABLE-USE.md`, Sovereignty tier, for which mechanism reaches which process). **Export it in the environment** every offense
process on this host inherits — the shell profile, the systemd unit, the container:

```
export CRUCIBLE_SOVEREIGNTY_TIER=AIR_GAPPED
export CRUCIBLE_SOVEREIGNTY_SEALED=1
```

**Do not rely on `~/.sigil/sigil.env` or the UI Settings screen for this.** The engine reads the tier
from the process environment and from nowhere else
(`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`); a value stored in that file reaches an
offense process only when `vigil up` launched it and injected the allowlisted variables
(`integration/vigil_integration/uiproxy.py:1631, 1712-1739`) — resolved at bring-up
(`:3122`) and re-resolved at each offense-plane restart (W10-2 #474, `:1026, 3210`), so a tier changed
in Settings reaches the offense children on the next offense-plane restart or a fresh `vigil up`, but
not a run already in flight. Anything else — `vigil engage` from a
shell, the engine CLI, a unit that does not export the variable — falls back to `PERMISSIVE`
**silently. This failure mode is fail-open**, which is exactly the wrong failure during containment.
Restart the running processes after exporting it, and confirm the result on the read-only tier pill on
the UI's Governance & Gate Audit screen (`#/governance`, `packages/vigil-ui/app.js:1803-1809`), which
reports the tier in force in the offense process serving the UI — and only in that process.

An unrecognised tier value fails closed to `AIR_GAPPED` rather than open
(`engine/crucible/framework/v2/kernel/sovereignty.py:186-191`), and the seal latches the tier for the
process lifetime so a later environment change cannot relax it (`:383-416`).

### 2.2 Preserve the signed ledger as evidence

**Do not run `sigil ingest --reset`.** It deletes the whole spine — data file, manifest, all segments,
trash — plus the cursor and the vector index (`apps/sigil/sigil/cli.py:20-33`;
`apps/sigil/sigil/spine/store.py:454-478`). In an incident it destroys your best evidence.

The ledger is designed for exactly this moment: hash-chained, owner-signed, keyless to verify
(`apps/sigil/sigil/spine/store.py:1-8`; `apps/sigil/sigil/spine/envelope.py:22-25`). Capture its state
**before** you change anything further:

```
sigil verify                      # sovereign spine chain + head
sigil floor status                # durable anti-rollback floor
vigil verify                      # offense spine segments, owner-tie aware
vigil verify-ledger               # usage-attestation ledger integrity
sigil doctor                      # vault sealing status, kernel pin, config drift
```

(`apps/sigil/sigil/cli.py:1515, 1547-1560`; `integration/vigil_integration/cli.py:1999-2018`;
`sigil doctor` reports vault status, kernel-binary pin and config drift at
`apps/sigil/sigil/cli.py:1059-1069`.)

Record the output verbatim, with timestamps, in the incident file. Then take a copy off the host:

```
VIGIL_BACKUP_PASSPHRASE=... vigil backup --out <path> --push <off-host destination>
```

The passphrase is read from an environment variable — `VIGIL_BACKUP_PASSPHRASE` by default, and never
passed on the command line (`integration/vigil_integration/cli.py:2484-2486`).

The two planes are backed up as **two separate encrypted files, never merged**
(`integration/vigil_integration/backup.py:36-40`); a push transports **ciphertext only**
(`tools/backup/transport.py:8-13`). Note that the sovereign part contains the owner private key and
the spine DEK sealed under a passphrase (`apps/sigil/sigil/backup.py:1-33`) — so where you put it
matters, and the passphrase is never stored: lose it and the backup is unrecoverable by design
(`:31-33`).

**Preserve the usage ledger together with its host-level anti-back-dating counter.** The monotonic
floor is persisted **host-level, outside the engagement base directory** (W10-3 #475), at
`~/.vigil/attestation/monotonic.counter` (`integration/vigil_integration/live/wiring.py:359`;
`integration/vigil_integration/attestation/anchor.py:48`). So a `rm -rf .vigil-live` destroys the
ledger but **not** the counter — which is the point: a base-dir reset cannot then re-attest under a
lower floor. Copy `<base_dir>/usage-ledger.jsonl` **and** `~/.vigil/attestation/` off-host, before any
cleanup, if they are to serve as evidence.

Two properties help an investigator, and are worth stating in the incident record:

- A **failed** `sigil verify` or a `ROLLBACK` report is itself a finding: the chain and the external
  floor are what make tampering visible (`apps/sigil/sigil/config.py:98-101`).
- The **usage-attestation ledger** is append-only and hash-chained, and its records carry a monotonic
  anti-back-dating counter whose floor is persisted **host-level** at
  `~/.vigil/attestation/monotonic.counter` — **outside** the engagement base directory
  (`integration/vigil_integration/live/wiring.py:359-360`;
  `integration/vigil_integration/attestation/anchor.py:48, 126-131`; read by the ledger writer at
  `integration/vigil_integration/attestation/ledger.py:186`). So a *truncation* of a still-present
  ledger is detectable (the floor stands above the surviving records), **and** a *deletion of the base
  directory* is survivable: `rm -rf .vigil-live` removes the ledger but the host counter remains, so a
  rollback cannot re-attest under a reset floor. The live wiring additively migrates any legacy in-base
  `attest-anchor.json` up into the host location without ever lowering it
  (`integration/vigil_integration/attestation/anchor.py:134`). Preserve `~/.vigil/attestation/`
  off-host **alongside** the ledger (see §2.2) before any cleanup.

### 2.3 Assess what was exposed

Work from `/PRIVACY.md` and `/DATA-GROUND-TRUTH.md` — they are the inventory. For a host-level compromise, assume the
attacker had whatever the host user had, then narrow with evidence.

| Ask | Where to look | What determines the answer |
|---|---|---|
| Was key material readable? | `sigil doctor` vault line | **If the vault was never provisioned, keys and spine payloads were plaintext at rest**, protected by `0600`/`0700` only (`packages/core/vigil_core/vigil_core/vault.py:73-75`; `apps/sigil/sigil/spine/envelope.py:101-104`). If it was provisioned, sealed blobs are bound to this machine's TPM and useless elsewhere (`packages/core/vigil_core/vigil_core/kek.py:1-17`) — but anything the running process could unseal, an attacker on that running host could too. |
| Whose personal data was on disk? | `targets/*/evidence/`, `targets/*/*.report.json`, `.vigil-live/chats/`, `.console/runs/` | Response bodies are stored **verbatim** (`engine/crucible/framework/v2/common/redact.py:17-22`). This is normally the most sensitive class, and it belongs to the client's users. |
| Which accounts existed? | `sigil accounts list`, and the ledger | Usernames, roles, credential hashes and salts, public keys are plaintext in the grant (`apps/sigil/sigil/governor/accounts.py:207-221`). TOTP secrets are AEAD-sealed; bearers are stored only as salted hashes; passwords only as scrypt hashes. |
| What left the machine, and when? | usage-attestation ledger, engagement audit logs, the egress controls in `ACCEPTABLE-USE.md` | The tier in force decides whether prompt content was eligible to reach a model provider. Check the tier that was actually set, not the one you intended. |
| What did the operator's assistant transcripts contain? | the spine, if `sigil ingest` was used | Assistant transcripts and git history are ingested into the append-only ledger (`apps/sigil/sigil/ingest/transcript.py:31-50`). |
| Which client deliverables are affected? | `<run-dir>/proof-bundle`, `<run-dir>/dossier.zip` | Copies already delivered are outside your control. |

Write the conclusion as three lists: **confirmed exposed**, **possibly exposed**, **ruled out — with
the evidence that rules it out**. Do not let "possibly" quietly become "no".

### 2.4 Rotation: what is shipped and what is not

Shipped and usable now:

| Action | Command |
|---|---|
| Revoke a user account | `sigil accounts revoke <username>` |
| Re-mint a user's bearer | `sigil accounts create <username> <role>` mints a fresh random bearer and prints it once; only its salted hash is stored (`apps/sigil/sigil/cli.py:415-420`). A proof-of-possession login likewise mints a fresh bearer rather than echoing a stored one (`apps/sigil/sigil/governor/accounts.py:366-387`) |
| Revoke an agent promotion | `sigil warden revoke <agent> --scope <scope>` |
| Revoke a device key | `sigil mesh revoke <device_id> <pubkey>` |
| Replace a provider secret | revoke at the provider, then store the new value through the settings surface / keyring |
| Provision at-rest sealing (if it was never done) | `sigil vault provision` — do this on the rebuilt host, not the compromised one |

**Not shipped: there is no owner-key rotation command.** The owner Ed25519 keypair is a 1-of-1 trust
root, generated once and thereafter only read; `ensure_owner_keypair()` generates only when the key is
absent (`apps/sigil/sigil/governor/identity.py:16-39, 68-80`). If the owner private key is exposed,
the honest position is:

- Everything that key signed remains verifiable **and** forgeable by whoever holds the copy. The
  ledger's tamper-evidence is relative to that key.
- Re-keying means standing up a new trust root on a clean host and treating the old ledger as a
  historical, no-longer-authoritative artifact — plus re-anchoring any external witness or client-held
  pin that referenced the old key.
- **This procedure is not shipped and is not verified here.** Plan it with counsel and with whoever
  holds your client-facing attestations before you need it; do not improvise it mid-incident.

The same applies to the offense-plane identity keys under `.vigil-live/`, which are plaintext at rest
unless the offense vault was provisioned (`integration/vigil_integration/live/wiring.py:288-302`).

### 2.5 Notification considerations

**Timelines and duties are jurisdiction-specific and this document does not state them.** Some regimes
measure a controller's breach-notification deadline in hours, others in days, others impose none; which
regime applies to you depends on where you are established, where your client is, whose personal data
was involved, and what you agreed contractually. That is a question for
`[COUNSEL / LEGAL CONTACT]`, and it is worth asking *before* an incident.

What to have ready, whatever the answer turns out to be:

1. **Tell the client early.** If evidence containing their systems' or users' data was exposed, the
   client is usually the party with the primary duty to its own users — and it cannot act on what it
   does not know. Your engagement contract may also set its own notice period, which can be shorter
   than any statutory one.
2. **A factual account, not a reassuring one.** What was on the host, what is confirmed exposed, what
   is possible, what is ruled out and why, when it started, when it was contained, what was done.
3. **The categories of personal data involved**, from `/DATA-GROUND-TRUTH.md` and `/PRIVACY.md` — distinguishing operator/user
   account data from target-derived data belonging to the client's users.
4. **Whether any third party received data** — under a permissive tier, prompt content may have gone to
   a model provider; that is a data flow to describe accurately, not to omit because it was routine.
5. **The honest retention position** from `DATA-RETENTION.md`: what you can delete, and what the
   append-only ledger and any delivered dossier mean for "make it go away".
6. **A dated, signed incident record.** Keep it even if you conclude no notification is required —
   the reasoning for *not* notifying is exactly what gets examined later.

Consider, and decide with counsel rather than by default: the client; the client's own users (usually
via the client); a supervisory authority, if one has jurisdiction; law enforcement; your insurer; and
any third party whose credentials or systems were reachable from the compromised host.

### 2.6 Post-incident review

Do it within `[N]` days, in writing, and keep it with the incident record.

- **Timeline** from first indicator to containment, with the evidence for each step.
- **What the mechanisms did.** Did the kill switch hold? Did `sigil verify` pass? Was the vault
  provisioned? Was the tier set? Each answer is either a control that worked or a gap with a name.
- **The gaps that were already known.** `/PRIVACY.md` (Honest limitations) lists the honest gaps — plaintext at rest
  without a TPM, unredacted response bodies, non-expiring bearers, the legacy owner token. If one of
  them was load-bearing in this incident, that is a decision to revisit, not a surprise.
- **What changes.** Provision the vault; export and seal a sovereignty tier in the environment those
  processes inherit; run sensitive engagements `--ephemeral` — which on this branch means running the
  CRUCIBLE engine CLI directly (`python3 -m framework.v2 engage … --ephemeral` from
  `engine/crucible/`, `engine/crucible/framework/v2/engage.py:1352`), since the flag is not available
  on `vigil engage` or in the UI; shorten the evidence retention in `DATA-RETENTION.md` §5; constrain
  what `sigil ingest` pulls into an append-only ledger.
- **What you told whom, and when.**

---

## 3. What to do if you are unsure whether it is an incident

Contain first, decide later. Halting the mesh and taking the UI down are cheap and reversible; a
release requires the owner key, so nothing un-halts behind your back
(`apps/sigil/sigil/governor/killswitch.py:1-19`). Losing an hour of availability is recoverable.
Losing the ledger, or letting an attacker keep a live session while you deliberate, is not.

---

## 4. Prepare now, so §2 works later

- Provision the vault (`sigil vault provision`) — otherwise §2.3's first row already has its worst
  answer.
- **Export** and seal a sovereignty tier in the environment every offense process inherits — not only
  in `~/.sigil/sigil.env` — so "what left the machine" is a bounded question (`ACCEPTABLE-USE.md`, Sovereignty tier).
- Take, push and **test** a backup, and store the passphrase where it cannot be lost with the host.
- Retain a witnessed checkpoint off-box (`sigil floor witness --retain <off-box path>`) so
  anti-rollback rests on external retention rather than on the compromised host
  (`apps/sigil/sigil/cli.py:1547-1560`).
- Decide the owner-key exposure procedure (§2.4) while nothing is on fire.
- Fill in §6.

---

## 5. Direction B — discovering a pre-existing compromise on a target

**Playbook:
[`engine/crucible/framework/playbooks/26-incident-response-pivot.md`](../../engine/crucible/framework/playbooks/26-incident-response-pivot.md).**
Follow it; this section is the pointer and the data-protection overlay, not a replacement.

The engagement transforms the moment you see signs that a real attacker is or has been in the client's
system — webshells in the webroot, modified core files, unknown admin accounts or API keys, suspicious
cron entries, egress to unknown hosts, or customer reports of unauthorized actions
(`26-incident-response-pivot.md`, "Trigger").

The playbook's first instruction is the important one: **stop offensive activity.** Stop sending
traffic — the intruder may be watching and your scans could tip them off. Tell the operator and the
client immediately, without "verifying a bit more". Switch to read-only, minimal-footprint,
forensic-aware posture and preserve what you found (`26-incident-response-pivot.md` §26.1-§26.2).

This is also a hard stop under the engagement constitution: evidence of prior compromise is one of the
named conditions to surface and pause on, alongside signs of degradation and access to real user PII
(`engine/crucible/CLAUDE.md:73-82`, "Hard stops"). Do not escalate the intruder's access to prove a
point; do not clean anything up; do not touch artifacts that a forensic investigator will want in
place.

Data-protection overlay specific to this direction:

1. **Document indicators, do not hoard data.** File paths, hashes, account names, IPs, timestamps —
   exactly as found. Capture the minimum needed to prove what you saw. Every extra byte of the client's
   user data you pull into `targets/<slug>/evidence/` is data you now hold, unredacted
   (`engine/crucible/framework/v2/common/redact.py:17-22`), under your retention schedule.
2. **Separate your footprint from theirs.** Your actions are logged, attested and signed — the
   usage-attestation ledger and the engagement audit log distinguish authorized testing from the
   intruder's activity (`integration/vigil_integration/attestation/models.py:60-82`). Hand that over;
   it is what keeps your traffic from being misread as the attack.
3. **The notification duty is most likely the client's**, since it is their system and their users —
   but your contract may impose an immediate-notice duty on you, and holding evidence of someone
   else's breach can carry its own obligations. Raise it with `[COUNSEL / LEGAL CONTACT]`; do not
   assume the answer either way.
4. **Agree evidence handling before you hand anything over.** Who holds the evidence, in what form,
   for how long, and who else may see it. A signed dossier is a durable artifact — decide deliberately
   what goes into one when it contains someone else's breach.
5. **Expect the engagement to pause.** The client may need to engage a DFIR firm, and the scope,
   authorization and timeline you were working under may no longer be the right ones. Re-authorize in
   writing before resuming.

---

## 6. Contacts and escalation — fill this in before you need it

| Role | Who | Reach |
|---|---|---|
| Incident lead (operator) | `[NAME]` | `[PHONE / EMAIL]` |
| Deputy, if the lead is unreachable | `[NAME]` | `[PHONE / EMAIL]` |
| Counsel / legal contact | `[NAME]` | `[PHONE / EMAIL]` |
| Client notification contact (per engagement) | `[IN THE ENGAGEMENT RECORD]` | `[…]` |
| DFIR provider, if retained | `[NAME]` | `[PHONE / EMAIL]` |
| Insurer / broker, if applicable | `[NAME]` | `[POLICY NO. / PHONE]` |
| Supervisory authority, if one has jurisdiction | `[AUTHORITY]` | `[CHANNEL]` |
| Hosting / tunnel provider | `[PROVIDER]` | `[SUPPORT CHANNEL]` |

Incident record location: `[PATH — off the affected host]`.

---

## 7. Verification record

- Verified against commit: `[COMMIT]`
- Date: `[DATE]`
- Verified by: `[NAME]`
