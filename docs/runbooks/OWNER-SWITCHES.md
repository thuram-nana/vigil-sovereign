# Runbook — the owner's instant switches (kill switch and customer latches)

These switches act on the running service at once: no restart, no deploy, no environment edit. Each is an
append-only record on the owner-signed spine, read fresh on every request.

| Switch | Turns OFF | Turns back ON |
|---|---|---|
| Kill switch | `sigil warden kill`, the phone's PANIC button, the cockpit | `sigil warden release` (owner-signed) |
| Customer latches | `sigil latch off <name>` or `sigil latch off all` (no key needed), the phone's switch buttons | `sigil latch on <name>` (owner-signed, one at a time) |

## Run `sigil latch` against the service's home

The switches are records on the spine under `SIGIL_HOME`, so `sigil latch` must run with the `SIGIL_HOME` the
units use. In the GO-LIVE layout that value lives only in the units' env files (`~/.sigil/cockpit.env`), so export
it first:

```bash
export SIGIL_HOME=/mnt/vigil-data/.sigil      # the SIGIL_HOME line of ~/.sigil/cockpit.env
```

`sigil latch` refuses (exit 2) and writes nothing anywhere when this shell's `SIGIL_HOME` is not the one
`sigil-cockpit.service` runs with, or when the home holds no owner identity or no spine. It never creates a key or
a spine. Every result prints the spine it read or wrote and its head seq: check it is the live one.

`sigil latch on` signs with the owner key, so the key must be usable in this shell too. On a host whose key is
sealed with a KMS KEK (AWS-DEPLOY), export the KEK settings the units use as well (`VIGIL_KEK_BACKEND=kms`,
`VIGIL_KMS_KEY_ID=...`); otherwise `on` refuses and switches nothing. `off` never needs the key.

## What each customer latch stops

A latch refuses only the **new** act. Everything already under way keeps working, so credits held for a launch
are never stranded and nothing half-made is left behind.

| Latch | Refused while OFF | Still open while OFF | Environment ceiling |
|---|---|---|---|
| `customer_launch` | a new launch reservation | start, cancel, pause, resume and settle of an existing launch | — |
| `customer_signup` | a new sign-up request, a new sign-up confirmation, a first Google sign-in | logging in; finishing a sign-up whose account already exists | — |
| `checkout` | a new hosted checkout | payments already made (their webhooks still credit) | `VIGIL_CUSTOMER_CHECKOUT_ENABLED` |
| `trial` | the trial credit of a new sign-up (the sign-up itself still completes), a new trial scan | a trial already granted | `VIGIL_TRIAL_CREDITS` |
| `founder_tester` | the founder tester role for a new sign-up: the sign-up still completes, its founding member an org admin (no self-serve testing) | existing founders keep testing; to withdraw it from them too, set `VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED=0` and restart the cockpit, or `sigil org demote-founders` | `VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED` (with `VIGIL_TRIAL_PREVIEW_ENABLED`) |

The environment setting stays the **ceiling**: a latch can only narrow what the environment allows. With the
checkout setting off, checkout stays off whatever the latch says. `sigil latch status` reads each ceiling from the
files `sigil-cockpit.service` loads (the customer provisioner runs in the cockpit), or from this shell's environment
when no cockpit unit is configured (and says which), and shows what the value means: an unset
`VIGIL_CUSTOMER_CHECKOUT_ENABLED` is off, an unset `VIGIL_TRIAL_CREDITS` is the default trial of 100 credits (on).

The **kill switch** also refuses a new launch reservation and the start of a reserved launch (nothing is written
to the seam); cancel, pause, resume and settle stay open. The customer is told only that new assessment launches are
paused; why (engaged, or a kill switch that could not be read) stays in the server log.

## Guarantees

- **No latch record means ON.** An upgrade switches no customer latch off.
- **The kill switch now also holds new customer launches.** A kill switch left engaged (a phone PANIC or a
  `sigil warden kill` drill that was never released) refuses every new customer launch and start from the release
  that wires it into the launch path. `sigil latch status`, `sigil status` and `sigil doctor` say so whenever it is
  engaged; check before upgrading (RELEASE-UPGRADE-ROLLBACK §2.2) and release it with `sigil warden release` once
  the incident is over.
- **OFF is instant and needs no key.** It takes effect on the next request. `sigil latch off` signs the record when
  the owner key is usable on this host and records it unsigned otherwise (a key kept off-box, a KEK the shell cannot
  reach) — it says which, and either way the latch is off. The phone records it without any private key (the
  bridge holds none): the phone's request is authenticated by its device signature, bound to the endpoint, fresh,
  and replay-gated by its nonce, exactly like PANIC.
- **ON needs your signature.** Only an owner-signed record turns a latch back on, and only if its `issued_at` is
  newer than every earlier ON for that latch: a captured ON replayed later, a forged ON, or an ON re-aimed at
  another latch never reopens it. There is no phone button for ON.
- **Only governor-written records count.** A latch or kill-switch record counts only when it has the shape the
  governor writes (`kind` `event`, `source` `governor`; a phone halt recorded earlier in the device shape stays a
  halt). No customer-facing write path appends a record of that shape (pinned by
  `apps/sigil/tests/test_latch_writer_shape.py`).
- **Fail-closed.** A spine that cannot be read answers OFF for every latch and refuses new launches when the kill
  switch cannot be read.
- **Prune-safe.** The latches ride the capability latch's snapshot fold, so an OFF and the anti-replay high-water
  survive a hard prune.

## Commands

```bash
export SIGIL_HOME=/mnt/vigil-data/.sigil   # the units' SIGIL_HOME (see above)
sigil latch status            # kill switch + every latch with its environment ceiling (--json for scripts)
sigil latch off checkout --reason "processor incident"
sigil latch off all --reason "stop new business now"
sigil latch on checkout --reason "processor back"      # owner-signed; one latch at a time
sigil status                  # one line: kill switch + any latch that is OFF
sigil doctor                  # advisory `switches` check (never fails the doctor: OFF is a choice)
```

On the phone, the Companion's **Customer switches** panel shows each latch's state and has one OFF button per
latch plus **ALL customer switches OFF**.

## In an incident

1. Stop new business first: export the units' `SIGIL_HOME`, then `sigil latch off all` (or the phone's ALL OFF
   button). Check the spine path it prints is the live one.
2. If the service itself must stop, `vigil panic` (see [PANIC-AND-CONTAINMENT.md](PANIC-AND-CONTAINMENT.md)).
3. When it is safe, turn each latch back on with `sigil latch on <name>` and confirm with `sigil latch status`.
