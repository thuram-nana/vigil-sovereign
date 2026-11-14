# Runbook — the owner's instant switches (kill switch and customer latches)

These switches act on the running service at once: no restart, no deploy, no environment edit. Each is an
append-only record on the owner-signed spine, read fresh on every request.

| Switch | Turns OFF | Turns back ON |
|---|---|---|
| Kill switch | `sigil warden kill`, the phone's PANIC button, the cockpit | `sigil warden release` (owner-signed) |
| Customer latches | `sigil latch off <name>` or `sigil latch off all`, the phone's switch buttons | `sigil latch on <name>` (owner-signed, one at a time) |

## What each customer latch stops

A latch refuses only the **new** act. Everything already under way keeps working, so credits held for a launch
are never stranded and nothing half-made is left behind.

| Latch | Refused while OFF | Still open while OFF | Environment ceiling |
|---|---|---|---|
| `customer_launch` | a new launch reservation | start, cancel, pause, resume and settle of an existing launch | — |
| `customer_signup` | a new sign-up request, a new sign-up confirmation, a first Google sign-in | logging in; finishing a sign-up whose account already exists | — |
| `checkout` | a new hosted checkout | payments already made (their webhooks still credit) | `VIGIL_CUSTOMER_CHECKOUT_ENABLED` |
| `trial` | the trial credit of a new sign-up (the sign-up itself still completes), a new trial scan | a trial already granted | `VIGIL_TRIAL_CREDITS` |
| `founder_tester` | the founder tester role for a new sign-up, where the deployment offers that role | existing memberships | `VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED` |

The environment setting stays the **ceiling**: a latch can only narrow what the environment allows. With the
checkout setting off, checkout stays off whatever the latch says.

The **kill switch** also refuses a new launch reservation and the start of a reserved launch (nothing is written
to the seam); cancel, pause, resume and settle stay open.

## Guarantees

- **No record means ON.** An upgrade changes nothing until you switch something off.
- **OFF is instant and needs no key.** It takes effect on the next request. The phone records it without any
  private key (the bridge holds none): the phone's request is authenticated by its device signature, bound to
  the endpoint, fresh, and replay-gated by its nonce, exactly like PANIC.
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

1. Stop new business first: `sigil latch off all` (or the phone's ALL OFF button).
2. If the service itself must stop, `vigil panic` (see [PANIC-AND-CONTAINMENT.md](PANIC-AND-CONTAINMENT.md)).
3. When it is safe, turn each latch back on with `sigil latch on <name>` and confirm with `sigil latch status`.
