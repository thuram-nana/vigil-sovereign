# GO-LIVE quickstart

The exact, ordered command sequence that takes VIGIL from a fresh host to **charging real
customers** — the turnkey companion to `hosting-and-persistence.md` (the *why* behind each gate),
`REMOTE-HOSTING.md` (the never-public-bind topology), `anchor-trust-root-out-of-band.md` (the owner-key
ceremony), `snapshot-down-migration.md`, and `egress-posture.md`.

Every step is **fail-closed**: nothing charges money or runs against a real customer target until the
two deliberate owner switches at the very end (§10–§11). Work top to bottom; do not skip §0 or §9–§11.

### Conventions

- `sigil …` = the **sovereign** CLI (`apps/sigil`, holds the owner key). `vigil …` = the **operator /
  integration** CLI (control surface: `up`, `doctor`, `engage`, `panic`).
- Ports (all bound **loopback/private**, fronted by TLS vhosts): `8735` pubui · `8734` custui ·
  `8733` cockpit+provisioner (`sigil serve`) · `8770` operator console (`vigil up`).
- `$SIGIL_HOME` defaults to `~/.sigil`. Examples assume the venv at `~/.sigil/venv` (the systemd units'
  convention); adjust to your layout.

---

## 0. Host prerequisites (you provide these — VIGIL cannot)

- A Linux host (systemd user services used below; root not required).
- A **durable, backed-up block volume** for `$SIGIL_HOME` — the owner-signed spine is the one
  irreplaceable asset (see hosting runbook §1, §3).
- **DNS** for your three origins, e.g. `vigil.example.com` (public), `app.vigil.example.com`
  (customer), `console.vigil.example.com` (operator — keep private/SSO/VPN).
- A **Flutterwave merchant account** with API keys and the payment-plan ids you will bind in §8–§9.
- A **cloud KMS/HSM** to seal the owner key in production (§3).

---

## 1. Install & build the planes

```bash
git clone <your-fork> ~/vigil && cd ~/vigil    # the units run the checkout at ~/vigil (%h/vigil)
./bootstrap.sh          # the hash-locked venvs (.venv-sovereign, .venv-offense) + the WARDEN kernel,
                        # and the link ~/.sigil/venv -> .venv-sovereign that every sigil unit runs
# Confirm the CLIs resolve:
~/.sigil/venv/bin/sigil --help >/dev/null && echo "sigil ok"
vigil doctor            # operator readiness: binaries, both venvs, writable dirs, UI ports, docker
```

Run `./bootstrap.sh` before §2 and with `SIGIL_HOME` unset, so the link lands at `~/.sigil/venv`, the path
the units execute. Install nothing into `~/.sigil/venv` by hand: `envs/build_envs.sh` (which bootstrap runs)
installs every dependency from hash-pinned requirements, and `vigil doctor` reports a `~/.sigil/venv` that is
not the symlink to a built `.venv-sovereign` as a hard issue.

`vigil doctor` exits non-zero on a hard prerequisite gap — clear those first.

## 2. Put `$SIGIL_HOME` on the durable volume

```bash
export SIGIL_HOME=/mnt/vigil-data/.sigil      # a durable, replicated volume — NOT instance storage
mkdir -p "$SIGIL_HOME"
```

Persist `SIGIL_HOME` in each unit's env file (`~/.sigil/cockpit.env`, `customer.env`, `public.env`, and
`~/.config/vigil/billing-drain.env` once you run the billing drain — §9).

## 3. Owner key + vault seal (the single most important secret)

The owner Ed25519 key lives **only** in the cockpit/provisioner process (`sigil serve`), never in the
edges or the offense plane (FATAL-2). Run the out-of-band genesis ceremony first
(`anchor-trust-root-out-of-band.md`), then **seal** the trust root at rest:

```bash
sigil key status            # confirm the owner key exists and is the pinned root
sigil vault provision       # seal the trust-root KEK (TPM/KMS-backed); dev file mode is local-only
sigil vault status          # must report SEALED in production
```

In cloud, back the seal with your KMS/HSM — **no plaintext owner key on disk** (hosting runbook §4).

## 4. Backups, a restore drill, and anti-rollback checkpoints

```bash
sigil backup /mnt/offbox/vigil-$(date +%F).enc          # passphrase-encrypted, OFF the spine dir
# Prove the backup restores + re-verifies (a backup you have not restored is not a backup):
sigil restore /mnt/offbox/vigil-YYYY-MM-DD.enc /tmp/restore-drill
SIGIL_HOME=/tmp/restore-drill sigil verify              # chain re-verifies + record counts match
rm -rf /tmp/restore-drill
```

Ship backups to object storage on a timer, and enable the in-product checkpoint cadence
(`sigil-checkpoint.timer` → `sigil checkpoint emit`). Keep ≥ 2 generations (hosting runbook §3).

## 5. (Optional) Populate the public CVE catalog

```bash
sigil cve ingest            # CISA-KEV exploited set (the one standing outbound path)
sigil cve ingest --epss     # + FIRST EPSS probability (optional)
sigil cve stats             # confirm it populated
```

## 6. Run the planes (hardened systemd **user** units)

Production runs each surface as its own process behind its own TLS origin (the same-origin `/customer`
mount on `vigil up` is a **dev-only** convenience). Units ship in `apps/sigil/deploy/systemd/`:

```bash
mkdir -p ~/.config/systemd/user
cp apps/sigil/deploy/systemd/sigil-{cockpit,customer,public,checkpoint}.* ~/.config/systemd/user/
cp apps/sigil/deploy/{cockpit,customer}.env.example ~/.sigil/ && \
  mv ~/.sigil/cockpit.env.example ~/.sigil/cockpit.env && \
  mv ~/.sigil/customer.env.example ~/.sigil/customer.env    # then EDIT both
```

In **both** `cockpit.env` and `customer.env`, set the **same** `VIGIL_PROVISION_HOP_KEY` (a long random
secret): it authenticates the keyless customer edge → cockpit/provisioner loopback hop. An empty hop key
fails signup/login **closed**. In `customer.env` also set `VIGIL_CUSTOMER_ALLOWED_HOSTS` /
`VIGIL_CUSTOMER_ALLOWED_ORIGINS` to your customer domain (the edge sets a cookie, so its anti-rebind +
CSRF gates must know the public host/origin).

```bash
systemctl --user daemon-reload
systemctl --user enable --now sigil-cockpit sigil-customer sigil-public sigil-checkpoint.timer
loginctl enable-linger "$USER"        # keep units up after logout
systemctl --user status sigil-cockpit sigil-customer sigil-public
```

The operator console (`vigil up`, :8770) is the control surface for ceremonies/engage/panic — keep it
**private** (SSO/VPN), never a public face. On this host the cockpit already runs as `sigil-cockpit` on
127.0.0.1:8733, so the console runs **proxy-only** in front of it: it starts no cockpit of its own and federates
`/sovereign/*` to the cockpit unit (a plain `vigil up` would start a second cockpit on the same port). Install
the console unit with its production drop-in:

```bash
cp infra/systemd/vigil-command.service ~/.config/systemd/user/
mkdir -p ~/.config/systemd/user/vigil-command.service.d
cp infra/systemd/vigil-command.service.d/production.conf ~/.config/systemd/user/vigil-command.service.d/
# ~/vigil/.vigil-live/service.env (plain KEY=VALUE, mode 0600): the console's hostname from §7 and the api key
# `vigil up --domain` requires. Add the same hostname to SIGIL_UI_ALLOWED_HOSTS / SIGIL_UI_ALLOWED_ORIGINS
# in ~/.sigil/cockpit.env.
#   VIGIL_CONSOLE_DOMAIN=console.vigil.example.com
#   CRUCIBLE_API_KEY=<a long random secret>
systemctl --user daemon-reload
systemctl --user enable --now vigil-command
vigil doctor            # reports a console that is not proxy-only beside the cockpit unit, as a hard issue
```

The drop-in runs `vigil up --proxy-only --sovereign-addr 127.0.0.1:8733`; if `cockpit.env` binds the cockpit
elsewhere, change `--sovereign-addr` to match (`vigil doctor` reports a mismatch). The console's `/offense/*`
screens federate to an offense console and API on this host (127.0.0.1:8787 / :8799) when you run them
(`docs/architecture/HA-PROFILE.md` §1.1). Do not also run a plain `vigil up` on this host.

**Settings every settling process must share.** `VIGIL_SETTLE_SPINE_RECORD` and the metered-settle pricing
(`VIGIL_BILLING_TARGET_MARGIN`, `VIGIL_RUN_FLOOR_CREDITS`, `VIGIL_BILLING_CANCEL_SETTLEMENT`) must hold the same
value in the cockpit, the customer edge, the settle drain and the shell that runs `sigil ops-sweep`. Set each
once in `$SIGIL_HOME/sigil.env` (every sigil process reads it beneath its own env file), or the same value in
`cockpit.env`, `customer.env` and `~/.config/vigil/settle-drain.env`. `vigil doctor` reads the env files the
installed units load and reports any disagreement as a hard issue.

## 7. Reverse proxy + TLS (three separate origins)

Each surface gets its own TLS vhost (templates in `apps/sigil/deploy/reverse-proxy/`), forwarding to the
loopback bind. Separate origins give the strongest cookie/CSRF isolation.

```
vigil.example.com         → vigil-public.nginx.conf   → 127.0.0.1:8735  (pubui; public)
app.vigil.example.com     → vigil-customer.nginx.conf  → 127.0.0.1:8734  (custui; tenant app)
console.vigil.example.com → vigil.nginx.conf           → 127.0.0.1:8770  (vigil up; keep private)
```

Edit each vhost's `server_name` + cert paths, obtain certs (`certbot certonly --nginx -d <host>`), then
`nginx -t && systemctl reload nginx`. Forward `Host`, `Origin`, `Referer` **unchanged** on the customer
vhost (done in the template) or its gates fail closed. Confirm every listener is loopback/private
(`ss -ltnp` shows nothing on the public interface except the proxy).

## 7b. Customer sign-in: email, Google, and the installed iPhone app

Everything below goes in the env files from §6; restart both units after a change
(`systemctl --user restart sigil-cockpit sigil-customer`). `vigil doctor` reads those files and reports a Google
setting that differs between the cockpit and the customer edge, a missing Google setting, or Google sign-in without
the installed-app hand-off (values are never printed).

**Email (sign-up confirmation and password reset).** In `cockpit.env` set `SIGIL_EMAIL_HOST`, `SIGIL_EMAIL_PORT`
(587, STARTTLS), `SIGIL_EMAIL_FROM`, `SIGIL_EMAIL_USER` and `SIGIL_EMAIL_PASSWORD` (the password from your secret
manager; never in `customer.env`, never in git). With `SIGIL_EMAIL_HOST` unset no email is sent at all, so nobody
can confirm a sign-up or reset a password. Amazon SES works well: verify the sending domain, add its DKIM CNAME
records in Cloudflare DNS with SPF and DMARC, and request production access before launch.

With `VIGIL_CUSTOMER_EMAIL_CODE=1` (the production example) each sign-up and reset email carries a **6-digit code**
beside the single-use token, so a person in the installed app types the code instead of following the email into
a browser. A code works once, for 10 minutes, for that address and that purpose only (a sign-up code is not a reset
code); its 5th wrong entry ends it, wrong codes are also limited per address across re-sent codes and per client
IP, and it is stored only as a salted hash. The token in the same email (valid 1 hour) keeps working.

**Google ("Continue with Google").** In Google Cloud console create an OAuth client of type *Web application* and
add the authorized redirect URI exactly `https://app.<your-domain>/api/customer/oidc/callback`. Set
`VIGIL_CUSTOMER_OIDC_ENABLED=1`, `VIGIL_CUSTOMER_OIDC_CLIENT_ID` and `VIGIL_CUSTOMER_OIDC_REDIRECT_URI` to the
**same** values in `cockpit.env` and `customer.env` (or once in `$SIGIL_HOME/sigil.env`), and
`VIGIL_CUSTOMER_OIDC_CLIENT_SECRET` in `cockpit.env` only — the customer edge never holds it. The sign-in and
sign-up screens show the button only while the switch is on and the client id and redirect URI are set (read when
the edge starts). A first Google sign-in creates a passwordless account for that Google identity; an address that
already has a password account is refused, never linked by email.

**Google inside the installed iPhone app.** `VIGIL_CUSTOMER_IOS_INSTALL_BANNER=1` (in `customer.env`) shows iPhone
and iPad visitors in the browser a guide to *Share → Add to Home Screen*; it disappears once the app runs from the
Home Screen and remembers a dismissal. An installed app runs standalone, and iOS finishes Google sign-in in a
separate browser with its own cookies, so with `VIGIL_CUSTOMER_OIDC_HANDOFF=1` (in `customer.env`) the app starts
the sign-in with a one-time challenge, the page where Google sign-in finished shows a 6-digit pairing code ("Only
enter it in the VIGIL app on this phone"), and the app exchanges its secret verifier plus that code for its own
session. The pairing code works once, for about 2 minutes; its 5th wrong entry ends it, and failed exchanges are
limited per client IP. Outside an installed app the normal browser sign-in is used.

Check on a real iPhone before announcing: open `https://app.<your-domain>` in Safari, follow the guide to add VIGIL
to the Home Screen, open it from there, tap *Continue with Google*, finish in the browser that opens, go back to
VIGIL and type the code — you are signed in inside the app. Then sign up a second address with the emailed 6-digit
code, and reset its password with the code from the reset email.

## 8. Pricing ↔ real Flutterwave plan-id binding (owner confirms)

The owner catalog (`apps/sigil/sigil/governor/catalog.py`) is the **sole money anchor** — no on-the-wire
amount decides money. Before go-live, confirm the three owner inputs (hosting runbook §8):

1. **COGS per credit** — price above your measured real cost/run for your target margin.
2. **Price coherence** — subscriptions must beat one-time top-ups per effective credit.
3. **Provider plan-id binding** — each subscription `price_id` must equal the **real Flutterwave
   payment_plan id** you create in your Flutterwave dashboard; each top-up `price_id` must be set as the
   checkout `meta.price_id`. VIGIL cannot mint these; `amount_minor` is the cross-check, not the charge.

A price change is an owner-reviewed commit + deploy (catalog validated fail-closed at import).

## 9. Flutterwave webhook drain + transaction verifier (payments; default-OFF)

`sigil billing-drain` ingests the inbound webhook spool, **server-side re-verifies** each transaction,
and mints only via the owner catalog. It is fail-closed and mints **nothing** until you provision the
real Flutterwave `/v3/transactions/{id}/verify` caller with your **secret key** — inject it via your KMS/
secret manager at the cockpit/provisioner only (never the repo, never a plaintext env var).

```bash
# In the cockpit env, with the secret injected by your secret manager:
export VIGIL_BILLING_DRAIN_ENABLED=1
export VIGIL_BILLING_WEBHOOK_SECRET=…        # from the secret manager, NOT committed
sigil billing-drain watch --spool "$SIGIL_HOME/billing-spool" --interval 2
```

To run it unattended, use the shipped `vigil-billing-drain` timer instead of `watch` (one pass every 60 s,
dead-man monitored). **Set `SIGIL_HOME` in `~/.config/vigil/billing-drain.env`** (§2) — always, even if you
never moved it: the drain never falls back to `~/.sigil`, and refuses (the unit goes FAILED) without it, when
`~/.sigil/cockpit.env` names a different `SIGIL_HOME`, or when that home holds no owner identity. The unit names
no spool: the drain derives this same `$SIGIL_HOME/billing-spool`, or drains the proxy's
`VIGIL_BILLING_WEBHOOK_SPOOL` when you copy that into the same env file — which you must do if the proxy spools
anywhere else (the drain cannot see the proxy's env); a spool that contradicts it is refused. Run the timer **or**
`watch`, never both — a per-spool lock serialises them: a timer pass that cannot get it within 120 s fails loudly,
and a `watch` that keeps finding it held warns on stderr every 120 s. See
`infra/systemd/vigil-billing-drain.service` for secret injection. Point your Flutterwave webhook at the
operator webhook ingress (see `REMOTE-HOSTING.md`). Until the verifier is provisioned, there is
**no live paid path** — by design.

## 9b. (Optional) Stripe instead of Flutterwave (default-OFF)

Stripe is a second processor with the same money rules: the proxy checks each delivery's `Stripe-Signature`
and spools it; the drain re-verifies that signature, **re-fetches** the Checkout Session / Invoice /
Subscription from Stripe with your key, and only then lets the owner catalog decide the credit. Nothing is
ever minted from the webhook body. Every setting below is default-OFF; secrets come from your secret manager.

1. **Stripe dashboard.** Create a **restricted** API key (read Checkout Sessions, Invoices, Subscriptions;
   write Checkout Sessions) and pin the API version you test against (one that accepts the Checkout Session
   `adaptive_pricing` setting: every session VIGIL creates turns it off). Turn **Adaptive Pricing off** in the
   Dashboard as well (the charge must be in the catalog currency). Stripe checkout charges only currencies whose
   Stripe minor unit is confirmed to match the catalog's (USD today), and a plan (subscription) checkout accepts
   card only. Add a webhook endpoint at `https://<operator ingress>/webhooks/stripe`
   subscribed to exactly: `checkout.session.completed`, `checkout.session.async_payment_succeeded`,
   `checkout.session.async_payment_failed`, `invoice.paid`, `invoice.payment_failed`.
2. **Proxy route.** Set `VIGIL_STRIPE_WEBHOOK_SPOOL` (e.g. `$SIGIL_HOME/stripe-billing-spool`) and
   `VIGIL_STRIPE_WEBHOOK_SECRET` (the endpoint's signing secret; it must differ from the Flutterwave one).
3. **Drain.** Install `infra/systemd/vigil-billing-drain-stripe.{service,timer}` with its env file:
   `VIGIL_STRIPE_BILLING_DRAIN_ENABLED=1`, `VIGIL_BILLING_ENABLE_STRIPE=1`, the same webhook secret,
   `VIGIL_STRIPE_SECRET_KEY` (the restricted key; its live/test prefix sets the mode) and
   `VIGIL_STRIPE_API_VERSION`. Its spool must equal the proxy's and must not be the Flutterwave spool. **Set
   `SIGIL_HOME` in `~/.config/vigil/billing-drain-stripe.env`** too, as for the Flutterwave drain (§9): the
   Stripe drain mints onto the same spine and refuses without it, when `~/.sigil/cockpit.env` names a different
   one, or when it holds no owner identity. Once `SIGIL_HOME` is moved, set `VIGIL_STRIPE_BILLING_SPOOL` to the
   proxy's spool: the drain refuses the unit's `~/.sigil` default then, and refuses any spool that contradicts a
   `VIGIL_STRIPE_WEBHOOK_SPOOL` copied into that env file. The same per-spool lock serialises passes. The
   webhook secret must be the proxy's exact value: a delivery the drain cannot verify is quarantined and the unit
   alarms (rotate both together). The Stripe drain always alarms on a paid charge it cannot credit.
4. **Prove it in test mode first**: a top-up purchase, a plan purchase, a renewal and a failed renewal (Stripe
   test clocks), each credited exactly once and visible in the tenant's billing history.
5. **Checkout.** Only then set `VIGIL_BILLING_PROVIDER=stripe` for the customer checkout (cockpit env), and
   finally swap in the live key and live endpoint secret. Enabling checkout before the drain would take payment
   with no credit.

`sigil ops-sweep tx-refs --provider stripe --spool <stripe spool> --checkouts <file>` reports Stripe checkouts
that never reached a drained webhook. Webhook-driven cancellation is not acted on: a cancelled plan expires at
the end of its paid period, as with Flutterwave.

## 10. The five production preconditions → `VIGIL_POSTURE=production`

With `VIGIL_POSTURE=production`, `vigil up` / `vigil engage` **refuse to start** unless **all five** hold
(each prints the failing control):

```bash
VIGIL_POSTURE=production vigil doctor      # and `sigil vault status`, `sigil status`
```

1. **vault SEALED** (§3) · 2. **sovereignty non-PERMISSIVE** · 3. **entitlement ACTIVE** ·
4. **backups ON** (§4) · 5. **charter PRESENT** (the signed engagement charter).

Only when `vigil doctor` is green under `VIGIL_POSTURE=production` do you start the planes in production
posture. Set `VIGIL_POSTURE=production` in each unit's env file.

## 11. The final switch — customer production execution (after acceptance)

`VIGIL_CUSTOMER_PROD_EXECUTION` is the hold that lets a paying customer run offense against their **own
verified** live target. Default OFF; `vigil up`/`engage` refuse a live customer arm while off
(loopback/staging proceed). **Flip it only after the K4-6 acceptance matrix is green for your
deployment** — a deliberate, separate owner act.

```bash
# Only after acceptance is green for YOUR deployment:
export VIGIL_CUSTOMER_PROD_EXECUTION=1
```

Billing (§9) and testing authority (owner-signed per-host `EngagementAuthority`) remain **independent**:
paying grants the product; only an owner-signed, ownership-proven authority grants testing. Neither flag
weakens that.

---

## 12. Post-launch verification (prove each origin + the chain)

```bash
curl -fsS https://vigil.example.com/            | grep -o '<title>[^<]*</title>'   # pubui landing
curl -fsS https://app.vigil.example.com/api/customer/whoami                         # {"authenticated": false}
curl -fsS https://vigil.example.com/api/cve?limit=1                                 # read-only CVE JSON
sigil verify            # the owner-signed spine chain re-verifies end-to-end
vigil verify-integrity  # chain + signed-head freshness + anti-rollback floor + clock skew
```

A real signup → Flutterwave checkout → verified webhook → credit grant → authorized assessment →
tenant report is the full acceptance drive (hosting runbook §7; the #25 capstone method).

## 13. Day-2 operations

| Need | Command |
|---|---|
| Stop everything fast | `vigil panic` / `vigil emergency-stop` |
| Kill one agent/engagement | `sigil warden kill <agent>` |
| Reconcile lapsed subscriptions → dunning | `vigil reconcile` |
| Sweep abandoned credit reservations (report) | `sigil ops-sweep reservations` |
| …and refund them (guarded) | `VIGIL_OPS_SWEEP_APPLY_ENABLED=1 sigil ops-sweep reservations --apply --completion-spool <dir>` |
| Schema upgrade (crash-safe, auto-rollback) | `sigil upgrade` (`--check` to dry-run) · down-path: `snapshot-down-migration.md` |
| Rotate backups / checkpoints | `sigil backup <dest>` · `sigil checkpoint emit` |
| HA failover (warm standby attaches the volume) | `sigil floor promote-passive --witnessed <off-box-checkpoint>` |

HA today = durable, replicated **storage** + a **warm standby** that attaches the volume; writes stay
single-host (hosting runbook §6).
