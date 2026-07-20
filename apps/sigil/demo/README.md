# SIGIL Phone Companion — demo & walkthrough

The companion turns your phone into a **signed remote-control + approval + gesture surface** over
WireGuard. The engine stays on your PC; the phone holds only its **own** Ed25519 device key — your owner
trust-root never leaves the desktop. The desktop **verifies** every request; it never signs on the
phone's behalf.

## 1. Runnable demo (no phone, no tunnel needed)

```bash
~/.sigil/venv/bin/python demo/companion_demo.py
```

Stands up the **real `BridgeServer`** on `127.0.0.1` (loopback ≙ the WireGuard tunnel) and drives it as a
phone would — a Python "phone" signs each request with its own key. It walks the whole flow with real
Ed25519 crypto and every real gate:

1. **Pair** — the phone shows its pubkey + a human fingerprint; the owner authorizes it once (owner-signed).
2. **Approve** a queued A2 action — the phone signs the approval; the desktop only verifies; the item clears.
3. **Relay** a natural-language command through the WARDEN-gated KERNEL (stubbed offline in the demo).
4. **Recall** — "where did I last see X?" answered from your own grounded, verbatim on-screen OCR history.
5. **Arm** a gesture session (the device-signed remote arm — the reviewed trust-widening): the desktop
   *records* the signed request; the gesture daemon *re-verifies* (auth · freshness · replay ·
   single-session · TTL ≤ 300 s) and actually arms.
6. **Panic** — any engage halts fail-safe; the armed session injects nothing on its next frame. (Release
   stays owner-only at the desktop — the dangerous direction is signed.)

It uses a throwaway `SIGIL_HOME`, so it never touches your real `~/.sigil`.

## 2. Real WireGuard (or Tailscale) walkthrough

**a. Bring up a tunnel** between the PC and the phone (either works):
- **WireGuard**: peer the phone and PC; the PC gets e.g. `10.13.13.1`, the phone `10.13.13.2`.
- **Tailscale**: both join your tailnet; the PC gets a `100.64.0.0/10` CGNAT address (now accepted by `bind_ok`).

**b. Serve the bridge, bound to the tunnel IP** (never `0.0.0.0`/public — the CLI and the server both refuse it):

```bash
sigil bridge serve --addr 10.13.13.1        # or your Tailscale IP
# prints:  https://10.13.13.1:8734
#          TLS fingerprint: AB:CD:…        <- pin this once on the phone
#          authorize this phone: sigil mesh authorize <id> <pubkey>
```

`bridge serve` mints an owner-pinned self-signed TLS cert for that IP (stable across restarts) so the PWA
gets a secure context (needed to install + register the service worker). `--no-tls` runs plain HTTP
(degraded: no install/offline).

**c. Open the PWA on the phone**: browse to `https://10.13.13.1:8734/`, accept the cert whose fingerprint
matches what `bridge serve` printed, and **Add to Home Screen**. On first run it generates its device key
in-browser (WebCrypto Ed25519, non-extractable) and shows its **pubkey + fingerprint**.

**d. Pair it** (on the PC), confirming the fingerprint matches what the phone shows:

```bash
sigil mesh authorize phone-1 <pubkey-from-the-phone>
# recomputes + prints the same fingerprint; type y to confirm
sigil mesh list-devices          # shows the authorized device
# sigil mesh revoke phone-1 <pubkey>   # to remove it later
```

**e. Use it** from the phone: approve/deny queued A2·A3 items, **panic**-halt, relay a command, view the
provenance-first read-only cockpit + live push feed, recall, and (opt-in) **arm a gesture session** and
use the phone as a remote trackpad (it streams hand landmarks; the PC pipeline drives the pointer, bounded
to A1 pointer moves — `type`/`launch` always queue for a separate approval).

## Security envelope (what holds over the tunnel)

- The phone holds **only its own key**; the owner trust-root never leaves the PC; server verifies, phone signs.
- Transport binds **`bind_ok` only** (loopback / WireGuard-private / Tailscale CGNAT) — never `0.0.0.0`/public.
- **No wire bearer secret** — auth *is* a per-request Ed25519 signature; anti-DNS-rebind Host/Origin gate;
  authorized-device set recomputed per request so a `revoke` takes effect immediately.
- A remote gesture is at most an **A1 pointer** move in a live, TTL-bounded session; `type`/`launch`
  **always queue**; the owner's disarm / panic / revoke always wins.
