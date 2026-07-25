# Hosting the SIGIL control plane on a server you own

This is how you reach the SIGIL cockpit (and phone bridge) from outside the box —
including behind a **real domain on a web-hosted server** — **without ever
exposing a public listener**.

The one rule that shapes everything here:

> **The tunnel / reverse proxy is the network boundary — never the transport.**
> No SIGIL surface binds a public interface. Each one *fails closed* (`bind_ok`,
> exit 2) if you point it at `0.0.0.0` or a public address. You put TLS + a
> domain in front; the surface itself stays private.

---

## Threat model

**What we defend against**
- **The open internet finding the cockpit.** It is never bound to a public IP;
  it listens on loopback or a private WireGuard/Tailscale address only. The only
  thing on a public port is your reverse proxy, terminating TLS for your domain.
- **DNS rebinding / cross-origin drive-by.** The action plane requires the
  session token **and** an exact-match `Host` **and** `Origin` from an allowlist.
  Fronting it with a domain means adding that exact domain to the allowlist
  (`--allow-host` / `--allow-origin`); every other `Host`/`Origin` is refused.
- **Token/secret leakage to the browser.** The owner private key never enters the
  browser — the server signs actions. The session token is printed to the
  terminal/journal, not embedded anywhere a cross-origin page can read.
- **A compromised proxy host reading traffic.** Prefer co-locating the proxy on
  the same host as the cockpit and forwarding over loopback, so cleartext never
  crosses a network. If the proxy is on a different host, put the hop on
  WireGuard/Tailscale (the cockpit binds the tunnel IP).

**What this does NOT do**
- It does not make the offense engine reachable from the web. Offense stays in
  its own env behind the WARDEN gate; hosting is a *sovereign*-plane concern.
- It does not replace authn. The token + owner-signed action plane still gate
  every request; the proxy only carries TLS and the domain name.

---

## Topologies

### A. Co-located proxy (recommended, simplest, safest)

Proxy and cockpit on the **same host**; the proxy forwards to loopback.

```
Internet ──TLS──▶ Caddy/nginx (:443, cockpit.example.com) ──http──▶ 127.0.0.1:8733 (sigil serve)
                  └ terminates TLS, forwards Host: cockpit.example.com          └ loopback bind
```

Cleartext never leaves the box. The cockpit stays on loopback; you only add the
domain to its allowlist.

### B. Split proxy over a private tunnel

Proxy on a public web host, cockpit on a different machine, joined by
WireGuard/Tailscale. The cockpit binds its **tunnel** IP; the proxy dials it
over the tunnel.

```
Internet ──TLS──▶ nginx (public host) ──WireGuard──▶ 10.13.13.2:8733 (sigil serve --host 10.13.13.2)
```

`bind_ok` permits loopback, RFC1918 private, IPv6 ULA/link-local, and the
Tailscale CGNAT range (`100.64.0.0/10`) — never a globally-routable address. The
cockpit binds `AF_INET6` automatically when you give it an IPv6 literal, so a
Tailscale/WireGuard **IPv6** address (`fd7a:…`, `fd…`) works as well as its IPv4
one. Public IPv4 and IPv6 are refused before any socket is created (a public bind
is rejected by classification; even so, the guarantee rests on both the `bind_ok`
classification and the socket layer).

> **⚠ A private *interface* is not the same as a private *network*.** `bind_ok`
> only checks that the bind address is non-public. If you bind a LAN address
> (`192.168.x`, `10.x`) that your router **port-forwards** or that lives on an
> untrusted LAN, the cockpit is reachable from outside — still token+Origin/Host
> gated, but exposed. Prefer loopback + a co-located proxy (topology A) or a
> tunnel IP (topology B); do not port-forward the cockpit directly.

### C. Tunnel only, no domain

No public proxy at all — reach the cockpit over WireGuard/Tailscale and browse
`http://<tunnel-ip>:8733`. Bind the tunnel IP; no allowlist entry needed beyond
the bound address (it is added automatically).

---

## Step by step (topology A, a domain on a server you own)

1. **Run the cockpit privately, teaching it the domain** (added to the
   anti-rebind allowlist):

   ```bash
   SIGIL_UI_ALLOWED_HOSTS=cockpit.example.com \
   SIGIL_UI_ALLOWED_ORIGINS=https://cockpit.example.com \
   sigil serve --host 127.0.0.1 --port 8733
   # equivalently: sigil serve --host 127.0.0.1 --port 8733 \
   #   --allow-host cockpit.example.com --allow-origin https://cockpit.example.com
   ```

   As a managed service instead: install `deploy/systemd/sigil-cockpit.service`
   and `deploy/cockpit.env.example` → `~/.sigil/cockpit.env`, then
   `systemctl --user enable --now sigil-cockpit`. Read the token from the journal:
   `journalctl --user -u sigil-cockpit -n 5 --no-pager`.

2. **Point DNS** `A`/`AAAA` for `cockpit.example.com` at this host.

3. **Run the reverse proxy** (obtains + renews TLS automatically with Caddy):

   ```bash
   # Caddy
   cp deploy/reverse-proxy/Caddyfile /etc/caddy/Caddyfile   # edit the domain
   sudo systemctl reload caddy

   # …or nginx + certbot
   sudo certbot certonly --nginx -d cockpit.example.com
   cp deploy/reverse-proxy/cockpit.nginx.conf /etc/nginx/sites-available/cockpit
   sudo ln -s /etc/nginx/sites-available/cockpit /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```

4. **Open** `https://cockpit.example.com/?token=<printed-token>`.

The proxy must forward the **original** `Host` header (Caddy does by default;
the nginx template sets `proxy_set_header Host $host;`). That is what the
allowlist matches on. `/api/stream` (SSE) needs buffering disabled and a long
read timeout — both templates already do this.

---

## Configuration reference

| Setting | Env var | CLI flag | Default | Notes |
|---|---|---|---|---|
| Bind address | `SIGIL_UI_BIND` | `--host` | `127.0.0.1` | loopback or private/tunnel IP; public → **exit 2** |
| Port | — | `--port` | `8733` | |
| Allowed `Host`(s) | `SIGIL_UI_ALLOWED_HOSTS` | `--allow-host` (repeatable) | — | your domain(s), e.g. `cockpit.example.com`; comma-separated in the env var |
| Allowed `Origin`(s) | `SIGIL_UI_ALLOWED_ORIGINS` | `--allow-origin` (repeatable) | — | e.g. `https://cockpit.example.com`; trailing slash normalized |

The bound address (and, for a loopback bind, the `127.0.0.1`/`localhost` pair)
are **always** in the allowlist automatically; the env/flags add your domain(s).
Flags and env vars are **unioned**.

---

## The phone bridge (unchanged: WireGuard-direct)

The phone bridge already binds a `bind_ok` (WireGuard/Tailscale) address and pins
its self-signed TLS fingerprint on the phone — keep it **WG-direct**; do **not**
put it behind a public reverse proxy (that would break the pinned-fingerprint
trust model). See `deploy/systemd/sigil-bridge@.service`. If you must front it,
run it `--no-tls` on a private bind behind an upstream TLS proxy and set the
symmetric `SIGIL_BRIDGE_ALLOWED_*` — but WG-direct is the supported path.

## CRUCIBLE console / offense API

The CRUCIBLE read-only console and API stay **loopback-only**. Reach the console
over `ssh -L`; front the API with the same reverse-proxy pattern behind the
existing `CRUCIBLE_API_KEY` if you need it remotely. There is no public-bind path
for the offense plane by design.

---

## Checklist

- [ ] Cockpit bound to loopback or a private/tunnel IP (never `0.0.0.0`/public).
- [ ] Domain(s) added to `SIGIL_UI_ALLOWED_HOSTS` + `SIGIL_UI_ALLOWED_ORIGINS`.
- [ ] Reverse proxy terminates TLS and forwards the **original** `Host`.
- [ ] `/api/stream` proxied with buffering off + a long read timeout.
- [ ] Session token kept private (terminal/journal only).
- [ ] Phone bridge left WG-direct; offense plane left loopback.
