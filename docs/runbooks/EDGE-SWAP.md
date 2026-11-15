# Edge swap and the edge-only fast path

The customer edge (`custui`, app.vigilguard.net) and the public site (`pubui`, vigilguard.net) can be replaced
by a new process without dropping a request, and a release that changes only their static files can be
delivered by that swap alone — no full upgrade, nothing else restarted.

## How it works

- Each edge runs as a systemd user instance named after its loopback port:
  `sigil-customer@8734` / `sigil-customer@8744`, `sigil-public@8735` / `sigil-public@8745`
  (`apps/sigil/deploy/systemd/sigil-{customer,public}@.service`; same env file, drain and hardening as the
  plain units).
- The shipped nginx vhosts (`apps/sigil/deploy/reverse-proxy/vigil-{customer,public}.nginx.conf`) name both
  ports in one `upstream`: nginx tries the first port for every request and the second (`backup`) when the first
  does not take the connection. A request moves to the other port only when it could not be delivered, or — for
  a GET — when the connection broke before an answer. A POST that reached an edge is never sent again. Both
  servers carry `max_fails=0`: nginx never marks a port unavailable, so a request an edge drops costs that one
  request, never the next seconds of traffic.
- An edge reads its whole tree once at startup and serves those bytes until it stops (`ui/static_site.py`), so a
  checkout under a running edge changes nothing it serves; the new process serves the new files.
- A new edge accepts connections only once it has read its files; until then its port refuses them and nginx
  keeps using the old edge, so a new edge that fails at startup drops nothing.
- A stopping edge (SIGTERM, `ui/graceful.py`) serves every connection it accepted, including the ones still waiting
  in its listen queue, then closes. On Linux it first stops taking new connection attempts; such an attempt is
  refused about a second later and nginx gives it to the other port before any byte of the request was sent, so
  this holds for a POST too.
- It exits only once every request it accepted is answered, waiting up to its drain deadline. The customer edge
  waits up to 75 s, longer than its slowest call to the cockpit (60 s, a sign-up or recovery email sent inline;
  45 s, a checkout or a Google sign-in), so an action the cockpit is still completing reaches the customer as the
  cockpit's own answer — never as the unavailable page for an email that was sent, a checkout that was created or
  a sign-in code that was spent. The public site serves only files and waits up to 10 s. Stopping the old
  customer edge therefore takes up to 75 s while such an action is in flight; its units allow 90 s
  (`TimeoutStopSec`). Units installed by an older release may allow less (20 s); the swap reads the stop timeout
  systemd will apply to every unit it stops or leaves running (`systemctl --user show -p TimeoutStopUSec`) and,
  below the edge's drain + 6 s (81 s for the customer edge, 16 s for the public site), changes nothing and names
  the units to re-install (`RELEASE-UPGRADE-ROLLBACK.md` §2.6). `vigil doctor` reports such a unit too.
- `tools/deploy/edge-swap.sh customer|public` moves the edge in hops, out to the second port and back to the
  first, so the edge always comes to rest on the FIRST port. There nginx's first try succeeds; on the second port
  alone, every request would first meet the refused first port, and nginx would log a `connect() failed (111:
  Connection refused)` line per request (and spend one of its two tries on it). Those lines appear only in the
  seconds between the two hops of a swap. A swap that stopped half way leaves the edge on the second port; the
  next run moves it to the first in one hop.
- Each hop starts the new instance on the free port, waits for its `/healthz` (not `/readyz`, which is 503 while
  the cockpit restarts), waits `VIGIL_EDGE_SWAP_SETTLE_S` (3 s) with both edges up and checks the new one still
  runs and answers, then stops the old one and leaves the new instance enabled for boot. If the new edge does not
  answer within `VIGIL_EDGE_SWAP_HEALTH_S` (30 s), or stops answering during the settle, it is stopped and the old
  one keeps serving.
- The script checks the reverse proxy itself, through the address it serves the edge at
  (`VIGIL_EDGE_SWAP_CUSTOMER_URL` / `VIGIL_EDGE_SWAP_PUBLIC_URL`, required): before the first hop
  `<url>/version.json` must name the build of the edge running now (so a wrong URL changes nothing), and after
  each hop the build of the new edge. If the proxy does not reach the new edge — a vhost that still names one port,
  or a Caddyfile — the script moves the edge back to the port the proxy reached and exits 1. Nothing stays
  unreachable, but on such a proxy every request gets the unavailable page from the moment the old edge stops
  taking connections until it exits: as long as its slowest action still in flight, at most 75 s for the customer
  edge (10 s for the public site), as in a restart.

The Caddy examples (`*.Caddyfile`) name one port only, so behind Caddy do not swap: the swap would find that Caddy
does not reach the second port, move the edge back and exit 1. Restart the plain unit there instead
(`systemctl --user restart sigil-customer.service`). That leaves the edge unreachable until the old edge has
answered what it accepted and the new one is up: a few seconds when nothing slow is in flight, and up to the
slowest action in flight — at most 75 s for the customer edge (a sign-up email sent inline) — when one is.

## One-time setup

```
cp apps/sigil/deploy/systemd/sigil-customer@.service apps/sigil/deploy/systemd/sigil-public@.service \
   ~/.config/systemd/user/
systemctl --user daemon-reload
sudo nginx -t && sudo systemctl reload nginx        # after installing the current vhosts (both ports upstream)
export VIGIL_EDGE_SWAP_CUSTOMER_URL=https://app.vigilguard.net
export VIGIL_EDGE_SWAP_PUBLIC_URL=https://vigilguard.net
tools/deploy/edge-swap.sh customer                  # moves sigil-customer.service to sigil-customer@8734
tools/deploy/edge-swap.sh public                    # moves sigil-public.service to sigil-public@8735
```

The two `export` lines belong in the deploy user's shell profile, so every later swap has them. Run either the
plain unit or the instances, never the plain unit and the first-port instance together. The full upgrade
(`RELEASE-UPGRADE-ROLLBACK.md` §2.4) records and stops the instances like every other unit, and installs each
release's version of the units (§2.6). On a host set up before the customer edge's longer drain, install the
current `sigil-customer.service` and `sigil-public.service` the same way before the first swap (the `cp` above
covers the template units only); the swap refuses until every unit allows the drain.

## Swap an edge

```
tools/deploy/edge-swap.sh customer      # or: public
```

It prints `edge-swap: <old> -> <new>` for each hop and `edge-swap: done — …` and exits 0, or names what stopped it
and exits 1 with an edge serving where the proxy reaches it. It takes about ten seconds, longer while the old
customer edge finishes a slow action (up to 75 s per hop). Open customer tabs see "A new version of VIGIL is available — Refresh" within ten minutes (sooner on
focus). After a swap of the public site, purge its pages at Cloudflare (`AWS-DEPLOY.md` §3.6) — see Cloudflare
below for what happens without it.

## The edge-only fast path

Use it when a release changes nothing but files the edges serve
(`apps/sigil/sigil/ui/customer_app/`, `apps/sigil/sigil/ui/public_site/`) and files no running process reads
(`VERSION`, `CHANGELOG.md`, `packages/vigil-brand/`, `tests/` directories). Anything else — Python code, the
console kit, `docs/` (some of it is read at run time), units, configuration — takes the full upgrade.

```
cd ~/vigil
git fetch origin --tags
TAG=vX.Y.Z
git merge-base --is-ancestor "$TAG^{commit}" origin/main && echo "$TAG is on main"
SHA="$(git rev-parse "$TAG^{commit}")"
python3 tools/deploy/edge_only.py HEAD "$SHA"       # exit 0 prints the edges to swap; 1 = full upgrade
git checkout --detach "$SHA"                        # only served static files and inert files change on disk
tools/deploy/edge-swap.sh customer                  # each edge the check printed
tools/deploy/edge-swap.sh public                    # then purge the public pages (AWS-DEPLOY.md §3.6)
curl -fsS https://app.vigilguard.net/version.json   # the new build id
```

Verify the tag exactly as for a full upgrade (`RELEASE-UPGRADE-ROLLBACK.md` §2.1). Nothing else is stopped,
migrated or backed up: no running process reads anything that changed except the new edges. To go back, check
out the previous release's commit and swap the same edges again.

## Cloudflare

The customer origin is never cached by Cloudflare (bypass rule, `AWS-DEPLOY.md` §3.5), so a swap reaches every
customer at once. The public site's pages may be held for up to 60 s (`s-maxage=60`), and a held page names the
previous build's `?v=` assets, which the new edge answers with 404 + `no-store` (it never serves today's bytes
under another build's name). So at a Cloudflare location that still holds an old page but not its assets, that
page loads without its styles and scripts until it expires — up to 60 s. Purging the public pages right after
the swap (`AWS-DEPLOY.md` §3.6) closes that window to the seconds before the purge lands.
