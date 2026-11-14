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
- `tools/deploy/edge-swap.sh customer|public` starts the new instance on the free port, waits for its
  `/healthz` (not `/readyz`, which is 503 while the cockpit restarts), waits `VIGIL_EDGE_SWAP_SETTLE_S` (3 s) with
  both edges up and checks the new one still runs and answers, then stops the old one and leaves the new instance
  enabled for boot. If the new edge does not answer within `VIGIL_EDGE_SWAP_HEALTH_S` (30 s), or stops answering
  during the settle, it is stopped and the old one keeps serving.

The Caddy examples (`*.Caddyfile`) name one port only, so behind Caddy do not swap: an edge moved to the second
port would never be reached. Restart the plain unit there instead (`systemctl --user restart
sigil-customer.service`), which leaves the edge unreachable for a few seconds.

## One-time setup

```
cp apps/sigil/deploy/systemd/sigil-customer@.service apps/sigil/deploy/systemd/sigil-public@.service \
   ~/.config/systemd/user/
systemctl --user daemon-reload
sudo nginx -t && sudo systemctl reload nginx        # after installing the current vhosts
tools/deploy/edge-swap.sh customer                  # moves sigil-customer.service to sigil-customer@8744
tools/deploy/edge-swap.sh public                    # moves sigil-public.service to sigil-public@8745
```

Run either the plain unit or the instances, never the plain unit and the first-port instance together. The
full upgrade (`RELEASE-UPGRADE-ROLLBACK.md` §2.4) records and stops the instances like every other unit.

## Swap an edge

```
tools/deploy/edge-swap.sh customer      # or: public
```

It prints `edge-swap: <old> -> <new>` and exits 0, or names what stopped it and exits 1 with the old edge still
serving. Open customer tabs see "A new version of VIGIL is available — Refresh" within ten minutes (sooner on
focus); the public site's pages are revalidated on every visit.

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
tools/deploy/edge-swap.sh public
curl -fsS https://app.vigilguard.net/version.json   # the new build id
```

Verify the tag exactly as for a full upgrade (`RELEASE-UPGRADE-ROLLBACK.md` §2.1). Nothing else is stopped,
migrated or backed up: no running process reads anything that changed except the new edges. To go back, check
out the previous release's commit and swap the same edges again.

## Cloudflare

The customer origin is never cached by Cloudflare (bypass rule, `AWS-DEPLOY.md` §3.5), so a swap reaches every
customer at once. The public site's pages may be held for up to 60 s (`s-maxage=60`); its versioned assets
never go stale, because a page names each asset by its content hash. A purge of the public pages is optional
(`AWS-DEPLOY.md` §3.6).
