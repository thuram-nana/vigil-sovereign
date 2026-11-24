"""AWS-DEPLOY.md §3 items 5-6 state the Cloudflare cache rules EXACTLY and the recommended purge safely:

* three cache rules, each on exact host names — the public site (vigilguard.net, www) eligible and respecting the
  origin's Cache-Control, the customer app (app.vigilguard.net) and the payment-webhook host (hooks.vigilguard.net)
  bypassed — and no rule expression anywhere that
  could also match the app (no wildcard, ends_with, contains, matches);
* the zone's Browser Cache TTL respects the origin, and no override TTL ever applies to the app;
* the cache headers the runbook quotes are the ones the edges send (read from their source);
* the purge — recommended after every release and public-site swap, because a page Cloudflare still holds names
  the previous build's ?v= assets, which the new edge answers 404 — uses a purge-only token scoped to the one zone,
  kept on the host (never GitHub), read from a 0600 header file, and purges the WHOLE zone cache: a hand-kept URL
  list misses most pages and every query-string variant, and the rules make the public site the only host the zone
  caches, so the whole-zone purge is exactly the public site;
* EDGE-SWAP.md names the tools, units and sections it relies on.

Stdlib only (reads files), so it rides the docs CI job.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AWS = (REPO / "docs" / "runbooks" / "AWS-DEPLOY.md").read_text(encoding="utf-8")
SWAP = (REPO / "docs" / "runbooks" / "EDGE-SWAP.md").read_text(encoding="utf-8")


def _section3() -> str:
    a = AWS.index("## 3. Point Namecheap at Cloudflare")
    return AWS[a: AWS.index("## 4.", a)]


def _item(n: int) -> str:
    s = _section3()
    a = s.index(f"\n{n}. **")
    nxt = s.find(f"\n{n + 1}. **", a)
    return s[a: nxt if nxt != -1 else s.index("\nVerify the chain", a)]


def _rules() -> dict:
    rows = re.findall(r"^\s*\| `(VIGIL [^`]+)` \| `([^`]+)` \| (.+?) \|\s*$", _item(5), re.M)
    return {name: (expr, then) for name, expr, then in rows}


def test_exactly_three_rules_on_exact_hosts():
    rules = _rules()
    assert set(rules) == {"VIGIL app — bypass", "VIGIL hooks — bypass", "VIGIL public site — cache"}
    expr, then = rules["VIGIL app — bypass"]
    assert expr == '(http.host eq "app.vigilguard.net")' and "**Bypass cache**" in then
    # the payment-webhook host is never cached either (its two POSTs must reach the origin every time)
    expr, then = rules["VIGIL hooks — bypass"]
    assert expr == '(http.host eq "hooks.vigilguard.net")' and "**Bypass cache**" in then
    expr, then = rules["VIGIL public site — cache"]
    assert expr == '(http.host in {"vigilguard.net" "www.vigilguard.net"})'
    assert "**Eligible for cache**" in then
    assert "**Use cache-control header if present, bypass cache if not**" in then
    assert "**Respect origin TTL**" in then
    assert "app." not in expr


def test_no_expression_anywhere_could_match_the_app_by_pattern():
    for expr, _then in _rules().values():
        assert not re.search(r"ends_with|contains|matches|wildcard|\*", expr), expr
    # the only place a wildcard or a substring match is named is the sentence that forbids it
    for m in re.finditer(r"\*\.vigilguard\.net|ends_with\(http\.host", AWS):
        line = AWS[AWS.rfind("\n", 0, m.start()) - 200: m.end()]
        assert "Never" in line, line


def test_the_browser_ttl_respects_the_origin_and_no_override_touches_the_app():
    five = _item(5)
    assert "Browser Cache TTL: Respect Existing Headers" in five
    assert 'Never set "Ignore cache-control header and use this TTL"' in five and "`app`" in five


def _const(path: str, name: str) -> str:
    m = re.search(rf'^{name} = "([^"]+)"', (REPO / path).read_text(encoding="utf-8"), re.M)
    assert m, (path, name)
    return m.group(1)


def test_the_quoted_headers_are_the_ones_the_edges_send():
    five = re.sub(r"\s+", " ", _item(5))
    page = _const("apps/sigil/sigil/ui/pubui.py", "_PAGE_CACHE")
    immutable = _const("apps/sigil/sigil/ui/static_site.py", "IMMUTABLE")
    app_page = _const("apps/sigil/sigil/ui/custui.py", "_APP_PAGE_CACHE")
    assert f"`{page}`" in five                            # the public pages
    assert f"`{immutable}`" in five
    assert f"`{app_page}` + ETag" in five
    assert "`no-store`" in five


def test_the_recommended_purge_is_zone_scoped_purge_only_and_kept_on_the_host():
    six = _item(6)
    assert "**Recommended — purge the public pages after every release and every public-site swap.**" in six
    flat = re.sub(r"\s+", " ", six)
    assert "previous build's `?v=<hash>` assets" in flat and "404 + `no-store`" in flat   # why: unstyled pages
    assert "optional" not in six.lower()
    assert "**Zone → Cache Purge → Purge**" in six and "Specific zone → vigilguard.net" in six
    assert "never in GitHub secrets or Actions" in six and "on the host only" in six
    assert "install -m 600 /dev/null ~/.sigil/cloudflare-purge.header" in six
    assert "read -rs CF_TOKEN" in six                     # never typed into the shell history
    assert '-H @"$HOME/.sigil/cloudflare-purge.header"' in six
    assert "app.vigilguard.net" not in six                # the app is never cached, so never purged


def test_the_purge_covers_every_public_page_not_a_hand_kept_list():
    # A list of URLs left most pages stale (/privacy, every /vs/..., /cve/<id>, /blog/..., any ?utm_ variant, which
    # Cloudflare keys separately) loading without their styles and scripts for up to 60 s after a release.
    six = _item(6)
    commands = re.findall(r"--data '([^']*)'", six)
    assert commands[0] == '{"purge_everything":true}', commands
    assert '"files"' not in six and '"prefixes"' not in six
    flat = re.sub(r"\s+", " ", six)
    assert "This purges exactly the public site" in flat and "query-string variant" in flat
    # ... which is exact only because the public site is the one host the zone caches:
    rules = _rules()
    eligible = [expr for expr, then in rules.values() if "**Eligible for cache**" in then]
    assert eligible == ['(http.host in {"vigilguard.net" "www.vigilguard.net"})']
    assert "**Bypass cache**" in rules["VIGIL app — bypass"][1]
    assert "| A | `console` | — | **OMIT — no public record** |" in _section3()
    # and the www name only redirects, with no Cache-Control (the cache rule bypasses a response without one)
    conf = (REPO / "apps/sigil/deploy/reverse-proxy/vigil-public.nginx.conf").read_text(encoding="utf-8")
    www = conf[conf.index("server_name www.vigilguard.net;"):]
    www = www[: www.index("\n}")]
    assert "return 301 https://vigilguard.net$request_uri;" in www and "Cache-Control" not in www


def test_the_edge_swap_runbook_names_what_it_relies_on():
    for needle in ("tools/deploy/edge-swap.sh customer", "tools/deploy/edge_only.py", "sigil-customer@8734",
                   "sigil-public@8745", "VIGIL_EDGE_SWAP_SETTLE_S", "max_fails=0", "/healthz",
                   "RELEASE-UPGRADE-ROLLBACK.md` §2.1", "`AWS-DEPLOY.md` §3.5", "`AWS-DEPLOY.md` §3.6"):
        assert needle in SWAP, needle
    # a public swap is followed by the purge, and the runbook says what happens without it
    assert "tools/deploy/edge-swap.sh public                    # then purge the public pages" in SWAP
    flat = re.sub(r"\s+", " ", SWAP)
    assert "without its styles and scripts" in flat and "never go stale" not in flat
    for rel in ("tools/deploy/edge-swap.sh", "tools/deploy/edge_only.py",
                "apps/sigil/deploy/systemd/sigil-customer@.service", "apps/sigil/deploy/systemd/sigil-public@.service"):
        assert (REPO / rel).is_file(), rel
    # every setting the swap script reads (the proxy URLs are required) is one the runbook tells the operator about
    settings = set(re.findall(r"VIGIL_EDGE_SWAP_[A-Z_]+", (REPO / "tools/deploy/edge-swap.sh").read_text("utf-8")))
    assert {"VIGIL_EDGE_SWAP_CUSTOMER_URL", "VIGIL_EDGE_SWAP_PUBLIC_URL"} <= settings
    assert not {s for s in settings if s not in SWAP}, settings
    assert "Cache Rules" in _item(5) and "purge" in _item(6).lower()   # §3.5 / §3.6 are those items
