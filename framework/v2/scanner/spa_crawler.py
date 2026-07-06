"""
scanner.spa_crawler — CDP-driven crawling of a modern JavaScript application.

The static crawler (``scanner.crawler``) parses the HTML the server sent; the
one-shot browser crawler (``scanner.browser_crawler``) parses a post-load DOM
*snapshot*. Neither sees what a single-page app actually *does*: the API calls it
fires from JavaScript, the routes its client-side router owns, the markup it hides
behind shadow-DOM boundaries. Those live only in a running page — so this crawler
drives a real one, over the CDP driver (``scanner.cdp``).

Four things it recovers that a static pass cannot:

  * **The endpoints the app calls.** Before navigation it wraps ``window.fetch``
    and ``XMLHttpRequest.prototype.open`` (installed as an *init script*, so the
    hook is in place BEFORE the page's own load-time requests run) and reports
    each call through a CDP binding. The result is the app's live API surface —
    the ``/api/...`` calls that never appear in the served HTML — ready to hand to
    the audit engine.
  * **Client-side routes.** Every same-origin ``<a href>`` the rendered app
    exposes, including links a router built at runtime.
  * **Shadow-DOM content.** A recursive walker descends every open ``shadowRoot``,
    so links and forms encapsulated inside web components are discovered, not
    missed the way ``document.querySelectorAll`` alone would miss them.
  * **The framework.** React / Angular / Vue / Svelte / Next / Nuxt / Preact /
    Ember / Backbone, identified from window globals and DOM markers — so the rest
    of the engine can scope which library-specific checks are worth running.

Pure-stdlib + the CDP driver; no third-party browser-automation dep. Drives the
browser only to operator-authorised URLs (loopback in tests). If no browser is
present the caller cannot construct a :class:`~framework.v2.scanner.cdp.CdpBrowser`
and simply skips the dynamic path — a browser check never guesses.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, Field

from .cdp import CdpBrowser, CdpError, CdpSession

# The binding the fetch/XHR hook calls. Only the driver registers it, so every
# call is an app-initiated request the hook observed — not a fabricated one.
_NET_BINDING = "__crucible_net"

# Frameworks detect_framework can name (plus "none"). A value outside this set is
# never returned — the detector fails closed to "none".
_FRAMEWORKS = frozenset({
    "react", "angular", "vue", "svelte", "next",
    "nuxt", "preact", "ember", "backbone", "none",
})


# ---------------------------------------------------------------------------
# result models
# ---------------------------------------------------------------------------


class SpaEndpoint(BaseModel):
    """One request the running app made — the ``method`` and the ``url`` exactly as
    the app passed it to ``fetch``/``XMLHttpRequest.open`` (so it may be relative,
    e.g. ``/api/items``; resolve against the page URL if an absolute form is
    needed). Deduplicated by ``(method, url)`` across the crawl."""

    model_config = ConfigDict(extra="forbid")

    method: str
    url: str


class SpaCrawlResult(BaseModel):
    """What a dynamic crawl of one SPA recovered: the framework, the live API
    surface, the client-side routes and form targets (shadow DOM included), and the
    number of shadow hosts pierced."""

    model_config = ConfigDict(extra="forbid")

    url: str
    framework: str = "none"
    endpoints: list[SpaEndpoint] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    forms: list[str] = Field(default_factory=list)
    shadow_hosts: int = 0


# ---------------------------------------------------------------------------
# injected JavaScript
# ---------------------------------------------------------------------------

# Installed via add_init_script, so it runs in EVERY new document BEFORE the page's
# own scripts — the app therefore captures our wrapped fetch/XHR, and any request
# it fires at load time is reported. The report is fire-and-forget: it happens at
# call/open time (before the response), so a request is captured even if the server
# 404s or the fetch rejects. Every access is guarded — the hook must never perturb
# the app it is observing.
_NET_HOOK = """
(function () {
  try {
    var report = function (method, url) {
      try {
        if (typeof window.__BINDING__ === 'function' && url) {
          window.__BINDING__(JSON.stringify({
            method: String(method || 'GET').toUpperCase(),
            url: String(url)
          }));
        }
      } catch (e) {}
    };
    var origFetch = window.fetch;
    if (typeof origFetch === 'function') {
      window.fetch = function (input, init) {
        try {
          var url = (typeof input === 'string') ? input
                    : (input && input.url) || '';
          var method = (init && init.method)
                    || (input && input.method) || 'GET';
          report(method, url);
        } catch (e) {}
        return origFetch.apply(this, arguments);
      };
    }
    if (window.XMLHttpRequest && XMLHttpRequest.prototype) {
      var origOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url) {
        try { report(method, url); } catch (e) {}
        return origOpen.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
""".replace("__BINDING__", _NET_BINDING)

# Recursively collects same-origin routes and form targets, descending into every
# open shadow root (document.querySelectorAll does NOT pierce shadow boundaries, so
# the explicit shadowRoot recursion is what surfaces web-component content). Returns
# a JSON string: {routes, forms, shadow_hosts}. Routes are kept same-origin only;
# forms keep the path when same-origin, else the absolute URL. Non-HTTP(S) schemes
# (javascript:, mailto:, ...) are dropped so they never pollute the surface.
_DOM_WALKER = """
(function () {
  var routes = [], forms = [], shadowHosts = 0;
  function classify(raw) {
    try {
      var u = new URL(raw, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      return {
        same: u.origin === location.origin,
        path: u.pathname + u.search + u.hash,
        href: u.href
      };
    } catch (e) { return null; }
  }
  function walk(root) {
    var nodes;
    try { nodes = root.querySelectorAll('*'); } catch (e) { return; }
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var tag = (el.tagName || '').toLowerCase();
      if (tag === 'a' && el.getAttribute('href') !== null) {
        var c = classify(el.href);
        if (c && c.same) routes.push(c.path);
      } else if (tag === 'form') {
        var cf = classify(el.action);
        if (cf) forms.push(cf.same ? cf.path : cf.href);
      }
      if (el.shadowRoot) { shadowHosts++; walk(el.shadowRoot); }
    }
  }
  function uniq(a) {
    var seen = {}, out = [];
    for (var i = 0; i < a.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(seen, a[i])) {
        seen[a[i]] = 1; out.push(a[i]);
      }
    }
    return out;
  }
  try { walk(document); } catch (e) {}
  return JSON.stringify({
    routes: uniq(routes), forms: uniq(forms), shadow_hosts: shadowHosts
  });
})()
"""

# First strong signal wins. Meta-frameworks (Next, Nuxt) are tested before the base
# library they build on (React, Vue) so the more specific name is returned. Cheap
# global / attribute markers first; a bounded per-element scan for framework
# instance keys (React fibers, Vue/Svelte instances, Vue [data-v-] scoping) only if
# nothing cheaper matched.
_DETECT_JS = """
(function () {
  try {
    var w = window, d = document;
    if (w.__NEXT_DATA__) return 'next';
    if (w.__NUXT__ || w.$nuxt) return 'nuxt';
    if (w.ng || w.angular || d.querySelector('[ng-version]')) return 'angular';
    if (w.React || w.__REACT_DEVTOOLS_GLOBAL_HOOK__
        || d.querySelector('[data-reactroot]')) return 'react';
    if (w.preact || w.__PREACT_DEVTOOLS__) return 'preact';
    if (w.Vue || d.querySelector('[data-v-app]')) return 'vue';
    if (w.__svelte) return 'svelte';
    if (w.Ember || d.querySelector('.ember-view')) return 'ember';
    if (w.Backbone) return 'backbone';
    var nodes = d.querySelectorAll('*');
    var n = Math.min(nodes.length, 400);
    for (var i = 0; i < n; i++) {
      var el = nodes[i];
      if (el.__vue__ || el.__vue_app__) return 'vue';
      var keys = Object.keys(el);
      for (var j = 0; j < keys.length; j++) {
        var k = keys[j];
        if (k.indexOf('__reactFiber') === 0
            || k.indexOf('__reactInternalInstance') === 0) return 'react';
        if (k.indexOf('__svelte') === 0) return 'svelte';
      }
      if (el.attributes) {
        for (var a = 0; a < el.attributes.length; a++) {
          if (el.attributes[a].name.indexOf('data-v-') === 0) return 'vue';
        }
      }
    }
    return 'none';
  } catch (e) { return 'none'; }
})()
"""


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def detect_framework(sess: CdpSession) -> str:
    """Name the front-end framework the page is built with, from window globals and
    DOM markers — one of the values in :data:`_FRAMEWORKS`. Fails closed to
    ``"none"`` (unknown page, or the probe could not run)."""
    try:
        value = sess.evaluate(_DETECT_JS)
    except CdpError:
        return "none"
    value = str(value or "none")
    return value if value in _FRAMEWORKS else "none"


def crawl_spa(
    url: str,
    *,
    browser: CdpBrowser | None = None,
    settle: float = 1.0,
    max_routes: int = 10,
) -> SpaCrawlResult:
    """Crawl the single-page app at ``url`` in a real headless browser and return
    its live surface: framework, app-initiated endpoints, client-side routes, form
    targets (shadow DOM included), and shadow-host count.

    The fetch/XHR hook is installed as an init script and the reporting binding is
    registered *before* navigation, so the app's own load-time requests are
    captured. After the page settles, up to ``max_routes`` in-app hash routes are
    driven (``location.hash``) to surface endpoints that only fire on navigation;
    the walk stops early once routes stop yielding new requests, so it never loops.

    A shared ``browser`` may be passed to amortise launch cost; otherwise one is
    started and torn down here. Raises :class:`CdpError` only if no browser is
    available."""
    own = browser is None
    br = browser or CdpBrowser().start()
    try:
        sess = br.session()
        # Order matters: the binding and the fetch/XHR hook must both be in place
        # before navigate(), so the app's load-time requests are wrapped and
        # reported. add_binding survives navigation; add_init_script runs in the
        # new document before the page's own scripts.
        sess.add_binding(_NET_BINDING)
        sess.add_init_script(_NET_HOOK)
        sess.navigate(url, settle=settle)
        # A late, post-load fetch/XHR may still be in flight — give the binding
        # calls a moment to surface before we read them.
        sess.drain_events(timeout=0.3)

        endpoints = _collect_endpoints(sess)
        routes, forms, shadow_hosts = _collect_dom(sess)
        framework = detect_framework(sess)

        if max_routes > 0 and routes:
            _follow_hash_routes(sess, routes, max_routes)
            # binding_calls accumulates since navigate, so re-reading picks up any
            # requests the route changes triggered.
            endpoints = _collect_endpoints(sess)

        return SpaCrawlResult(
            url=url,
            framework=framework,
            endpoints=endpoints,
            routes=routes,
            forms=forms,
            shadow_hosts=shadow_hosts,
        )
    finally:
        if own:
            br.stop()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _collect_endpoints(sess: CdpSession) -> list[SpaEndpoint]:
    """Parse the hook's binding calls into deduplicated ``(method, url)`` endpoints,
    dropping anything malformed or empty."""
    seen: set[tuple[str, str]] = set()
    out: list[SpaEndpoint] = []
    for payload in sess.binding_calls(_NET_BINDING):
        try:
            obj = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        method = str(obj.get("method", "GET")).upper() or "GET"
        endpoint_url = str(obj.get("url", ""))
        if not endpoint_url:
            continue
        key = (method, endpoint_url)
        if key in seen:
            continue
        seen.add(key)
        out.append(SpaEndpoint(method=method, url=endpoint_url))
    return out


def _collect_dom(sess: CdpSession) -> tuple[list[str], list[str], int]:
    """Run the shadow-piercing DOM walker; return ``(routes, forms, shadow_hosts)``.
    Failures degrade to empties rather than crashing the crawl."""
    try:
        raw = sess.evaluate(_DOM_WALKER)
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (CdpError, ValueError, TypeError):
        data = None
    if not isinstance(data, dict):
        return [], [], 0
    routes = [str(r) for r in data.get("routes", []) if r]
    forms = [str(f) for f in data.get("forms", []) if f]
    try:
        shadow_hosts = int(data.get("shadow_hosts", 0) or 0)
    except (ValueError, TypeError):
        shadow_hosts = 0
    return routes, forms, shadow_hosts


def _follow_hash_routes(sess: CdpSession, routes: list[str], max_routes: int) -> None:
    """Drive up to ``max_routes`` distinct in-app *hash* routes via ``location.hash``
    to surface endpoints that only fire on client-side navigation.

    Only hash routes are followed — a path route would be a full navigation that
    could leave the app or 404. The walk stops after three consecutive routes yield
    no new binding calls, so a router that ignores unknown fragments cannot make it
    spin."""
    fragments: list[str] = []
    for route in routes:
        idx = route.find("#")
        if 0 <= idx < len(route) - 1:
            frag = route[idx:]  # keep the leading '#'
            if frag not in fragments:
                fragments.append(frag)

    followed = 0
    stale = 0
    prev = len(sess.binding_calls(_NET_BINDING))
    for frag in fragments:
        if followed >= max_routes or stale >= 3:
            break
        try:
            sess.evaluate("location.hash = " + json.dumps(frag) + "; void 0")
            sess.drain_events(timeout=0.3)
        except CdpError:
            continue
        followed += 1
        now = len(sess.binding_calls(_NET_BINDING))
        stale = stale + 1 if now == prev else 0
        prev = now
