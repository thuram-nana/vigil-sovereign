"use strict";
/* ==========================================================================
   VIGIL COMMAND — ui.js : the no-build, CSP-native micro-kit.
   No framework, no eval/new Function, no inline handlers. Everything is built
   with createElement / textContent / addEventListener. Shared by both planes.
   Exposed on window.VUI.
   ========================================================================== */
(function () {
  // -- h(): hyperscript. h('div.card#x', {onClick, dataset,...}, [children]) --
  function h(tag, props, children) {
    let tagName = "div", id = null; const classes = [];
    const m = String(tag).match(/^([a-zA-Z0-9]+)?([.#][^\s]*)?$/);
    if (m) {
      tagName = m[1] || "div";
      const rest = tag.slice((m[1] || "").length);
      rest.split(/(?=[.#])/).forEach(function (t) {
        if (t[0] === ".") classes.push(t.slice(1));
        else if (t[0] === "#") id = t.slice(1);
      });
    }
    const el = document.createElement(tagName);
    if (id) el.id = id;
    if (classes.length) el.className = classes.join(" ");
    props = props || {};
    for (const k in props) {
      const v = props[k];
      if (v == null || v === false) continue;
      if (k === "class") el.className = (el.className ? el.className + " " : "") + v;
      else if (k === "text") el.textContent = v;
      else if (k === "html") el.innerHTML = v; // caller guarantees static/trusted (icons only)
      else if (k === "dataset") { for (const d in v) el.dataset[d] = v[d]; }
      else if (k === "style" && typeof v === "object") { for (const s in v) el.style[s] = v[s]; }
      else if (k.slice(0, 2) === "on" && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === "for") el.htmlFor = v;
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, v);
    }
    append(el, children);
    return el;
  }
  function append(el, children) {
    if (children == null) return;
    if (Array.isArray(children)) children.forEach(function (c) { append(el, c); });
    else if (children instanceof Node) el.appendChild(children);
    else el.appendChild(document.createTextNode(String(children)));
  }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); return el; }
  function mount(el, node) { clear(el); append(el, node); return el; }
  function $(sel, root) { return (root || document).querySelector(sel); }

  // -- store(): a tiny observable state container -----------------------------
  function store(initial) {
    let state = initial || {}; const subs = new Set();
    return {
      get: function () { return state; },
      set: function (patch) { state = Object.assign({}, state, patch); subs.forEach(function (fn) { fn(state); }); },
      sub: function (fn) { subs.add(fn); return function () { subs.delete(fn); }; },
    };
  }

  // -- fetch helpers (federated, same-origin under one proxy) ------------------
  // Base paths are configured once at boot from window.VIGIL_CFG.
  function api() { return (window.VIGIL_CFG && window.VIGIL_CFG.api) || {}; }
  function token() { return (window.VIGIL_CFG && window.VIGIL_CFG.token) || ""; }
  function _headers(extra) {
    const hh = Object.assign({ "X-Requested-With": "vigil-ui" }, extra || {});
    if (token()) hh["X-SIGIL-Token"] = token();
    return hh;
  }
  async function getJSON(url) {
    const r = await fetch(url, { headers: _headers(), credentials: "same-origin" });
    if (!r.ok) throw new Error(r.status + " " + url);
    return r.json();
  }
  async function postJSON(url, body) {
    const r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: _headers({ "Content-Type": "application/json" }),
      body: JSON.stringify(body || {}),
    });
    const txt = await r.text();
    let data = null; try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = { raw: txt }; }
    if (!r.ok) { const err = new Error((data && data.error) || (r.status + " " + url)); err.status = r.status; err.data = data; throw err; }
    return data;
  }
  // SSE with query-param auth (EventSource can't set headers). onEvent(kind, data, id).
  function sse(url, onEvent, onError) {
    const sep = url.indexOf("?") === -1 ? "?" : "&";
    const full = token() ? url + sep + "token=" + encodeURIComponent(token()) : url;
    const es = new EventSource(full, { withCredentials: true });
    es.onmessage = function (e) { let d; try { d = JSON.parse(e.data); } catch (_) { d = e.data; } onEvent(d, e.lastEventId); };
    if (onError) es.onerror = onError;
    return es;
  }

  // -- toasts -----------------------------------------------------------------
  function toast(msg, isErr) {
    let host = $("#toasts"); if (!host) { host = h("div#toasts"); document.body.appendChild(host); }
    const t = h("div.toast" + (isErr ? ".err" : ""), null, msg);
    host.appendChild(t);
    setTimeout(function () { t.remove(); }, isErr ? 6000 : 3500);
  }

  // -- hash router ------------------------------------------------------------
  function router(routes, onChange) {
    function resolve() {
      const hash = (location.hash || "#/home").slice(1);
      const path = hash.split("?")[0];
      const route = routes[path] || routes[Object.keys(routes).find(function (r) { return path.indexOf(r) === 0 && r !== "/"; })] || routes["/home"];
      onChange(path, route, hash);
    }
    window.addEventListener("hashchange", resolve);
    return { start: resolve, go: function (p) { location.hash = p; } };
  }

  // -- small component builders (return DOM nodes) ----------------------------
  function pill(text, cls, dotColor) {
    return h("span.pill" + (cls ? "." + cls.split(" ").join(".") : ""), null,
      [dotColor ? h("span.dot", { style: { background: dotColor } }) : null, text]);
  }
  function statusBadge(state) {
    const s = String(state || "idle").toLowerCase();
    return h("span.st.st-" + s, null, [h("span.dot"), s]);
  }
  function tile(k, v, foot, footCls) {
    return h("div.tile", null, [h("div.k", null, k), h("div.v", null, v),
      foot ? h("div.foot" + (footCls ? "." + footCls : ""), null, foot) : null]);
  }
  function card(title, label, body, ownerPlane) {
    const head = (title || label) ? h("div.card-h", null,
      [label ? h("span.label", null, label) : null, title ? h("h3", null, title) : null]) : null;
    return h("div.card" + (ownerPlane ? ".owner" : ""), null, [head, body]);
  }
  function icon(name) {
    // inline stroke icons (static markup, no external fetch). 20x20 currentColor.
    const P = {
      home: "M3 11l9-8 9 8M5 10v10h14V10", assess: "M12 3v18M3 12h18",
      live: "M4 12a8 8 0 018-8m0 16a8 8 0 01-8-8M12 8a4 4 0 100 8 4 4 0 000-8z",
      find: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5", fixes: "M14 7l3 3-8 8H6v-3z M13 8l3 3",
      shield: "M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z", brain: "M9 4a3 3 0 00-3 3 3 3 0 00-1 5 3 3 0 001 5 3 3 0 006 0V4zM15 4a3 3 0 013 3 3 3 0 011 5 3 3 0 01-1 5 3 3 0 01-6 0",
      gear: "M12 9a3 3 0 100 6 3 3 0 000-6zM19 12l2-1-2-4-2 1-2-1V4h-4v3l-2 1-2-1-2 4 2 1v2l-2 1 2 4 2-1 2 1v3h4v-3l2-1 2 1 2-4-2-1z",
      key: "M14 7a4 4 0 11-4 4l-6 6v3h3l1-1v-2h2v-2h2l1-1", search: "M11 4a7 7 0 100 14 7 7 0 000-14zM21 21l-5-5",
      bolt: "M13 3L4 14h6l-1 7 9-11h-6z", check: "M4 12l5 5L20 6", x: "M6 6l12 12M18 6L6 18",
      dot: "M12 12m-3 0a3 3 0 106 0 3 3 0 10-6 0", play: "M6 4l14 8-14 8z",
    };
    return h("span.glyph", { html: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="' + (P[name] || P.dot) + '"/></svg>' });
  }

  window.VUI = { h: h, clear: clear, mount: mount, append: append, $: $, store: store,
    getJSON: getJSON, postJSON: postJSON, sse: sse, toast: toast, router: router,
    pill: pill, statusBadge: statusBadge, tile: tile, card: card, icon: icon, api: api, token: token };
})();
