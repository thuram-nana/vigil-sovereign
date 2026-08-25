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
  // -- per-user session (Claim 6 RBAC) ---------------------------------------------------------------
  // The SAME X-SIGIL-Token carrier bears EITHER the embedded owner token (VIGIL_CFG.token, injected into
  // the page for the owner physically at the host) OR a per-user bearer a teammate logged in with, kept in
  // sessionStorage. A per-user bearer takes PRECEDENCE so a logged-in teammate acts as themselves; logout
  // clears it and falls back to the owner token if the page carries one. Because token() is the single
  // source both _headers() and authUrl() read, this reaches every fetch/SSE/download with no other change.
  var _SESSION_TOKEN_KEY = "vigil.session.token";
  var _principal = null;   // {authenticated, username, role, permissions} from /api/whoami or /api/login
  function _sessionToken() { try { return sessionStorage.getItem(_SESSION_TOKEN_KEY) || ""; } catch (e) { return ""; } }
  function token() { return _sessionToken() || (window.VIGIL_CFG && window.VIGIL_CFG.token) || ""; }
  function setSessionToken(t) {
    try { if (t) sessionStorage.setItem(_SESSION_TOKEN_KEY, t); else sessionStorage.removeItem(_SESSION_TOKEN_KEY); }
    catch (e) { /* storage disabled: the token still holds for this page load via the arg passed to callers */ }
  }
  function setPrincipal(p) { _principal = (p && p.authenticated) ? p : null; }
  function principal() { return _principal; }
  // can(perm): does the CURRENT principal carry `perm`? Owner carries all. Used for real nav/action gating.
  // Fail-closed: no principal (not yet loaded) → false, so an owner-only control never flashes before whoami.
  function can(perm) {
    return !!(_principal && _principal.permissions && _principal.permissions.indexOf(perm) >= 0);
  }
  function _headers(extra) {
    const hh = Object.assign({ "X-Requested-With": "vigil-ui" }, extra || {});
    if (token()) hh["X-SIGIL-Token"] = token();
    return hh;
  }
  async function getJSON(url) {
    // Symmetric with postJSON: on a non-2xx, carry the SERVER'S error body up to the caller
    // (message + .status + .data) instead of the old opaque "500 <url>". Read panels used to
    // catch this and render a generic "offline/empty" state, masking a real backend 4xx/5xx as
    // "plane down" — the single biggest source of silent-ish failures in the UI.
    const r = await fetch(url, { headers: _headers(), credentials: "same-origin" });
    const txt = await r.text();
    let data = null; try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = { raw: txt }; }
    if (!r.ok) {
      const err = new Error((data && data.error) || (r.status + " " + url));
      err.status = r.status; err.data = data; err.url = url;
      throw err;
    }
    return data;
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
  // -- chunked upload: a big file over the SAME small-JSON POST plane ----------------------------
  // The console refuses a POST body over 1 MiB (and an oversize body is read as `{}`, i.e. it fails
  // SILENTLY), so a zip can never be posted in one shot. This slices the File, base64s each slice and
  // posts each one as an ordinary JSON action through postJSON() — which is the point: postJSON uses
  // _headers(), so every chunk carries the custom request header the console requires (without it: 403)
  // and the token (without it: 401). Nothing here relaxes either, and no new content type is invented.
  //
  // Sizing: 512 KiB of raw bytes → ~700 KB of base64 → comfortably under the 1 MiB body cap with room
  // for the JSON envelope. The server may ask for SMALLER chunks (begin → `chunk_bytes`); it can never
  // talk us into a bigger one, because the cap that matters is the console's, not the response's.
  //
  // THE WIRE NAMES ARE THE CONSOLE'S, not this helper's own: `filename` on begin/finish and `b64` on
  // chunk are what `console.chat.attach_*` actually reads. A helper that invented its own (`name`,
  // `data`) does not fail loudly — the handler simply sees no filename and no payload, and the upload
  // dies as a generic refusal with nothing pointing at the cause. So they are written here, once.
  const UPLOAD_CHUNK_MAX = 512 * 1024;
  const UPLOAD_MAX_REQUESTS = 20000;     // a sane bound on round trips, so a silly chunk size fails LOUDLY

  function _b64(u8) {
    // btoa over a binary string built in 32 KiB windows — one apply() over a 512 KiB array would blow
    // the argument stack in several browsers.
    let s = ""; const W = 0x8000;
    for (let i = 0; i < u8.length; i += W) s += String.fromCharCode.apply(null, u8.subarray(i, i + W));
    return btoa(s);
  }
  function _blobBytes(blob) {
    if (blob.arrayBuffer) return blob.arrayBuffer().then(function (b) { return new Uint8Array(b); });
    return new Promise(function (res, rej) {                       // older engines: FileReader fallback
      const fr = new FileReader();
      fr.onload = function () { res(new Uint8Array(fr.result)); };
      fr.onerror = function () { rej(fr.error || new Error("could not read the file")); };
      fr.readAsArrayBuffer(blob);
    });
  }
  function _uploadErr(payload, fallback) {
    const e = new Error(String((payload && payload.error) || fallback));
    e.data = payload || null;
    return e;
  }
  // uploadChunked({begin, chunk, finish, abort?}, File, {fields, finishFields, onProgress, abortRef})
  //   → resolves with the FINISH payload (which may carry refusals the caller must show in full).
  //   onProgress(sentBytes, totalBytes, phase) is called at least once per chunk; phase is
  //   "begin" | "chunk" | "finish". `abortRef` is an object whose `.aborted` the caller may set.
  async function uploadChunked(routes, file, opts) {
    opts = opts || {};
    const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : function () {};
    const abortRef = opts.abortRef || {};
    const total = Number(file.size) || 0;
    onProgress(0, total, "begin");
    const started = await postJSON(routes.begin, Object.assign({
      filename: String(file.name || "file"), size: total, type: String(file.type || ""),
    }, opts.fields || {}));
    const uploadId = started && (started.upload_id || started.id);
    if (!started || started.error || !uploadId) throw _uploadErr(started, "the console did not open an upload");
    // The console MINTS the chat when the first file is dropped into a brand-new one, and tells us its
    // id in the begin response. Every later call in this sequence is scoped by that id, so carrying it
    // forward is what makes "drag a zip onto an empty chat" work at all: without it the chunks arrive
    // with no chat to belong to and the very first upload of every new chat 404s.
    const fields = Object.assign({}, opts.fields || {});
    (opts.carry || ["chat_id"]).forEach(function (k) {
      if (typeof started[k] === "string" && started[k]) fields[k] = started[k];
    });
    // The server's `chunk_bytes` is a MAXIMUM, so it is only ever clamped DOWN — sending a bigger chunk
    // than it asked for would be refused chunk-by-chunk. A value so small that the upload would need an
    // absurd number of round trips fails here, loudly, instead of hammering the console.
    const asked = Number(started.chunk_bytes || started.chunk_size);
    let size = asked > 0 ? Math.min(UPLOAD_CHUNK_MAX, Math.floor(asked)) : UPLOAD_CHUNK_MAX;
    if (!(size > 0)) size = UPLOAD_CHUNK_MAX;
    if (total / size > UPLOAD_MAX_REQUESTS) {
      throw new Error("the console asked for " + size + "-byte chunks, which would take "
        + Math.ceil(total / size) + " requests for this file — refusing");
    }

    // Cancelling TELLS THE SERVER. The staged bytes live in a `.part` sink on the operator's disk, so
    // walking away from an upload without saying so leaves them there until a sweep — the abort route
    // exists to make "I cancelled that" true on disk, not just on screen. Best effort: if the abort
    // itself fails the caller still learns the upload did not happen.
    async function giveUp(reason) {
      if (routes.abort) {
        try { await postJSON(routes.abort, Object.assign({ upload_id: uploadId }, fields)); }
        catch (e) { /* best effort — the sink is swept on a timer either way */ }
      }
      throw new Error(reason);
    }
    let sent = 0, seq = 0;
    while (sent < total) {
      if (abortRef.aborted) await giveUp("upload cancelled");
      const end = Math.min(sent + size, total);
      const bytes = await _blobBytes(file.slice(sent, end));
      const r = await postJSON(routes.chunk, Object.assign(
        { upload_id: uploadId, seq: seq, offset: sent, b64: _b64(bytes) }, fields));
      if (!r || r.error || r.ok === false) throw _uploadErr(r, "a chunk was refused");
      sent = end; seq += 1;
      onProgress(sent, total, "chunk");
    }
    onProgress(total, total, "finish");
    const fin = await postJSON(routes.finish, Object.assign({
      upload_id: uploadId, size: total, chunks: seq, filename: String(file.name || "file"),
    }, fields, opts.finishFields || {}));
    if (!fin) throw _uploadErr(null, "the console returned nothing for the finished upload");
    return fin;                      // may be {error, refusals:[…]} — a refusal is the caller's to render
  }

  // Query-param auth for the carriers that CANNOT set a request header: EventSource and a download
  // navigation (<a href download>). Both backends accept the token as `?token=` for exactly this,
  // so a credentialed console still streams events and still serves a dossier ZIP to a click.
  function authUrl(url) {
    if (!token()) return url;
    const sep = url.indexOf("?") === -1 ? "?" : "&";
    return url + sep + "token=" + encodeURIComponent(token());
  }
  // SSE with query-param auth (EventSource can't set headers). onEvent(kind, data, id).
  // sse() stays MINIMAL — it wires onError only when the caller passes one. A blanket default toast is
  // WRONG for streams that legitimately END (and then poll for completion) or are ambient/optional (the
  // SIGIL HUD): they would false-alarm on a clean close. Streams that SHOULD stay connected opt IN by
  // passing sseErrorToast(label) below.
  function sse(url, onEvent, onError) {
    const es = new EventSource(authUrl(url), { withCredentials: true });
    es.onmessage = function (e) { let d; try { d = JSON.parse(e.data); } catch (_) { d = e.data; } onEvent(d, e.lastEventId); };
    if (onError) es.onerror = onError;
    return es;
  }
  // Opt-in terminal-failure surface: pass as sse()'s 3rd arg for a stream that should stay connected.
  // Fires ONE toast only on a TERMINAL failure the browser will not retry (readyState === CLOSED);
  // transient reconnects (readyState === CONNECTING) stay silent. NOT a default — see the note above.
  function sseErrorToast(label) {
    return function (e) {
      const es = e && e.target;
      if (es && es.readyState === EventSource.CLOSED) {
        toast("Live stream disconnected" + (label ? " (" + label + ")" : "") + " — data may be stale", true);
      }
    };
  }

  // -- toasts -----------------------------------------------------------------
  function toast(msg, isErr) {
    let host = $("#toasts"); if (!host) { host = h("div#toasts"); document.body.appendChild(host); }
    const t = h("div.toast" + (isErr ? ".err" : ""), null, msg);
    host.appendChild(t);
    setTimeout(function () { t.remove(); }, isErr ? 6000 : 3500);
  }

  // -- persistent error banner (route-surviving) ------------------------------
  // Unlike a toast (auto-dismisses), a banner STAYS until dismissed — for a hard failure the
  // operator must see and act on. errorBanner(msg, detail?) mounts/updates a single #error-banner.
  function errorBanner(msg, detail) {
    let host = $("#error-banner");
    if (!host) { host = h("div#error-banner"); document.body.appendChild(host); }
    clear(host);
    host.appendChild(h("div.eb-row", null, [
      h("span.eb-ico", null, "!"),
      h("div.eb-msg", null, [
        h("strong", null, String(msg || "Something went wrong")),
        detail ? h("div.eb-detail", null, String(detail)) : null,
      ]),
      h("button.eb-x", { title: "dismiss", onClick: function () { host.remove(); } }, "×"),
    ]));
    return host;
  }
  function clearErrorBanner() { const b = $("#error-banner"); if (b) b.remove(); }

  // -- reusable percentage progress bar ---------------------------------------
  // progressBar({label?, pct?, className?}) → { el, set(pct,label), done(label), fail(msg) }.
  // set(pct=null) keeps the current width and only updates the label — an indeterminate step.
  function progressBar(opts) {
    opts = opts || {};
    const fill = h("div.pbar-fill");
    const pctlbl = h("span.pbar-pct", null, "0%");
    const label = h("span.pbar-label", null, opts.label || "");
    const track = h("div.pbar-track", null, fill);
    const el = h("div.pbar" + (opts.className ? "." + opts.className : ""), null, [
      h("div.pbar-head", null, [label, pctlbl]), track,
    ]);
    function set(pct, lbl) {
      if (pct != null && isFinite(Number(pct))) {
        const p = Math.max(0, Math.min(100, Number(pct)));
        fill.style.width = p + "%";
        pctlbl.textContent = Math.round(p) + "%";
        el.classList.remove("pbar-err");   // a REAL progress update clears a prior error; a label-only
      }                                    // (indeterminate) set must NOT wipe an existing error state.
      if (lbl != null) label.textContent = String(lbl);
    }
    function done(lbl) { set(100, lbl != null ? lbl : "done"); el.classList.add("pbar-done"); }
    function fail(msg) { el.classList.add("pbar-err"); if (msg != null) label.textContent = String(msg); }
    set(opts.pct != null ? opts.pct : 0, opts.label);
    return { el: el, set: set, done: done, fail: fail };
  }

  // Drive a progressBar from a server SSE stream of {op,label,pct,phase,error?} frames.
  //   streamProgress(url, bar, {onDone?, onError?}) → the EventSource (.close() to stop).
  // A frame carrying .error fails the bar and stops; phase==="done" (or pct>=100) completes it.
  function streamProgress(url, bar, opts) {
    opts = opts || {};
    const es = sse(url, function (d) {
      if (!d || typeof d !== "object") return;
      if (d.error) { bar.fail(String(d.error)); es.close(); if (opts.onError) opts.onError(d); return; }
      bar.set(typeof d.pct === "number" ? d.pct : null, d.label != null ? d.label : null);
      // Complete ONLY on an explicit done signal — a sub-phase hitting 100% (e.g. "layer 1 pulled:
      // 100%") must NOT close the stream and discard the phases that follow.
      if (d.phase === "done" || d.done === true) {
        bar.done(d.label != null ? d.label : null); es.close(); if (opts.onDone) opts.onDone(d);
      }
    }, function (e) {
      const s = e && e.target;
      if (s && s.readyState === EventSource.CLOSED) {
        bar.fail("stream disconnected"); if (opts.onError) opts.onError(new Error("stream closed"));
      }
    });
    return es;
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
      book: "M4 5a2 2 0 012-2h12v16H6a2 2 0 01-2-2zM18 3v16M8 7h6M8 11h6",
      info: "M12 8h.01M11 12h1v5h1M12 3a9 9 0 100 18 9 9 0 000-18z",
      clip: "M16 8l-6.5 6.5a2.5 2.5 0 003.5 3.5L20 11a4.5 4.5 0 10-6.4-6.4L6 12.2a6.5 6.5 0 009.2 9.2l4.3-4.3",
      link: "M10.5 13.5a4 4 0 005.7 0l2.8-2.8a4 4 0 10-5.7-5.7L12 6.3M13.5 10.5a4 4 0 00-5.7 0l-2.8 2.8a4 4 0 105.7 5.7L12 17.7",
      edit: "M4 20h4L19 9a2.1 2.1 0 00-3-3L5 17z M14 6l4 4",
      trash: "M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13",
    };
    return h("span.glyph", { html: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="' + (P[name] || P.dot) + '"/></svg>' });
  }

  window.VUI = { h: h, clear: clear, mount: mount, append: append, $: $, store: store,
    getJSON: getJSON, postJSON: postJSON, uploadChunked: uploadChunked, sse: sse, sseErrorToast: sseErrorToast,
    authUrl: authUrl,
    toast: toast, errorBanner: errorBanner, clearErrorBanner: clearErrorBanner,
    progressBar: progressBar, streamProgress: streamProgress, router: router,
    pill: pill, statusBadge: statusBadge, tile: tile, card: card, icon: icon, api: api, token: token,
    setSessionToken: setSessionToken, setPrincipal: setPrincipal, principal: principal, can: can };
})();
